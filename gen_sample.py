#!/usr/bin/env python3
"""Örnek bir .pcap üretir (sample.pcap + sample.js). Yalnızca standart kütüphane kullanır."""
import struct, base64, random, os

random.seed(7)
T0 = 1730000000.0
PK = []

MAC = {
    '192.168.1.23': 'aa:bb:cc:00:00:23',
    '192.168.1.1': 'aa:bb:cc:00:00:01',
    '192.168.1.5': 'aa:bb:cc:00:00:05',
    '192.168.1.50': 'aa:bb:cc:00:00:50',
    '192.168.1.99': 'aa:bb:cc:00:00:99',
}
CLI, GW, NAS, SCAN = '192.168.1.23', '192.168.1.1', '192.168.1.5', '192.168.1.99'
SYN_OPTS = b'\x02\x04\x05\xb4\x01\x01\x04\x02\x01\x03\x03\x07'
FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16


def add(t, b):
    PK.append((T0 + t, b))


def m(s): return bytes(int(x, 16) for x in s.split(':'))
def ip(s): return bytes(int(x) for x in s.split('.'))
def mac_of(a): return MAC.get(a, MAC[GW])
def eth(src, dst, t, pl, dmac=None): return m(dmac or mac_of(dst)) + m(mac_of(src)) + struct.pack('!H', t) + pl


def ipv4(src, dst, proto, pl, ttl=64):
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(pl), random.getrandbits(16), 0x4000, ttl, proto, 0, ip(src), ip(dst)) + pl


def tcp(sp, dp, seq, ack, fl, pl=b'', win=64240, opts=b''):
    return struct.pack('!HHIIBBHHH', sp, dp, seq, ack, ((20 + len(opts)) // 4) << 4, fl, win, 0, 0) + opts + pl


def udp(sp, dp, pl): return struct.pack('!HHHH', sp, dp, 8 + len(pl), 0) + pl


def udp_pkt(t, src, dst, sp, dp, pl, dmac=None):
    add(t, eth(src, dst, 0x0800, ipv4(src, dst, 17, udp(sp, dp, pl)), dmac))


def dname(n): return b''.join(bytes([len(l)]) + l.encode() for l in n.split('.')) + b'\0'


def dns_q(i, name, qt=1): return struct.pack('!HHHHHH', i, 0x0100, 1, 0, 0, 0) + dname(name) + struct.pack('!HH', qt, 1)


def dns_r(i, name, ips, rcode=0):
    b = struct.pack('!HHHHHH', i, 0x8180 | rcode, 1, len(ips), 0, 0) + dname(name) + struct.pack('!HH', 1, 1)
    for a in ips:
        b += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + ip(a)
    return b


def dns(t, name, ips, lat, rcode=0):
    i = random.getrandbits(16)
    sp = random.randint(40000, 60000)
    udp_pkt(t, CLI, GW, sp, 53, dns_q(i, name))
    udp_pkt(t + lat, GW, CLI, 53, sp, dns_r(i, name, ips, rcode))


def rnd(n): return bytes(random.getrandbits(8) for _ in range(n))


def client_hello(sni):
    n = sni.encode()
    sn = struct.pack('!BH', 0, len(n)) + n
    snl = struct.pack('!H', len(sn)) + sn
    ext = struct.pack('!HH', 0, len(snl)) + snl
    body = b'\x03\x03' + rnd(32) + b'\x00' + struct.pack('!H', 4) + b'\x13\x01\x13\x02' + b'\x01\x00' + struct.pack('!H', len(ext)) + ext
    hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs


def server_hello():
    body = b'\x03\x03' + rnd(32) + b'\x00' + b'\x13\x01' + b'\x00' + b'\x00\x00'
    hs = b'\x02' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x03' + struct.pack('!H', len(hs)) + hs


def cert(n=1200):
    hs = b'\x0b' + struct.pack('!I', n)[1:] + rnd(n)
    return b'\x16\x03\x03' + struct.pack('!H', len(hs)) + hs


def appdata(n): return b'\x17\x03\x03' + struct.pack('!H', n) + rnd(n)


class Conn:
    def __init__(s, t, c, sv, cp, sp, rtt):
        s.t, s.c, s.s, s.cp, s.sp, s.rtt = t, c, sv, cp, sp, rtt
        s.cseq = random.getrandbits(31)
        s.sseq = random.getrandbits(31)

    def send(s, frm, fl, pl=b'', dt=0.0, seq=None, win=64240, opts=b''):
        s.t += dt
        if frm == 'c':
            sq = s.cseq if seq is None else seq
            ak = s.sseq if fl & ACK else 0
            add(s.t, eth(s.c, s.s, 0x0800, ipv4(s.c, s.s, 6, tcp(s.cp, s.sp, sq, ak, fl, pl, win, opts))))
            if seq is None:
                s.cseq = (s.cseq + len(pl) + (1 if fl & 3 else 0)) & 0xffffffff
        else:
            sq = s.sseq if seq is None else seq
            ak = s.cseq if fl & ACK else 0
            add(s.t, eth(s.s, s.c, 0x0800, ipv4(s.s, s.c, 6, tcp(s.sp, s.cp, sq, ak, fl, pl, win, opts))))
            if seq is None:
                s.sseq = (s.sseq + len(pl) + (1 if fl & 3 else 0)) & 0xffffffff
        return sq

    def handshake(s):
        s.send('c', SYN, opts=SYN_OPTS)
        s.send('s', SYN | ACK, dt=s.rtt, opts=SYN_OPTS)
        s.send('c', ACK, dt=0.0002)

    def close(s):
        s.send('c', FIN | ACK, dt=0.01)
        s.send('s', FIN | ACK, dt=s.rtt)
        s.send('c', ACK, dt=0.0002)


def port():
    return random.randint(40000, 60000)


# 1) ARP
add(0.00, eth(CLI, GW, 0x0806, struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, m(MAC[CLI]), ip(CLI), b'\0' * 6, ip(GW)), 'ff:ff:ff:ff:ff:ff'))
add(0.003, eth(GW, CLI, 0x0806, struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 2, m(MAC[GW]), ip(GW), m(MAC[CLI]), ip(CLI))))

# 2) HTTPS - www.google.com (sağlıklı, hızlı)
dns(0.5, 'www.google.com', ['142.250.74.46'], 0.012)
c = Conn(0.52, CLI, '142.250.74.46', port(), 443, 0.020)
c.handshake()
c.send('c', PSH | ACK, client_hello('www.google.com'), dt=0.001)
c.send('s', ACK, dt=0.020)
c.send('s', PSH | ACK, server_hello(), dt=0.002)
c.send('s', PSH | ACK, cert(), dt=0.001)
c.send('c', PSH | ACK, appdata(120), dt=0.02)
for i in range(40):
    c.send('s', ACK, appdata(1400), dt=0.002)
    if i % 2:
        c.send('c', ACK, dt=0.0005)
c.close()

# 3) HTTP - example.com (düz metin)
dns(2.0, 'example.com', ['93.184.216.34'], 0.015)
c = Conn(2.02, CLI, '93.184.216.34', port(), 80, 0.030)
c.handshake()
c.send('c', PSH | ACK, b'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5\r\nAccept: */*\r\n\r\n', dt=0.001)
body = b'<html><body>Example Domain</body></html>' * 20
c.send('s', PSH | ACK, b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n' % len(body) + body, dt=0.035)
c.send('c', ACK, dt=0.0005)
c.close()

# 4) Yavaş DNS + kayıplı bağlantı (retransmission + zero window)
dns(4.0, 'api.slow-service.net', ['104.18.32.7'], 0.65)
c = Conn(4.7, CLI, '104.18.32.7', port(), 443, 0.180)
c.handshake()
c.send('c', PSH | ACK, client_hello('api.slow-service.net'), dt=0.001)
c.send('s', PSH | ACK, server_hello(), dt=0.18)
c.send('s', PSH | ACK, cert(), dt=0.001)
seqs = []
for i in range(12):
    sq = c.send('s', ACK, appdata(1400), dt=0.01)
    seqs.append(sq)
    if i % 2:
        c.send('c', ACK, dt=0.0005)
for sq in (seqs[3], seqs[4], seqs[7]):
    c.send('s', ACK, appdata(1400), dt=0.4, seq=sq)
c.send('c', ACK, dt=0.01, win=0)
c.send('c', ACK, dt=0.3)
c.close()

# 5) Var olmayan alan adı
dns(6.5, 'nonexistent.invalid', [], 0.03, rcode=3)

# 6) Yanıtsız SYN (3 deneme)
s_seq = random.getrandbits(31)
sp6 = port()
for dt in (0.0, 1.0, 3.0):
    add(7.0 + dt, eth(CLI, '10.9.9.9', 0x0800, ipv4(CLI, '10.9.9.9', 6, tcp(sp6, 8080, s_seq, 0, SYN, b'', 64240, SYN_OPTS))))

# 7) Bağlantı sıfırlama (RST)
dns(9.0, 'pages.example-cdn.com', ['185.199.108.153'], 0.02)
c = Conn(9.03, CLI, '185.199.108.153', port(), 443, 0.025)
c.handshake()
c.send('c', PSH | ACK, client_hello('pages.example-cdn.com'), dt=0.001)
c.send('s', RST | ACK, dt=0.03)

# 8) UDP -> ICMP "port ulaşılamaz"
sp8 = port()
payload = b'hello'
inner_ip = ipv4(CLI, '192.168.1.50', 17, udp(sp8, 5000, payload))
udp_pkt(11.0, CLI, '192.168.1.50', sp8, 5000, payload)
icmp = struct.pack('!BBHI', 3, 3, 0, 0) + inner_ip[:20] + udp(sp8, 5000, payload)[:8]
add(11.002, eth('192.168.1.50', CLI, 0x0800, ipv4('192.168.1.50', CLI, 1, icmp)))

# 9) NTP, mDNS
udp_pkt(12.0, CLI, '162.159.200.1', 123, 123, b'\x23' + b'\0' * 47)
udp_pkt(12.04, '162.159.200.1', CLI, 123, 123, b'\x24\x01\x03\xec' + b'\0' * 44)
udp_pkt(12.5, CLI, '224.0.0.251', 5353, 5353, dns_q(0, '_googlecast._tcp.local', 12), dmac='01:00:5e:00:00:fb')

# 10) QUIC (UDP/443)
qp = port()
for i in range(25):
    udp_pkt(13.0 + i * 0.005, CLI, '142.250.74.46', qp, 443, b'\xc3' + rnd(1199))
    udp_pkt(13.0 + i * 0.005 + 0.02, '142.250.74.46', CLI, 443, qp, b'\x43' + rnd(1100))

# 11) SSH
c = Conn(15.0, CLI, NAS, port(), 22, 0.002)
c.handshake()
c.send('s', PSH | ACK, b'SSH-2.0-OpenSSH_9.6\r\n', dt=0.001)
c.send('c', PSH | ACK, b'SSH-2.0-OpenSSH_9.7\r\n', dt=0.001)
for _ in range(6):
    c.send('c', PSH | ACK, rnd(96), dt=0.01)
    c.send('s', PSH | ACK, rnd(96), dt=0.003)
c.close()

# 12) Port taraması (192.168.1.99 -> 192.168.1.23)
for i, dp in enumerate(range(20, 46)):
    sp = 50000 + i
    sq = random.getrandbits(31)
    t = 17.0 + i * 0.01
    add(t, eth(SCAN, CLI, 0x0800, ipv4(SCAN, CLI, 6, tcp(sp, dp, sq, 0, SYN, b'', 1024))))
    add(t + 0.0003, eth(CLI, SCAN, 0x0800, ipv4(CLI, SCAN, 6, tcp(dp, sp, 0, sq + 1, RST | ACK, b'', 0))))

# 13) Ping
for i in range(3):
    t = 19.0 + i
    add(t, eth(CLI, GW, 0x0800, ipv4(CLI, GW, 1, struct.pack('!BBHHH', 8, 0, 0, 1, i) + rnd(48))))
    add(t + 0.004, eth(GW, CLI, 0x0800, ipv4(GW, CLI, 1, struct.pack('!BBHHH', 0, 0, 0, 1, i) + rnd(48))))

PK.sort(key=lambda x: x[0])
out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
for ts, b in PK:
    sec = int(ts)
    out += struct.pack('<IIII', sec, int((ts - sec) * 1e6), len(b), len(b)) + b

here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, 'sample.pcap'), 'wb') as f:
    f.write(out)
with open(os.path.join(here, 'sample.js'), 'w') as f:
    f.write('window.SAMPLE_PCAP_B64="%s";\n' % base64.b64encode(out).decode())
print('sample.pcap: %d paket, %d bayt' % (len(PK), len(out)))
