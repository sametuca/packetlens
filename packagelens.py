#!/usr/bin/env python3
"""PackageLens - Kali/Linux için canlı paket yakalama + yerel GUI sunucusu.

Kullanım:
    sudo python3 packagelens.py                 # arayüzü açar, canlı yakalama için root gerekir
    python3 packagelens.py --no-capture         # root olmadan sadece .pcap dosyası analizi
    sudo python3 packagelens.py -i eth0 --port 8765

Bağımlılık yok: yalnızca Python 3 standart kütüphanesi (AF_PACKET). Wireshark/libpcap gerekmez.
Sunucu sadece 127.0.0.1 üzerinde dinler ve rastgele bir erişim anahtarı (token) ister.
"""
import argparse, base64, json, os, secrets, socket, struct, subprocess, sys, threading, time, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from capfilter import compile_filter, FilterError

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = {'/': ('index.html', 'text/html; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8'),
          '/app.js': ('app.js', 'application/javascript; charset=utf-8'), '/parser.js': ('parser.js', 'application/javascript; charset=utf-8'),
          '/sample.js': ('sample.js', 'application/javascript; charset=utf-8'),
          '/filter.js': ('filter.js', 'application/javascript; charset=utf-8'),
          '/extras.js': ('extras.js', 'application/javascript; charset=utf-8'),
          '/views.js': ('views.js', 'application/javascript; charset=utf-8'),
          '/tools.js': ('tools.js', 'application/javascript; charset=utf-8'),
          '/features.js': ('features.js', 'application/javascript; charset=utf-8'),
          '/i18n.js': ('i18n.js', 'application/javascript; charset=utf-8'),
          '/lang-en.js': ('lang-en.js', 'application/javascript; charset=utf-8')}
SNAP = 1600           # paket başına saklanan en fazla bayt (başlıklar + TLS hello için yeterli)
MAX_PACKETS = 300000  # bellek koruması


class Capture:
    def __init__(self):
        self.lock = threading.Lock()
        self.packets = []   # (ts, orig_len, bytes)
        self.dropped = 0
        self.running = False
        self.iface = None
        self.error = None
        self.thread = None
        self.stop_ev = threading.Event()
        self.snap, self.max_packets, self.duration = SNAP, MAX_PACKETS, 0
        self.flt = None
        self.flt_text = ''

    def start(self, iface, flt_text='', snap=SNAP, max_packets=MAX_PACKETS, duration=0, promisc=True):
        self.stop()
        self.snap, self.max_packets, self.duration = snap, max_packets, duration
        self.flt = compile_filter(flt_text)   # FilterError çağırana gider
        self.flt_text = (flt_text or '').strip()
        with self.lock:
            self.packets, self.dropped, self.error = [], 0, None
        self.iface = iface
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            if iface and iface != 'any':
                s.bind((iface, 0))
                if promisc:   # Wireshark gibi: başka cihazlara giden trafiği de gör (PACKET_ADD_MEMBERSHIP / PACKET_MR_PROMISC)
                    try:
                        s.setsockopt(263, 1, struct.pack('iHH8s', socket.if_nametoindex(iface), 1, 0, b'\0' * 8))
                    except OSError:
                        pass
            s.settimeout(0.3)
        except PermissionError:
            self.error = 'Yakalama için root yetkisi gerekir. Şu şekilde başlatın: sudo python3 packagelens.py'
            return False
        except OSError as e:
            self.error = 'Arayüz açılamadı: %s' % e
            return False
        self.stop_ev.clear()
        self.running = True
        self.thread = threading.Thread(target=self._loop, args=(s,), daemon=True)
        self.thread.start()
        return True

    def _loop(self, s):
        t_end = time.time() + self.duration if self.duration else None
        try:
            while not self.stop_ev.is_set():
                if t_end and time.time() >= t_end:
                    break
                try:
                    data, addr = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if self.flt and not self.flt(data):
                    continue
                # lo arayüzünde her paket hem "giden" (PACKET_OUTGOING=4) hem "gelen" olarak görünür: kopyayı at
                if addr[0] == 'lo' and addr[2] == 4:
                    continue
                # PackageLens'in kendi arayüz trafiğini (127.0.0.1:<port>) yakalama: geri besleme döngüsü olmasın
                if SELF_PORT and len(data) >= 38 and data[12:14] == b'\x08\x00' and data[23] == 6 and data[26:34] == b'\x7f\x00\x00\x01\x7f\x00\x00\x01':
                    ihl = (data[14] & 15) * 4
                    if len(data) >= 14 + ihl + 4 and SELF_PORT in struct.unpack('!HH', data[14 + ihl:18 + ihl]):
                        continue
                with self.lock:
                    if len(self.packets) >= self.max_packets:
                        self.dropped += 1
                        continue
                    self.packets.append((time.time(), len(data), data[:self.snap]))
        finally:
            s.close()
            self.running = False

    def stop(self):
        self.stop_ev.set()
        if self.thread:
            self.thread.join(timeout=1.5)
        self.thread = None
        self.running = False

    def poll(self, since):
        with self.lock:
            chunk = self.packets[since:since + 3000]
            total = len(self.packets)
        return {'running': self.running, 'iface': self.iface, 'filter': self.flt_text, 'error': self.error, 'total': total, 'dropped': self.dropped,
                'since': since, 'packets': [[round(t, 6), n, base64.b64encode(d).decode()] for t, n, d in chunk]}

    def pcap_bytes(self):
        with self.lock:
            pk = list(self.packets)
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        for t, n, d in pk:
            sec = int(t)
            out.append(struct.pack('<IIII', sec, int((t - sec) * 1e6), len(d), n) + d)
        return b''.join(out)


CAP = Capture()
ARGS = None
SELF_PORT = 0
TOKEN = secrets.token_urlsafe(16)


def _read(path, default=''):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def _ioctl_ip(name, req):
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


def _hex_ip(h):
    try:
        return socket.inet_ntoa(struct.pack('<I', int(h, 16)))
    except Exception:
        return ''


def interfaces():
    """Ağ adaptörleri: ad, durum, tür, MAC, IPv4, hız, MTU, sayaçlar, varsayılan çıkış mı."""
    res = []
    gw_if = default_gateway()[0]
    try:
        names = sorted(os.listdir('/sys/class/net'))
    except OSError:
        names = []
    for n in names:
        base = '/sys/class/net/%s/' % n
        kind = 'loopback' if n == 'lo' else 'wifi' if os.path.isdir(base + 'wireless') or os.path.isdir(base + 'phy80211') \
            else 'virtual' if os.path.exists('/sys/devices/virtual/net/%s' % n) else 'ethernet'
        try:
            speed = int(_read(base + 'speed', '-1'))
        except ValueError:
            speed = -1
        res.append({'name': n, 'state': _read(base + 'operstate', '?'), 'kind': kind, 'mac': _read(base + 'address'),
                    'ipv4': _ioctl_ip(n, 0x8915), 'mask': _ioctl_ip(n, 0x891b), 'speed': speed if speed > 0 else None,
                    'mtu': _read(base + 'mtu'), 'rx': _read(base + 'statistics/rx_bytes'), 'tx': _read(base + 'statistics/tx_bytes'),
                    'default': n == gw_if})
    return res


def default_gateway():
    for line in _read('/proc/net/route').split('\n')[1:]:
        f = line.split()
        if len(f) > 3 and f[1] == '00000000' and int(f[3], 16) & 2:
            return f[0], _hex_ip(f[2])
    return '', ''


def net_info():
    """Bağlı olunan ağ: varsayılan ağ geçidi, DNS sunucuları ve ARP tablosundaki komşular."""
    gi, gip = default_gateway()
    dns = [l.split()[1] for l in _read('/etc/resolv.conf').split('\n') if l.startswith('nameserver') and len(l.split()) > 1]
    arp = []
    for line in _read('/proc/net/arp').split('\n')[1:]:
        f = line.split()
        if len(f) >= 6 and f[2] != '0x0' and f[3] != '00:00:00:00:00:00':
            arp.append({'ip': f[0], 'mac': f[3], 'iface': f[5]})
    return {'gateway': {'iface': gi, 'ip': gip}, 'dns': dns, 'arp': arp}


class H(BaseHTTPRequestHandler):
    server_version = 'PackageLens'

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='application/json; charset=utf-8', extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self):
        # DNS rebinding koruması: yalnızca localhost / 127.0.0.1 Host başlıklarını kabul et
        host = (self.headers.get('Host') or '').rsplit(':', 1)[0]
        return host in ('127.0.0.1', 'localhost')

    def _handle(self, method):
        if not self._host_ok():
            return self._send(403, {'error': 'host'})
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in STATIC and method == 'GET':
            name, ctype = STATIC[u.path]
            p = os.path.join(HERE, name)
            if not os.path.exists(p):
                return self._send(404, {'error': 'yok'})
            with open(p, 'rb') as f:
                return self._send(200, f.read(), ctype)
        if not u.path.startswith('/api/'):
            return self._send(404, {'error': 'yok'})
        if not secrets.compare_digest(q.get('t', [''])[0], TOKEN):
            return self._send(401, {'error': 'token'})
        if u.path == '/api/info':
            return self._send(200, {'interfaces': interfaces(), 'root': os.geteuid() == 0, 'capture': not ARGS.no_capture, 'default_iface': ARGS.iface})
        if u.path == '/api/net':
            return self._send(200, net_info())
        if u.path == '/api/start' and method == 'POST':
            if ARGS.no_capture:
                return self._send(400, {'error': 'Canlı yakalama kapalı (--no-capture).'})
            iface = q.get('iface', ['any'])[0]
            if iface != 'any' and iface not in [i['name'] for i in interfaces()]:
                return self._send(400, {'error': 'Geçersiz arayüz'})
            def num(name, default, lo, hi):
                try:
                    return min(hi, max(lo, int(q.get(name, [default])[0])))
                except ValueError:
                    return default
            try:
                ok = CAP.start(iface, q.get('filter', [''])[0][:300], num('snap', SNAP, 64, 65535), num('max', MAX_PACKETS, 1000, 2000000),
                               num('duration', 0, 0, 86400), q.get('promisc', ['1'])[0] != '0')
            except FilterError as e:
                return self._send(400, {'ok': False, 'error': 'Yakalama filtresi hatası: %s' % e})
            return self._send(200 if ok else 400, {'ok': ok, 'error': CAP.error})
        if u.path == '/api/stop' and method == 'POST':
            CAP.stop()
            return self._send(200, {'ok': True})
        if u.path == '/api/poll':
            try:
                since = max(0, int(q.get('since', ['0'])[0]))
            except ValueError:
                since = 0
            return self._send(200, CAP.poll(since))
        if u.path == '/api/save':
            fn = time.strftime('capture-%Y%m%d-%H%M%S.pcap')
            return self._send(200, CAP.pcap_bytes(), 'application/vnd.tcpdump.pcap', {'Content-Disposition': 'attachment; filename="%s"' % fn})
        return self._send(404, {'error': 'yok'})

    def do_GET(self): self._handle('GET')
    def do_POST(self): self._handle('POST')


def open_browser(url):
    """root olarak çalışıyorsak tarayıcıyı normal kullanıcı olarak aç (Firefox root'u sevmez)."""
    user = os.environ.get('SUDO_USER')
    try:
        if os.geteuid() == 0 and user and user != 'root':
            env = {k: v for k, v in os.environ.items() if k in ('DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'XAUTHORITY', 'PATH')}
            env.setdefault('XAUTHORITY', os.path.expanduser('~%s/.Xauthority' % user))
            subprocess.Popen(['sudo', '-u', user, '--preserve-env=DISPLAY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR,XAUTHORITY', 'xdg-open', url],
                             env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        webbrowser.open(url)
    except Exception:
        pass


def main():
    global ARGS, SELF_PORT
    ap = argparse.ArgumentParser(description='PackageLens - kolay kullanımlı paket analizcisi')
    ap.add_argument('-i', '--iface', default='any', help='varsayılan arayüz (any = hepsi)')
    ap.add_argument('--port', type=int, default=8765)
    ap.add_argument('--no-capture', action='store_true', help='canlı yakalamayı kapat (root gerekmez)')
    ap.add_argument('--no-browser', action='store_true', help='tarayıcıyı otomatik açma')
    ARGS = ap.parse_args()
    if not sys.platform.startswith('linux') and not ARGS.no_capture:
        print('Uyarı: canlı yakalama yalnızca Linux’ta çalışır; --no-capture ile devam ediliyor.')
        ARGS.no_capture = True
    if not ARGS.no_capture and os.geteuid() != 0:
        print('Not: root değilsiniz, canlı yakalama başlatılamaz (dosya analizi çalışır). Canlı yakalama için: sudo python3 packagelens.py')
    srv = ThreadingHTTPServer(('127.0.0.1', ARGS.port), H)
    SELF_PORT = srv.server_address[1]
    url = 'http://127.0.0.1:%d/?t=%s' % (SELF_PORT, TOKEN)
    print('PackageLens çalışıyor → %s' % url)
    print('Durdurmak için Ctrl+C')
    if not ARGS.no_browser:
        threading.Timer(0.5, open_browser, (url,)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        CAP.stop()
        srv.server_close()


if __name__ == '__main__':
    main()
