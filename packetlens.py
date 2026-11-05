#!/usr/bin/env python3
"""PacketLens - Kali/Linux için canlı paket yakalama + yerel GUI sunucusu.

Kullanım:
    sudo python3 packetlens.py                 # arayüzü açar, canlı yakalama için root gerekir
    python3 packetlens.py --no-capture         # root olmadan sadece .pcap dosyası analizi
    sudo python3 packetlens.py -i eth0 --port 8765

Bağımlılık yok: yalnızca Python 3 standart kütüphanesi (AF_PACKET). Wireshark/libpcap gerekmez.
Sunucu sadece 127.0.0.1 üzerinde dinler (localhost).
"""
import argparse, base64, json, os, signal, socket, struct, subprocess, sys, threading, time, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import urllib.error
import urllib.request

from capfilter import compile_filter, FilterError
from ptentes import PT as PTENTES
from deviceintel import REGISTRY as DEVICE_REG, scheduled_scan_loop

HERE = os.path.dirname(os.path.abspath(__file__))

def local_commit():
    """Çalışan kopyanın git HEAD özeti (kısa sha). Repo değilse veya git yoksa None."""
    try:
        r = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=HERE, capture_output=True, text=True, timeout=2)
        h = r.stdout.strip()
        return h if r.returncode == 0 and h else None
    except Exception:
        return None


LOCAL_COMMIT = local_commit()
STATIC = {'/': ('index.html', 'text/html; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8'),
          '/app.js': ('app.js', 'application/javascript; charset=utf-8'), '/parser.js': ('parser.js', 'application/javascript; charset=utf-8'),
          '/tlspassive.js': ('tlspassive.js', 'application/javascript; charset=utf-8'),
          '/sample.js': ('sample.js', 'application/javascript; charset=utf-8'),
          '/filter.js': ('filter.js', 'application/javascript; charset=utf-8'),
          '/extras.js': ('extras.js', 'application/javascript; charset=utf-8'),
          '/views.js': ('views.js', 'application/javascript; charset=utf-8'),
          '/tools.js': ('tools.js', 'application/javascript; charset=utf-8'),
          '/features.js': ('features.js', 'application/javascript; charset=utf-8'),
          '/i18n.js': ('i18n.js', 'application/javascript; charset=utf-8'),
          '/ptentes-ui.js': ('ptentes-ui.js', 'application/javascript; charset=utf-8'),
          '/lang-en.js': ('lang-en.js', 'application/javascript; charset=utf-8'),
          '/update.js': ('update.js', 'application/javascript; charset=utf-8'),
          '/oui.json': ('oui.json', 'application/json; charset=utf-8')}
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
            self.error = 'Yakalama için root yetkisi gerekir. Şu şekilde başlatın: sudo python3 packetlens.py'
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
                # PacketLens'in kendi arayüz trafiğini (127.0.0.1:<port>) yakalama: geri besleme döngüsü olmasın
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
        if len(f) <= 3 or f[1] != '00000000':
            continue
        try:
            if int(f[3], 16) & 2:
                return f[0], _hex_ip(f[2])
        except ValueError:
            continue
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
    server_version = 'PacketLens'

    def log_message(self, *a):
        pass

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header('Location', loc)
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()

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
        # DNS rebinding koruması: yalnızca localhost Host başlıklarını kabul et
        raw = (self.headers.get('Host') or '').strip().lower()
        if not raw:
            return False
        if raw.startswith('['):
            host = raw.split(']', 1)[0][1:]
        elif raw.count(':') == 1 and raw.rsplit(':', 1)[1].isdigit():
            host = raw.rsplit(':', 1)[0]
        else:
            host = raw
        return host in ('127.0.0.1', 'localhost', '::1')

    def _json(self):
        try:
            n = max(0, min(1 << 20, int(self.headers.get('Content-Length') or 0)))
            raw = self.rfile.read(n) if n else b''
            j = json.loads(raw.decode('utf-8')) if raw else {}
            return j if isinstance(j, dict) else {}
        except Exception:
            return {}

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
        if u.path == '/api/info':
            try:
                payload = {'interfaces': interfaces(), 'root': os.geteuid() == 0, 'capture': not ARGS.no_capture,
                           'default_iface': ARGS.iface, 'commit': LOCAL_COMMIT, 'repo': 'sametuca/packetlens', 'platform': sys.platform}
                return self._send(200, payload)
            except Exception as e:
                sys.stderr.write('PacketLens /api/info hatası: %s\n' % e)
                return self._send(500, {'error': 'info', 'detail': str(e)})
        if u.path == '/api/net':
            ni = net_info()
            DEVICE_REG.merge_arp(ni.get('arp'))
            return self._send(200, ni)
        if u.path == '/api/devices/registry':
            ni = net_info()
            DEVICE_REG.merge_arp(ni.get('arp'))
            st = PTENTES.status()
            if st.get('hosts'):
                DEVICE_REG.merge_ptentes(st.get('hosts'))
            gw = (ni.get('gateway') or {}).get('ip') or ''
            return self._send(200, DEVICE_REG.snapshot(gw))
        if u.path == '/api/devices/history':
            return self._send(200, {'history': DEVICE_REG.history})
        if u.path == '/api/devices/compare':
            try:
                a = int(q.get('a', ['-2'])[0])
                b = int(q.get('b', ['-1'])[0])
            except ValueError:
                a, b = -2, -1
            return self._send(200, DEVICE_REG.compare_history(a, b))
        if u.path == '/api/devices/scan' and method == 'POST':
            body = self._json()
            try:
                st = PTENTES.status()
                pt_h = st.get('hosts') if st.get('running') else None
                r = DEVICE_REG.scan(body, pt_hosts=pt_h)
            except Exception as e:
                r = {'ok': False, 'error': str(e)}
            return self._send(200 if r.get('ok') else 400, r)
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
        if u.path.startswith('/api/ptentes/'):
            return self._ptentes(u.path, method)
        if u.path == '/api/save':
            fn = time.strftime('capture-%Y%m%d-%H%M%S.pcap')
            return self._send(200, CAP.pcap_bytes(), 'application/vnd.tcpdump.pcap', {'Content-Disposition': 'attachment; filename="%s"' % fn})
        return self._send(404, {'error': 'yok'})

    def _ptentes(self, path, method):
        name = path[len('/api/ptentes/'):]
        if name == 'status':
            return self._send(200, PTENTES.status())
        if name == 'report':
            fn = time.strftime('ptentes-%Y%m%d-%H%M%S.json')
            return self._send(200, json.dumps(PTENTES.report(), indent=2),
                              'application/json; charset=utf-8',
                              {'Content-Disposition': 'attachment; filename="%s"' % fn})
        if name == 'discover' and method == 'POST':
            body = self._json()
            try:
                r = PTENTES.discover(body.get('iface') or '')
            except Exception as e:
                r = {'ok': False, 'error': str(e)}
            return self._send(200 if r.get('ok') else 400, r)
        if name == 'start' and method == 'POST':
            body = self._json()
            try:
                r = PTENTES.start(body)
            except Exception as e:
                r = {'ok': False, 'error': 'Başlatılamadı: %s' % e}
            return self._send(200 if r.get('ok') else 400, r)
        if name == 'stop' and method == 'POST':
            return self._send(200, PTENTES.stop())
        if name == 'dnsmap' and method == 'POST':
            body = self._json()
            m = PTENTES.set_dns_map(body.get('map') or {})
            return self._send(200, {'ok': True, 'map': m})
        return self._send(404, {'error': 'yok'})

    def do_GET(self): self._handle('GET')
    def do_POST(self): self._handle('POST')


def _probe_api(port):
    """Porttaki /api/info durumu: ok | stale_token | busy | closed."""
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/api/info' % port, timeout=1.2) as r:
            data = json.loads(r.read().decode('utf-8'))
        if data.get('repo') == 'sametuca/packetlens':
            return 'ok', data
        return 'busy', None
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return 'stale_token', None
        return 'busy', None
    except Exception:
        return 'closed', None


def stop_running_packetlens():
    """Arka planda kalan packetlens.py süreçlerini sonlandır (kendi PID hariç)."""
    me = os.getpid()
    try:
        r = subprocess.run(['pgrep', '-f', 'packetlens.py'], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line.isdigit():
                continue
            pid = int(line)
            if pid == me:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        time.sleep(0.8)
    except Exception:
        pass


def _running_instance_url(port):
    """Aynı portta güncel sunucumuz zaten çalışıyor mu? Çalışıyorsa adresini döner."""
    st, _ = _probe_api(port)
    if st == 'ok':
        return 'http://127.0.0.1:%d/' % port
    if st == 'stale_token':
        print('Uyarı: %d portunda eski PacketLens (token’lı sürüm) çalışıyor.' % port)
        print('  Yeniden başlatın: ./start.sh --restart   veya: pkill -f packetlens.py')
    return None


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
    ap = argparse.ArgumentParser(description='PacketLens - kolay kullanımlı paket analizcisi')
    ap.add_argument('-i', '--iface', default='any', help='varsayılan arayüz (any = hepsi)')
    ap.add_argument('--port', type=int, default=8765)
    ap.add_argument('--no-capture', action='store_true', help='canlı yakalamayı kapat (root gerekmez)')
    ap.add_argument('--no-browser', action='store_true', help='tarayıcıyı otomatik açma')
    ap.add_argument('--restart', action='store_true',
                      help='çalışan eski packetlens sürecini kapatıp bu oturumu ön planda başlat')
    ap.add_argument('--attach', action='store_true',
                      help='zaten çalışıyorsa yeni süreç başlatma, yalnızca tarayıcıyı aç ve çık')
    ap.add_argument('--keep-running', action='store_true',
                      help='--attach ile aynı: arka plandaki sürece dokunma')
    ap.add_argument('--scan-interval', type=int, default=0, metavar='DK',
                    help='dakikada bir ARP cihaz taraması (0=kapalı, root gerekir)')
    ARGS = ap.parse_args()
    scan_stop = threading.Event()
    if not sys.platform.startswith('linux') and not ARGS.no_capture:
        print('Uyarı: canlı yakalama yalnızca Linux’ta çalışır; --no-capture ile devam ediliyor.')
        ARGS.no_capture = True
    if not ARGS.no_capture and os.geteuid() != 0:
        print('Not: root değilsiniz, canlı yakalama başlatılamaz (dosya analizi çalışır). Canlı yakalama için: sudo python3 packetlens.py')

    if ARGS.restart:
        stop_running_packetlens()

    running = None if ARGS.restart else _running_instance_url(ARGS.port)
    if running and (ARGS.attach or ARGS.keep_running):
        print('PacketLens zaten çalışıyor → %s' % running)
        print('(Arka plandaki süreç çalışmaya devam eder; durdurmak: pkill -f packetlens.py)')
        if not ARGS.no_browser:
            threading.Timer(0.3, open_browser, (running,)).start()
        sys.exit(10)

    if running:
        print('Eski PacketLens süreci kapatılıyor…')
        stop_running_packetlens()

    srv, port = None, ARGS.port
    for _ in range(20):
        try:
            srv = ThreadingHTTPServer(('127.0.0.1', port), H)
            break
        except OSError:
            if port == ARGS.port:
                st, _ = _probe_api(port)
                if st in ('stale_token', 'busy', 'ok'):
                    print('Hata: %d portu meşgul. Deneyin: pkill -f packetlens.py  veya  python3 packetlens.py --restart' % port)
                    sys.exit(1)
            port += 1
    if srv is None:
        print('Boş port bulunamadı (%d - %d arası denendi).' % (ARGS.port, port - 1))
        return
    SELF_PORT = srv.server_address[1]
    url = 'http://127.0.0.1:%d/' % SELF_PORT
    if SELF_PORT != ARGS.port:
        print('Not: %d portu doluydu, %d kullanılıyor.' % (ARGS.port, SELF_PORT))
    print('PacketLens çalışıyor → %s' % url)
    print('Durdurmak için Ctrl+C')
    if not ARGS.no_browser:
        threading.Timer(0.5, open_browser, (url,)).start()
    if ARGS.scan_interval > 0 and os.geteuid() == 0 and sys.platform.startswith('linux'):
        iface = ARGS.iface if ARGS.iface != 'any' else (default_gateway()[0] or 'eth0')
        threading.Thread(target=scheduled_scan_loop, args=(iface, max(60, ARGS.scan_interval * 60), scan_stop), daemon=True).start()
        print('Zamanlanmış ARP taraması: her %d dk (%s)' % (ARGS.scan_interval, iface))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        scan_stop.set()
        CAP.stop()
        PTENTES.stop()
        srv.server_close()


if __name__ == '__main__':
    main()
