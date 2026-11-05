"""Platform helpers: Windows + Linux arayüz/ağ bilgisi, süreç yönetimi."""
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time


def is_privileged():
    if sys.platform == 'win32':
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def stop_running_packetlens():
    me = os.getpid()
    if sys.platform == 'win32':
        try:
            subprocess.run([
                'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
                'Get-CimInstance Win32_Process | Where-Object { '
                '($_.Name -eq "python.exe" -or $_.Name -eq "python3.exe") -and '
                '$_.CommandLine -like "*packetlens.py*" -and $_.ProcessId -ne %d '
                '} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }' % me,
            ], capture_output=True, timeout=25)
        except Exception:
            pass
        time.sleep(0.6)
        return
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


def default_gateway_linux():
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


def interfaces_linux():
    res = []
    gw_if = default_gateway_linux()[0]
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


def net_info_linux():
    gi, gip = default_gateway_linux()
    dns = [l.split()[1] for l in _read('/etc/resolv.conf').split('\n') if l.startswith('nameserver') and len(l.split()) > 1]
    arp = []
    for line in _read('/proc/net/arp').split('\n')[1:]:
        f = line.split()
        if len(f) >= 6 and f[2] != '0x0' and f[3] != '00:00:00:00:00:00':
            arp.append({'ip': f[0], 'mac': f[3], 'iface': f[5]})
    return {'gateway': {'iface': gi, 'ip': gip}, 'dns': dns, 'arp': arp}


def _guess_kind(label):
    t = (label or '').lower()
    if 'wi-fi' in t or 'wifi' in t or 'wireless' in t or 'wlan' in t:
        return 'wifi'
    if 'loopback' in t:
        return 'loopback'
    if 'virtual' in t or 'vethernet' in t or 'hyper-v' in t or 'vmware' in t or 'virtualbox' in t:
        return 'virtual'
    return 'ethernet'


def interfaces_windows(dumpcap_ifaces=None):
    """dumpcap -D listesi varsa onu kullan (yakalama indeksleri); yoksa PowerShell."""
    res = []
    if dumpcap_ifaces:
        for row in dumpcap_ifaces:
            res.append({
                'name': row['id'],
                'state': 'up',
                'kind': _guess_kind(row.get('label', '')),
                'mac': '',
                'ipv4': '',
                'mask': '',
                'speed': None,
                'mtu': '',
                'rx': '0',
                'tx': '0',
                'default': row.get('default', False),
                'label': row.get('label', ''),
            })
        return res
    try:
        out = subprocess.check_output([
            'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
            'Get-NetAdapter | ForEach-Object { $_.Name + "|" + $_.Status + "|" + $_.MacAddress + "|" + $_.InterfaceDescription }',
        ], text=True, errors='replace', timeout=20)
        for line in out.splitlines():
            parts = line.strip().split('|')
            if len(parts) < 4:
                continue
            name, status, mac, desc = parts[0], parts[1], parts[2], parts[3]
            res.append({
                'name': name,
                'state': 'up' if status == 'Up' else 'down',
                'kind': _guess_kind(desc),
                'mac': (mac or '').replace('-', ':').lower(),
                'ipv4': '',
                'mask': '',
                'speed': None,
                'mtu': '',
                'rx': '0',
                'tx': '0',
                'default': False,
                'label': desc,
            })
    except Exception:
        pass
    return res


def _ifconfig_darwin(name):
    try:
        out = subprocess.check_output(['ifconfig', name], text=True, errors='replace', timeout=8)
    except Exception:
        return '', '', 'down'
    state = 'up' if re.search(r'status:\s*active', out, re.I) or re.match(r'\S+:\s*flags=\d+<[^>]*UP', out) else 'down'
    ipv4 = ''
    m = re.search(r'\binet (\d+\.\d+\.\d+\.\d+)', out)
    if m:
        ipv4 = m.group(1)
    mac = ''
    m = re.search(r'\bether ([0-9a-f:]+)', out, re.I)
    if m:
        mac = m.group(1).lower()
    return ipv4, mac, state


def interfaces_darwin(tcpdump_ifaces=None):
    res = []
    rows = tcpdump_ifaces or []
    if not rows:
        try:
            names = subprocess.check_output(['ifconfig', '-l'], text=True, timeout=8).split()
            rows = [{'id': n, 'label': n, 'state': 'up', 'default': i == 0} for i, n in enumerate(names)]
        except Exception:
            rows = []
    gi = net_info_darwin()['gateway'].get('iface') or ''
    for row in rows:
        name = row['id']
        ipv4, mac, st = _ifconfig_darwin(name)
        res.append({
            'name': name,
            'state': st if st else row.get('state', 'up'),
            'kind': _guess_kind(row.get('label', name)),
            'mac': mac,
            'ipv4': ipv4,
            'mask': '',
            'speed': None,
            'mtu': '',
            'rx': '0',
            'tx': '0',
            'default': name == gi or row.get('default', False),
            'label': row.get('label', name),
        })
    return res


def net_info_darwin():
    gi, gip = '', ''
    dns = []
    try:
        out = subprocess.check_output(['route', '-n', 'get', 'default'], text=True, errors='replace', timeout=8)
        for line in out.splitlines():
            if line.strip().startswith('interface:'):
                gi = line.split(':', 1)[1].strip()
            if line.strip().startswith('gateway:'):
                gip = line.split(':', 1)[1].strip()
    except Exception:
        pass
    try:
        out = subprocess.check_output(['scutil', '--dns'], text=True, errors='replace', timeout=8)
        for line in out.splitlines():
            m = re.search(r'nameserver\[0\] :\s*(\S+)', line)
            if m:
                dns.append(m.group(1))
    except Exception:
        pass
    return {'gateway': {'iface': gi, 'ip': gip}, 'dns': dns[:4], 'arp': []}


def net_info_windows():
    gip, gi = '', ''
    dns = []
    try:
        out = subprocess.check_output(['ipconfig'], text=True, errors='replace', timeout=15)
        for line in out.splitlines():
            m = re.search(r'Default Gateway[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', line, re.I)
            if m and not gip:
                gip = m.group(1)
        for line in out.splitlines():
            m = re.search(r'DNS Servers[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', line, re.I)
            if m:
                dns.append(m.group(1))
    except Exception:
        pass
    return {'gateway': {'iface': gi, 'ip': gip}, 'dns': dns, 'arp': []}


def list_interfaces(dumpcap_ifaces=None, tcpdump_ifaces=None):
    if sys.platform == 'win32':
        return interfaces_windows(dumpcap_ifaces)
    if sys.platform == 'darwin':
        return interfaces_darwin(tcpdump_ifaces)
    return interfaces_linux()


def network_info():
    if sys.platform == 'win32':
        return net_info_windows()
    if sys.platform == 'darwin':
        return net_info_darwin()
    return net_info_linux()
