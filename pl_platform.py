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


def list_interfaces(dumpcap_ifaces=None):
    if sys.platform == 'win32':
        return interfaces_windows(dumpcap_ifaces)
    return interfaces_linux()


def network_info():
    if sys.platform == 'win32':
        return net_info_windows()
    return net_info_linux()
