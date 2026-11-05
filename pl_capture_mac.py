"""macOS canlı yakalama: sistem tcpdump (monitör modu gerekmez)."""
import os
import re
import subprocess
import sys
import threading

from pl_pcap_stream import pcap_stdout_loop, stop_subproc_capture


def find_tcpdump():
    if sys.platform != 'darwin':
        return None
    for p in (
        '/usr/sbin/tcpdump',
        '/sbin/tcpdump',
    ):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    try:
        r = subprocess.run(['which', 'tcpdump'], capture_output=True, text=True, timeout=5)
        p = r.stdout.strip()
        if r.returncode == 0 and p and os.path.isfile(p):
            return p
    except Exception:
        pass
    return None


def list_tcpdump_interfaces(tcpdump=None):
    td = tcpdump or find_tcpdump()
    if not td:
        return []
    try:
        out = subprocess.check_output([td, '-D'], text=True, stderr=subprocess.STDOUT, timeout=15)
    except Exception:
        return []
    res = []
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r'^(\d+)\.(\S+)(?:\s+(.*))?$', line)
        if not m:
            continue
        name, extra = m.group(2), (m.group(3) or '').strip()
        up = 'down' not in extra.lower() or '[up' in extra.lower()
        res.append({
            'id': name,
            'label': (name + (' ' + extra if extra else '')).strip(),
            'default': len(res) == 0 and name != 'lo0',
            'state': 'up' if up or name == 'lo0' else 'down',
        })
    return res


def _resolve_iface(iface, ifaces):
    if not iface or iface == 'any':
        for row in ifaces:
            if row['id'] not in ('lo0', 'lo') and row.get('state') != 'down':
                return row['id']
        return ifaces[0]['id'] if ifaces else 'en0'
    for row in ifaces:
        if row['id'] == iface or row.get('label') == iface:
            return row['id']
    return iface


def start_mac_capture(capture, iface, flt_text, snap, max_packets, duration, promisc):
    td = find_tcpdump()
    if not td:
        capture.error = 'tcpdump bulunamadı. Xcode Command Line Tools: xcode-select --install'
        return False
    ifaces = list_tcpdump_interfaces(td)
    if not ifaces:
        capture.error = 'Arayüz listesi alınamadı. sudo ile başlatın: sudo python3 packetlens.py'
        return False
    capture.stop()
    capture.snap, capture.max_packets, capture.duration = snap, max_packets, duration
    from capfilter import compile_filter
    capture.flt = compile_filter(flt_text)
    capture.flt_text = (flt_text or '').strip()
    with capture.lock:
        capture.packets, capture.dropped, capture.error = [], 0, None
    if_name = _resolve_iface(iface, ifaces)
    capture.iface = if_name
    cmd = [td, '-i', if_name, '-s', str(snap), '-w', '-', '-U', '-n', '-q']
    if not promisc:
        cmd.append('-p')
    if flt_text and flt_text.strip():
        cmd.append(flt_text.strip()[:300])
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    except OSError as e:
        capture.error = 'tcpdump başlatılamadı: %s' % e
        return False
    capture.stop_ev.clear()
    capture.running = True
    capture._cap_proc = proc
    capture.thread = threading.Thread(
        target=pcap_stdout_loop,
        args=(capture, proc, capture.stop_ev, snap, max_packets, duration),
        daemon=True,
    )
    capture.thread.start()
    threading.Timer(0.4, _check_tcpdump_stderr, args=(capture, proc)).start()
    return True


def _check_tcpdump_stderr(capture, proc):
    if not capture.running or proc.poll() is None:
        return
    try:
        err = (proc.stderr.read() or b'').decode('utf-8', errors='replace').strip()
    except Exception:
        err = ''
    if err and not capture.packets:
        if 'must be root' in err.lower() or 'permission' in err.lower():
            capture.error = 'Yakalama için sudo gerekir: sudo python3 packetlens.py veya start.command'
        else:
            capture.error = err.split('\n')[0][:200]


def stop_mac_capture(capture):
    stop_subproc_capture(capture)
