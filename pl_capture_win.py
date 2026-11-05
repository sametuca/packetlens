"""Windows canlı yakalama: Wireshark dumpcap + Npcap (monitör modu gerekmez)."""
import os
import re
import subprocess
import sys
import threading

from pl_pcap_stream import pcap_stdout_loop, stop_subproc_capture


def find_dumpcap():
    if sys.platform != 'win32':
        return None
    for name in ('dumpcap.exe', 'dumpcap'):
        for folder in os.environ.get('PATH', '').split(os.pathsep):
            p = os.path.join(folder, name)
            if os.path.isfile(p):
                return p
    for p in (
        r'C:\Program Files\Wireshark\dumpcap.exe',
        r'C:\Program Files (x86)\Wireshark\dumpcap.exe',
    ):
        if os.path.isfile(p):
            return p
    return None


def list_dumpcap_interfaces(dumpcap=None):
    dc = dumpcap or find_dumpcap()
    if not dc:
        return []
    try:
        out = subprocess.check_output([dc, '-D'], text=True, errors='replace', timeout=15)
    except Exception:
        return []
    res = []
    for line in out.splitlines():
        m = re.match(r'^(\d+)\.\s+(.+)$', line.strip())
        if not m:
            continue
        label = m.group(2).strip()
        res.append({'id': m.group(1), 'label': label, 'default': len(res) == 0})
    return res


def _resolve_iface_id(iface, dumpcap_ifaces):
    if not iface or iface == 'any':
        for row in dumpcap_ifaces:
            if 'loopback' not in row.get('label', '').lower():
                return row['id']
        return dumpcap_ifaces[0]['id'] if dumpcap_ifaces else '1'
    for row in dumpcap_ifaces:
        if row['id'] == str(iface) or row.get('label') == iface:
            return row['id']
    return str(iface)


def start_win_capture(capture, iface, flt_text, snap, max_packets, duration, promisc):
    dc = find_dumpcap()
    if not dc:
        capture.error = 'dumpcap bulunamadı. Programı yeniden başlatın (Npcap otom kurulur) veya: winget install WiresharkFoundation.Wireshark'
        return False
    ifaces = list_dumpcap_interfaces(dc)
    if not ifaces:
        capture.error = 'dumpcap arayüz listesi alınamadı. Npcap kurulu mu? Yönetici olarak deneyin.'
        return False
    capture.stop()
    capture.snap, capture.max_packets, capture.duration = snap, max_packets, duration
    from capfilter import compile_filter
    capture.flt = compile_filter(flt_text)
    capture.flt_text = (flt_text or '').strip()
    with capture.lock:
        capture.packets, capture.dropped, capture.error = [], 0, None
    if_id = _resolve_iface_id(iface, ifaces)
    capture.iface = if_id
    cmd = [dc, '-i', if_id, '-s', str(snap), '-P', '-w', '-', '-q']
    if flt_text and flt_text.strip():
        cmd.extend(['-f', flt_text.strip()[:300]])
    if not promisc:
        cmd.append('-p')
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    except OSError as e:
        capture.error = 'dumpcap başlatılamadı: %s' % e
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
    return True


def stop_win_capture(capture):
    stop_subproc_capture(capture)
