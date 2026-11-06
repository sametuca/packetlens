"""tcpdump/dumpcap stdout üzerinden pcap akışını okur."""
import struct
import time

# İlk 4 baytın little-endian değeri → (kayıt endian'ı, zaman böleni)
# 0xA1B23C4D: dumpcap 4.x libpcap çıktısı, kesir nanosaniye.
_PCAP_CLOCK = {
    0xA1B2C3D4: ('<', 1e6),
    0xA1B23C4D: ('<', 1e9),
    0xD4C3B2A1: ('>', 1e6),
    0x4D3CB2A1: ('>', 1e9),
}


def take_pcap_packets(buf, fmt, div, snap, limit):
    """Başlığı tüketilmiş pcap gövdesinden tam paketleri ayırır.

    Dönüş: (paketler, kalan, hata).
    """
    out = []
    while len(buf) >= 16 and len(out) < limit:
        ts_sec, ts_frac, incl, orig = struct.unpack(fmt + 'IIII', buf[:16])
        if incl > 1048576:
            return out, buf, 'pcap akışı okunamadı'
        if len(buf) < 16 + incl:
            break
        data = buf[16:16 + incl]
        buf = buf[16 + incl:]
        out.append((ts_sec + ts_frac / div, orig, data[:snap]))
    return out, buf, None


def pcap_stdout_loop(capture, proc, stop_ev, snap, max_packets, duration):
    t_end = time.time() + duration if duration else None
    buf = b''
    fmt = None
    div = 1e6
    try:
        while not stop_ev.is_set():
            if t_end and time.time() >= t_end:
                break
            chunk = proc.stdout.read(65536)
            if not chunk:
                if proc.poll() is not None:
                    break
                continue
            buf += chunk
            if fmt is None:
                if len(buf) < 24:
                    continue
                clock = _PCAP_CLOCK.get(struct.unpack('<I', buf[:4])[0])
                if not clock:
                    capture.error = 'pcap akışı okunamadı'
                    break
                fmt, div = clock
                buf = buf[24:]
            with capture.lock:
                room = max_packets - len(capture.packets)
            if room <= 0:
                capture.dropped += 1
                buf = b''
                continue
            pkts, buf, err = take_pcap_packets(buf, fmt, div, snap, room)
            if err:
                capture.error = err
                break
            if not pkts:
                continue
            with capture.lock:
                space = max_packets - len(capture.packets)
                keep = pkts[:space]
                capture.dropped += len(pkts) - len(keep)
                for ts, orig, data in keep:
                    if capture.flt and not capture.flt(data):
                        continue
                    capture.packets.append((ts, orig, data))
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        capture.running = False


def stop_subproc_capture(capture):
    capture.stop_ev.set()
    proc = getattr(capture, '_cap_proc', None)
    if proc:
        try:
            proc.terminate()
        except Exception:
            pass
    if capture.thread:
        capture.thread.join(timeout=2)
    capture.thread = None
    capture._cap_proc = None
    capture.running = False
