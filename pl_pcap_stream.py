"""tcpdump/dumpcap stdout üzerinden pcap akışını okur."""
import struct
import time


def pcap_stdout_loop(capture, proc, stop_ev, snap, max_packets, duration):
    t_end = time.time() + duration if duration else None
    buf = b''
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
            if len(buf) < 24:
                continue
            if struct.unpack('<I', buf[:4])[0] != 0xA1B2C3D4:
                capture.error = 'pcap akışı okunamadı'
                break
            if len(buf) == 24:
                continue
            pos = 24
            while pos + 16 <= len(buf):
                ts_sec, ts_usec, incl, orig = struct.unpack('<IIII', buf[pos:pos + 16])
                end = pos + 16 + incl
                if end > len(buf):
                    break
                data = buf[pos + 16:end]
                pos = end
                if capture.flt and not capture.flt(data):
                    continue
                with capture.lock:
                    if len(capture.packets) >= max_packets:
                        capture.dropped += 1
                        continue
                    capture.packets.append((ts_sec + ts_usec / 1e6, orig, data[:snap]))
            buf = buf[pos:]
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
