#!/usr/bin/env python3
"""Yerel ağ cihaz keşfi, üretici (OUI) ve birleşik cihaz kaydı."""
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

from ptentes import (
    arp_request,
    arp_table,
    default_gateway,
    iface_info,
    mac_bytes,
)

OUI = {
    '000c29': 'VMware', '005056': 'VMware', '000569': 'VMware', '080027': 'VirtualBox', '525400': 'QEMU/KVM',
    '00155d': 'Microsoft Hyper-V', 'b827eb': 'Raspberry Pi', 'dca632': 'Raspberry Pi', 'e45f01': 'Raspberry Pi',
    '00000c': 'Cisco', '001b54': 'Cisco', '001e7a': 'Cisco', '000393': 'Apple', '001b63': 'Apple', '3c22fb': 'Apple',
    'f01898': 'Apple', 'acbc32': 'Apple', 'a483e7': 'Apple', '28ff3c': 'Apple', '24a43c': 'Ubiquiti', '802aa8': 'Ubiquiti',
    'fc65de': 'Amazon', '44650d': 'Amazon', '246f28': 'Espressif (IoT)', '30aea4': 'Espressif (IoT)', '001b21': 'Intel',
    'a4c3f0': 'Intel', '001e06': 'Apple', '0026bb': 'Apple', '0050f2': 'Microsoft', '001dd8': 'Samsung', '002454': 'Samsung',
    '4844f7': 'Samsung', 'c0b6f9': 'Samsung', '00259c': 'Huawei', '001882': 'Huawei', '00265a': 'Huawei',
    '001d0f': 'TP-Link', '50c7bf': 'TP-Link', 'a842a1': 'TP-Link', '0018e7': 'Hikvision', 'bcad28': 'Hikvision',
    '00163e': 'Xiaomi', '640980': 'Xiaomi', 'f8a763': 'Xiaomi', '0013d3': 'Asus', '107b44': 'Asus',
}

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_oui():
    path = os.path.join(HERE, 'oui.json')
    if not os.path.isfile(path):
        return
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict):
            OUI.update({str(k).lower(): str(v) for k, v in data.items()})
    except (OSError, json.JSONDecodeError, ValueError):
        pass


_load_oui()

DEFAULT_PORTS = (21, 22, 23, 53, 80, 135, 139, 443, 445, 554, 8080, 8443, 5353)
MAX_PING = 256
MAX_PORT_HOSTS = 32


def vendor(mac):
    if not mac:
        return ''
    k = mac.lower().replace(':', '').replace('-', '')[:6]
    if OUI.get(k):
        return OUI[k]
    try:
        if int(k[:2], 16) & 2:
            return 'Rastgele MAC'
    except ValueError:
        pass
    return ''


def _open_packet(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((iface, 0))
    s.settimeout(0.25)
    return s


def arp_scan(iface, wait=1.5, limit=512):
    info = iface_info(iface)
    if not info['mac'] or not info['ip']:
        return {'ok': False, 'error': 'Arayüz bilgisi okunamadı.'}
    try:
        net = ipaddress.IPv4Network('%s/%s' % (info['ip'], info['mask'] or '255.255.255.0'), strict=False)
    except Exception:
        return {'ok': False, 'error': 'Alt ağ hesaplanamadı.'}
    if os.geteuid() != 0:
        return {'ok': False, 'error': 'ARP taraması için root gerekir.'}
    try:
        sock = _open_packet(iface)
    except OSError as e:
        return {'ok': False, 'error': 'Soket açılamadı: %s' % e}
    hosts = [str(h) for h in net.hosts()][:limit]
    try:
        for _ in range(2):
            for ip in hosts:
                try:
                    sock.send(arp_request(b'\xff' * 6, mac_bytes(info['mac']), info['ip'], ip))
                except OSError:
                    break
            time.sleep(wait / 2)
        table = arp_table()
        found = [{'ip': ip, 'mac': table[ip], 'vendor': vendor(table[ip]), 'alive': True, 'via': 'arp'}
                 for ip in hosts if ip in table]
        return {'ok': True, 'subnet': str(net), 'found': found}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _ping_one(ip, timeout=1):
    try:
        r = subprocess.run(['ping', '-c', '1', '-W', str(max(1, int(timeout))), ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def ping_scan(ips, timeout=1.0, workers=24):
    ips = list(dict.fromkeys(ips))[:MAX_PING]
    alive = []
    lock = threading.Lock()

    def worker(batch):
        for ip in batch:
            if _ping_one(ip, timeout):
                with lock:
                    alive.append(ip)

    threads = []
    step = max(1, len(ips) // workers)
    for i in range(0, len(ips), step):
        t = threading.Thread(target=worker, args=(ips[i:i + step],), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout + 2)
    return alive


def tcp_probe(ip, ports, timeout=0.35):
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
    return open_ports


def webhook_notify(payload):
    url = os.environ.get('PACKETLENS_WEBHOOK', '').strip()
    if not url:
        return
    try:
        import urllib.request
        body = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, body, {'Content-Type': 'application/json; charset=utf-8'})
        urllib.request.urlopen(req, timeout=6)
    except Exception:
        pass


class DeviceRegistry:
    """Sunucu tarafı birleşik cihaz listesi (ARP, tarama, ptentes)."""

    def __init__(self):
        self.lock = threading.RLock()
        self.devices = {}
        self.last_scan = None
        self.history = []

    def _upsert(self, ip, **fields):
        if not ip:
            return
        d = self.devices.get(ip) or {'ip': ip, 'mac': '', 'vendor': '', 'name': '', 'alive': False,
                                     'ports': [], 'roles': [], 'source': [], 'risk': 0, 'last': 0}
        for k, v in fields.items():
            if v is None:
                continue
            if k == 'source' and v:
                if v not in d['source']:
                    d['source'].append(v)
            elif k == 'roles' and v:
                for r in v:
                    if r not in d['roles']:
                        d['roles'].append(r)
            elif k == 'ports' and v:
                merged = set(d['ports']) | set(v)
                d['ports'] = sorted(merged)
            elif k == 'name' and v and not d['name']:
                d['name'] = v
            elif k in ('mac', 'vendor', 'alive', 'risk') and v:
                d[k] = v
            elif k == 'last':
                d['last'] = max(d['last'], v)
        self.devices[ip] = d

    def merge_arp(self, arp_list):
        with self.lock:
            for n in arp_list or []:
                ip, mac = n.get('ip'), n.get('mac')
                self._upsert(ip, mac=mac, vendor=vendor(mac), source='arp', last=time.time())

    def merge_scan(self, found, via='scan'):
        with self.lock:
            for h in found or []:
                self._upsert(h.get('ip'), mac=h.get('mac'), vendor=h.get('vendor') or vendor(h.get('mac', '')),
                             alive=h.get('alive', True), ports=h.get('ports'), name=h.get('name'),
                             source=via, last=time.time())

    def merge_ptentes(self, hosts):
        with self.lock:
            for h in hosts or []:
                ip = h.get('ip')
                self._upsert(ip, mac=h.get('mac'), alive=True, source='ptentes', last=h.get('last', time.time()))

    def snapshot(self, gateway_ip=''):
        with self.lock:
            items = sorted(self.devices.values(), key=lambda x: x.get('last', 0), reverse=True)
            if gateway_ip:
                for d in items:
                    if d['ip'] == gateway_ip and 'Ağ geçidi (router)' not in d['roles']:
                        d['roles'].append('Ağ geçidi (router)')
            return {'devices': items, 'last_scan': self.last_scan, 'updated': time.time(), 'history_len': len(self.history)}

    def push_history(self):
        with self.lock:
            snap = {ip: dict(d) for ip, d in self.devices.items()}
            self.history.append({'t': time.time(), 'devices': snap})
            if len(self.history) > 12:
                del self.history[: len(self.history) - 12]

    def compare_history(self, a=-2, b=-1):
        with self.lock:
            if len(self.history) < 2:
                return {'ok': False, 'error': 'Karşılaştırma için en az iki kayıt gerekir (tarama çalıştırın).'}
            try:
                sa, sb = self.history[a], self.history[b]
            except IndexError:
                return {'ok': False, 'error': 'Geçersiz kayıt indeksi.'}
        da, db = sa['devices'], sb['devices']
        new_ips = sorted(set(db) - set(da))
        gone = sorted(set(da) - set(db))
        changed = []
        for ip in set(da) & set(db):
            pa, pb = set(da[ip].get('ports') or []), set(db[ip].get('ports') or [])
            if pa != pb or da[ip].get('mac') != db[ip].get('mac'):
                changed.append({'ip': ip, 'ports_added': sorted(pb - pa), 'ports_removed': sorted(pa - pb),
                                'mac_before': da[ip].get('mac'), 'mac_after': db[ip].get('mac')})
        return {'ok': True, 't_a': sa['t'], 't_b': sb['t'], 'new': new_ips, 'gone': gone, 'changed': changed}

    def scan(self, cfg, pt_hosts=None):
        if not sys.platform.startswith('linux'):
            return {'ok': False, 'error': 'Cihaz taraması yalnızca Linux üzerinde çalışır.'}
        if os.geteuid() != 0:
            return {'ok': False, 'error': 'Aktif tarama için root gerekir: sudo python3 packetlens.py'}
        iface = (cfg.get('iface') or '').strip()
        if not iface:
            return {'ok': False, 'error': 'Arayüz zorunlu.'}
        modes = cfg.get('modes') or ['arp']
        if isinstance(modes, str):
            modes = [modes]
        ports = cfg.get('ports') or list(DEFAULT_PORTS)
        try:
            ports = [int(p) for p in ports][:24]
        except (TypeError, ValueError):
            ports = list(DEFAULT_PORTS)
        result = {'ok': True, 'subnet': '', 'found': [], 'modes': modes}
        alive_ips = []

        if 'arp' in modes:
            ar = arp_scan(iface, limit=int(cfg.get('limit') or 512))
            if not ar.get('ok'):
                return ar
            result['subnet'] = ar.get('subnet', '')
            result['found'].extend(ar.get('found', []))
            alive_ips = [h['ip'] for h in ar.get('found', [])]

        if 'ping' in modes:
            info = iface_info(iface)
            if not alive_ips and info.get('ip'):
                try:
                    net = ipaddress.IPv4Network('%s/%s' % (info['ip'], info['mask'] or '255.255.255.0'), strict=False)
                    alive_ips = [str(h) for h in net.hosts()][:MAX_PING]
                except Exception:
                    alive_ips = []
            pinged = ping_scan(alive_ips or cfg.get('ips') or [])
            by_ip = {h['ip']: h for h in result['found']}
            for ip in pinged:
                if ip in by_ip:
                    by_ip[ip]['alive'] = True
                    by_ip[ip]['via'] = (by_ip[ip].get('via') or '') + '+ping'
                else:
                    entry = {'ip': ip, 'mac': arp_table().get(ip, ''), 'vendor': '', 'alive': True, 'via': 'ping'}
                    entry['vendor'] = vendor(entry['mac'])
                    result['found'].append(entry)
            alive_ips = pinged or alive_ips

        if 'ports' in modes:
            targets = (cfg.get('ips') or alive_ips or [h['ip'] for h in result['found']])[:MAX_PORT_HOSTS]
            for ip in targets:
                open_p = tcp_probe(ip, ports)
                if not open_p:
                    continue
                by_ip = {h['ip']: h for h in result['found']}
                if ip in by_ip:
                    by_ip[ip]['ports'] = open_p
                else:
                    result['found'].append({'ip': ip, 'mac': arp_table().get(ip, ''), 'vendor': vendor(arp_table().get(ip, '')),
                                            'alive': True, 'via': 'ports', 'ports': open_p})

        _, gw_ip = default_gateway()
        with self.lock:
            self.last_scan = {'t': time.time(), 'iface': iface, 'modes': modes, 'count': len(result['found'])}
            self.merge_scan(result['found'])
            if pt_hosts:
                self.merge_ptentes(pt_hosts)
            if gw_ip:
                self._upsert(gw_ip, roles=['Ağ geçidi (router)'], source='system', last=time.time())
            self.push_history()
        result['registry'] = self.snapshot(gw_ip)
        result['compare'] = self.compare_history(-2, -1) if len(self.history) >= 2 else None
        webhook_notify({'event': 'device_scan', 'count': len(result['found']), 'modes': modes, 'subnet': result.get('subnet')})
        return result


REGISTRY = DeviceRegistry()


def scheduled_scan_loop(iface, interval_sec, stop_ev):
    while not stop_ev.wait(interval_sec):
        try:
            REGISTRY.scan({'iface': iface, 'modes': ['arp']})
        except Exception:
            pass
