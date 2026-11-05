/* PacketLens - araçlar: pcap yazma, anonimleştirme, siteler, HTTP dosyaları, CSV/JSON dışa aktarma (tarayıcı + Node) */
(function (root) {
'use strict';

function install(PL) {
  const u16 = (d, o) => (d[o] << 8) | d[o + 1];
  const w16 = (d, o, v) => { d[o] = (v >> 8) & 255; d[o + 1] = v & 255; };

  /* ---------- pcap yazma ---------- */
  // records: [{ts, len, data(Uint8Array), link}]  ->  Uint8Array (klasik pcap, mikro saniye)
  PL.pcapBytes = function (records, link) {
    const lt = link || (records[0] && records[0].link) || 1;
    let n = 24; for (const r of records) n += 16 + r.data.length;
    const out = new Uint8Array(n), dv = new DataView(out.buffer);
    dv.setUint32(0, 0xa1b2c3d4, true); dv.setUint16(4, 2, true); dv.setUint16(6, 4, true); dv.setUint32(16, 262144, true); dv.setUint32(20, lt, true);
    let o = 24;
    for (const r of records) {
      let sec = Math.floor(r.ts), us = Math.round((r.ts - sec) * 1e6); if (us >= 1e6) { sec++; us -= 1e6; }
      dv.setUint32(o, sec, true); dv.setUint32(o + 4, us, true); dv.setUint32(o + 8, r.data.length, true); dv.setUint32(o + 12, Math.max(r.len || 0, r.data.length), true);
      out.set(r.data, o + 16); o += 16 + r.data.length;
    }
    return out;
  };

  /* ---------- anonimleştirme ---------- */
  function csum(d, s, e, init) {
    let sum = init || 0;
    for (let i = s; i + 1 < e; i += 2) sum += (d[i] << 8) | d[i + 1];
    if ((e - s) & 1) sum += d[e - 1] << 8;
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    return sum;
  }
  const sumBytes = (d, s, e) => csum(d, s, e, 0);

  // o: { addr: IP/MAC maskele (varsayılan true), payload: uygulama verisini sil (varsayılan false) }
  PL.anonymize = function (records, o) {
    o = Object.assign({ addr: true, payload: false }, o || {});
    const macs = new Map(), ips = new Map(), ip6s = new Map();
    const stats = { packets: 0, macs: 0, ips: 0, ip6: 0, payloadZeroed: 0 };
    const hex = (d, s, n) => { let k = ''; for (let i = 0; i < n; i++) k += d[s + i].toString(16).padStart(2, '0'); return k; };
    const mapMac = (d, s) => {
      if (!o.addr || (d[s] & 1)) return; // yayın/çoklu gönderim kalsın
      const k = hex(d, s, 6); let v = macs.get(k);
      if (!v) { const n = macs.size + 1; v = [0x02, 0, 0, (n >> 16) & 255, (n >> 8) & 255, n & 255]; macs.set(k, v); stats.macs++; }
      for (let i = 0; i < 6; i++) d[s + i] = v[i];
    };
    const priv4 = (a, b) => a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
    const mapIp4 = (d, s) => {
      if (!o.addr) return;
      const a = d[s], b = d[s + 1];
      if (a === 0 || a === 127 || a >= 224) return; // 0.0.0.0, loopback, çoklu/yayın
      const k = (a << 24 | b << 16 | d[s + 2] << 8 | d[s + 3]) >>> 0; let v = ips.get(k);
      if (!v) { const n = ips.size + 1, hi = (n >> 16) & 63; v = priv4(a, b) ? [10, (n >> 16) & 255, (n >> 8) & 255, n & 255] : [100, 64 + hi, (n >> 8) & 255, n & 255]; ips.set(k, v); stats.ips++; }
      for (let i = 0; i < 4; i++) d[s + i] = v[i];
    };
    const mapIp6 = (d, s) => {
      if (!o.addr) return;
      if (d[s] === 0xff) return; // çoklu gönderim
      let zero = true; for (let i = 0; i < 15; i++) if (d[s + i]) { zero = false; break; }
      if (zero && (d[s + 15] === 0 || d[s + 15] === 1)) return; // :: ve ::1
      const k = hex(d, s, 16); let v = ip6s.get(k);
      if (!v) { const n = ip6s.size + 1; v = new Array(16).fill(0); if (d[s] === 0xfe && (d[s + 1] & 0xc0) === 0x80) { v[0] = 0xfe; v[1] = 0x80; } else v[0] = 0xfd; v[12] = (n >>> 24) & 255; v[13] = (n >> 16) & 255; v[14] = (n >> 8) & 255; v[15] = n & 255; ip6s.set(k, v); stats.ip6++; }
      for (let i = 0; i < 16; i++) d[s + i] = v[i];
    };
    const fixIp4Header = (d, off) => { const ihl = (d[off] & 15) * 4; d[off + 10] = 0; d[off + 11] = 0; const c = ~csum(d, off, off + ihl, 0) & 0xffff; w16(d, off + 10, c); };
    const l4sum = (d, l4, end, proto, pseudoSum, ckOff) => {
      if (ckOff === 6 && u16(d, l4 + 6) === 0) return; // UDP: sağlama toplamı yok
      d[l4 + ckOff] = 0; d[l4 + ckOff + 1] = 0;
      let c = ~csum(d, l4, end, pseudoSum) & 0xffff; if (c === 0 && proto === 17) c = 0xffff; w16(d, l4 + ckOff, c);
    };

    const out = [];
    for (const r of records) {
      const d = new Uint8Array(r.data); stats.packets++;
      if ((r.link || 1) === 1 && d.length >= 14) {
        mapMac(d, 0); mapMac(d, 6);
        let off = 14, et = u16(d, 12);
        while ((et === 0x8100 || et === 0x88a8) && off + 4 <= d.length) { et = u16(d, off + 2); off += 4; }
        if (et === 0x0806 && d.length >= off + 28) { mapMac(d, off + 8); mapIp4(d, off + 14); mapMac(d, off + 18); mapIp4(d, off + 24); }
        else if (et === 0x0800 && d.length >= off + 20 && (d[off] >> 4) === 4) {
          const ihl = (d[off] & 15) * 4, tot = u16(d, off + 2), proto = d[off + 9], frag = u16(d, off + 6) & 0x1fff, mf = (d[off + 6] & 0x20) !== 0;
          mapIp4(d, off + 12); mapIp4(d, off + 16);
          const l4 = off + ihl, end = Math.min(d.length, off + tot), whole = d.length >= off + tot && frag === 0 && !mf;
          if (frag === 0 && l4 < end) {
            if (o.payload) {
              let st = -1;
              if (proto === 6 && end - l4 >= 20) st = l4 + (d[l4 + 12] >> 4) * 4; else if (proto === 17) st = l4 + 8; else if (proto === 1) st = l4 + 8;
              if (st >= 0 && st < end) { d.fill(0, st, end); stats.payloadZeroed += end - st; }
            } else if (proto === 1 && end - l4 > 8 && [3, 4, 5, 11, 12].includes(d[l4]) && (d[l4 + 8] >> 4) === 4 && end - l4 >= 8 + 20) {
              mapIp4(d, l4 + 8 + 12); mapIp4(d, l4 + 8 + 16); fixIp4Header(d, l4 + 8); // ICMP hata mesajının içindeki asıl paket başlığı
            }
          }
          fixIp4Header(d, off);
          if (whole) {
            const ps = sumBytes(d, off + 12, off + 20) + proto + (end - l4);
            if (proto === 6 && end - l4 >= 20) l4sum(d, l4, end, 6, ps, 16);
            else if (proto === 17 && end - l4 >= 8) l4sum(d, l4, end, 17, ps, 6);
            else if (proto === 1 && end - l4 >= 4) l4sum(d, l4, end, 1, 0, 2);
          }
        } else if (et === 0x86dd && d.length >= off + 40) {
          const nh = d[off + 6], pl = u16(d, off + 4);
          mapIp6(d, off + 8); mapIp6(d, off + 24);
          const l4 = off + 40, end = Math.min(d.length, l4 + pl), whole = d.length >= l4 + pl;
          if (o.payload && l4 < end) { let st = -1; if (nh === 6 && end - l4 >= 20) st = l4 + (d[l4 + 12] >> 4) * 4; else if (nh === 17) st = l4 + 8; if (st >= 0 && st < end) { d.fill(0, st, end); stats.payloadZeroed += end - st; } }
          if (whole && (nh === 6 || nh === 17 || nh === 58) && end - l4 >= 4) {
            const ps = sumBytes(d, off + 8, off + 40) + (end - l4) + nh;
            l4sum(d, l4, end, nh, ps, nh === 6 ? 16 : nh === 17 ? 6 : 2);
          }
        }
      }
      out.push({ ts: r.ts, len: r.len, data: d, link: r.link || 1 });
    }
    return { records: out, stats };
  };

  /* ---------- siteler ---------- */
  const HTTP_REQ = /^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\b/;
  // opts.flows: Set(flow id) | null, opts.nos: Set(paket no) | null  (görünen kümeye göre sınırla)
  PL.sites = function (A, opts) {
    opts = opts || {};
    const byFlow = new Map();
    for (const p of A.packets) {
      if (byFlow.has(p.flow)) continue;
      if (p.sni) byFlow.set(p.flow, { d: p.sni, via: 'SNI', clear: false });
      else if (p.http && p.http.host && HTTP_REQ.test(p.http.first || '')) byFlow.set(p.flow, { d: p.http.host, via: 'Host', clear: true });
    }
    const rows = new Map();
    const get = (client, domain) => {
      const k = client + '|' + domain; let r = rows.get(k);
      if (!r) rows.set(k, r = { client, domain, flows: new Set(), bytes: 0, first: Infinity, last: 0, apps: new Set(), dnsQ: 0, clear: false, via: new Set() });
      return r;
    };
    for (const f of A.flows) {
      if (opts.flows && !opts.flows.has(f.id)) continue;
      if (f.bPort == null || (f.proto !== 'TCP' && f.proto !== 'UDP')) continue;
      let hit = byFlow.get(f.id), d = hit && hit.d, via = hit && hit.via, clear = hit ? hit.clear : false;
      if (!d) { const n = A.names.get(f.server); if (n) { d = n; via = 'DNS'; } else if (!PL.isPrivate(f.server)) { d = f.server; via = 'IP'; } }
      if (!d) continue;
      d = String(d).toLowerCase();
      const r = get(f.client, d); r.flows.add(f.id); r.bytes += f.bytes; r.first = Math.min(r.first, f.start); r.last = Math.max(r.last, f.end); r.apps.add(f.app); r.via.add(via); if (clear || f.app === 'HTTP') r.clear = true;
    }
    for (const p of A.packets) {
      if (!p.dns || p.dns.qr || p.app !== 'DNS' || !p.dns.questions[0]) continue;
      if (opts.nos && !opts.nos.has(p.no)) continue;
      const d = String(p.dns.questions[0].name).toLowerCase().replace(/\.$/, ''); if (!d) continue;
      const r = get(p.src, d); r.dnsQ++; r.first = Math.min(r.first, p.ts); r.last = Math.max(r.last, p.ts); r.via.add('DNS');
    }
    return [...rows.values()].map(r => ({ ...r, flows: r.flows.size, apps: [...r.apps], via: [...r.via] })).sort((a, b) => b.bytes - a.bytes || b.dnsQ - a.dnsQ || a.domain.localeCompare(b.domain));
  };

  /* ---------- HTTP dosyaları ---------- */
  const latin = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 8192) s += String.fromCharCode.apply(null, u8.subarray(i, i + 8192)); return s; };
  const concat = list => { let n = 0; for (const b of list) n += b.length; const o = new Uint8Array(n); let k = 0; for (const b of list) { o.set(b, k); k += b.length; } return o; };
  function findHdrEnd(u8, from) { for (let i = from; i + 3 < u8.length; i++) if (u8[i] === 13 && u8[i + 1] === 10 && u8[i + 2] === 13 && u8[i + 3] === 10) return i; return -1; }
  function parseHeaders(txt) { const h = {}; txt.split('\r\n').slice(1).forEach(l => { const i = l.indexOf(':'); if (i > 0) h[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim(); }); return h; }
  function dechunk(u8, from) {
    const parts = []; let i = from;
    for (;;) {
      let e = i; while (e + 1 < u8.length && !(u8[e] === 13 && u8[e + 1] === 10)) e++;
      if (e + 1 >= u8.length) return { body: concat(parts), next: u8.length, complete: false };
      const n = parseInt(latin(u8.subarray(i, e)).split(';')[0], 16);
      if (isNaN(n)) return { body: concat(parts), next: u8.length, complete: false };
      if (n === 0) { let t = e + 2; const te = findHdrEnd(u8, e); return { body: concat(parts), next: te >= 0 ? te + 4 : Math.min(u8.length, t + 2), complete: true }; }
      if (e + 2 + n > u8.length) { parts.push(u8.subarray(e + 2)); return { body: concat(parts), next: u8.length, complete: false }; }
      parts.push(u8.subarray(e + 2, e + 2 + n)); i = e + 2 + n + 2;
    }
  }
  function magic(b) {
    const s = (i) => b[i];
    if (b.length >= 4 && s(0) === 0x89 && s(1) === 0x50 && s(2) === 0x4e && s(3) === 0x47) return { kind: 'PNG', exec: false };
    if (b.length >= 3 && s(0) === 0xff && s(1) === 0xd8 && s(2) === 0xff) return { kind: 'JPEG', exec: false };
    if (b.length >= 4 && latin(b.subarray(0, 4)) === 'GIF8') return { kind: 'GIF', exec: false };
    if (b.length >= 4 && latin(b.subarray(0, 4)) === '%PDF') return { kind: 'PDF', exec: false };
    if (b.length >= 4 && s(0) === 0x50 && s(1) === 0x4b && s(2) === 3 && s(3) === 4) return { kind: 'ZIP', exec: false };
    if (b.length >= 2 && s(0) === 0x1f && s(1) === 0x8b) return { kind: 'GZIP', exec: false };
    if (b.length >= 4 && s(0) === 0x7f && latin(b.subarray(1, 4)) === 'ELF') return { kind: 'ELF', exec: true };
    if (b.length >= 2 && s(0) === 0x4d && s(1) === 0x5a) return { kind: 'PE/EXE', exec: true };
    if (b.length >= 4 && s(0) === 0xcf && s(1) === 0xfa && s(2) === 0xed && s(3) === 0xfe) return { kind: 'Mach-O', exec: true };
    if (b.length >= 2 && latin(b.subarray(0, 2)) === '#!') return { kind: 'Script', exec: true };
    const h = latin(b.subarray(0, 64)).toLowerCase();
    if (/^\s*<(!doctype|html)/.test(h)) return { kind: 'HTML', exec: false };
    if (/^\s*[{[]/.test(h)) return { kind: 'JSON', exec: false };
    if (/^[\x09\x0a\x0d\x20-\x7e]*$/.test(h) && b.length) return { kind: 'Metin', exec: false };
    return { kind: '?', exec: false };
  }
  PL.fileMagic = magic;

  PL.httpObjects = function (A) {
    const out = [];
    for (const f of A.flows) {
      if (f.app !== 'HTTP' || f.proto !== 'TCP') continue;
      let r; try { r = PL.followStream(A, f.id); } catch (e) { continue; }
      const dirs = { AB: [], BA: [] }; let gapped = { AB: false, BA: false };
      for (const s of r.segs) { if (s.gap) { gapped[s.dir] = true; continue; } if (!gapped[s.dir]) dirs[s.dir].push(s); }
      const reqDir = dirs.AB.length && HTTP_REQ.test(latin(dirs.AB[0].bytes.subarray(0, 8))) ? 'AB' : (dirs.BA.length && HTTP_REQ.test(latin(dirs.BA[0].bytes.subarray(0, 8))) ? 'BA' : null);
      if (!reqDir) continue;
      const resDir = reqDir === 'AB' ? 'BA' : 'AB';
      const rq = concat(dirs[reqDir].map(s => s.bytes)), rs = concat(dirs[resDir].map(s => s.bytes));
      const reqs = []; let i = 0;
      while (i < rq.length) {
        const e = findHdrEnd(rq, i); if (e < 0) break;
        const head = latin(rq.subarray(i, e)), line = head.split('\r\n')[0], m = /^(\S+) (\S+)/.exec(line), h = parseHeaders(head);
        if (!m) break; reqs.push({ method: m[1], path: m[2], host: h.host || '' });
        i = e + 4;
        if (h['transfer-encoding'] && /chunked/i.test(h['transfer-encoding'])) i = dechunk(rq, i).next; else i += parseInt(h['content-length'] || '0', 10) || 0;
      }
      i = 0; let ri = 0;
      while (i < rs.length) {
        const e = findHdrEnd(rs, i); if (e < 0) break;
        const head = latin(rs.subarray(i, e)), m = /^HTTP\/1\.[01] (\d{3})/.exec(head); if (!m) break;
        const status = +m[1], h = parseHeaders(head), rqi = reqs[ri++] || { method: '?', path: '', host: '' };
        i = e + 4; let body, ok = true;
        if (status < 200 || status === 204 || status === 304 || rqi.method === 'HEAD') body = new Uint8Array(0);
        else if (h['transfer-encoding'] && /chunked/i.test(h['transfer-encoding'])) { const d = dechunk(rs, i); body = d.body; i = d.next; ok = d.complete; }
        else if (h['content-length'] != null) { const n = parseInt(h['content-length'], 10) || 0; body = rs.subarray(i, i + n); ok = rs.length - i >= n; i += n; }
        else { body = rs.subarray(i); i = rs.length; }
        if (!body.length) continue;
        const path = rqi.path.split('?')[0], name = decodeURIComponent((path.split('/').filter(Boolean).pop() || 'index').replace(/[\\/:*?"<>|]/g, '_')) || 'index';
        const mg = magic(body);
        out.push({ flow: f.id, host: rqi.host || A.nm(f.server), method: rqi.method, path: rqi.path, status, ctype: (h['content-type'] || '').split(';')[0], enc: h['content-encoding'] || '', name, bytes: body, size: body.length, kind: mg.kind, exec: mg.exec, complete: ok, t: r.segs.find(s => !s.gap && s.dir === resDir) ? r.segs.find(s => !s.gap && s.dir === resDir).t : f.start });
      }
    }
    return out;
  };

  /* ---------- CSV / JSON ---------- */
  const csvCell = v => {
    if (v == null) return '';
    let s = String(v);
    if (/^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?$/.test(s)) s = "'" + s; // Excel formül enjeksiyonunu engelle
    return /[",\n\r;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  PL.toCSV = (headers, rows) => '﻿' + [headers.map(csvCell).join(',')].concat(rows.map(r => r.map(csvCell).join(','))).join('\r\n') + '\r\n';
  PL.csvCell = csvCell;


  /* ---------- cihazlar / yerel ağ ---------- */
  const OUI = { '000c29': 'VMware', '005056': 'VMware', '000569': 'VMware', '080027': 'VirtualBox', '525400': 'QEMU/KVM', '00155d': 'Microsoft Hyper-V',
    'b827eb': 'Raspberry Pi', 'dca632': 'Raspberry Pi', 'e45f01': 'Raspberry Pi', 'd83add': 'Raspberry Pi', '2ccf67': 'Raspberry Pi',
    '00000c': 'Cisco', '001b54': 'Cisco', '000393': 'Apple', '000a95': 'Apple', '001b63': 'Apple', '3c22fb': 'Apple', 'f01898': 'Apple', 'acbc32': 'Apple', 'a483e7': 'Apple',
    '24a43c': 'Ubiquiti', '44d9e7': 'Ubiquiti', '802aa8': 'Ubiquiti', 'fcecda': 'Ubiquiti', '3c5ab4': 'Google', 'f4f5d8': 'Google', '546009': 'Google',
    'fc65de': 'Amazon', '44650d': 'Amazon', '246f28': 'Espressif (IoT)', '30aea4': 'Espressif (IoT)', '840d8e': 'Espressif (IoT)', '001b21': 'Intel', 'a4c3f0': 'Intel' };
  PL.vendor = function (mac) {
    if (!mac) return '';
    const k = mac.toLowerCase().replace(/[^0-9a-f]/g, '').slice(0, 6);
    if (OUI[k]) return OUI[k];
    if (parseInt(k.slice(0, 2), 16) & 2) return "Rastgele MAC";
    return '';
  };
  const macHex = (d, o) => { let s = ''; for (let i = 0; i < 6; i++) s += (i ? ':' : '') + d[o + i].toString(16).padStart(2, '0'); return s; };
  // net: { gateway:{ip}, dns:[...], arp:[{ip,mac}] , self:[ip,...] } (isteğe bağlı, sunucudan)
  PL.devices = function (A, net) {
    net = net || {};
    const macs = new Map(), gwCount = new Map();
    const isLocalIp = ip => PL.isPrivate(ip) || /^fe80:/i.test(ip);
    const ipOk = ip => ip && !/^(0\.0\.0\.0|255\.|22[4-9]\.|23\d\.|ff)/i.test(ip) && (/^\d+\.\d+\.\d+\.\d+$/.test(ip) || ip.includes(':')) && !/^([0-9a-f]{2}:){5}/i.test(ip);
    for (const p of A.packets) {
      const d = p.raw; if (!d || d.length < 14) continue;
      if (p.arp && p.arp.si && p.arp.si !== '0.0.0.0' && p.arp.sm) { let m = macs.get(p.arp.si); if (!m) macs.set(p.arp.si, m = new Map()); m.set(String(p.arp.sm).toLowerCase(), (m.get(String(p.arp.sm).toLowerCase()) || 0) + 5); continue; }
      const et = u16(d, 12); if (et !== 0x0800 && et !== 0x86dd) continue;
      if (d[6] & 1) continue; // kaynak MAC unicast olmalı
      const sm = macHex(d, 6);
      if (isLocalIp(p.src)) { let m = macs.get(p.src); if (!m) macs.set(p.src, m = new Map()); m.set(sm, (m.get(sm) || 0) + 1); }
      else if (ipOk(p.src)) gwCount.set(sm, (gwCount.get(sm) || 0) + 1);
    }
    const macOf = new Map(); for (const [ip, m] of macs) macOf.set(ip, [...m.entries()].sort((a, b) => b[1] - a[1])[0][0]);
    for (const n of (net.arp || [])) if (n.ip && n.mac && !macOf.has(n.ip)) macOf.set(n.ip, n.mac.toLowerCase());
    let gwMac = [...gwCount.entries()].sort((a, b) => b[1] - a[1])[0]; gwMac = gwMac && gwMac[1] >= 2 ? gwMac[0] : null;
    let gwIp = net.gateway && net.gateway.ip || ''; if (!gwIp && gwMac) for (const [ip, m] of macOf) if (m === gwMac) { gwIp = ip; break; }
    const dnsServers = new Map(); for (const f of A.flows) if (f.app === 'DNS' && f.bPort === 53) dnsServers.set(f.server, (dnsServers.get(f.server) || 0) + f.pkts);
    const dhcp = new Set(); for (const f of A.flows) if (f.app === 'DHCP') dhcp.add(f.server);
    const self = new Set(net.self || []);
    const appsOf = new Map(); for (const f of A.flows) for (const ip of [f.client, f.server]) { let m = appsOf.get(ip); if (!m) appsOf.set(ip, m = new Map()); m.set(f.app, (m.get(f.app) || 0) + f.bytes); }
    const out = new Map();
    const mk = ip => { let o = out.get(ip); if (!o) { const mac = macOf.get(ip) || ''; out.set(ip, o = { ip, mac, vendor: PL.vendor(mac), name: A.names.get(ip) || '', os: '', roles: [], bytesTx: 0, bytesRx: 0, flows: 0, apps: [], first: Infinity, last: 0, silent: false, self: self.has(ip) }); } return o; };
    for (const [ip, h] of A.hosts) {
      if (!ipOk(ip) || !isLocalIp(ip) || !(h.pktsTx > 0 || macOf.has(ip))) continue; // hiç yanıt vermeyen tarama hedefleri cihaz sayılmaz
      const o = mk(ip); o.os = h.os || ''; o.bytesTx = h.bytesTx; o.bytesRx = h.bytesRx; o.flows = h.flows ? h.flows.size : 0;
      o.first = h.first != null ? h.first : o.first; o.last = h.last != null ? h.last : o.last;
    }
    for (const f of A.flows) for (const ip of [f.client, f.server]) { const o = out.get(ip); if (o) { o.first = Math.min(o.first, f.start); o.last = Math.max(o.last, f.end); } }
    for (const n of (net.arp || [])) if (ipOk(n.ip) && !out.has(n.ip)) { const o = mk(n.ip); o.silent = true; }
    if (gwIp) { const o = out.get(gwIp) || mk(gwIp); if (!o.roles.includes('Ağ geçidi (router)')) o.roles.push('Ağ geçidi (router)'); }
    for (const [ip, c] of dnsServers) { const o = out.get(ip); if (o && !o.roles.includes('DNS sunucusu')) o.roles.push('DNS sunucusu'); }
    for (const ip of dhcp) { const o = out.get(ip); if (o && !o.roles.includes('DHCP sunucusu')) o.roles.push('DHCP sunucusu'); }
    for (const o of out.values()) { if (o.self) o.roles.unshift('Bu bilgisayar'); const m = appsOf.get(o.ip); o.apps = m ? [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(x => x[0]) : []; }
    const list = [...out.values()].sort((a, b) => (b.bytesTx + b.bytesRx) - (a.bytesTx + a.bytesRx) || a.ip.localeCompare(b.ip));
    // alt ağ tahmini: en sık görülen /24 (IPv4)
    const nets = new Map(); list.forEach(o => { const m = /^(\d+\.\d+\.\d+)\.\d+$/.exec(o.ip); if (m) nets.set(m[1], (nets.get(m[1]) || 0) + 1); });
    const subnet = [...nets.entries()].sort((a, b) => b[1] - a[1])[0];
    return { devices: list, gateway: gwIp, gatewayMac: gwMac || (gwIp && macOf.get(gwIp)) || '', dns: [...dnsServers.entries()].sort((a, b) => b[1] - a[1]).map(x => x[0]), subnet: subnet ? subnet[0] + '.0/24' : '' };
  };

  /* ---------- hazır filtre kütüphanesi (Wireshark'ta aratıp bulunan filtreler) ---------- */
  PL.FILTER_LIB = [
    { cat: 'Temel', items: [
      ['ip.addr == 192.168.1.10', 'Bir cihazın gönderdiği ve aldığı tüm trafik'],
      ['ip.src == 192.168.1.10 && ip.dst == 8.8.8.8', 'İki cihaz arasında tek yönlü trafik'],
      ['ip.addr == 192.168.0.0/16', 'Yerel ağdaki (CIDR aralığındaki) tüm trafik'],
      ['ip && !(ip.addr == 192.168.0.0/16) && !(ip.addr == 10.0.0.0/8)', 'İnternete giden/gelen trafik (yerel ağ hariç)'],
      ['!(arp || dns || icmp)', 'Gürültüyü gizle: ARP, DNS ve ICMP hariç'],
      ['tcp.port == 443', 'HTTPS (443) trafiği'],
      ['tcp.port == 22', 'SSH trafiği'],
      ['udp.port == 53', 'DNS trafiği (UDP 53)'],
      ['frame.len > 1000', 'Büyük paketler (1000 bayttan büyük)'],
      ['frame contains "password"', 'Paket içeriğinde “password” geçenler'],
    ] },
    { cat: 'Sorun giderme', items: [
      ['pl.problem', 'PacketLens’in sorun işaretlediği tüm paketler'],
      ['tcp.analysis.retransmission', 'Yeniden iletilen paketler (kayıp / yavaşlık)'],
      ['tcp.analysis.zero_window', 'Alıcının tamponu dolu (Zero Window)'],
      ['tcp.analysis.flags', 'TCP’nin tüm sorun işaretleri'],
      ['tcp.flags.reset == 1', 'Aniden kesilen bağlantılar (RST)'],
      ['tcp.flags.syn == 1 && tcp.flags.ack == 0', 'Yeni bağlantı denemeleri (SYN)'],
      ['icmp.type == 3', 'Hedefe ulaşılamadı mesajları'],
      ['tcp.window_size == 0', 'Pencere boyutu sıfır olan paketler'],
    ] },
    { cat: 'DNS', items: [
      ['dns', 'Tüm DNS trafiği'],
      ['dns.flags.response == 0', 'Yalnızca DNS sorguları'],
      ['dns.flags.rcode == 3', 'Alan adı bulunamadı (NXDOMAIN)'],
      ['dns.time > 0.25', 'Yavaş DNS yanıtları (250 ms üzeri)'],
      ['dns.qry.name contains "google"', 'Adında “google” geçen DNS sorguları'],
    ] },
    { cat: 'Web ve TLS', items: [
      ['http.request.method == "POST"', 'HTTP POST istekleri (form / giriş gönderimi)'],
      ['http.host contains "example"', 'Belirli bir siteye giden HTTP istekleri'],
      ['http.response.code >= 400', 'HTTP hata yanıtları (4xx / 5xx)'],
      ['tls.handshake.type == 1', 'TLS ClientHello (şifreli bağlantı başlangıçları)'],
      ['tls.handshake.extensions_server_name contains "google"', 'Belirli bir siteye (SNI) giden HTTPS bağlantıları'],
    ] },
    { cat: 'Güvenlik', items: [
      ['arp.opcode == 2', 'ARP yanıtları (ARP sahteciliği kontrolü)'],
      ['dns.qry.name matches "^[a-z0-9]{20,}\\."', 'Çok uzun, rastgele görünen alan adları (DGA / tünelleme)'],
      ['tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.port == 445', 'SMB (445) bağlantı denemeleri'],
      ['http && http.request', 'Şifresiz HTTP istekleri'],
    ] },
  ];
}

if (typeof module !== 'undefined' && module.exports) module.exports = install; else if (root.PL) install(root.PL);
})(typeof window !== 'undefined' ? window : globalThis);
