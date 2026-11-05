/* PaketLens - paket çözümleyici ve analiz motoru (tarayıcı + Node, bağımlılıksız) */
(function (root) {
'use strict';

const u16 = (v, o) => (v[o] << 8) | v[o + 1];
const u32 = (v, o) => ((v[o] << 24) | (v[o + 1] << 16) | (v[o + 2] << 8) | v[o + 3]) >>> 0;
const hx = n => n.toString(16).padStart(2, '0');
const macStr = (v, o) => { const s = []; for (let i = 0; i < 6; i++) s.push(hx(v[o + i])); return s.join(':'); };
const ip4Str = (v, o) => v[o] + '.' + v[o + 1] + '.' + v[o + 2] + '.' + v[o + 3];
function ip6Str(v, o) {
  const g = []; for (let i = 0; i < 8; i++) g.push(u16(v, o + 2 * i));
  let bs = -1, bl = 0;
  for (let i = 0; i < 8;) { if (g[i] === 0) { let j = i; while (j < 8 && g[j] === 0) j++; if (j - i > bl) { bs = i; bl = j - i; } i = j; } else i++; }
  const h = g.map(x => x.toString(16));
  return bl >= 2 ? h.slice(0, bs).join(':') + '::' + h.slice(bs + bl).join(':') : h.join(':');
}
const ascii = (v, s, e) => { let r = ''; for (let i = s; i < e && i < v.length; i++) { const c = v[i]; r += c >= 32 && c < 127 ? String.fromCharCode(c) : '.'; } return r; };

const PROTO = { 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP' };
const protoName = n => PROTO[n] || ('IP/' + n);
const ETYPE = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: 'VLAN', 0x88cc: 'LLDP' };
const SVC_TCP = { 20: 'FTP', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS (TLS)', 445: 'SMB', 465: 'SMTP', 587: 'SMTP', 993: 'IMAP', 995: 'POP3', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP', 8443: 'HTTPS (TLS)' };
const SVC_UDP = { 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 123: 'NTP', 137: 'NetBIOS', 138: 'NetBIOS', 443: 'QUIC', 1900: 'SSDP', 5353: 'mDNS', 5355: 'LLMNR' };
const QTYPE = { 1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY' };
const RCODE = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };
const ICMP_T = { 0: 'Echo yanıtı (ping cevabı)', 3: 'Hedefe ulaşılamadı', 5: 'Yönlendirme', 8: 'Echo isteği (ping)', 11: 'Zaman aşımı (TTL doldu)' };
const ICMP_UNREACH = { 0: 'ağ ulaşılamaz', 1: 'host ulaşılamaz', 2: 'protokol ulaşılamaz', 3: 'port ulaşılamaz', 4: 'parçalanma gerekli', 13: 'filtre nedeniyle yasak' };
const GENERIC = new Set(['TCP', 'UDP', 'Diğer', 'ICMP', 'ICMPv6']);
const FLAGN = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'];
const flagStr = f => FLAGN.filter((_, i) => f & (1 << i)).join(', ');

/* ---------------- Dosya okuma (pcap / pcapng) ---------------- */
function parseCapture(buf) {
  const u8 = new Uint8Array(buf), dv = new DataView(buf);
  if (u8.length < 24) throw new Error('Dosya çok küçük, geçerli bir yakalama dosyası değil.');
  const magic = dv.getUint32(0, false);
  if (magic === 0x0a0d0d0a) return parsePcapng(dv, u8);
  let le, nano;
  if (magic === 0xa1b2c3d4) { le = false; nano = false; }
  else if (magic === 0xd4c3b2a1) { le = true; nano = false; }
  else if (magic === 0xa1b23c4d) { le = false; nano = true; }
  else if (magic === 0x4d3cb2a1) { le = true; nano = true; }
  else throw new Error('Bu dosya .pcap veya .pcapng biçiminde görünmüyor.');
  const link = dv.getUint32(20, le), out = [];
  let off = 24;
  while (off + 16 <= u8.length) {
    const sec = dv.getUint32(off, le), frac = dv.getUint32(off + 4, le), incl = dv.getUint32(off + 8, le), orig = dv.getUint32(off + 12, le);
    off += 16;
    if (off + incl > u8.length) break;
    out.push({ ts: sec + frac / (nano ? 1e9 : 1e6), data: u8.subarray(off, off + incl), len: orig, link });
    off += incl;
  }
  return out;
}

function parsePcapng(dv, u8) {
  const le = dv.getUint32(8, false) !== 0x1a2b3c4d;
  const ifs = [], out = [];
  let off = 0;
  while (off + 12 <= u8.length) {
    const type = dv.getUint32(off, le), len = dv.getUint32(off + 4, le);
    if (len < 12 || off + len > u8.length) break;
    const b = off + 8;
    if (type === 1) {
      const link = dv.getUint16(b, le); let res = 1e-6;
      for (let o = b + 8; o + 4 <= off + len - 4;) {
        const code = dv.getUint16(o, le), l = dv.getUint16(o + 2, le);
        if (code === 0) break;
        if (code === 9) { const x = u8[o + 4]; res = (x & 0x80) ? Math.pow(2, -(x & 0x7f)) : Math.pow(10, -x); }
        o += 4 + ((l + 3) & ~3);
      }
      ifs.push({ link, res });
    } else if (type === 6) {
      const id = dv.getUint32(b, le), hi = dv.getUint32(b + 4, le), lo = dv.getUint32(b + 8, le);
      const cap = dv.getUint32(b + 12, le), orig = dv.getUint32(b + 16, le), f = ifs[id] || { link: 1, res: 1e-6 };
      out.push({ ts: (hi * 4294967296 + lo) * f.res, data: u8.subarray(b + 20, b + 20 + cap), len: orig, link: f.link });
    } else if (type === 3) {
      const orig = dv.getUint32(b, le), f = ifs[0] || { link: 1 };
      out.push({ ts: 0, data: u8.subarray(b + 4, off + len - 4), len: orig, link: f.link });
    }
    off += (len + 3) & ~3;
  }
  return out;
}

/* ---------------- Paket çözme ---------------- */
function dissect(r, no) {
  const v = r.data;
  const p = { no, ts: r.ts, len: r.len, caplen: v.length, raw: v, layers: [], proto: 'Diğer', src: '', dst: '', sport: null, dport: null, info: '', app: 'Diğer', appSure: false, anoms: [], flags: 0, payloadLen: 0, payOff: 0, flow: null };
  const L = (name, fields) => p.layers.push({ name, fields });
  L('Çerçeve (Frame)', [['Paket no', no], ['Yakalanan boyut', v.length + ' bayt'], ['Gerçek boyut', r.len + ' bayt']]);
  try {
    let et = null, o = 0;
    if (r.link === 1) {
      if (v.length < 14) throw new Error('kısa');
      let t = u16(v, 12); o = 14; let vlan = null;
      while ((t === 0x8100 || t === 0x88a8) && o + 4 <= v.length) { vlan = u16(v, o) & 0xfff; t = u16(v, o + 2); o += 4; }
      const f = [['Kaynak MAC', macStr(v, 6)], ['Hedef MAC', macStr(v, 0)], ['Tür', '0x' + t.toString(16).padStart(4, '0') + (ETYPE[t] ? ' (' + ETYPE[t] + ')' : '')]];
      if (vlan !== null) f.push(['VLAN', vlan]);
      L('Ethernet', f);
      p.macSrc = macStr(v, 6); p.macDst = macStr(v, 0); et = t;
    } else if (r.link === 113) { et = u16(v, 14); o = 16; }
    else if (r.link === 0 || r.link === 108) { const af = v[0] | v[3] << 24 ? v[3] : v[0]; et = (af === 2) ? 0x0800 : 0x86dd; o = 4; }
    else if (r.link === 101 || r.link === 12) { et = (v[0] >> 4) === 4 ? 0x0800 : 0x86dd; o = 0; }
    else { p.info = 'Desteklenmeyen bağlantı katmanı (' + r.link + ')'; }
    if (et === 0x0800) dIPv4(p, v, o);
    else if (et === 0x86dd) dIPv6(p, v, o);
    else if (et === 0x0806) dARP(p, v, o);
    else if (et !== null) { p.proto = ETYPE[et] || ('0x' + et.toString(16)); p.info = p.proto + ' çerçevesi'; }
  } catch (e) {
    p.info = p.info || 'Bozuk veya eksik paket'; p.anoms.push('malformed');
  }
  if (!p.src) { p.src = p.macSrc || '?'; p.dst = p.macDst || '?'; }
  if (!p.info) p.info = p.proto;
  return p;
}

function dARP(p, v, o) {
  const op = u16(v, o + 6), sm = macStr(v, o + 8), si = ip4Str(v, o + 14), tm = macStr(v, o + 18), ti = ip4Str(v, o + 24);
  p.proto = 'ARP'; p.app = 'ARP'; p.src = si; p.dst = ti;
  p.arp = { op, sm, si, tm, ti };
  p.info = op === 1 ? `Kim ${ti}? ${si} adresine söyle` : `${si} adresi ${sm} MAC adresinde`;
  p.layers.push({ name: 'ARP', fields: [['İşlem', op === 1 ? 'İstek (1)' : 'Yanıt (2)'], ['Gönderen MAC', sm], ['Gönderen IP', si], ['Hedef MAC', tm], ['Hedef IP', ti]] });
}

function dIPv4(p, v, o) {
  const ihl = (v[o] & 15) * 4, tot = u16(v, o + 2), id = u16(v, o + 4), ff = u16(v, o + 6), ttl = v[o + 8], pr = v[o + 9];
  p.src = ip4Str(v, o + 12); p.dst = ip4Str(v, o + 16); p.ttl = ttl; p.ipv = 4;
  const end = tot >= ihl ? Math.min(v.length, o + tot) : v.length, frag = (ff & 0x1fff) * 8;
  p.layers.push({ name: 'IPv4', fields: [['Kaynak IP', p.src], ['Hedef IP', p.dst], ['Protokol', pr + ' (' + protoName(pr) + ')'], ['TTL', ttl], ['Toplam uzunluk', tot + ' bayt'], ['Tanımlayıcı (ID)', '0x' + id.toString(16).padStart(4, '0')], ['Parçalanma', (ff & 0x4000 ? 'DF ' : '') + (ff & 0x2000 ? 'MF ' : '') + 'ofset=' + frag]] });
  p.proto = protoName(pr);
  if (frag > 0) { p.info = 'IP parçası (fragment)'; return; }
  dL4(p, v, o + ihl, end, pr);
}

function dIPv6(p, v, o) {
  let nh = v[o + 6]; const plen = u16(v, o + 4), hop = v[o + 7];
  p.src = ip6Str(v, o + 8); p.dst = ip6Str(v, o + 24); p.ttl = hop; p.ipv = 6;
  const end = Math.min(v.length, o + 40 + plen); let q = o + 40;
  while ((nh === 0 || nh === 43 || nh === 60 || nh === 44) && q + 8 <= end) { const l = nh === 44 ? 8 : (v[q + 1] + 1) * 8; nh = v[q]; q += l; }
  p.layers.push({ name: 'IPv6', fields: [['Kaynak IP', p.src], ['Hedef IP', p.dst], ['Sonraki başlık', nh + ' (' + protoName(nh) + ')'], ['Hop limit (TTL)', hop], ['Yük uzunluğu', plen + ' bayt']] });
  p.proto = protoName(nh);
  dL4(p, v, q, end, nh);
}

function dL4(p, v, o, end, pr) {
  if (pr === 6) dTCP(p, v, o, end);
  else if (pr === 17) dUDP(p, v, o, end);
  else if (pr === 1) dICMP(p, v, o, end, false);
  else if (pr === 58) dICMP(p, v, o, end, true);
  else { p.app = protoName(pr); p.info = protoName(pr) + ' paketi'; }
}

function dTCP(p, v, o, end) {
  if (end - o < 20) { p.info = 'Eksik TCP başlığı'; p.anoms.push('malformed'); return; }
  const sp = u16(v, o), dp = u16(v, o + 2), seq = u32(v, o + 4), ack = u32(v, o + 8), doff = (v[o + 12] >> 4) * 4, fl = v[o + 13], win = u16(v, o + 14);
  const po = o + doff;
  Object.assign(p, { proto: 'TCP', sport: sp, dport: dp, seq, ack, flags: fl, win, payOff: po, payloadLen: Math.max(0, end - po) });
  let mss = null, ws = null, sack = false;
  for (let i = o + 20; i < po && i < end;) { const k = v[i]; if (k === 0) break; if (k === 1) { i++; continue; } const l = v[i + 1]; if (!l) break; if (k === 2) mss = u16(v, i + 2); if (k === 3) ws = v[i + 2]; if (k === 4) sack = true; i += l; }
  const f = [['Kaynak port', sp], ['Hedef port', dp], ['Sıra no (Seq)', seq], ['Onay no (Ack)', ack], ['Bayraklar', flagStr(fl) || '-'], ['Pencere (Window)', win], ['Veri uzunluğu', p.payloadLen + ' bayt']];
  if (mss !== null) f.push(['MSS', mss]); if (ws !== null) f.push(['Pencere ölçeği', ws]); if (sack) f.push(['SACK', 'destekleniyor']);
  p.layers.push({ name: 'TCP', fields: f });
  p.info = `${sp} → ${dp} [${flagStr(fl)}] Seq=${seq} Ack=${ack} Win=${win} Len=${p.payloadLen}`;
  p.app = SVC_TCP[dp] || SVC_TCP[sp] || 'TCP';
  if (p.payloadLen > 0) sniffTCP(p, v, po, end);
}

function sniffTCP(p, v, po, end) {
  const n = end - po;
  if (n >= 6 && v[po] >= 20 && v[po] <= 23 && v[po + 1] === 3 && v[po + 2] <= 4) { dTLS(p, v, po, end); return; }
  const head = ascii(v, po, Math.min(end, po + 8));
  if (/^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT) /.test(head) || head.startsWith('HTTP/1.')) {
    const txt = ascii(v, po, Math.min(end, po + 2048)).replace(/\./g, c => c);
    const raw = String.fromCharCode.apply(null, Array.from(v.subarray(po, Math.min(end, po + 2048)))).split('\r\n');
    const first = raw[0].replace(/[^\x20-\x7e]/g, '.'); let host = null, ctype = null;
    for (let i = 1; i < raw.length && raw[i]; i++) { const m = /^([^:]+):\s*(.*)$/.exec(raw[i]); if (!m) continue; const k = m[1].toLowerCase(); if (k === 'host') host = m[2]; if (k === 'content-type') ctype = m[2]; }
    if (host) host = host.replace(/:\d+$/, '');
    p.http = { first, host, ctype }; p.app = 'HTTP'; p.appSure = true;
    p.layers.push({ name: 'HTTP', fields: [['İlk satır', first]].concat(host ? [['Host', host]] : [], ctype ? [['İçerik türü', ctype]] : []) });
    p.info = first + (host ? '  (Host: ' + host + ')' : ''); return;
  }
  const t = ascii(v, po, Math.min(end, po + 4));
  if (t === 'SSH-') { p.app = 'SSH'; p.appSure = true; p.info = 'SSH sürüm bildirimi: ' + ascii(v, po, Math.min(end, po + 40)).replace(/\.+$/, ''); }
}

function dTLS(p, v, po, end) {
  const rt = v[po], ver = u16(v, po + 1), rl = u16(v, po + 3);
  const RT = { 20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'Uygulama verisi' };
  p.app = 'HTTPS (TLS)'; p.appSure = true;
  const f = [['Kayıt türü', rt + ' (' + RT[rt] + ')'], ['Sürüm', '0x' + ver.toString(16).padStart(4, '0')], ['Kayıt uzunluğu', rl]];
  if (rt === 22 && end - po > 9) {
    const ht = v[po + 5], HT = { 1: 'ClientHello', 2: 'ServerHello', 4: 'NewSessionTicket', 11: 'Certificate', 12: 'ServerKeyExchange', 14: 'ServerHelloDone', 16: 'ClientKeyExchange', 20: 'Finished' };
    f.push(['Handshake türü', ht + ' (' + (HT[ht] || '?') + ')']);
    p.info = 'TLS ' + (HT[ht] || 'Handshake');
    if (ht === 1) {
      try {
        let q = po + 43; q += 1 + v[q]; q += 2 + u16(v, q); q += 1 + v[q];
        const eend = Math.min(end, q + 2 + u16(v, q)); q += 2;
        while (q + 4 <= eend) {
          const et = u16(v, q), el = u16(v, q + 2);
          if (et === 0 && el > 5) { const nl = u16(v, q + 7); p.sni = ascii(v, q + 9, q + 9 + nl); }
          if (et === 16) { /* ALPN atla */ }
          q += 4 + el;
        }
      } catch (e) { /* SNI okunamadı */ }
      if (p.sni) { f.push(['Sunucu adı (SNI)', p.sni]); p.info += ' → ' + p.sni; }
    }
  } else if (rt === 23) p.info = 'TLS şifreli uygulama verisi (' + rl + ' bayt)';
  else p.info = 'TLS ' + RT[rt];
  p.layers.push({ name: 'TLS', fields: f });
}

function dUDP(p, v, o, end) {
  if (end - o < 8) { p.info = 'Eksik UDP başlığı'; return; }
  const sp = u16(v, o), dp = u16(v, o + 2), po = o + 8;
  Object.assign(p, { proto: 'UDP', sport: sp, dport: dp, payOff: po, payloadLen: Math.max(0, end - po) });
  p.layers.push({ name: 'UDP', fields: [['Kaynak port', sp], ['Hedef port', dp], ['Uzunluk', u16(v, o + 4) + ' bayt']] });
  p.app = SVC_UDP[dp] || SVC_UDP[sp] || 'UDP';
  p.info = `${sp} → ${dp} Len=${p.payloadLen}`;
  if ((p.app === 'DNS' || p.app === 'mDNS' || p.app === 'LLMNR') && p.payloadLen >= 12) {
    try { dDNS(p, v, po, end); } catch (e) { p.info += ' (DNS çözülemedi)'; }
  } else if (p.app === 'QUIC') p.info = 'QUIC şifreli trafik (' + p.payloadLen + ' bayt)';
}

function readName(v, o, base, end) {
  const labels = []; let ret = o, jumped = false, hops = 0;
  while (o < end) {
    const l = v[o];
    if (l === 0) { if (!jumped) ret = o + 1; break; }
    if ((l & 0xc0) === 0xc0) { const ptr = ((l & 0x3f) << 8) | v[o + 1]; if (!jumped) ret = o + 2; jumped = true; o = base + ptr; if (++hops > 20) break; continue; }
    labels.push(ascii(v, o + 1, o + 1 + l)); o += l + 1; if (!jumped) ret = o; if (labels.length > 127) break;
  }
  return [labels.join('.') || '.', ret];
}

function dDNS(p, v, base, end) {
  const id = u16(v, base), fl = u16(v, base + 2), qd = u16(v, base + 4), an = u16(v, base + 6);
  const qr = (fl >> 15) & 1, rcode = fl & 15;
  let o = base + 12; const questions = [], answers = [];
  for (let i = 0; i < qd && o < end; i++) { const [n, no] = readName(v, o, base, end); o = no; questions.push({ name: n, type: u16(v, o), cls: u16(v, o + 2) }); o += 4; }
  for (let i = 0; i < an && o + 10 <= end; i++) {
    const [n, no] = readName(v, o, base, end); o = no;
    const type = u16(v, o), ttl = u32(v, o + 4), rl = u16(v, o + 8); o += 10; let data = '';
    if (type === 1 && rl === 4) data = ip4Str(v, o); else if (type === 28 && rl === 16) data = ip6Str(v, o);
    else if (type === 5 || type === 2 || type === 12) data = readName(v, o, base, end)[0];
    else if (type === 16) data = ascii(v, o + 1, o + rl); else data = rl + ' bayt';
    answers.push({ name: n, type, ttl, data }); o += rl;
  }
  p.dns = { id, qr, rcode, questions, answers }; p.app = p.app === 'mDNS' ? 'mDNS' : 'DNS'; p.appSure = true;
  const q = questions[0], qn = q ? q.name : '?', qt = q ? (QTYPE[q.type] || q.type) : '?';
  if (!qr) p.info = `Sorgu ${qt} ${qn}`;
  else if (rcode) p.info = `Yanıt: ${RCODE[rcode] || rcode} (${qn})`;
  else p.info = `Yanıt ${qn} → ${answers.map(a => a.data).join(', ') || '(kayıt yok)'}`;
  const f = [['İşlem kimliği', '0x' + id.toString(16).padStart(4, '0')], ['Tür', qr ? 'Yanıt' : 'Sorgu'], ['Sonuç kodu', rcode + ' (' + (RCODE[rcode] || '?') + ')']];
  questions.forEach(x => f.push(['Soru', `${x.name} (${QTYPE[x.type] || x.type})`]));
  answers.forEach(x => f.push(['Cevap', `${x.name} → ${x.data} (${QTYPE[x.type] || x.type}, TTL ${x.ttl}s)`]));
  p.layers.push({ name: 'DNS', fields: f });
}

function dICMP(p, v, o, end, six) {
  const t = v[o], c = v[o + 1];
  p.app = six ? 'ICMPv6' : 'ICMP';
  const f = [['Tür', t + (!six && ICMP_T[t] ? ' (' + ICMP_T[t] + ')' : '')], ['Kod', c]];
  p.icmp = { type: t, code: c, six };
  if (!six && (t === 8 || t === 0)) { f.push(['Tanımlayıcı', u16(v, o + 4)], ['Sıra no', u16(v, o + 6)]); p.info = (t === 8 ? 'Echo isteği' : 'Echo yanıtı') + ` id=${u16(v, o + 4)} seq=${u16(v, o + 6)}`; }
  else if (!six && (t === 3 || t === 11)) {
    p.info = (ICMP_T[t] || 'ICMP') + (t === 3 ? ' – ' + (ICMP_UNREACH[c] || 'kod ' + c) : '');
    p.anoms.push(t === 3 ? 'icmp-unreach' : 'icmp-ttl');
    const q = o + 8;
    if (end - q >= 20 && (v[q] >> 4) === 4) {
      const ihl = (v[q] & 15) * 4, pr = v[q + 9], inner = { proto: protoName(pr), src: ip4Str(v, q + 12), dst: ip4Str(v, q + 16), sport: null, dport: null };
      if ((pr === 6 || pr === 17) && end - q - ihl >= 4) { inner.sport = u16(v, q + ihl); inner.dport = u16(v, q + ihl + 2); }
      p.icmpInner = inner;
      f.push(['İlgili paket', `${inner.proto} ${inner.src}${inner.sport !== null ? ':' + inner.sport : ''} → ${inner.dst}${inner.dport !== null ? ':' + inner.dport : ''}`]);
    }
  } else p.info = (six ? 'ICMPv6' : 'ICMP') + ` tür=${t} kod=${c}`;
  p.layers.push({ name: six ? 'ICMPv6' : 'ICMP', fields: f });
}

/* ---------------- Analiz ---------------- */
const isPrivate = ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fe80:|fc|fd)/i.test(ip) || /^(22[4-9]|23\d)\./.test(ip);

function analyze(packets) {
  const A = { packets, flows: [], flowMap: new Map(), hosts: new Map(), apps: [], names: new Map(), problems: [], stats: {}, timeline: null, pending: new Map() };
  const n = packets.length;
  const t0 = n ? packets[0].ts : 0, t1 = n ? packets[n - 1].ts : 0, dur = Math.max(t1 - t0, 1e-6);
  A.t0 = t0; A.t1 = t1;

  // ön geçiş: ip -> ad
  for (const p of packets) {
    if (p.dns && p.dns.qr && p.dns.questions[0]) for (const a of p.dns.answers) if ((a.type === 1 || a.type === 28) && !A.names.has(a.data)) A.names.set(a.data, p.dns.questions[0].name);
  }
  for (const p of packets) { if (p.sni) A.names.set(p.dst, p.sni); else if (p.http && p.http.host && /^GET|POST|HEAD|PUT/.test(p.http.first)) A.names.set(p.dst, p.http.host); }

  const addProblem = pr => { pr.id = A.problems.length + 1; A.problems.push(pr); return pr; };

  for (const p of packets) {
    // host
    const hs = ip => { let h = A.hosts.get(ip); if (!h) { h = { ip, pktsTx: 0, pktsRx: 0, bytesTx: 0, bytesRx: 0, flows: new Set() }; A.hosts.set(ip, h); } return h; };
    const hsrc = hs(p.src), hdst = hs(p.dst);
    hsrc.pktsTx++; hsrc.bytesTx += p.len; hdst.pktsRx++; hdst.bytesRx += p.len;

    // akış
    let key, innerFlow = null;
    const ek = (ip, port) => ip + (port != null ? ':' + port : '');
    const mk = (pr, a, b) => pr + '|' + (a < b ? a + '|' + b : b + '|' + a);
    key = mk(p.proto, ek(p.src, p.sport), ek(p.dst, p.dport));
    if (p.icmpInner) {
      const i = p.icmpInner, k2 = mk(i.proto, ek(i.src, i.sport), ek(i.dst, i.dport));
      if (A.flowMap.has(k2)) { innerFlow = A.flowMap.get(k2); key = k2; }
    }
    let f = A.flowMap.get(key);
    if (!f) {
      f = { id: A.flows.length + 1, key, proto: p.proto, a: p.src, aPort: p.sport, b: p.dst, bPort: p.dport, pkts: 0, bytes: 0, start: p.ts, end: p.ts, bytesAB: 0, bytesBA: 0, pktsAB: 0, pktsBA: 0, payloadBytes: 0, app: p.app, appSure: false, host: null, pnos: [], syn: false, synack: false, rst: 0, fin: 0, retrans: 0, zeroWin: 0, rtt: null, synTime: null, synTries: 0, seen: { AB: new Set(), BA: new Set() }, probs: [], icmpErr: null, rstFirst: null };
      A.flows.push(f); A.flowMap.set(key, f);
    }
    p.flow = f.id;
    const dir = (p.src === f.a && p.sport === f.aPort) ? 'AB' : 'BA';
    f.pkts++; f.bytes += p.len; f.end = p.ts; f.pnos.push(p.no);
    if (dir === 'AB') { f.bytesAB += p.len; f.pktsAB++; } else { f.bytesBA += p.len; f.pktsBA++; }
    hsrc.flows.add(f.id); hdst.flows.add(f.id);
    if (p.appSure && !f.appSure) { f.app = p.app; f.appSure = true; } else if (!f.appSure && GENERIC.has(f.app) && !GENERIC.has(p.app)) f.app = p.app;
    f.payloadBytes += p.payloadLen;
    if (p.sni) f.host = p.sni; else if (p.http && p.http.host) f.host = f.host || p.http.host; else if (p.dns && p.dns.questions[0]) f.host = f.host || p.dns.questions[0].name;
    if (p.icmpInner && innerFlow) f.icmpErr = p;

    if (p.proto === 'TCP') {
      const syn = p.flags & 2, ack = p.flags & 16, rst = p.flags & 4, fin = p.flags & 1;
      if (syn && !ack) { f.syn = true; f.synTries++; if (f.synTime == null) f.synTime = p.ts; }
      if (syn && ack) { f.synack = true; if (f.synTime != null && f.rtt == null) f.rtt = p.ts - f.synTime; }
      if (rst) { f.rst++; p.anoms.push('rst'); if (!f.rstFirst) f.rstFirst = { no: p.no, dir, afterData: f.payloadBytes > 0 }; }
      if (fin) f.fin++;
      if ((p.payloadLen > 0 || syn || fin) && !rst) {
        const k = p.seq + ':' + (p.payloadLen + (syn ? 1 : 0) + (fin ? 1 : 0));
        if (f.seen[dir].has(k)) { f.retrans++; p.anoms.push('retrans'); } else f.seen[dir].add(k);
      }
      if (p.win === 0 && !rst && !syn) { f.zeroWin++; p.anoms.push('zerowin'); }
    }

    // DNS gecikme
    if (p.dns) {
      const qn = p.dns.questions[0] ? p.dns.questions[0].name : '';
      if (!p.dns.qr) A.pending.set(p.dns.id + '|' + qn + '|' + p.src, p);
      else {
        const k = p.dns.id + '|' + qn + '|' + p.dst, q = A.pending.get(k);
        if (q) { p.dnsLatency = p.ts - q.ts; q.dnsAnswered = true; A.pending.delete(k); if (p.dnsLatency > 0.25) p.anoms.push('dns-slow'); }
        if (p.dns.rcode === 3) p.anoms.push('dns-nx'); else if (p.dns.rcode) p.anoms.push('dns-error');
      }
    }
  }
  for (const q of A.pending.values()) if (t1 - q.ts > 2 && q.app === 'DNS') q.anoms.push('dns-noresp');

  const nm = ip => A.names.get(ip) || ip;
  A.nm = nm;
  for (const f of A.flows) f.client = f.a, f.server = f.b;
  const fl = id => A.flows[id - 1];

  /* sorunlar */
  const portScan = new Map();
  for (const p of packets) if (p.proto === 'TCP' && (p.flags & 18) === 2) { let s = portScan.get(p.src); if (!s) portScan.set(p.src, s = { set: new Set(), pk: [] }); s.set.add(p.dst + ':' + p.dport); s.pk.push(p.no); }
  const scanners = new Set();
  for (const [src, s] of portScan) if (s.set.size >= 15) {
    scanners.add(src);
    addProblem({ sev: 'high', type: 'scan', title: 'Olası port taraması', flow: null, pkts: s.pk, ts: packets[s.pk[0] - 1] ? packets[s.pk[0] - 1].ts : t0,
      plain: `${nm(src)} adresi kısa sürede ${s.set.size} farklı hedef/porta bağlantı denemesi yaptı. Bu, ağdaki açık servisleri arayan bir tarama davranışına benzer.`,
      advice: 'Tarama sizin yetkiniz dahilinde değilse bu cihazı izole edin ve kaynağını inceleyin; güvenlik duvarında tarama kaynağını engelleyebilirsiniz.' });
  }
  const refused = [];
  for (const f of A.flows) {
    const where = `${nm(f.server)}${f.bPort != null ? ':' + f.bPort : ''}`;
    const base = { flow: f.id, ts: f.start };
    if (f.proto === 'TCP') {
      if (f.retrans > 0 && !(f.syn && !f.synack)) addProblem({ ...base, sev: f.retrans >= 3 ? 'med' : 'low', type: 'retrans', title: `Yeniden iletim (${f.retrans} paket)`, pkts: packets.filter(p => p.flow === f.id && p.anoms.includes('retrans')).map(p => p.no),
        plain: `${where} ile olan bağlantıda ${f.retrans} paket tekrar gönderildi. Paket ya kayboldu ya da onayı (ACK) gelmedi. Yavaşlama ve takılmalara yol açar.`,
        advice: 'Wi-Fi sinyalini/kabloyu ve ağ yoğunluğunu kontrol edin. Sorun yalnızca bu sunucuda oluyorsa sorun sunucu veya servis sağlayıcı tarafında olabilir.' });
      if (f.zeroWin > 0) addProblem({ ...base, sev: 'med', type: 'zerowin', title: 'Alıcı veri almayı durdurdu (Zero Window)', pkts: packets.filter(p => p.flow === f.id && p.anoms.includes('zerowin')).map(p => p.no),
        plain: `${where} ile olan bağlantıda bir taraf alma tamponunun dolduğunu bildirdi (pencere=0). Karşı taraf veri göndermeyi bırakmak zorunda kaldı.`,
        advice: 'Alıcı uygulama/cihaz verileri yeterince hızlı işleyemiyor olabilir (CPU, disk veya uygulama yavaşlığı).' });
      if (f.syn && !f.synack && !f.rst) addProblem({ ...base, sev: 'high', type: 'nosyn', title: 'Bağlantı kurulamadı', pkts: packets.filter(p => p.flow === f.id).map(p => p.no),
        plain: `${where} adresine ${f.synTries} kez bağlanılmaya çalışıldı ancak hiç yanıt gelmedi.`,
        advice: 'Hedef kapalı olabilir, adres yanlış olabilir ya da bir güvenlik duvarı paketleri sessizce düşürüyor olabilir.' });
      else if (f.syn && !f.synack && f.rst) refused.push(f);
      else if (f.synack && f.rst > 0) addProblem({ ...base, sev: f.rstFirst && f.rstFirst.afterData ? 'med' : 'high', type: 'rst', title: 'Bağlantı aniden sıfırlandı (RST)', pkts: packets.filter(p => p.flow === f.id && p.anoms.includes('rst')).map(p => p.no),
        plain: `${where} ile olan bağlantı normal kapanmak yerine ${f.rstFirst && f.rstFirst.dir === 'BA' ? 'sunucu' : 'istemci'} tarafından aniden kesildi (RST).`,
        advice: 'Sunucu bağlantıyı reddetmiş, bir güvenlik duvarı/IPS bağlantıyı kesmiş veya uygulama çökmüş olabilir. Sunucu günlüklerine bakın.' });
      if (f.rtt != null && f.rtt > 0.15) addProblem({ ...base, sev: 'low', type: 'slowrtt', title: `Yavaş bağlantı kurulumu (${Math.round(f.rtt * 1000)} ms)`, pkts: packets.filter(p => p.flow === f.id).slice(0, 3).map(p => p.no),
        plain: `${where} ile TCP el sıkışması ${Math.round(f.rtt * 1000)} ms sürdü. Sunucu uzak veya hat yavaş olabilir.`,
        advice: 'Daha yakın bir sunucu/CDN kullanmak veya VPN/proxy varsa kontrol etmek gecikmeyi azaltabilir.' });
    }
    if (f.icmpErr) { const e = f.icmpErr; addProblem({ ...base, sev: 'med', type: 'icmp', title: 'Hedefe ulaşılamadı (ICMP)', pkts: [e.no], ts: e.ts,
      plain: `${nm(e.src)}, ${f.proto} ${nm(f.b)}${f.bPort != null ? ':' + f.bPort : ''} hedefinin ${ICMP_UNREACH[e.icmp.code] || 'ulaşılamaz'} olduğunu bildirdi.`,
      advice: 'Hedefte o portu dinleyen bir servis yok ya da ağ yolu kesik. Adres/port bilgisini ve hedef servisin çalıştığını kontrol edin.' }); }
  }
  if (refused.length) {
    const rf = refused.filter(f => !scanners.has(f.a) && !scanners.has(f.b));
    const list = rf.length ? rf : [];
    if (list.length && list.length <= 5) list.forEach(f => addProblem({ sev: 'low', type: 'refused', title: 'Bağlantı reddedildi', flow: f.id, ts: f.start, pkts: f.pnos, plain: `${nm(f.server)}:${f.bPort} bağlantı isteğini reddetti (RST) – o portta dinleyen servis yok.`, advice: 'Doğru adres ve port kullandığınızdan, servisin çalıştığından emin olun.' }));
    else if (list.length) addProblem({ sev: 'low', type: 'refused', title: `${list.length} bağlantı reddedildi`, flow: null, ts: list[0].start, pkts: list.flatMap(f => f.pnos), plain: 'Birçok bağlantı isteği RST ile reddedildi.', advice: 'Hedef servislerin çalıştığını doğrulayın.' });
  }
  for (const p of packets) {
    if (p.anoms.includes('dns-slow')) addProblem({ sev: 'med', type: 'dnsslow', title: `Yavaş DNS yanıtı (${Math.round(p.dnsLatency * 1000)} ms)`, flow: p.flow, ts: p.ts, pkts: [p.no], plain: `"${p.dns.questions[0].name}" adının çözülmesi ${Math.round(p.dnsLatency * 1000)} ms sürdü. Her yeni bağlantı bu kadar bekler.`, advice: 'Daha hızlı bir DNS sunucusu (ör. 1.1.1.1, 8.8.8.8) denenebilir veya yerel DNS sunucusu kontrol edilebilir.' });
    if (p.anoms.includes('dns-nx')) addProblem({ sev: 'low', type: 'dnsnx', title: 'Alan adı bulunamadı (NXDOMAIN)', flow: p.flow, ts: p.ts, pkts: [p.no], plain: `"${p.dns.questions[0].name}" diye bir alan adı yok ya da yanlış yazılmış.`, advice: 'Adresin yazımını kontrol edin. Sık tekrarlanıyorsa bir uygulama eski/hatalı bir adrese erişmeye çalışıyor olabilir.' });
    if (p.anoms.includes('dns-error')) addProblem({ sev: 'high', type: 'dnserr', title: 'DNS sunucusu hata döndürdü', flow: p.flow, ts: p.ts, pkts: [p.no], plain: `"${p.dns.questions[0].name}" sorgusu ${RCODE[p.dns.rcode] || p.dns.rcode} ile sonuçlandı.`, advice: 'DNS sunucusunu değiştirmeyi veya sunucunun durumunu kontrol etmeyi deneyin.' });
    if (p.anoms.includes('dns-noresp')) addProblem({ sev: 'high', type: 'dnsno', title: 'DNS sorgusu yanıtsız', flow: p.flow, ts: p.ts, pkts: [p.no], plain: `"${p.dns.questions[0] ? p.dns.questions[0].name : '?'}" sorgusuna yanıt gelmedi.`, advice: 'DNS sunucusuna erişimi (güvenlik duvarı, ağ bağlantısı) kontrol edin.' });
  }
  const order = { high: 0, med: 1, low: 2 };
  A.problems.sort((x, y) => order[x.sev] - order[y.sev] || x.ts - y.ts);
  A.problems.forEach((pr, i) => { pr.id = i + 1; if (pr.flow) fl(pr.flow).probs.push(pr); });
  for (const f of A.flows) f.status = f.probs.some(x => x.sev !== 'low') ? 'bad' : f.probs.length ? 'warn' : 'ok';

  /* uygulama özetleri */
  const am = new Map();
  for (const f of A.flows) { let a = am.get(f.app); if (!a) am.set(f.app, a = { app: f.app, pkts: 0, bytes: 0, flows: 0 }); a.pkts += f.pkts; a.bytes += f.bytes; a.flows++; }
  A.apps = [...am.values()].sort((x, y) => y.bytes - x.bytes);

  /* zaman çizelgesi */
  const NB = 60, tl = { n: NB, bytes: new Array(NB).fill(0), probs: new Array(NB).fill(0), t0, dur };
  for (const p of packets) { const i = Math.min(NB - 1, Math.floor((p.ts - t0) / dur * NB)); tl.bytes[i] += p.len; tl.probs[i] += p.anoms.filter(a => a !== 'dns-nx').length; }
  A.timeline = tl;

  const bytes = packets.reduce((s, p) => s + p.len, 0);
  A.stats = { packets: n, bytes, duration: t1 - t0, flows: A.flows.length, hosts: A.hosts.size, problems: A.problems.length, high: A.problems.filter(x => x.sev === 'high').length, avgRate: bytes * 8 / Math.max(dur, 1e-3) };
  return A;
}

/* ---------------- Düz dil açıklamaları ---------------- */
function describePacket(p, A) {
  const nm = A.nm, c = nm(p.src), s = nm(p.dst);
  if (p.arp) return p.arp.op === 1 ? `${p.arp.si} cihazı, ${p.arp.ti} adresine sahip cihazın MAC adresini soruyor (ağdaki herkese yayın).` : `${p.arp.si} adresinin MAC adresinin ${p.arp.sm} olduğu bildiriliyor.`;
  if (p.dns) {
    const q = p.dns.questions[0] || { name: '?', type: 1 }, t = QTYPE[q.type] || q.type;
    if (!p.dns.qr) return `${c}, "${q.name}" adının ${t === 'AAAA' ? 'IPv6' : t === 'A' ? 'IP' : t} kaydını DNS sunucusuna soruyor.`;
    if (p.dns.rcode) return `DNS sunucusu "${q.name}" için hata döndürdü: ${RCODE[p.dns.rcode] || p.dns.rcode}${p.dns.rcode === 3 ? ' (böyle bir alan adı yok)' : ''}.`;
    return `DNS sunucusu "${q.name}" adının ${p.dns.answers.map(a => a.data).join(', ') || 'kaydı yok'} olduğunu söylüyor${p.dnsLatency != null ? ` (${Math.round(p.dnsLatency * 1000)} ms'de yanıtladı)` : ''}.`;
  }
  if (p.icmp) {
    if (p.icmp.type === 8) return `${c}, ${s} adresine ping gönderiyor (ulaşılabilir mi diye soruyor).`;
    if (p.icmp.type === 0) return `${c}, ping'e yanıt veriyor – cihaz ayakta.`;
    if (p.icmp.type === 3) return `${c}, gönderilen paketin hedefe ulaşamadığını bildiriyor: ${ICMP_UNREACH[p.icmp.code] || 'ulaşılamaz'}.`;
    return `${p.info}.`;
  }
  if (p.proto === 'TCP') {
    const f = p.flags, syn = f & 2, ack = f & 16, rst = f & 4, fin = f & 1;
    let t;
    if (p.sni && !p.dns) t = `${c}, ${p.sni} ile şifreli (TLS) bağlantı kurmak için "merhaba" (ClientHello) gönderiyor.`;
    else if (p.http) t = `HTTP (şifresiz!): ${p.http.first}`;
    else if (p.app === 'HTTPS (TLS)' && /^TLS (?!şifreli)/.test(p.info)) t = `${c}: ${p.info} – şifreli bağlantının kurulum adımı.`;
    else if (syn && !ack) t = `${c}, ${s}${p.dport ? ' (port ' + p.dport + ')' : ''} ile bağlantı başlatmak istiyor (SYN).`;
    else if (syn && ack) t = `${c} bağlantı isteğini kabul etti (SYN-ACK).`;
    else if (rst) t = `${c}, bağlantıyı aniden sonlandırdı (RST).`;
    else if (fin) t = `${c}, bağlantıyı düzgünce kapatıyor (FIN).`;
    else if (p.payloadLen === 0) t = `Alındı onayı (ACK) – "şimdiye kadarki veriyi aldım".`;
    else t = `${c} → ${s}: ${p.payloadLen} bayt ${p.app === 'HTTPS (TLS)' ? 'şifreli ' : ''}veri.`;
    if (p.anoms.includes('retrans')) t += ' ⚠ Bu paket daha önce gönderilmişti (yeniden iletim).';
    if (p.anoms.includes('zerowin')) t += ' ⚠ Alıcı tamponu dolu (pencere=0).';
    return t;
  }
  if (p.proto === 'UDP') return `${c} → ${s}: ${p.payloadLen} bayt ${p.app === 'UDP' ? 'UDP' : p.app} verisi.`;
  return p.info;
}

function describeFlow(f, A) {
  const nm = A.nm, dur = f.end - f.start;
  const bits = [`${nm(f.client)} ↔ ${nm(f.server)}${f.bPort != null ? ' (port ' + f.bPort + ')' : ''} arasında ${f.app} trafiği.`];
  bits.push(`${f.pkts} paket, ${f.bytes} bayt, ${dur < 1 ? Math.round(dur * 1000) + ' ms' : dur.toFixed(1) + ' sn'} sürdü.`);
  if (f.proto === 'TCP') {
    if (f.synack) bits.push(`Bağlantı kuruldu${f.rtt != null ? ' (el sıkışma ' + Math.round(f.rtt * 1000) + ' ms)' : ''}.`);
    else if (f.syn) bits.push('Bağlantı kurulamadı.');
    bits.push(f.rst ? 'Bağlantı RST ile kesildi.' : f.fin ? 'Bağlantı düzgün kapatıldı.' : 'Yakalama sırasında bağlantı hâlâ açıktı.');
  }
  return bits.join(' ');
}

const API = { parseCapture, dissect, analyze, describePacket, describeFlow, isPrivate, flagStr, QTYPE, RCODE };
if (typeof module !== 'undefined' && module.exports) module.exports = API; else root.PL = API;
})(typeof self !== 'undefined' ? self : this);
