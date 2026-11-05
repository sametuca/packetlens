/* PacketLens - Wireshark tarzı display filter dili
   Örnekler:  ip.addr == 192.168.1.0/24 && tcp.port == 443
              dns.qry.name contains "google" || http.host == "example.com"
              tcp.analysis.retransmission && !(ip.src == 10.0.0.1)                              */
(function (root) {
'use strict';

const PROTO_APPS = { tls: ['HTTPS (TLS)'], http: ['HTTP'], dns: ['DNS', 'mDNS'], mdns: ['mDNS'], ssh: ['SSH'], ntp: ['NTP'], dhcp: ['DHCP'], quic: ['QUIC'], smtp: ['SMTP'], ftp: ['FTP'], telnet: ['Telnet'], pop: ['POP3'], imap: ['IMAP'], smb: ['SMB'], rdp: ['RDP'], mysql: ['MySQL'], postgresql: ['PostgreSQL'], netbios: ['NetBIOS'], ssdp: ['SSDP'], llmnr: ['LLMNR'] };
const F = {};
const def = (name, t, get, doc) => { F[name] = { t, get, doc }; };
const tcp = p => p.proto === 'TCP', udp = p => p.proto === 'UDP';

const toAscii = u8 => { let s = ''; for (let i = 0; i < u8.length; i++) { const c = u8[i]; s += c >= 32 && c < 127 ? String.fromCharCode(c) : '.'; } return s; };
def('frame', 'raw', p => p._asc || (p._asc = toAscii(p.raw)), 'Ham paket içeriği (contains ile aranır)');
def('frame.number', 'num', p => p.no, 'Paket numarası'); def('frame.len', 'num', p => p.len, 'Paket boyutu (bayt)');
def('frame.cap_len', 'num', p => p.caplen); def('frame.time_relative', 'num', (p, A) => p.ts - A.t0, 'Yakalama başından beri geçen saniye');
def('frame.time_epoch', 'num', p => p.ts);
def('eth', 'bool', p => !!p.macSrc); def('eth.src', 'str', p => p.macSrc); def('eth.dst', 'str', p => p.macDst); def('eth.addr', 'str', p => p.macSrc ? [p.macSrc, p.macDst] : undefined);
const v4 = p => p.ipv === 4, v6 = p => p.ipv === 6;
def('ip', 'bool', v4); def('ip.src', 'ip', p => v4(p) ? p.src : undefined, 'Kaynak IPv4'); def('ip.dst', 'ip', p => v4(p) ? p.dst : undefined, 'Hedef IPv4');
def('ip.addr', 'ip', p => v4(p) ? [p.src, p.dst] : undefined, 'Kaynak veya hedef IPv4 (CIDR: 10.0.0.0/8)'); def('ip.ttl', 'num', p => v4(p) ? p.ttl : undefined);
def('ipv6', 'bool', v6); def('ipv6.src', 'ip', p => v6(p) ? p.src : undefined); def('ipv6.dst', 'ip', p => v6(p) ? p.dst : undefined); def('ipv6.addr', 'ip', p => v6(p) ? [p.src, p.dst] : undefined);
def('tcp', 'bool', tcp); def('tcp.srcport', 'num', p => tcp(p) ? p.sport : undefined); def('tcp.dstport', 'num', p => tcp(p) ? p.dport : undefined);
def('tcp.port', 'num', p => tcp(p) ? [p.sport, p.dport] : undefined, 'Kaynak veya hedef TCP portu');
def('tcp.flags', 'num', p => tcp(p) ? p.flags : undefined);
[['fin', 1], ['syn', 2], ['reset', 4], ['push', 8], ['ack', 16], ['urg', 32]].forEach(([n, b]) => def('tcp.flags.' + n, 'bool', p => tcp(p) ? !!(p.flags & b) : undefined, 'TCP ' + n.toUpperCase() + ' bayrağı'));
def('tcp.seq', 'num', p => tcp(p) ? p.seq : undefined); def('tcp.ack', 'num', p => tcp(p) ? p.ack : undefined);
def('tcp.window_size', 'num', p => tcp(p) ? p.win : undefined); def('tcp.len', 'num', p => tcp(p) ? p.payloadLen : undefined, 'TCP veri uzunluğu');
def('tcp.stream', 'num', p => tcp(p) ? p.flow : undefined, 'Bağlantı (akış) numarası');
def('tcp.analysis.retransmission', 'bool', p => tcp(p) ? p.anoms.includes('retrans') : undefined, 'Yeniden iletim');
def('tcp.analysis.zero_window', 'bool', p => tcp(p) ? p.anoms.includes('zerowin') : undefined, 'Sıfır pencere');
def('tcp.analysis.flags', 'bool', p => tcp(p) ? (p.anoms.includes('retrans') || p.anoms.includes('zerowin')) : undefined, 'Herhangi bir TCP analiz uyarısı');
def('udp', 'bool', udp); def('udp.srcport', 'num', p => udp(p) ? p.sport : undefined); def('udp.dstport', 'num', p => udp(p) ? p.dport : undefined);
def('udp.port', 'num', p => udp(p) ? [p.sport, p.dport] : undefined, 'Kaynak veya hedef UDP portu');
def('icmp', 'bool', p => p.proto === 'ICMP'); def('icmp.type', 'num', p => p.icmp && !p.icmp.six ? p.icmp.type : undefined); def('icmp.code', 'num', p => p.icmp && !p.icmp.six ? p.icmp.code : undefined);
def('icmpv6', 'bool', p => p.proto === 'ICMPv6'); def('icmpv6.type', 'num', p => p.icmp && p.icmp.six ? p.icmp.type : undefined);
def('arp', 'bool', p => !!p.arp); def('arp.opcode', 'num', p => p.arp ? p.arp.op : undefined); def('arp.src.proto_ipv4', 'ip', p => p.arp ? p.arp.si : undefined); def('arp.dst.proto_ipv4', 'ip', p => p.arp ? p.arp.ti : undefined);
def('arp.src.hw_mac', 'str', p => p.arp ? p.arp.sm : undefined);
def('dns', 'bool', p => !!p.dns && p.app === 'DNS'); def('mdns', 'bool', p => p.app === 'mDNS');
def('dns.qry.name', 'str', p => p.dns ? p.dns.questions.map(q => q.name) : undefined, 'Sorgulanan alan adı');
def('dns.qry.type', 'num', p => p.dns ? p.dns.questions.map(q => q.type) : undefined, '1=A, 28=AAAA, 16=TXT, 5=CNAME');
def('dns.flags.response', 'bool', p => p.dns ? !!p.dns.qr : undefined); def('dns.flags.rcode', 'num', p => p.dns ? p.dns.rcode : undefined, '0=başarılı, 3=NXDOMAIN, 2=SERVFAIL');
def('dns.id', 'num', p => p.dns ? p.dns.id : undefined);
def('dns.a', 'ip', p => p.dns ? p.dns.answers.filter(a => a.type === 1).map(a => a.data) : undefined); def('dns.aaaa', 'ip', p => p.dns ? p.dns.answers.filter(a => a.type === 28).map(a => a.data) : undefined);
def('dns.resp.name', 'str', p => p.dns ? p.dns.answers.map(a => a.name) : undefined); def('dns.count.answers', 'num', p => p.dns ? p.dns.answers.length : undefined);
def('dns.time', 'num', p => p.dnsLatency != null ? p.dnsLatency : undefined, 'DNS yanıt süresi (sn)');
def('http', 'bool', p => !!p.http); def('http.host', 'str', p => p.http && p.http.host ? p.http.host : undefined);
def('http.request', 'bool', p => p.http ? !!p.http.method : undefined); def('http.response', 'bool', p => p.http ? p.http.status != null : undefined);
def('http.request.method', 'str', p => p.http && p.http.method ? p.http.method : undefined); def('http.request.uri', 'str', p => p.http && p.http.path ? p.http.path : undefined);
def('http.response.code', 'num', p => p.http && p.http.status != null ? p.http.status : undefined); def('http.content_type', 'str', p => p.http && p.http.ctype ? p.http.ctype : undefined);
def('http.content_length', 'num', p => p.http && p.http.clen != null ? p.http.clen : undefined);
def('tls', 'bool', p => !!p.tls); def('tls.handshake.extensions_server_name', 'str', p => p.sni || undefined, 'TLS SNI (site adı)');
def('tls.handshake.type', 'num', p => p.tls && p.tls.ht != null ? p.tls.ht : undefined, '1=ClientHello, 2=ServerHello, 11=Certificate');
def('tls.record.content_type', 'num', p => p.tls ? p.tls.rt : undefined); def('tls.handshake.ciphersuite', 'num', p => p.tls && p.tls.cipher != null ? p.tls.cipher : undefined);
def('pl.problem', 'bool', p => p.anoms.length > 0, 'PacketLens: sorun işaretli paket'); def('pl.app', 'str', p => p.app, 'PacketLens: uygulama adı');
def('pl.host', 'str', (p, A) => [A.nm(p.src), A.nm(p.dst)], 'PacketLens: cihaz/alan adı'); def('pl.flow', 'num', p => p.flow); def('pl.info', 'str', p => p.info);
Object.keys(PROTO_APPS).forEach(n => { if (!F[n]) def(n, 'bool', p => PROTO_APPS[n].includes(p.app)); });

/* ----- sözcükleme ----- */
const WORDOPS = { and: '&&', or: '||', not: '!', eq: '==', ne: '!=', gt: '>', lt: '<', ge: '>=', le: '<=', contains: 'contains', matches: 'matches' };
const TOK = /\s*(?:("(?:[^"\\]|\\.)*")|(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)|((?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?:\/\d{1,3})?)|(0x[0-9a-fA-F]+|\d+(?:\.\d+)?)|([A-Za-z_][\w.]*)|(==|!=|>=|<=|&&|\|\||[<>()!~]))/y;
function tokenize(text) {
  const out = []; TOK.lastIndex = 0; let pos = 0;
  while (pos < text.length) {
    if (/^\s*$/.test(text.slice(pos))) break;
    TOK.lastIndex = pos; const m = TOK.exec(text);
    if (!m) throw new Error(`Beklenmeyen karakter: "${text.slice(pos).trim().slice(0, 12)}"`);
    pos = TOK.lastIndex;
    if (m[1] !== undefined) out.push({ k: 'lit', v: JSON.parse(m[1].replace(/\\(?!["\\nrt])/g, '\\\\')), s: 'str' });
    else if (m[2] !== undefined || m[3] !== undefined) out.push({ k: 'lit', v: m[2] || m[3], s: 'ip' });
    else if (m[4] !== undefined) out.push({ k: 'lit', v: m[4].startsWith('0x') ? parseInt(m[4], 16) : parseFloat(m[4]), s: 'num' });
    else if (m[5] !== undefined) { const lw = m[5].toLowerCase(); if (WORDOPS[lw]) out.push({ k: 'op', v: WORDOPS[lw] }); else if (lw === 'true' || lw === 'false') out.push({ k: 'lit', v: lw === 'true' ? 1 : 0, s: 'num' }); else out.push({ k: 'id', v: m[5] }); }
    else out.push({ k: 'op', v: m[6] === '~' ? 'matches' : m[6] });
  }
  return out;
}

/* ----- ayrıştırma + derleme ----- */
const CMP = new Set(['==', '!=', '>', '<', '>=', '<=', 'contains', 'matches']);
function suggest(id) {
  const names = Object.keys(F), pre = id.includes('.') ? id.slice(0, id.lastIndexOf('.')) : id.slice(0, 2);
  const c = names.filter(n => n.startsWith(pre)).slice(0, 6);
  return c.length ? ' Benzer alanlar: ' + c.join(', ') : '';
}
function ipv4Int(s) { const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s); return m ? ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0 : null; }
function ipEq(val, lit) {
  if (lit.includes('/')) {
    const [a, n] = lit.split('/'), ai = ipv4Int(a), vi = ipv4Int(val), bits = +n;
    if (ai === null || vi === null) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0; return ((ai & mask) >>> 0) === ((vi & mask) >>> 0);
  }
  return val.toLowerCase() === lit.toLowerCase();
}
function compile(text) {
  try {
    const toks = tokenize(text); let i = 0;
    const peek = () => toks[i], next = () => toks[i++];
    const isOp = v => peek() && peek().k === 'op' && peek().v === v;
    function pOr() { let l = pAnd(); while (isOp('||')) { next(); const a = l, b = pAnd(); l = (p, A) => a(p, A) || b(p, A); } return l; }
    function pAnd() { let l = pNot(); while (isOp('&&')) { next(); const a = l, b = pNot(); l = (p, A) => a(p, A) && b(p, A); } return l; }
    function pNot() { if (isOp('!')) { next(); const a = pNot(); return (p, A) => !a(p, A); } return pPrim(); }
    function pPrim() {
      const t = next();
      if (!t) throw new Error('Filtre eksik: bir alan adı bekleniyordu');
      if (t.k === 'op' && t.v === '(') { const e = pOr(); if (!isOp(')')) throw new Error('Kapanış parantezi ")" eksik'); next(); return e; }
      if (t.k !== 'id') throw new Error(`Alan adı bekleniyordu, "${t.v}" bulundu`);
      const fld = F[t.v];
      if (!fld) throw new Error(`Bilinmeyen alan veya protokol: "${t.v}".` + suggest(t.v));
      const nx = peek();
      if (nx && nx.k === 'op' && CMP.has(nx.v)) {
        next(); const op = nx.v, lit = next();
        if (!lit || lit.k !== 'lit') throw new Error(`"${t.v} ${op}" sonrasında bir değer bekleniyordu`);
        return cmp(fld, t.v, op, lit);
      }
      return (p, A) => { const v = fld.get(p, A); return v !== undefined && v !== false && v !== null && !(Array.isArray(v) && !v.length); };
    }
    function cmp(fld, name, op, lit) {
      let lv = lit.v, re = null;
      if (op === 'matches') { try { re = new RegExp(String(lv), 'i'); } catch (e) { throw new Error('Geçersiz düzenli ifade: ' + lv); } }
      if ((fld.t === 'num' || fld.t === 'bool') && typeof lv !== 'number' && op !== 'contains' && op !== 'matches') throw new Error(`"${name}" bir sayı ile karşılaştırılmalı (örn. ${name} == 1)`);
      if (fld.t === 'raw' && op !== 'contains' && op !== 'matches') throw new Error('"frame" yalnızca contains veya matches ile kullanılır');
      const sv = String(lv).toLowerCase();
      const eq = x => fld.t === 'num' ? Number(x) === lv : fld.t === 'bool' ? Number(!!x) === lv : fld.t === 'ip' ? ipEq(String(x), String(lv)) : String(x).toLowerCase() === sv;
      return (p, A) => {
        const v = fld.get(p, A); if (v === undefined || v === null) return false;
        const xs = Array.isArray(v) ? v : [v]; if (!xs.length) return false;
        switch (op) {
          case '==': return xs.some(eq);
          case '!=': return !xs.some(eq);
          case '>': return xs.some(x => Number(x) > lv); case '<': return xs.some(x => Number(x) < lv);
          case '>=': return xs.some(x => Number(x) >= lv); case '<=': return xs.some(x => Number(x) <= lv);
          case 'contains': return xs.some(x => String(x).toLowerCase().includes(sv));
          case 'matches': return xs.some(x => re.test(String(x)));
        }
        return false;
      };
    }
    if (!toks.length) throw new Error('Boş filtre');
    const fn = pOr();
    if (i < toks.length) throw new Error(`Beklenmeyen ifade: "${toks[i].v}" (&& veya || eksik olabilir)`);
    return { ok: true, test: fn };
  } catch (e) { return { ok: false, error: e.message }; }
}

/* Metin bir filtre ifadesine mi benziyor, yoksa doğal dil mi? */
function looksLikeFilter(t) {
  return /==|!=|>=|<=|&&|\|\||\bcontains\b|\bmatches\b/i.test(t) || /(^|[\s(!])(frame|eth|ip|ipv6|tcp|udp|icmp|icmpv6|dns|http|tls|arp|pl)\.[a-z_]/i.test(t);
}

const API = { compile, looksLikeFilter, fields: F, fieldNames: () => Object.keys(F).sort() };
if (typeof module !== 'undefined' && module.exports) module.exports = API; else root.PLF = API;
})(typeof self !== 'undefined' ? self : this);
