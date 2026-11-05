/* PacketLens - TLS/QUIC pasif metadata (JA3/JA4, ECH, sertifika, QUIC SNI) */
(function (root) {
'use strict';

function install(PL) {
  const u16 = PL.u16, ascii = PL.ascii, isGrease = x => (x & 0x0f0f) === 0x0a0a && (x >> 8) === (x & 0xff);
  const ECH_EXT = 0xfe0d;

  function md5hex(s) {
    if (typeof require === 'function') {
      try { return require('crypto').createHash('md5').update(s, 'utf8').digest('hex'); } catch (e) { /* yok say */ }
    }
    return PL.ja3DigestLegacy ? PL.ja3DigestLegacy(s) : s;
  }
  function sha256hex(s) {
    if (typeof require === 'function') {
      try { return require('crypto').createHash('sha256').update(s, 'utf8').digest('hex'); } catch (e) { /* yok say */ }
    }
    return md5hex(s);
  }

  PL.ja3DigestLegacy = PL.ja3Digest;
  PL.ja3Digest = md5hex;

  function ja4FromParts(proto, tlsVer, sni, alpn, ciphers, extensions) {
    const verMap = { 0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10' };
    const v = verMap[tlsVer] || '00';
    const snLen = String(Math.min(99, (sni || '').length)).padStart(2, '0');
    const al = (alpn && alpn[0]) || '';
    const alpn4 = al.length >= 2 ? (al[0] + al[al.length - 1]) : '00';
    const cSorted = [...ciphers].sort((a, b) => a - b).join(',');
    const eSorted = [...extensions].filter(e => !isGrease(e)).sort((a, b) => a - b).join(',');
    return `${proto}${v}${snLen}${alpn4}_${sha256hex(cSorted).slice(0, 12)}_${sha256hex(eSorted).slice(0, 12)}`;
  }

  function parseClientHelloBody(v, q, qend) {
    if (qend - q < 38 || v[q] !== 1) return null;
    const legacy = u16(v, q + 1);
    let o = q + 4 + 2 + 32;
    o += 1 + v[o];
    const cl = u16(v, o); o += 2;
    const ciphers = [];
    for (let i = o; i + 1 < o + cl && i + 1 < qend; i += 2) { const c = u16(v, i); if (!isGrease(c)) ciphers.push(c); }
    o += cl;
    const cm = v[o]; o += 1 + cm;
    const extLen = u16(v, o); o += 2;
    const eend = Math.min(qend, o + extLen);
    const extensions = [], versions = [], alpn = [], curves = [], points = [];
    let sni = null, ech = false;
    let oExt = o;
    while (oExt + 4 <= eend) {
      const et = u16(v, oExt), el = u16(v, oExt + 2);
      const eb = oExt + 4, ee = Math.min(eend, eb + el);
      if (et === 0 && el > 5 && eb + 5 <= ee) { const nl = u16(v, eb + 3); if (eb + 5 + nl <= ee) sni = ascii(v, eb + 5, eb + 5 + nl); }
      else if (et === 43 && el >= 3) { const l = v[eb]; for (let i = eb + 1; i < eb + 1 + l && i + 1 < ee; i += 2) { const x = u16(v, i); if (!isGrease(x)) versions.push(x); } }
      else if (et === 16 && el >= 3) { const ll = u16(v, eb); let i = eb + 2; while (i < eb + 2 + ll && i < ee) { const n = v[i]; alpn.push(ascii(v, i + 1, i + 1 + n)); i += 1 + n; } }
      else if (et === 10 && el >= 2) { const gl = u16(v, eb); for (let i = eb + 2; i + 1 < eb + 2 + gl && i + 1 < ee; i += 2) { const g = u16(v, i); if (!isGrease(g)) curves.push(g); } }
      else if (et === 11 && el >= 1) { for (let i = eb + 1; i < eb + 1 + v[eb] && i < ee; i++) points.push(v[i]); }
      else if (et === ECH_EXT) ech = true;
      if (!isGrease(et)) extensions.push(et);
      oExt += 4 + el;
    }
    const ja3Str = [legacy, ciphers.join('-'), extensions.join('-'), curves.join('-'), points.join('-')].join(',');
    return {
      legacy, ciphers, versions, alpn, sni, ech, ja3: ja3Str, ja3Hash: md5hex(ja3Str),
      ja4: ja4FromParts('t', legacy, sni, alpn, ciphers, extensions),
    };
  }

  PL.parseTlsClientHelloAt = function (v, po, end) {
    if (end - po < 44 || v[po] !== 22) return null;
    const rec = u16(v, po + 3), q = po + 5, qend = Math.min(end, q + rec);
    if (v[po + 5] !== 1) return null;
    return parseClientHelloBody(v, q, qend);
  };

  PL.scanTlsClientHello = function (v, po, end) {
    const lim = Math.min(end, po + 4096);
    for (let i = po; i + 44 < lim; i++) {
      if (v[i] === 0x16 && v[i + 1] === 0x03 && v[i + 5] === 0x01) {
        const ch = PL.parseTlsClientHelloAt(v, i, end);
        if (ch) return Object.assign({ off: i }, ch);
      }
    }
    return null;
  };

  PL.parseX509Cert = function (v, from, to) {
    const out = { subject: '', issuer: '', sans: [], notBefore: '', notAfter: '', selfSigned: false };
    const oList = [], cnList = [];
    for (let i = from; i + 5 < to; i++) {
      if (v[i] === 0x55 && v[i + 1] === 4) {
        const n = v[i + 3]; if (n > 0 && n < 128 && i + 4 + n <= to) {
          const s = ascii(v, i + 4, i + 4 + n);
          if (v[i + 2] === 3) cnList.push(s);
          if (v[i + 2] === 0x0a) oList.push(s);
        }
      }
      if (v[i] === 0x82 && i + 2 < to) {
        const n = v[i + 1]; if (n > 2 && n < 200 && i + 2 + n <= to) {
          const s = ascii(v, i + 2, i + 2 + n).toLowerCase();
          if (/^[a-z0-9.*-]+(\.[a-z0-9.-]+)+$/i.test(s)) out.sans.push(s);
        }
      }
      if (v[i] === 0x17 && v[i + 1] === 13 && i + 15 <= to) out.notBefore = ascii(v, i + 2, i + 15);
      if (v[i] === 0x18 && v[i + 1] === 13 && i + 15 <= to) out.notAfter = ascii(v, i + 2, i + 15);
    }
    if (cnList.length) out.subject = cnList[cnList.length - 1];
    if (oList.length) out.issuer = oList[0];
    if (out.issuer && out.subject && out.issuer === out.subject) out.selfSigned = true;
    return out;
  };

  PL.parseCertHandshake = function (v, po, end) {
    if (end - po < 16 || v[po + 5] !== 11) return null;
    const cl = (v[po + 12] << 16) | (v[po + 13] << 8) | v[po + 14], cs = po + 15, ce = Math.min(end, cs + cl);
    if (ce - cs < 4) return null;
    const len = (v[cs] << 16) | (v[cs + 1] << 8) | v[cs + 2];
    return PL.parseX509Cert(v, cs + 3, Math.min(ce, cs + 3 + len));
  };

  PL.DOMAIN_TRUST = {
    'google.com': /Google Trust Services|GTS|Google LLC/i,
    'youtube.com': /Google Trust Services|GTS/i,
    'apple.com': /Apple Inc|Apple Public/i,
    'icloud.com': /Apple Inc/i,
    'microsoft.com': /Microsoft Corporation/i,
    'facebook.com': /DigiCert|Meta Platforms/i,
    'instagram.com': /DigiCert|Meta Platforms/i,
  };

  PL.certAnomaly = function (sni, cert) {
    if (!cert || !cert.issuer) return null;
    const iss = cert.issuer;
    if (/charles|mitmproxy|burp|fiddler|portswigger|zscaler|blue coat|websense|forcepoint|fortinet|squid proxy|proxyman|httptoolkit|superproxy/i.test(iss)) {
      return { kind: 'inspection', title: 'TLS inspection / debug CA', detail: iss };
    }
    if (cert.selfSigned && sni && !/localhost|\.local|\.test|\.lan$/i.test(sni)) {
      return { kind: 'selfsigned', title: 'Kendinden imzalı sertifika (genel site)', detail: iss };
    }
    if (sni) {
      const base = sni.replace(/^www\./, '').toLowerCase();
      const rule = PL.DOMAIN_TRUST[base];
      if (rule && !rule.test(iss) && !/Let's Encrypt|DigiCert|Amazon|Cloudflare|Sectigo|GlobalSign|Entrust|Go Daddy|ISRG/i.test(iss)) {
        return { kind: 'issuer', title: 'Beklenmeyen sertifika veren', detail: `${base} → ${iss}` };
      }
      if (cert.sans && cert.sans.length && !cert.sans.some(s => s === base || s === '*.' + base.split('.').slice(1).join('.') || sni.endsWith(s.replace(/^\*\./, '')))) {
        if (!cert.subject || !cert.subject.includes(base.split('.')[0])) {
          return { kind: 'san', title: 'SNI / SAN uyuşmazlığı', detail: sni };
        }
      }
    }
    return null;
  };

  PL.DOH_HOSTS = new Set([
    'dns.google', 'dns.google.com', 'cloudflare-dns.com', 'one.one.one.one', 'mozilla.cloudflare-dns.com',
    'dns.quad9.net', 'doh.opendns.com', 'doh.cleanbrowsing.org', 'dns.nextdns.io', 'dns.adguard.com',
    'chrome.cloudflare-dns.com', 'dns64.dns.google',
  ]);
  PL.isDohHost = h => PL.DOH_HOSTS.has(String(h || '').toLowerCase().replace(/\.$/, ''));
}

if (typeof module !== 'undefined' && module.exports) module.exports = install;
else if (root.PL) install(root.PL);
})(typeof self !== 'undefined' ? self : globalThis);
