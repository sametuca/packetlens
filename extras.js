/* PackageLens - akış takibi, günlükler, istatistikler ve güvenlik tespitleri */
(function (root) {
'use strict';

function install(PL) {
  const MAXSTREAM = 512 * 1024;
  const b64decode = s => { try { return typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString('latin1'); } catch (e) { return ''; } };
  const latin = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 8192) s += String.fromCharCode.apply(null, u8.subarray(i, i + 8192)); return s; };
  const dirOf = (p, f) => (p.src === f.a && p.sport === f.aPort) ? 'AB' : 'BA';
  PL.payload = p => p.payloadLen > 0 ? p.raw.subarray(p.payOff, p.payOff + p.payloadLen) : new Uint8Array(0);

  /* ---------- TCP/UDP akışını takip et ---------- */
  PL.followStream = function (A, id) {
    const f = A.flows[id - 1], segs = [], next = { AB: null, BA: null }, bytes = { AB: 0, BA: 0 };
    let total = 0, truncated = false;
    for (const no of f.pnos) {
      const p = A.packets[no - 1]; if (!p.payloadLen) continue;
      const dir = dirOf(p, f); let data = PL.payload(p), seq = p.seq;
      if (p.proto === 'TCP') {
        const ne = next[dir];
        if (ne !== null) {
          const d = (seq - ne) | 0;
          if (d < 0) { if (-d >= data.length) continue; data = data.subarray(-d); seq = ne; }
          else if (d > 0) segs.push({ dir, t: p.ts, no, gap: d });
        }
        next[dir] = (seq + data.length) >>> 0;
      }
      if (total + data.length > MAXSTREAM) { truncated = true; break; }
      total += data.length; bytes[dir] += data.length;
      const last = segs[segs.length - 1];
      if (last && !last.gap && last.dir === dir && p.proto === 'TCP') last.chunks.push(data);
      else segs.push({ dir, t: p.ts, no, chunks: [data] });
    }
    return { flow: f, bytes, truncated, segs: segs.map(s => {
      if (s.gap) return s;
      const n = s.chunks.reduce((a, c) => a + c.length, 0), out = new Uint8Array(n); let o = 0;
      for (const c of s.chunks) { out.set(c, o); o += c.length; }
      return { dir: s.dir, t: s.t, no: s.no, bytes: out };
    }) };
  };

  /* ---------- günlükler ---------- */
  PL.dnsLog = function (A) {
    const resp = new Map(); for (const p of A.packets) if (p.dns && p.dns.qr && p.dnsQNo) resp.set(p.dnsQNo, p);
    const out = [];
    for (const p of A.packets) if (p.dns && !p.dns.qr) {
      const q = p.dns.questions[0], r = resp.get(p.no);
      out.push({ no: p.no, t: p.ts, client: p.src, server: p.dst, app: p.app, name: q ? q.name : '?', qtype: q ? q.type : 0, rcode: r ? r.dns.rcode : null, answers: r ? r.dns.answers.map(a => a.data) : [], latency: r ? r.dnsLatency : null, answered: !!r, rno: r ? r.no : null, flow: p.flow });
    }
    return out;
  };
  PL.httpLog = function (A) {
    const out = [], pending = new Map();
    for (const p of A.packets) if (p.http) {
      const h = p.http;
      if (h.status != null) {
        const q = (pending.get(p.flow) || []).shift();
        if (q) { q.status = h.status; q.ctype = h.ctype; q.size = h.clen; q.latency = p.ts - q.t; q.rno = p.no; }
        else out.push({ no: p.no, t: p.ts, client: p.dst, server: p.src, host: A.nm(p.src), method: '—', path: '', status: h.status, ctype: h.ctype, size: h.clen, latency: null, flow: p.flow, rno: p.no });
      } else if (h.method) {
        const e = { no: p.no, t: p.ts, client: p.src, server: p.dst, host: h.host || A.nm(p.dst), method: h.method, path: h.path, status: null, ctype: null, size: null, latency: null, flow: p.flow };
        out.push(e); if (!pending.has(p.flow)) pending.set(p.flow, []); pending.get(p.flow).push(e);
      }
    }
    return out;
  };
  PL.tlsLog = function (A) {
    const by = new Map();
    for (const p of A.packets) if (p.tls) {
      let e = by.get(p.flow);
      if (!e) { const f = A.flows[p.flow - 1]; e = { flow: p.flow, client: f.client, server: f.server, no: p.no, t: p.ts, sni: null, offered: [], ciphers: [], alpn: [], version: null, cipher: null, cert: null, hsMs: null, weak: [] }; by.set(p.flow, e); }
      const t = p.tls;
      if (t.ht === 1) { e.sni = p.sni || e.sni; e.offered = t.versions && t.versions.length ? t.versions : [t.legacy]; e.ciphers = t.ciphers || []; e.alpn = t.alpn || []; e.tCH = p.ts; e.chNo = p.no; }
      else if (t.ht === 2) { e.version = t.version; e.cipher = t.cipher; e.shNo = p.no; }
      else if (t.ht === 11 && t.cert) e.cert = t.cert;
      if ((t.rt === 23 || t.ht === 20) && e.tCH != null && e.hsMs == null) e.hsMs = (p.ts - e.tCH) * 1000;
    }
    const out = [...by.values()];
    for (const e of out) {
      if (e.version != null && e.version <= 0x0302) e.weak.push((PL.TLSV[e.version] || 'eski sürüm') + ' kullanılıyor');
      if (e.cipher != null && PL.WEAK_CIPHERS.has(e.cipher)) e.weak.push('zayıf şifre: ' + PL.cipherName(e.cipher));
      if (e.version == null && e.offered.length && Math.max.apply(null, e.offered) <= 0x0302) e.weak.push('yalnızca eski TLS sürümleri öneriliyor');
    }
    return out;
  };

  /* ---------- istatistikler ---------- */
  PL.stats = function (A) {
    const root = { name: 'Çerçeve', pkts: 0, bytes: 0, ch: new Map() };
    for (const p of A.packets) {
      let n = root; n.pkts++; n.bytes += p.len;
      for (const l of p.layers.slice(1)) {
        let c = n.ch.get(l.name); if (!c) n.ch.set(l.name, c = { name: l.name, pkts: 0, bytes: 0, ch: new Map() });
        c.pkts++; c.bytes += p.len; n = c;
      }
    }
    const flat = (n, d, out) => { out.push({ name: n.name, d, pkts: n.pkts, bytes: n.bytes }); [...n.ch.values()].sort((a, b) => b.bytes - a.bytes).forEach(c => flat(c, d + 1, out)); return out; };
    const convMap = new Map();
    for (const f of A.flows) {
      if (!f.a || !f.b || f.a.includes(':') && f.a.split(':').length === 6) continue;
      const k = f.a < f.b ? f.a + '|' + f.b : f.b + '|' + f.a; let c = convMap.get(k);
      if (!c) convMap.set(k, c = { a: f.a < f.b ? f.a : f.b, b: f.a < f.b ? f.b : f.a, pkts: 0, bytes: 0, flows: 0, probs: 0, start: f.start, end: f.end });
      c.pkts += f.pkts; c.bytes += f.bytes; c.flows++; c.probs += f.probs.length; c.start = Math.min(c.start, f.start); c.end = Math.max(c.end, f.end);
    }
    const B = [[0, 39], [40, 79], [80, 159], [160, 319], [320, 639], [640, 1279], [1280, 2559], [2560, Infinity]].map(([lo, hi]) => ({ lo, hi, pkts: 0, bytes: 0 }));
    for (const p of A.packets) { const b = B.find(x => p.len >= x.lo && p.len <= x.hi); b.pkts++; b.bytes += p.len; }
    const rtts = A.flows.filter(f => f.rtt != null).map(f => f.rtt * 1000).sort((x, y) => x - y);
    const q = x => rtts.length ? rtts[Math.min(rtts.length - 1, Math.floor(x * rtts.length))] : null;
    const dns = PL.dnsLog(A).filter(e => e.app === 'DNS'), lat = dns.filter(e => e.latency != null).map(e => e.latency * 1000);
    const names = new Map(); dns.forEach(e => names.set(e.name, (names.get(e.name) || 0) + 1));
    const http = PL.httpLog(A), codes = new Map(); http.forEach(e => { if (e.status != null) codes.set(e.status, (codes.get(e.status) || 0) + 1); });
    return {
      hier: flat(root, 0, []), total: { pkts: root.pkts, bytes: root.bytes },
      convs: [...convMap.values()].sort((x, y) => y.bytes - x.bytes), lenHist: B,
      tcp: { n: rtts.length, min: rtts[0] || null, med: q(0.5), p95: q(0.95), max: rtts[rtts.length - 1] || null, retrans: A.flows.reduce((s, f) => s + f.retrans, 0), resets: A.flows.filter(f => f.rst).length },
      dns: { n: dns.length, answered: dns.filter(e => e.answered).length, avg: lat.length ? lat.reduce((a, b) => a + b, 0) / lat.length : null, max: lat.length ? Math.max.apply(null, lat) : null, nx: dns.filter(e => e.rcode === 3).length, top: [...names].sort((a, b) => b[1] - a[1]).slice(0, 8) },
      http: { n: http.length, codes: [...codes].sort((a, b) => a[0] - b[0]), hosts: new Set(http.map(e => e.host)).size },
    };
  };

  /* ---------- güvenlik tespitleri ---------- */
  const entropy = s => { const m = new Map(); for (const c of s) m.set(c, (m.get(c) || 0) + 1); let h = 0; for (const n of m.values()) { const p = n / s.length; h -= p * Math.log2(p); } return h; };
  const mask = pw => (pw.length ? pw[0] + '•'.repeat(Math.min(pw.length - 1, 8)) : '') + ` (${pw.length} karakter)`;
  const osGuess = (ttl, win, opt) => ttl > 128 ? 'Ağ cihazı / Solaris' : ttl > 64 ? 'Windows' : (win === 65535 || (opt && opt.ws === 6)) ? 'macOS / iOS / BSD' : 'Linux / Android';
  const SVC_CLEAR = { Telnet: 'med', FTP: 'med', POP3: 'med', IMAP: 'med', HTTP: 'low' };

  PL.securityHook = function (A, addProblem) {
    const nm = A.nm, pk = A.packets, t0 = A.t0;
    A.creds = [];

    // 1) İşletim sistemi tahmini
    for (const p of pk) if (p.proto === 'TCP' && (p.flags & 2) && p.ttl != null) { const h = A.hosts.get(p.src); if (h && !h.os) h.os = osGuess(p.ttl, p.win, p.opt); }

    // 2) Şifresiz kimlik bilgileri
    const seen = new Set(), state = new Map();
    const report = (proto, user, pw, p, extra) => {
      const key = p.flow + '|' + proto + '|' + user; if (seen.has(key) || seen.size >= 30) return; seen.add(key);
      const f = A.flows[p.flow - 1];
      A.creds.push({ proto, user, pass: mask(pw), flow: p.flow, no: p.no });
      addProblem({ sev: 'high', type: 'cred', title: `Şifresiz kimlik bilgisi (${proto})`, flow: p.flow, ts: p.ts, pkts: [p.no],
        plain: `${nm(f.client)}, ${nm(f.server)} sunucusuna kullanıcı adını ("${user}") ve parolasını (${mask(pw)}) şifrelenmeden gönderdi.${extra ? ' ' + extra : ''} Aynı ağı dinleyen herkes bunu okuyabilir.`,
        advice: 'Bu hizmetin şifreli sürümünü (HTTPS, SFTP/SSH, IMAPS/POP3S) kullanın ve açığa çıkan parolayı hemen değiştirin.' });
    };
    for (const p of pk) {
      if (p.proto !== 'TCP' || p.payloadLen < 4) continue;
      const f = A.flows[p.flow - 1], txt = latin(PL.payload(p).subarray(0, 1500));
      if (p.http && p.http.method || /Authorization:/i.test(txt)) {
        const m = /\r\n(?:Proxy-)?Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i.exec(txt);
        if (m) { const d = b64decode(m[1]), i = d.indexOf(':'); if (i > 0) report('HTTP Basic', d.slice(0, i), d.slice(i + 1), p); }
        const body = txt.split('\r\n\r\n')[1];
        if (body && p.http && p.http.method === 'POST') {
          const pw = /(?:^|&)(?:pass(?:word)?|pwd|passwd|pw|sifre|parola)=([^&\s]+)/i.exec(body), us = /(?:^|&)(?:user(?:name)?|login|email|uname|kullanici|usr)=([^&\s]+)/i.exec(body);
          if (pw) report('HTTP form', us ? decodeURIComponent(us[1].replace(/\+/g, ' ')) : '(bilinmiyor)', decodeURIComponent(pw[1].replace(/\+/g, ' ')), p, p.http.path ? `(adres: ${p.http.path})` : '');
        }
      } else if (p.app === 'FTP' || p.app === 'POP3') {
        const u = /^USER\s+(\S+)/im.exec(txt), pw = /^PASS\s+(.+?)\r?$/im.exec(txt);
        if (u) state.set(p.flow, u[1]);
        if (pw) report(p.app, state.get(p.flow) || '(bilinmiyor)', pw[1], p);
      } else if (p.app === 'IMAP') {
        const m = /^\S+\s+LOGIN\s+("?)([^"\s]+)\1\s+("?)([^"\s]+)\3/im.exec(txt); if (m) report('IMAP', m[2], m[4], p);
      } else if (p.app === 'SMTP') {
        const m = /AUTH PLAIN\s+([A-Za-z0-9+/=]+)/i.exec(txt);
        if (m) { const parts = b64decode(m[1]).split('\0'); if (parts.length >= 3) report('SMTP AUTH', parts[1], parts[2], p); }
      } else if (p.app === 'Telnet' && p.dport === 23 && !seen.has('telnet' + p.flow)) {
        seen.add('telnet' + p.flow);
        addProblem({ sev: 'high', type: 'cred', title: 'Telnet oturumu (şifresiz)', flow: p.flow, ts: p.ts, pkts: [p.no], plain: `${nm(f.client)}, ${nm(f.server)} ile Telnet kullanıyor: oturum açma bilgileri dahil her tuş vuruşu şifrelenmeden gider.`, advice: 'Telnet yerine SSH kullanın ve cihazda Telnet servisini kapatın.' });
      }
    }

    // 3) Şifresiz protokol kullanımı (kısa uyarı)
    const clear = new Map();
    for (const f of A.flows) if (SVC_CLEAR[f.app] && f.proto === 'TCP' && f.synack !== false && f.pkts > 3) { if (!clear.has(f.app)) clear.set(f.app, []); clear.get(f.app).push(f); }
    for (const [app, fl] of clear) addProblem({ sev: SVC_CLEAR[app], type: 'clear', title: `Şifresiz protokol: ${app} (${fl.length} bağlantı)`, flow: fl.length === 1 ? fl[0].id : null, ts: fl[0].start, pkts: fl.slice(0, 5).flatMap(f => f.pnos.slice(0, 3)),
      plain: `${fl.length} bağlantı şifresiz ${app} kullanıyor (ör. ${nm(fl[0].client)} → ${nm(fl[0].server)}). İçerik ağda okunabilir ve değiştirilebilir.`, advice: 'Mümkünse şifreli karşılığını (HTTPS, SFTP/SSH, POP3S/IMAPS) kullanın.' });

    // 4) ARP sahteciliği
    const arp = new Map();
    for (const p of pk) if (p.arp && p.arp.si !== '0.0.0.0') { let e = arp.get(p.arp.si); if (!e) arp.set(p.arp.si, e = { macs: new Set(), nos: [] }); e.macs.add(p.arp.sm); e.nos.push(p.no); }
    for (const [ip, e] of arp) if (e.macs.size > 1) addProblem({ sev: 'high', type: 'arp', title: 'Olası ARP sahteciliği (ARP spoofing)', flow: null, ts: pk[e.nos[0] - 1].ts, pkts: e.nos,
      plain: `${ip} adresini birden fazla cihaz kendi adresi olarak duyurdu: ${[...e.macs].join(', ')}. Saldırganlar trafiği kendi üzerinden geçirmek (ortadaki adam) için bu yöntemi kullanır.`,
      advice: 'Gerçek cihazın MAC adresini doğrulayın. Anahtarda Dynamic ARP Inspection / port güvenliğini açın, kritik cihazlar için statik ARP girin.' });

    // 5) DNS tünelleme ve DGA
    const par = new Map(), nx = new Map();
    for (const p of pk) {
      if (!p.dns || p.app !== 'DNS') continue;
      if (p.dns.qr && p.dns.rcode === 3 && p.dns.questions[0]) { let e = nx.get(p.dst); if (!e) nx.set(p.dst, e = { names: new Set(), nos: [] }); e.names.add(p.dns.questions[0].name); e.nos.push(p.no); }
      if (p.dns.qr || !p.dns.questions[0]) continue;
      const lab = p.dns.questions[0].name.toLowerCase().split('.'); if (lab.length < 3 || /^(local|arpa|invalid)$/.test(lab[lab.length - 1])) continue;
      const parent = lab.slice(-2).join('.'), long = lab.slice(0, -2).sort((a, b) => b.length - a.length)[0];
      let e = par.get(parent); if (!e) par.set(parent, e = { subs: new Set(), nos: [], ent: 0, len: 0, max: 0, client: p.src });
      e.subs.add(lab.slice(0, -2).join('.')); e.nos.push(p.no); e.ent += entropy(long); e.len += long.length; e.max = Math.max(e.max, long.length);
    }
    for (const [parent, e] of par) {
      const n = e.nos.length, ae = e.ent / n, al = e.len / n;
      if ((e.subs.size >= 15 && ae >= 3.2 && al >= 12) || e.max >= 52 || e.subs.size >= 40) addProblem({ sev: 'high', type: 'dnstunnel', title: 'Olası DNS tünelleme / veri sızdırma', flow: null, ts: pk[e.nos[0] - 1].ts, pkts: e.nos.slice(0, 200),
        plain: `${nm(e.client)}, "${parent}" alan adı için ${e.subs.size} farklı, uzun ve rastgele görünümlü alt alan adı sorguladı (ort. ${al.toFixed(0)} karakter). Bu, DNS üzerinden gizlice veri taşıma (tünelleme) davranışına benzer.`,
        advice: 'Bu alan adının meşru olup olmadığını doğrulayın. Şüpheliyse DNS çıkışını kısıtlayın, alan adını engelleyin ve cihazı zararlı yazılım için inceleyin.' });
    }
    for (const [client, e] of nx) if (e.names.size >= 20) addProblem({ sev: 'med', type: 'dga', title: 'Çok sayıda geçersiz alan adı (DGA olasılığı)', flow: null, ts: pk[e.nos[0] - 1].ts, pkts: e.nos.slice(0, 200),
      plain: `${nm(client)} kısa sürede ${e.names.size} farklı, var olmayan alan adı sorguladı. Bazı zararlı yazılımlar komuta sunucusunu bulmak için rastgele alan adları dener.`, advice: 'Sorgulayan uygulamayı/süreci belirleyin ve cihazı tarayın.' });

    // 6) Düzenli aralıklı bağlantılar (beacon)
    const groups = new Map();
    for (const f of A.flows) if (f.proto === 'TCP' && f.syn) { const k = f.client + '|' + f.server + '|' + f.bPort; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(f); }
    for (const fl of groups.values()) {
      if (fl.length < 6) continue;
      const ts = fl.map(f => f.start).sort((a, b) => a - b), iv = []; for (let i = 1; i < ts.length; i++) iv.push(ts[i] - ts[i - 1]);
      const mean = iv.reduce((a, b) => a + b, 0) / iv.length, sd = Math.sqrt(iv.reduce((a, b) => a + (b - mean) ** 2, 0) / iv.length);
      if (mean >= 1 && sd / mean < 0.2) addProblem({ sev: 'med', type: 'beacon', title: 'Düzenli aralıklı bağlantılar (beacon olasılığı)', flow: null, ts: ts[0], pkts: fl.slice(0, 8).map(f => f.pnos[0]),
        plain: `${nm(fl[0].client)}, ${nm(fl[0].server)}:${fl[0].bPort} adresine yaklaşık her ${mean.toFixed(1)} saniyede bir (${fl.length} kez) bağlanıyor. Zararlı yazılımların komuta merkeziyle haberleşmesi buna benzer; ama meşru güncelleme/sağlık kontrolleri de olabilir.`,
        advice: 'Bu bağlantıyı hangi uygulamanın başlattığını bulun. Tanınmayan bir uygulamaysa ağdan izole edip inceleyin.' });
    }

    // 7) Ping taraması, SYN seli
    const sweep = new Map();
    for (const p of pk) if (p.icmp && p.icmp.type === 8 && !p.icmp.six) { let e = sweep.get(p.src); if (!e) sweep.set(p.src, e = { d: new Set(), nos: [] }); e.d.add(p.dst); e.nos.push(p.no); }
    for (const [src, e] of sweep) if (e.d.size >= 15) addProblem({ sev: 'med', type: 'sweep', title: 'Olası ping taraması', flow: null, ts: pk[e.nos[0] - 1].ts, pkts: e.nos.slice(0, 100),
      plain: `${nm(src)} adresi ${e.d.size} farklı cihaza ping gönderdi. Ağdaki canlı cihazları keşfetmek için kullanılan bir yöntemdir.`, advice: 'Tarama yetkiniz dahilinde değilse kaynağı inceleyin.' });
    const tgt = new Map();
    for (const f of A.flows) if (f.proto === 'TCP' && f.syn) { const k = f.server + ':' + f.bPort; let e = tgt.get(k); if (!e) tgt.set(k, e = { n: 0, ok: 0, f: f }); e.n++; if (f.synack) e.ok++; }
    for (const [k, e] of tgt) if (e.n >= 100 && e.ok / e.n < 0.3) addProblem({ sev: 'high', type: 'synflood', title: 'Olası SYN seli (DoS)', flow: null, ts: e.f.start, pkts: e.f.pnos.slice(0, 5),
      plain: `${k} hedefine ${e.n} bağlantı isteği geldi ve yalnızca %${Math.round(e.ok / e.n * 100)} kadarı yanıtlandı.`, advice: 'SYN cookie açın, bağlantı hız sınırı uygulayın ve kaynak adresleri inceleyin.' });

    // 8) Zayıf TLS
    for (const e of PL.tlsLog(A)) if (e.weak.length) addProblem({ sev: 'med', type: 'weaktls', title: 'Zayıf/eski TLS ayarı', flow: e.flow, ts: e.t, pkts: [e.shNo || e.chNo || e.no],
      plain: `${nm(e.client)} ↔ ${e.sni || nm(e.server)}: ${e.weak.join('; ')}. Eski sürümler ve şifreler bilinen saldırılara açıktır.`, advice: 'Sunucu/istemcide TLS 1.2 veya 1.3 ve modern şifre takımlarını zorunlu kılın.' });
  };
  return PL;
}

if (typeof module !== 'undefined' && module.exports) module.exports = install;
else if (root.PL) install(root.PL);
})(typeof self !== 'undefined' ? self : this);
