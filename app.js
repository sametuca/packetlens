/* PacketLens arayüzü */
(function () {
'use strict';
const PL = window.PL, PLF = window.PLF;
const $ = (s, r) => (r || document).querySelector(s);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const S = { A: null, raw: [], pk: [], mode: 'simple', tab: 'summary', timeRange: null, visPre: [], logTab: 'dns', probCat: 'all', query: null, qtext: '', flowFilter: null, pktSet: null, pktSetLabel: '', vis: [], visFlows: new Set(), selPkt: null, flowSort: 'start', follow: true, srv: null, live: { running: false, since: 0, timer: null, iface: 'any', dirty: false }, appColors: new Map() };
let srvInit = 'pending';
const DEFAULTS = { lang: 'tr', theme: 'auto', density: 'normal', timefmt: 'rel', names: true,
  dnsSlow: 250, rttSlow: 150, retransMed: 3, scanTargets: 15, tunnelSubs: 15, dgaNames: 20, sweepHosts: 15, off: [],
  iface: '', capfilter: '', snap: 1600, max: 300000, duration: 0, promisc: true, follow: true, presets: [] };
S.set = Object.assign({}, DEFAULTS); S.notes = {}; S.find = null; S.liveOpen = false; S.deviceRegistry = [];
try { const j = JSON.parse(localStorage.getItem('pl-settings') || 'null'); if (j && typeof j === 'object') Object.assign(S.set, j); } catch (e) { /* yok say */ }
if (!S.set.lang || !['tr', 'en'].includes(S.set.lang)) { try { S.set.lang = /^tr/i.test(navigator.language || '') ? 'tr' : 'en'; } catch (e) { S.set.lang = 'tr'; } }
try { const m = localStorage.getItem('pl-mode'); if (m === 'adv' || m === 'simple') S.mode = m; } catch (e) { /* yok say */ }
S.follow = S.set.follow !== false;
let ROW = 26;
function saveSettings() { try { localStorage.setItem('pl-settings', JSON.stringify(S.set)); } catch (e) { /* yok say */ } }
function applySettings(re) {
  const st = S.set, c = PL.cfg;
  document.documentElement.dataset.theme = st.theme || 'auto'; document.documentElement.lang = st.lang;
  ROW = st.density === 'compact' ? 22 : 26; document.documentElement.style.setProperty('--row', ROW + 'px');
  c.dnsSlow = st.dnsSlow / 1000; c.rttSlow = st.rttSlow / 1000; c.retransMed = st.retransMed; c.scanTargets = st.scanTargets; c.tunnelSubs = st.tunnelSubs; c.dgaNames = st.dgaNames; c.sweepHosts = st.sweepHosts; c.off = new Set(st.off || []);
  if (window.PLI) window.PLI.setLang(st.lang, false);
  if (re && S.pk.length) { reanalyze(); render(); }
}
const L = () => (S.set.lang === 'en' ? 'en-US' : 'tr-TR');
const T = s => (window.PLI ? window.PLI.t(s) : s);

/* ---------- yardımcılar ---------- */
const fmtB = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1073741824).toFixed(2) + ' GB';
const fmtD = s => s < 1 ? Math.round(s * 1000) + ' ms' : s < 60 ? s.toFixed(1) + ' sn' : Math.floor(s / 60) + ' dk ' + Math.round(s % 60) + ' sn';
const tcol = p => {
  const f = S.set.timefmt;
  if (f === 'abs') { const d = new Date(p.ts * 1000); return d.toTimeString().slice(0, 8) + '.' + String(d.getMilliseconds()).padStart(3, '0'); }
  if (f === 'delta') { const q = S.A.packets[p.no - 2]; return (q ? p.ts - q.ts : 0).toFixed(6); }
  return rel(p).slice(0, 9);
};
const fmtRate = bps => bps < 1e3 ? bps.toFixed(0) + ' bit/s' : bps < 1e6 ? (bps / 1e3).toFixed(1) + ' Kbit/s' : (bps / 1e6).toFixed(2) + ' Mbit/s';
const rel = p => (p.ts - S.A.t0).toFixed(6);
const nm = ip => (S.set.names === false ? ip : S.A.nm(ip));
const toast = msg => { const t = $('#toast'); t.textContent = msg; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => t.hidden = true, 2200); };
const ANOM_SEV = { rst: 'bad', malformed: 'bad', 'dns-noresp': 'bad', 'icmp-unreach': 'bad', 'dns-error': 'bad', retrans: 'warn', zerowin: 'warn', 'dns-slow': 'warn', 'dns-nx': 'warn', 'icmp-ttl': 'warn' };
const pSev = p => p.anoms.reduce((s, a) => ANOM_SEV[a] === 'bad' ? 'bad' : (s === 'bad' ? s : (ANOM_SEV[a] || s)), '');
function appColor(app) {
  if (!S.appColors.has(app)) { const i = S.appColors.size; S.appColors.set(app, i < 8 ? `var(--c${i})` : 'var(--cx)'); }
  return S.appColors.get(app);
}

const EXPLAIN = {
  'Kaynak MAC': 'Paketi gönderen cihazın ağ kartı (donanım) adresi. Yalnızca aynı yerel ağ içinde anlamlıdır; yönlendiriciden geçince değişir.',
  'Hedef MAC': 'Paketin bu ağ segmentindeki bir sonraki alıcısının donanım adresi. İnternete giden trafikte genellikle yönlendiricinin (gateway) MAC adresidir.',
  'Tür': 'Ethernet çerçevesinin içinde hangi protokolün taşındığını söyler (IPv4, IPv6, ARP…).',
  'Kaynak IP': 'Paketi gönderen cihazın IP adresi.', 'Hedef IP': 'Paketin ulaşması gereken cihazın IP adresi.',
  'Protokol': 'IP paketinin içinde taşınan üst katman protokolü (TCP, UDP, ICMP…).',
  'TTL': 'Yaşam süresi. Paket her yönlendiriciden geçtiğinde 1 azalır; 0 olursa atılır. Sonsuz döngüleri engeller. Başlangıç değeri işletim sistemini de ele verir (Linux 64, Windows 128).',
  'Hop limit (TTL)': 'IPv6’daki TTL karşılığı: paket en fazla kaç yönlendirici geçebilir.',
  'Toplam uzunluk': 'IP başlığı + veri toplam boyutu.', 'Tanımlayıcı (ID)': 'Parçalanmış paketleri birleştirmek için kullanılan numara.',
  'Parçalanma': 'DF = parçalama yapma, MF = devamı var. Büyük paketler küçük parçalara bölünebilir.',
  'Kaynak port': 'Gönderen tarafın uygulama kapısı. İstemcilerde genelde rastgele yüksek bir sayıdır.',
  'Hedef port': 'Hangi servise ulaşılmak istendiği (80=HTTP, 443=HTTPS, 53=DNS, 22=SSH…).',
  'Sıra no (Seq)': 'Gönderilen baytların sıra numarası. Karşı taraf eksik/yinelenen paketi bununla anlar.',
  'Onay no (Ack)': 'Karşı taraftan “şu numaraya kadar aldım, sıradaki bayt bu olsun” bilgisi.',
  'Bayraklar': 'SYN=bağlantı başlat, ACK=onay, FIN=düzgün kapat, RST=aniden kes, PSH=hemen ilet.',
  'Pencere (Window)': 'Alıcının tamponunda ne kadar boş yer var. 0 olursa gönderici durmak zorundadır (Zero Window).',
  'Veri uzunluğu': 'Bu pakette taşınan gerçek uygulama verisi (başlıklar hariç).', 'MSS': 'Bir pakette taşınabilecek en büyük veri miktarı.',
  'Pencere ölçeği': 'Pencere değerini büyütmek için çarpan; hızlı hatlarda gereklidir.', 'SACK': 'Seçici onay: kayıp paketlerin tümünü yeniden göndermeden sadece eksikleri iste.',
  'Uzunluk': 'UDP başlığı + veri boyutu.',
  'Kayıt türü': 'TLS’in kayıt tipi: 22=el sıkışma, 23=şifreli uygulama verisi, 21=uyarı.', 'Sürüm': 'Protokol sürümü (0x0303 = TLS 1.2 uyumluluk değeri; TLS 1.3 de bunu kullanır).',
  'Handshake türü': 'TLS el sıkışması adımı: ClientHello → ServerHello → Certificate → Finished.',
  'Sunucu adı (SNI)': 'İstemci, bağlanmak istediği site adını şifrelemeden önce açıkça söyler. İçerik şifreli olsa bile hangi siteye gidildiği buradan görülür.',
  'İşlem kimliği': 'DNS sorgusunu yanıtıyla eşleştiren numara.', 'Sonuç kodu': '0 NOERROR=başarılı, 3 NXDOMAIN=böyle bir ad yok, 2 SERVFAIL=sunucu hatası.',
  'Soru': 'DNS’e sorulan alan adı ve kayıt türü (A=IPv4, AAAA=IPv6).', 'Cevap': 'DNS’in verdiği cevap ve önbellekte tutulabileceği süre (TTL).',
  'Önerilen sürümler': 'İstemcinin desteklediğini söylediği TLS sürümleri. Sunucu bunlardan birini seçer.',
  'Şifre takımları': 'İstemcinin önerdiği şifreleme algoritmaları (güvenlik sırasına göre). Sunucu birini seçer.',
  'ALPN (uygulama protokolü)': 'TLS içinde hangi protokolün konuşulacağı: h2 = HTTP/2, http/1.1 = HTTP/1.1.',
  'Seçilen sürüm': 'Sunucunun seçtiği gerçek TLS sürümü. 1.2 ve 1.3 güvenlidir; 1.0/1.1 eskidir.',
  'Seçilen şifre takımı': 'Bu bağlantıda kullanılacak şifreleme algoritması.',
  'Sertifika sahibi': 'Sunucunun sertifikasında yazan alan adı (CN). SNI ile aynı olmalı.', 'Sertifikayı veren': 'Sertifikayı imzalayan kuruluş (CA).',
  'İlk satır': 'HTTP isteğinin yöntemi ve adresi ya da yanıtın durum kodu.', 'Host': 'İstek yapılan site adı.', 'İçerik türü': 'Dönen verinin türü.',
  'İlgili paket': 'ICMP hata mesajı hangi orijinal paket için gönderildi.',
  'İşlem': 'ARP isteği “bu IP kimde?”, yanıtı “bende, MAC adresim şu” demektir.',
};
const KNOWN = ['tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'https', 'tls', 'ssh', 'ntp', 'dhcp', 'quic', 'smtp', 'mdns'];

/* ---------- doğal dil arama ---------- */
const STOP = new Set('ve ile olan göster bana tüm bütün the show me all bağlantılar bağlantı paketler paket akışlar trafik trafiği için ne neden bir bu şu of and with in on to var mı mi mu'.split(' '));
function parseQuery(text) {
  let t = ' ' + text.trim().toLowerCase() + ' ';
  const cl = [], protos = [];
  const addPort = pt => { pt = +pt; cl.push({ label: 'port ' + pt, wire: `(tcp.port == ${pt} || udp.port == ${pt})`, f: p => p.sport === pt || p.dport === pt }); };
  t = t.replace(/\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b/g, (m, ip, pt) => { cl.push({ label: 'IP ' + ip, wire: `ip.addr == ${ip}`, f: p => p.src === ip || p.dst === ip }); if (pt) addPort(pt); return ' '; });
  t = t.replace(/\bport\s*[:=]?\s*(\d{1,5})\b/g, (m, pt) => { addPort(pt); return ' '; });
  const P = {
    tcp: ['TCP', 'tcp', p => p.proto === 'TCP'], udp: ['UDP', 'udp', p => p.proto === 'UDP'], icmp: ['ICMP', 'icmp || icmpv6', p => /ICMP/.test(p.proto)], arp: ['ARP', 'arp', p => p.proto === 'ARP'],
    dns: ['DNS', 'dns', p => p.app === 'DNS' || p.app === 'mDNS'], mdns: ['mDNS', 'mdns', p => p.app === 'mDNS'], http: ['HTTP', 'http', p => p.app === 'HTTP'],
    https: ['HTTPS/TLS', 'tls', p => p.app === 'HTTPS (TLS)'], tls: ['HTTPS/TLS', 'tls', p => p.app === 'HTTPS (TLS)'], ssh: ['SSH', 'ssh', p => p.app === 'SSH'], ntp: ['NTP', 'ntp', p => p.app === 'NTP'],
    dhcp: ['DHCP', 'dhcp', p => p.app === 'DHCP'], quic: ['QUIC', 'quic', p => p.app === 'QUIC'], smtp: ['SMTP', 'smtp', p => p.app === 'SMTP'],
  };
  const W = [
    [['sorun', 'sorunlar', 'sorunlu', 'hata', 'hatalar', 'hatalı', 'problem', 'error', 'errors', 'issue', 'issues', 'sıkıntı', 'bozuk', 'arıza'], 'sorunlu paketler', 'tcp.analysis.flags || dns.flags.rcode > 0 || icmp.type == 3 || tcp.flags.reset == 1', p => p.anoms.length > 0],
    [['yavaş', 'yavas', 'slow', 'gecikme', 'gecikmeli', 'latency'], 'yavaşlık belirtileri', 'dns.time > 0.25 || tcp.analysis.retransmission || tcp.analysis.zero_window', p => p.anoms.some(a => ['dns-slow', 'retrans', 'zerowin'].includes(a)) || ((S.A.flows[p.flow - 1] || {}).rtt > 0.15)],
    [['retransmission', 'yeniden', 'tekrar', 'retrans'], 'yeniden iletimler', 'tcp.analysis.retransmission', p => p.anoms.includes('retrans')],
    [['rst', 'reset', 'sıfırlama', 'sıfırlanan', 'kesilen'], 'RST (ani kesme)', 'tcp.flags.reset == 1', p => p.anoms.includes('rst')],
    [['büyük', 'large', 'big'], 'büyük paketler (≥1000 B)', 'frame.len >= 1000', p => p.len >= 1000],
    [['syn'], 'SYN (bağlantı başlatma)', 'tcp.flags.syn == 1 && tcp.flags.ack == 0', p => p.proto === 'TCP' && (p.flags & 18) === 2],
    [['şifresiz', 'sifresiz', 'plaintext', 'cleartext'], 'şifresiz protokoller', 'http || ftp || telnet || pop', p => ['HTTP', 'FTP', 'Telnet', 'POP3'].includes(p.app)],
  ];
  const words = [];
  for (const tok of t.split(/[\s,;]+/).filter(Boolean)) {
    if (P[tok]) { protos.push(P[tok]); continue; }
    const w = W.find(x => x[0].includes(tok));
    if (w) { cl.push({ label: w[1], wire: w[2].includes('||') ? '(' + w[2] + ')' : w[2], f: w[3] }); continue; }
    if (STOP.has(tok) || tok.length < 2) continue;
    words.push(tok);
  }
  for (const tok of words) cl.push({ label: `“${tok}” içeren`, wire: `frame contains "${tok}"`, f: p => {
    const hay = [nm(p.src), nm(p.dst), p.src, p.dst, p.info, p.app, p.sni || '', (p.http && p.http.host) || ''].join(' ').toLowerCase(); return hay.includes(tok); } });
  const labels = [...new Set(protos.map(x => x[0]))].map(l => ({ label: l }));
  const fs = cl.map(c => c.f);
  const test = (cl.length || protos.length) ? (p => (!protos.length || protos.some(x => x[2](p))) && fs.every(f => f(p))) : null;
  let wire = cl.map(c => c.wire);
  if (protos.length) { const pw = [...new Set(protos.map(x => x[1]))]; wire.unshift(pw.length > 1 || pw[0].includes('||') ? '(' + pw.join(' || ') + ')' : pw[0]); }
  if (wire.length === 1 && /^\([^()]*\)$/.test(wire[0])) wire[0] = wire[0].slice(1, -1);
  return { test, labels: labels.concat(cl.map(c => ({ label: c.label }))), wire: wire.join(' && ') };
}

/* ---------- veri yükleme ---------- */
function ingest(rawList, name) {
  S.raw = rawList; S.pk = rawList.map((r, i) => PL.dissect(r, i + 1));
  S.live.name = name || ''; if (!S.live.running) S.live.since = 0; S.flowFilter = null; S.pktSet = null; S.selPkt = null; S.timeRange = null; S.appColors.clear();
  reanalyze(true);
  $('#empty').hidden = true; $('#app').hidden = false; S.find = null; S.liveOpen = false; renderLivebar();
  if (S.tab === 'packets' && S.mode === 'simple') S.tab = 'summary';
  if (S.tab === 'settings') S.tab = 'summary';
  render();
}
function reanalyze(full) {
  S.A = PL.analyze(S.pk);
  if (S.set.names === false) S.A.nm = ip => ip;
  S.A.packets.forEach(p => { p._s = p.anoms.length ? pSev(p) : ''; });
  S.A.apps.forEach(a => appColor(a.app));
  computeVisible();
}
function computeVisible() {
  let l = S.A.packets;
  if (S.query && S.query.test) l = l.filter(S.query.test);
  if (S.flowFilter) l = l.filter(p => p.flow === S.flowFilter);
  if (S.pktSet) l = l.filter(p => S.pktSet.has(p.no));
  S.visPre = l;
  if (S.timeRange) { const t0 = S.A.t0, a = S.timeRange[0], b = S.timeRange[1]; l = l.filter(p => { const x = p.ts - t0; return x >= a && x <= b; }); }
  S.vis = l; S.visFlows = new Set(l.map(p => p.flow));
}
function loadBuffer(buf, name) {
  try { const raw = PL.parseCapture(buf); if (!raw.length) throw new Error('Dosyada paket bulunamadı.'); stopLiveUI(); ingest(raw, name); toast(`${raw.length} paket yüklendi`); }
  catch (e) { toast(e.message || 'Dosya okunamadı'); }
}
function loadFile(f) { const r = new FileReader(); r.onload = () => loadBuffer(r.result, f.name); r.readAsArrayBuffer(f); }
function loadSample() {
  if (!window.SAMPLE_PCAP_B64) return toast('Örnek dosya bulunamadı (sample.js)');
  const bin = atob(window.SAMPLE_PCAP_B64), u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  loadBuffer(u.buffer, 'örnek');
}

/* ---------- üst çubuk / mod / sekmeler ---------- */
function renderChrome() {
  $('#m-simple').classList.toggle('on', S.mode === 'simple'); $('#m-adv').classList.toggle('on', S.mode === 'adv');
  $('#b-set').classList.toggle('on', S.tab === 'settings');
  $('#l-tr').classList.toggle('on', S.set.lang === 'tr'); $('#l-en').classList.toggle('on', S.set.lang === 'en');
  const A = S.A;
  $('#app').classList.toggle('nodata', !A);
  if (!A) {
    if (S.tab === 'ptentes') {
      $('#tabs').innerHTML = `<button class="tab on" data-act="tab" data-v="ptentes" role="tab">ptentes</button>`;
      $('#qmeta').innerHTML = '<span class="muted small">Araya girme motoru — yakalama dosyası olmadan da çalışır.</span>';
      return;
    }
    $('#tabs').innerHTML = ''; $('#qmeta').innerHTML = ''; return;
  }
  const tabs = [['summary', 'Özet'], ['problems', 'Sorunlar', A.problems.length], ['flows', 'Bağlantılar', A.flows.length], ['devices', 'Cihazlar'], ['sites', 'Siteler'], ['map', 'Harita'], ['charts', 'Grafik']];
  if (S.mode === 'adv') tabs.push(['packets', 'Paketler', A.packets.length], ['stats', 'İstatistik'], ['logs', 'Günlükler'], ['ptentes', 'ptentes']);
  tabs.push(['settings', '⚙ Ayarlar']);
  if (!tabs.some(t => t[0] === S.tab)) S.tab = 'summary';
  $('#tabs').innerHTML = tabs.map(t => `<button class="tab ${S.tab === t[0] ? 'on' : ''}" data-act="tab" data-v="${t[0]}" role="tab">${t[1]}${t[2] != null ? `<span class="badge ${t[0] === 'problems' && A.stats.high ? 'bad' : ''}">${t[2]}</span>` : ''}</button>`).join('');
  const meta = [];
  if (S.query && S.query.test) { S.query.labels.forEach(l => meta.push(`<span class="chip on">${esc(l.label)}</span>`)); meta.push(`<span>→ ${S.vis.length} paket, ${S.visFlows.size} bağlantı</span>`); }
  if (S.query && S.query.error) meta.push(`<span class="chip err" title="Filtre ifadesi geçersiz">⚠ ${esc(S.query.error)}</span>`);
  if (S.timeRange) meta.push(`<button class="chip on" data-act="cleartime">Zaman: ${S.timeRange[0].toFixed(2)}–${S.timeRange[1].toFixed(2)} sn ✕</button>`);
  if (S.flowFilter) meta.push(`<button class="chip on" data-act="clrflow">Bağlantı #${S.flowFilter} ✕</button>`);
  if (S.pktSet) meta.push(`<button class="chip on" data-act="clrset">${esc(S.pktSetLabel)} ✕</button>`);
  if (S.query && S.query.wire) meta.push(`<span>Wireshark filtresi:</span><span class="wire">${esc(S.query.wire)}</span><button class="btn sm ghost" data-act="copywire">Kopyala</button>`);
  if (!meta.length) { meta.push(['sorunlar', 'yavaş dns', 'tls', 'şifresiz', 'tcp.port == 443', 'dns.time > 0.1'].map(x => `<button class="chip" data-act="try" data-v="${esc(x)}">${esc(x)}</button>`).join(' '));
    if ((S.set.presets || []).length) meta.push('<span class="muted">|</span>', S.set.presets.map(x => `<button class="chip pre" data-act="try" data-v="${esc(x.f)}" title="${esc(x.f)}">★ ${esc(x.n)}</button>`).join(' ')); }
  $('#qmeta').innerHTML = meta.join(' ');
  $('#clearq').hidden = !S.qtext;
}
function render() {
  renderChrome();
  if (!S.A && S.tab !== 'settings' && S.tab !== 'ptentes') return;
  const v = $('#view'), sc = v.scrollTop;
  const R = Object.assign({ summary: renderSummary, problems: renderProblems, flows: renderFlows, packets: renderPackets }, (window.PLApp && window.PLApp.views) || {});
  (R[S.tab] || renderSummary)(v);
  if (S.tab !== 'packets') v.scrollTop = sc;
}

/* ---------- Özet ---------- */
function timelineSVG(tl, W) {
  const H = 150, base = 120, top = 28, bw = W / tl.n, max = Math.max(1, ...tl.bytes);
  let g = '';
  tl.bytes.forEach((b, i) => {
    const h = b / max * (base - top), x = i * bw;
    g += `<rect x="${(x + 1).toFixed(1)}" y="${(base - h).toFixed(1)}" width="${(bw - 2).toFixed(1)}" height="${Math.max(h, b ? 1 : 0).toFixed(1)}" rx="1.5" fill="var(--c0)" opacity=".85"><title>${fmtB(b)}${tl.probs[i] ? ' • ' + tl.probs[i] + ' sorun belirtisi' : ''}</title></rect>`;
    if (tl.probs[i]) g += `<circle cx="${(x + bw / 2).toFixed(1)}" cy="12" r="4.5" fill="var(--high)"><title>${tl.probs[i]} sorun belirtisi</title></circle>`;
  });
  return `<svg class="spark" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="Zamana göre veri miktarı">
    <line x1="0" y1="${base}" x2="${W}" y2="${base}" stroke="var(--line)"/>${g}
    <text x="0" y="${H - 8}" style="text-anchor:start">0 sn</text><text x="${W}" y="${H - 8}" style="text-anchor:end">${fmtD(tl.dur)}</text><text x="${W}" y="${top - 8}" style="text-anchor:end" dy="0">en yoğun: ${fmtB(max)}</text></svg>`;
}
function renderSummary(v) {
  const A = S.A, st = A.stats;
  const hosts = [...A.hosts.values()].map(h => ({ ...h, b: h.bytesTx + h.bytesRx })).sort((x, y) => y.b - x.b).slice(0, 8);
  const maxH = Math.max(1, hosts[0] ? hosts[0].b : 1), maxA = Math.max(1, A.apps[0] ? A.apps[0].bytes : 1);
  const banner = st.high ? ['bad', '⚠', `${st.high} ciddi sorun bulundu`, 'Aşağıdaki “Sorunlar” sekmesinde nedenleriyle ve önerilerle listelendi.']
    : st.problems ? ['warn', '!', `${st.problems} küçük uyarı var`, 'Ciddi bir sorun yok ama dikkat edilmesi gereken noktalar bulundu.'] : ['ok', '✓', 'Belirgin bir sorun bulunamadı', 'Bu yakalamada hata, yeniden iletim veya kopma tespit edilmedi.'];
  v.innerHTML = `
  <div class="banner ${banner[0]}"><span style="font-size:22px">${banner[1]}</span><div><b>${banner[2]}</b><span class="muted">${banner[3]}</span></div>
    ${st.problems ? '<button class="btn" style="margin-left:auto" data-act="tab" data-v="problems">Sorunları gör</button>' : ''}</div>
  <div class="kpis">
    <div class="kpi"><div class="v">${st.packets.toLocaleString(L())}</div><div class="l">paket</div></div>
    <div class="kpi"><div class="v">${fmtB(st.bytes)}</div><div class="l">toplam veri · ort. ${fmtRate(st.avgRate)}</div></div>
    <div class="kpi"><div class="v">${fmtD(st.duration)}</div><div class="l">süre</div></div>
    <div class="kpi"><div class="v">${st.flows}</div><div class="l">bağlantı</div></div>
    <div class="kpi"><div class="v">${st.hosts}</div><div class="l">cihaz / adres</div></div>
    <div class="kpi ${st.problems ? 'bad' : 'ok'}"><div class="v">${st.problems}</div><div class="l">sorun / uyarı</div></div>
    <div class="kpi ${A.problems.some(x => SEC.has(x.type)) ? 'bad' : 'ok'}"><div class="v">${A.problems.filter(x => SEC.has(x.type)).length}</div><div class="l">güvenlik bulgusu</div></div>
  </div>
  <div class="quick"><span class="muted">Hızlı görünümler:</span>
    <button class="chip" data-act="quick" data-v="apps">Uygulama başına trafik</button>
    <button class="chip" data-act="quick" data-v="top">En çok veri kullananlar</button>
    <button class="chip" data-act="quick" data-v="errors">Hata özeti</button></div>
  <div class="card" style="margin-bottom:14px"><h3>Zamana göre trafik <small>kırmızı noktalar sorun belirtisi olan anları gösterir</small></h3>${timelineSVG(A.timeline, Math.max(320, Math.round(v.clientWidth - 34)))}</div>
  <div class="grid g2">
    <div class="card" id="sec-apps"><h3>Uygulama başına trafik <small>tıklayın: o uygulamanın bağlantıları</small></h3><div class="bars">
      ${A.apps.slice(0, 10).map(a => `<div class="bar click" data-act="try" data-v="${esc(a.app.split(' ')[0].toLowerCase())}" title="${a.flows} bağlantı, ${a.pkts} paket"><span class="nm"><i class="dot" style="background:${appColor(a.app)}"></i>${esc(a.app)}</span><span class="track"><span class="fill" style="display:block;width:${Math.max(2, a.bytes / maxA * 100)}%;background:${appColor(a.app)}"></span></span><span class="val">${fmtB(a.bytes)}</span></div>`).join('')}</div></div>
    <div class="card" id="sec-top"><h3>En çok konuşan cihazlar <small>gönderilen + alınan</small></h3><div class="bars wide">
      ${hosts.map(h => { const n = nm(h.ip); return `<div class="bar click" data-act="try" data-v="${esc(h.ip)}" title="${esc(h.ip)} • ${h.flows.size} bağlantı"><span class="nm">${PL.isPrivate(h.ip) ? '<span class="pill ok">yerel</span>' : '<span class="pill low">internet</span>'}<span class="mono" style="overflow:hidden;text-overflow:ellipsis">${esc(n)}</span></span><span class="track"><span class="fill" style="display:block;width:${Math.max(2, h.b / maxH * 100)}%;background:var(--c0)"></span></span><span class="val">${fmtB(h.b)}</span></div>`; }).join('')}</div></div>
  </div>
  ${A.problems.length ? `<div class="card" id="sec-err" style="margin-top:14px"><h3>Hata özeti <small>en önemli ${Math.min(4, A.problems.length)} sorun</small></h3>${A.problems.slice(0, 4).map(probHTML).join('')}<button class="btn" data-act="tab" data-v="problems">Tümünü gör (${A.problems.length})</button></div>` : ''}`;
}

/* ---------- Sorunlar ---------- */
function probHTML(pr) {
  const L = { high: 'Ciddi', med: 'Orta', low: 'Düşük' };
  return `<div class="prob"><div class="sev ${pr.sev}"></div><div><h4><span class="pill ${pr.sev}">${L[pr.sev]}</span> ${esc(pr.title)}</h4><p>${esc(pr.plain)}</p><p class="advice">${esc(pr.advice)}</p>
    <div class="muted small">${(pr.ts - S.A.t0).toFixed(2)}. saniye · ${pr.pkts.length} paket${pr.flow ? ' · bağlantı #' + pr.flow : ''}</div></div>
    <div><button class="btn sm" data-act="probpk" data-v="${pr.id}">Paketleri göster</button></div></div>`;
}
const SEC = new Set(['scan', 'cred', 'arp', 'dnstunnel', 'dga', 'beacon', 'sweep', 'synflood', 'weaktls', 'clear', 'certanom']);
const PERF = new Set(['retrans', 'zerowin', 'slowrtt', 'dnsslow']);
const catOf = t => SEC.has(t) ? 'sec' : PERF.has(t) ? 'perf' : 'net';
function renderProblems(v) {
  let l = S.A.problems;
  if (S._devProbIp && PL.problemsForIp) l = PL.problemsForIp(S.A, S._devProbIp);
  if (S.query && S.query.test || S.flowFilter || S.pktSet || S.timeRange) { const nos = new Set(S.vis.map(p => p.no)); l = l.filter(pr => pr.pkts.some(n => nos.has(n))); }
  const cnt = { all: l.length, sec: 0, perf: 0, net: 0 }; l.forEach(pr => cnt[catOf(pr.type)]++);
  const shown = S.probCat === 'all' ? l : l.filter(pr => catOf(pr.type) === S.probCat);
  const devChip = S._devProbIp ? `<button class="chip on" data-act="clrdevprob">Cihaz: ${esc(S._devProbIp)} ✕</button>` : '';
  v.innerHTML = `<div class="toolbar">${devChip}${[['all', 'Hepsi'], ['sec', 'Güvenlik'], ['perf', 'Performans'], ['net', 'Ağ / bağlantı']].map(([k, t]) => `<button class="chip ${S.probCat === k ? 'on' : ''}" data-act="probcat" data-v="${k}">${t} (${cnt[k]})</button>`).join('')}</div>` +
    (shown.length ? shown.map(probHTML).join('') : `<div class="empty-note">${S.A.problems.length ? 'Bu filtreyle eşleşen sorun yok.' : '✓ Bu yakalamada sorun bulunamadı.'}</div>`);
}

/* ---------- Bağlantılar ---------- */
function renderFlows(v) {
  const A = S.A;
  let l = A.flows.filter(f => S.visFlows.has(f.id));
  const sorts = { start: ['Zaman', (a, b) => a.start - b.start], bytes: ['En çok veri', (a, b) => b.bytes - a.bytes], bad: ['Sorunlu önce', (a, b) => ({ bad: 0, warn: 1, ok: 2 }[a.status] - { bad: 0, warn: 1, ok: 2 }[b.status]) || a.start - b.start], dur: ['En uzun süre', (a, b) => (b.end - b.start) - (a.end - a.start)] };
  l.sort(sorts[S.flowSort][1]);
  const adv = S.mode === 'adv';
  const LBL = { ok: 'sağlıklı', warn: 'uyarı', bad: 'sorunlu' };
  const rows = l.slice(0, 1500).map(f => `<tr data-act="flow" data-v="${f.id}">
    <td><span class="st ${f.status}" title="${LBL[f.status]}"></span>${S.notes[f.id] ? '<span title="Not var">📝</span>' : ''}</td>
    <td><i class="dot" style="background:${appColor(f.app)};display:inline-block;margin-right:6px"></i>${esc(f.app)}</td>
    <td>${esc(nm(f.client))}${adv && f.aPort != null ? '<span class="muted">:' + f.aPort + '</span>' : ''} <span class="muted">→</span> ${esc(nm(f.server))}${f.bPort != null ? '<span class="muted">:' + f.bPort + '</span>' : ''}</td>
    ${adv ? `<td>${f.proto}</td><td class="num">${f.pkts}</td><td class="num">${f.rtt != null ? Math.round(f.rtt * 1000) + ' ms' : '–'}</td><td class="num">${f.retrans || ''}</td>` : ''}
    <td class="num">${fmtB(f.bytes)}</td><td class="num">${fmtD(f.end - f.start)}</td><td>${f.probs.length ? `<span class="pill ${f.probs.some(p => p.sev === 'high') ? 'high' : f.probs.some(p => p.sev === 'med') ? 'med' : 'low'}">${f.probs.length}</span>` : ''}</td></tr>`).join('');
  v.innerHTML = `<div class="toolbar"><label class="muted">Sırala: <select id="fsort">${Object.entries(sorts).map(([k, s]) => `<option value="${k}" ${S.flowSort === k ? 'selected' : ''}>${s[0]}</option>`).join('')}</select></label><span class="muted">${l.length} bağlantı</span></div>
  ${l.length ? `<div class="tablewrap"><table class="t"><thead><tr><th></th><th>Uygulama</th><th>Kim → Kime</th>${adv ? '<th>Proto</th><th class="num">Paket</th><th class="num">El sıkışma</th><th class="num">Yeniden</th>' : ''}<th class="num">Veri</th><th class="num">Süre</th><th>Sorun</th></tr></thead><tbody>${rows}</tbody></table></div>` : '<div class="empty-note">Eşleşen bağlantı yok.</div>'}`;
  $('#fsort').onchange = e => { S.flowSort = e.target.value; renderFlows(v); };
}

/* ---------- Paketler (sanal liste) ---------- */
function renderPackets(v) {
  v.innerHTML = `<div class="pk-split"><div class="pk-list">${X().findBar ? X().findBar() : ''}<div class="pk-head"><span>No</span><span>${S.set.timefmt === 'delta' ? 'Fark' : S.set.timefmt === 'abs' ? 'Saat' : 'Zaman'}</span><span>Kaynak</span><span>Hedef</span><span>Protokol</span><span>Boyut</span><span>Bilgi</span></div>
    <div class="pk-body" id="pkb" tabindex="0"><div id="pki" style="position:relative"></div></div>
    <div class="muted small" style="padding:6px 10px;border-top:1px solid var(--line);display:flex;gap:12px;align-items:center"><span id="pkcount"></span>${S.live.running ? '<label><input type="checkbox" id="follow" ' + (S.follow ? 'checked' : '') + '> Otomatik kaydır</label>' : ''}<span style="margin-left:auto">↑↓ ile gezin</span></div></div>
    <div class="pk-detail" id="pkd"></div></div>`;
  const body = $('#pkb');
  body.onscroll = drawRows;
  body.onclick = e => { const r = e.target.closest('.pk-row'); if (r) { selectPacket(+r.dataset.no); } };
  body.onkeydown = e => { if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); stepSel(e.key === 'ArrowDown' ? 1 : -1); } };
  const fl = $('#follow'); if (fl) fl.onchange = () => { S.follow = fl.checked; };
  updatePacketList(true); renderDetail();
}
const X = () => (window.PLApp && window.PLApp.extra) || {};
function idxOf(no) { const l = S.vis; let lo = 0, hi = l.length - 1; while (lo <= hi) { const m = (lo + hi) >> 1; if (l[m].no === no) return m; if (l[m].no < no) lo = m + 1; else hi = m - 1; } return -1; }
function updatePacketList(reset) {
  const body = $('#pkb'); if (!body) return;
  $('#pki').style.height = S.vis.length * ROW + 'px';
  $('#pkcount').textContent = `${S.vis.length.toLocaleString(L())} / ${S.A.packets.length.toLocaleString(L())} paket`;
  if (S.live.running && S.follow && !reset) body.scrollTop = body.scrollHeight;
  drawRows();
}
function drawRows() {
  const body = $('#pkb'); if (!body) return;
  const top = body.scrollTop, h = body.clientHeight, s = Math.max(0, Math.floor(top / ROW) - 6), e = Math.min(S.vis.length, Math.ceil((top + h) / ROW) + 6);
  let html = '';
  for (let i = s; i < e; i++) {
    const p = S.vis[i];
    html += `<div class="pk-row ${p._s} ${p.no === S.selPkt ? 'sel' : ''} ${S.find && S.find.set.has(p.no) ? 'hit' : ''}" data-no="${p.no}" style="top:${i * ROW}px;border-left-color:${appColor(S.A.flows[p.flow - 1].app)}">
      <span>${p.no}</span><span>${tcol(p)}</span><span title="${esc(p.src)}">${esc(nm(p.src))}</span><span title="${esc(p.dst)}">${esc(nm(p.dst))}</span><span>${esc(p.app)}</span><span>${p.len}</span><span title="${esc(p.info)}">${esc(p.info)}</span></div>`;
  }
  $('#pki').innerHTML = html;
}
function selectPacket(no, scroll) {
  S.selPkt = no; drawRows(); renderDetail();
  if (scroll) { const i = idxOf(no), b = $('#pkb'); if (i >= 0 && b) b.scrollTop = Math.max(0, i * ROW - b.clientHeight / 2); drawRows(); }
}
function stepSel(d) {
  if (!S.vis.length) return;
  let i = S.selPkt == null ? -1 : idxOf(S.selPkt); i = Math.min(S.vis.length - 1, Math.max(0, i + d));
  S.selPkt = S.vis[i].no; const b = $('#pkb'), y = i * ROW;
  if (y < b.scrollTop) b.scrollTop = y; else if (y + ROW > b.scrollTop + b.clientHeight) b.scrollTop = y + ROW - b.clientHeight;
  drawRows(); renderDetail();
}
function hexdump(u8) {
  const n = Math.min(u8.length, 1024), out = [];
  for (let o = 0; o < n; o += 16) {
    let h = '', a = '';
    for (let i = 0; i < 16; i++) { if (o + i < n) { const c = u8[o + i]; h += c.toString(16).padStart(2, '0') + ' '; a += c >= 32 && c < 127 ? String.fromCharCode(c) : '.'; } else h += '   '; if (i === 7) h += ' '; }
    out.push(o.toString(16).padStart(4, '0') + '  ' + h + ' ' + esc(a));
  }
  return out.join('\n') + (u8.length > n ? `\n… (${u8.length - n} bayt daha)` : '');
}
function renderDetail() {
  const d = $('#pkd'); if (!d) return;
  const p = S.selPkt != null ? S.A.packets[S.selPkt - 1] : null;
  if (!p) { d.innerHTML = '<div class="empty-note">Ayrıntı için bir paket seçin.</div>'; return; }
  const f = S.A.flows[p.flow - 1];
  d.innerHTML = `<div class="plain ${p._s === 'bad' ? 'bad' : ''}"><b>Ne oluyor?</b><br>${esc(PL.describePacket(p, S.A))}</div>
    <div class="small muted" style="margin-bottom:10px">Paket #${p.no} · ${rel(p)} sn · <a href="#" data-act="flowpk" data-v="${f.id}">bu bağlantıdaki tüm paketler</a> · <a href="#" data-act="vfollow" data-v="${f.id}">akışı takip et</a></div>
    ${p.layers.map((l, i) => `<details class="layer" ${i > 0 ? 'open' : ''}><summary>${esc(l.name)}</summary><div class="fields">${l.fields.map(([k, val]) => `<div class="fld"><span class="k">${esc(k)}</span><span class="vv">${esc(val)}</span>${EXPLAIN[k] ? `<button class="q" data-act="expl" title="Bu ne demek?">?</button>` : '<span></span>'}${EXPLAIN[k] ? `<div class="expl" hidden>${esc(EXPLAIN[k])}</div>` : ''}</div>`).join('')}</div></details>`).join('')}
    <details class="layer"><summary>Ham veri (hex)</summary><pre class="hex">${hexdump(p.raw)}</pre></details>`;
}

/* ---------- Çekmece ---------- */
function openDrawer(html) { $('#drawer').innerHTML = `<button class="btn dr-close" data-act="closedr">Kapat ✕</button>${html}`; $('#drawer').hidden = false; $('#drawer-bg').hidden = false; $('#drawer').scrollTop = 0; }
function closeDrawer() { $('#drawer').hidden = true; $('#drawer-bg').hidden = true; }
function evtList(pkts) {
  const A = S.A;
  return pkts.slice(0, 400).map(p => `<div class="evt ${p._s}"><span class="tm">${(p.ts - A.t0).toFixed(3)}s</span><span>${esc(S.mode === 'adv' ? p.info : PL.describePacket(p, A))}${S.mode === 'adv' ? ` <a href="#" data-act="gopkt" data-v="${p.no}">#${p.no}</a>` : ''}</span></div>`).join('') + (pkts.length > 400 ? `<p class="muted">… ve ${pkts.length - 400} paket daha</p>` : '');
}
function openFlow(id) {
  const A = S.A, f = A.flows[id - 1], pk = f.pnos.map(n => A.packets[n - 1]), X = window.PLApp.extra;
  openDrawer(`<h2>${esc(nm(f.client))} ↔ ${esc(nm(f.server))}</h2><p>${esc(PL.describeFlow(f, A))}</p>
    <div class="row" style="justify-content:flex-start;margin:10px 0"><button class="btn sm primary" data-act="vfollow" data-v="${id}">⇄ Akışı takip et</button><button class="btn sm" data-act="flowpk" data-v="${id}">${S.mode === 'adv' ? 'Paketler sekmesinde aç' : 'Gelişmiş modda paketleri aç'}</button></div>
    ${X && X.noteBox ? X.noteBox(id) : ''}
    ${X && X.tlsHTML ? X.tlsHTML(f) : ''}
    ${f.probs.length ? '<h3>Sorunlar</h3>' + f.probs.map(probHTML).join('') : '<p><span class="pill ok">sağlıklı</span> Bu bağlantıda sorun tespit edilmedi.</p>'}
    ${X && X.seqSVG ? '<h3>Sıra diyagramı</h3>' + X.seqSVG(f) : ''}
    <h3>Olay akışı</h3>${evtList(pk)}`);
}
function openProbPk(id) {
  const pr = S.A.problems[id - 1], pk = pr.pkts.map(n => S.A.packets[n - 1]);
  openDrawer(`<h2>${esc(pr.title)}</h2><p>${esc(pr.plain)}</p><p class="muted">${esc(pr.advice)}</p>
    <div class="row" style="justify-content:flex-start;margin:10px 0">${S.mode === 'adv' ? `<button class="btn sm" data-act="setpk" data-v="${id}">Paketler sekmesinde filtrele</button>` : ''}${pr.flow ? `<button class="btn sm" data-act="flow" data-v="${pr.flow}">Bağlantıyı aç</button>` : ''}</div>
    <h3>İlgili paketler</h3>${evtList(pk)}`);
}

/* ---------- Canlı yakalama ---------- */
const api = (path, opt) => fetch(path, opt).then(r => r.json().then(j => ({ ok: r.ok, j })).catch(() => ({ ok: r.ok, j: {} })));
function b64u8(s) { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
function maskBits(m) { return String(m).split('.').reduce((n, o) => n + (+o).toString(2).replace(/0/g, '').length, 0); }
async function loadNet() { try { const { ok, j } = await api('/api/net'); if (ok) S.net = j; } catch (e) { /* yok say */ } }
async function initServer() {
  if (location.protocol === 'file:') { srvInit = 'file'; return; }
  srvInit = 'loading';
  try {
    const { ok, j } = await api('/api/info');
    if (!ok) { srvInit = 'fail'; S.srv = null; renderLivebar(); return; }
    S.srv = j;
    srvInit = 'ok';
    await loadNet(); if (PL.loadOui) PL.loadOui(); renderLivebar();
    const hint = $('#live-hint');
    if (hint) {
      if (!j.capture) hint.textContent = sysPlatformHint(j);
      else hint.textContent = j.root ? 'Canlı analiz hazır: “▶ Analiz et” düğmesine basın.' : 'Canlı analiz için programı sudo ile başlatın (şu an root değil).';
    }
    if (window.PLApp && window.PLApp.checkUpdate) window.PLApp.checkUpdate(j.commit);
  } catch (e) { srvInit = 'fail'; S.srv = null; renderLivebar(); }
}
function sysPlatformHint(j) {
  if (j && j.platform && !j.platform.startsWith('linux')) return 'macOS/Windows: canlı paket yakalama yok; pcap yükleyin veya Linux’ta sudo ile çalıştırın.';
  return 'Canlı yakalama kapalı (--no-capture).';
}
function renderLivebar() {
  const bar = $('#livebar'), s = S.srv, b = $('#b-live');
  if (S.live.running) { b.textContent = '■ Durdur'; b.className = 'btn danger big'; b.dataset.act = 'livestop'; }
  else { b.textContent = '▶ Analiz et'; b.className = 'btn primary big'; b.dataset.act = 'analyze'; }
  if (!S.live.running && !S.liveOpen) { bar.hidden = true; return; }
  bar.hidden = false;
  const cmd = '<span class="mono">sudo python3 packetlens.py</span>';
  if (S.live.running) {
    bar.innerHTML = `<span class="rec">CANLI</span><span class="muted">${esc(S.live.iface)}${S.live.filter ? ' · filtre: <span class="mono">' + esc(S.live.filter) + '</span>' : ''} · <b id="livecount">${S.pk.length}</b> paket</span><button class="btn danger sm" data-act="livestop">Durdur</button><a class="btn sm" href="/api/save" download>.pcap olarak kaydet</a>`;
  } else if (!s) {
    let msg;
    if (srvInit === 'file') msg = 'Sayfa dosyadan (file://) açılmış. Terminalde <span class="mono">python3 packetlens.py</span> çalıştırıp <span class="mono">http://127.0.0.1:8765</span> adresini açın.';
    else if (srvInit === 'loading') msg = 'Sunucuya bağlanılıyor…';
    else if (srvInit === 'fail') msg = 'Sunucu yanıt vermedi. Programın çalıştığından emin olun ve <span class="mono">http://127.0.0.1:8765</span> (veya terminalde yazan port) adresini açın.';
    else msg = `Sunucu bilinmiyor. Program çalışmıyorsa: ${cmd}`;
    bar.innerHTML = `<b>Canlı analiz</b><span class="muted">${msg}</span><button class="btn sm ghost" data-act="analyze">Kapat ✕</button>`;
  } else if (!s.capture) {
    const plat = (s.platform && !s.platform.startsWith('linux')) ? ' Bu ortamda (macOS/Windows) yalnızca .pcap dosyası analizi desteklenir; canlı yakalama için Linux gerekir.' : '';
    bar.innerHTML = `<b>Canlı analiz</b><span class="muted">Canlı yakalama kapalı (--no-capture).${plat} Dosya sürükleyip bırakabilirsiniz.</span><button class="btn sm ghost" data-act="analyze">Kapat ✕</button>`;
  } else {
    const st = S.set, defIf = (s.interfaces.find(i => i.default) || {}).name, ifc = S.live.iface && S.live.iface !== 'any' ? S.live.iface : (st.iface || s.default_iface || defIf || 'any');
    const opts = [st.duration ? T(st.duration + ' sn sonra otomatik durur') : T('süre sınırı yok'), T('en fazla ' + st.max.toLocaleString(L()) + ' paket'), st.promisc ? T('promiscuous açık') : T('promiscuous kapalı')].join(' · ');
    const kindIc = { ethernet: '🖧', wifi: '📶', loopback: '↺', virtual: '⧉' }, kindTx = { ethernet: 'Ethernet', wifi: 'Wi-Fi', loopback: 'Loopback', virtual: 'Sanal' };
    const cards = [{ name: 'any', kind: 'any', state: 'up' }].concat(s.interfaces).map(i => i.kind === 'any'
      ? `<button class="ifc ${ifc === 'any' ? 'on' : ''}" data-act="pickif" data-v="any"><span class="ifc-ic">🌐</span><b>${T('Tüm arayüzler')}</b><span class="muted small">any</span></button>`
      : `<button class="ifc ${ifc === i.name ? 'on' : ''} ${i.state !== 'up' ? 'down' : ''}" data-act="pickif" data-v="${esc(i.name)}"><span class="ifc-ic">${kindIc[i.kind] || '🖧'}</span><b>${esc(i.name)}</b>${i.default ? `<span class="iftag">${T('internet çıkışı')}</span>` : ''}<span class="muted small">${T(kindTx[i.kind] || 'Ethernet')} · ${i.state === 'up' ? T('bağlı') : T('kapalı')}${i.speed > 0 ? ' · ' + i.speed + ' Mb/s' : ''}</span><span class="mono small">${esc(i.ipv4 ? i.ipv4 + (i.mask ? '/' + maskBits(i.mask) : '') : '—')}</span><span class="mono small muted">${esc(i.mac || '')}</span><span class="muted small">↓ ${fmtB(i.rx)} · ↑ ${fmtB(i.tx)}</span></button>`).join('');
    const gw = S.net && S.net.gateway && S.net.gateway.ip ? `<span class="muted small">${T('Ağ geçidi')}: <span class="mono">${esc(S.net.gateway.ip)}</span>${S.net.dns && S.net.dns.length ? ' · DNS: <span class="mono">' + esc(S.net.dns.slice(0, 2).join(', ')) + '</span>' : ''}</span>` : '';
    bar.innerHTML = `<div class="ifgrid" role="listbox" aria-label="${T('Ağ adaptörü')}">${cards}</div><input type="hidden" id="iface" value="${esc(ifc)}">${gw}<b class="sr"></b><input id="capf" class="capf" value="${esc(S.live.filter != null && S.live.since ? S.live.filter : (S.live.filter || st.capfilter || ''))}" placeholder="Yakalama filtresi (isteğe bağlı): host 192.168.1.5 and port 443" spellcheck="false" autocomplete="off">
      <button class="btn primary" data-act="livestart" ${s.root ? '' : 'disabled title="sudo ile başlatın"'}>▶ Analizi başlat</button>
      ${S.pk.length && S.live.since ? `<a class="btn sm" href="/api/save" download>.pcap olarak kaydet</a>` : ''}
      <span class="muted small">${opts} · <a href="#" data-act="settings">değiştir</a></span>
      ${s.root ? '' : `<span class="muted small">Root değilsiniz: canlı analiz için ${cmd}</span>`}
      <button class="btn sm ghost" data-act="analyze" title="Kapat">✕</button>`;
  }
}
async function liveStart() {
  const iface = $('#iface').value, flt = ($('#capf').value || '').trim(), st = S.set;
  const qs = `iface=${encodeURIComponent(iface)}&filter=${encodeURIComponent(flt)}&snap=${st.snap}&max=${st.max}&duration=${st.duration}&promisc=${st.promisc ? 1 : 0}`;
  const { ok, j } = await api('/api/start?' + qs, { method: 'POST' });
  if (!ok) { toast(j.error || 'Başlatılamadı'); return; }
  S.liveOpen = false;
  S.live.running = true; S.live.since = 0; S.live.iface = iface; S.live.filter = flt; S.timeRange = null; S.pk = []; S.raw = []; S.selPkt = null; S.flowFilter = null; S.pktSet = null; S.find = null; S.appColors.clear();
  $('#empty').hidden = true; $('#app').hidden = false;
  S.A = PL.analyze([]); S.A.nm = ip => ip; S.vis = []; S.visFlows = new Set();
  if (S.tab === 'settings') S.tab = 'summary';
  if (S.mode === 'adv') S.tab = 'packets';
  renderLivebar(); render(); livePoll(); S.live.timer = setInterval(livePoll, 700);
}
async function livePoll() {
  if (livePoll.busy) return; livePoll.busy = true;
  try {
    const { ok, j } = await api('/api/poll?since=' + S.live.since); if (!ok) return;
    if (j.error) { toast(j.error); }
    if (j.packets.length) {
      for (const [ts, len, b] of j.packets) { const r = { ts, len, data: b64u8(b), link: 1 }; S.raw.push(r); S.pk.push(PL.dissect(r, S.pk.length + 1)); }
      S.live.since += j.packets.length;
      if (S.pk.length < 20000 || Date.now() - (S.live.last || 0) > 3000) { reanalyze(false); S.live.last = Date.now(); }
      const c = $('#livecount'); if (c) c.textContent = S.pk.length.toLocaleString(L());
      if (S.tab === 'packets' && $('#pkb')) { renderChrome(); updatePacketList(); } else render();
    }
    if (!j.running && S.live.running) { stopLiveUI(); toast('Yakalama sona erdi'); }
  } catch (e) { /* ağ hatası: bir sonraki turda tekrar dener */ } finally { livePoll.busy = false; }
}
function stopLiveUI() { S.live.running = false; clearInterval(S.live.timer); S.live.timer = null; renderLivebar(); }
async function liveStop() { try { await api('/api/stop', { method: 'POST' }); } catch (e) { /* yok say */ } await livePoll(); stopLiveUI(); render(); }

/* ---------- olaylar ---------- */
function buildQuery(text) {
  const t = text.trim(); if (!t) return null;
  if (PLF && PLF.looksLikeFilter(t)) {
    const c = PLF.compile(t);
    if (!c.ok) return { test: null, labels: [], wire: '', error: c.error };
    return { test: p => c.test(p, S.A), labels: [{ label: 'Filtre: ' + (t.length > 46 ? t.slice(0, 46) + '…' : t) }], wire: '' };
  }
  return parseQuery(t);
}
function setQuery(text) {
  S.qtext = text; S.query = buildQuery(text); $('#q').value = text;
  if (S.A) { computeVisible(); if (S.query && S.query.test && S.tab === 'summary') S.tab = S.mode === 'adv' ? 'packets' : 'flows'; render(); }
}
function setPktFilter(id) {
  const pr = S.A.problems[id - 1]; S.pktSet = new Set(pr.pkts); S.pktSetLabel = pr.title; S.flowFilter = null; S.tab = 'packets'; S.selPkt = null; computeVisible(); closeDrawer(); render();
}
document.addEventListener('click', e => {
  if (e.target.id === 'drawer-bg') return closeDrawer();
  const el = e.target.closest('[data-act]'); if (!el) return;
  const act = el.dataset.act, v = el.dataset.v;
  if (el.tagName === 'A') e.preventDefault();
  if (el.classList.contains('menu-item')) { const mp = $('#menu-pop'); if (mp) mp.hidden = true; }
  switch (act) {
    case 'mode': S.mode = v; try { localStorage.setItem('pl-mode', v); } catch (x) { /* yok say */ } if (S.mode === 'simple' && ['packets', 'stats', 'logs'].includes(S.tab)) S.tab = 'flows'; render(); renderChrome(); break;
    case 'menu': { const p = $('#menu-pop'); p.hidden = !p.hidden; $('#b-menu').setAttribute('aria-expanded', String(!p.hidden)); return; }
    case 'open': $('#file').click(); break;
    case 'pickif': { const c = $('#capf'); if (c) S.live.filter = c.value; S.live.iface = v; S.set.iface = v; renderLivebar(); return; }
    case 'analyze': S.liveOpen = !S.liveOpen; if (S.liveOpen && !S.srv && srvInit !== 'loading') initServer().then(() => renderLivebar()); else if (S.liveOpen) loadNet().then(renderLivebar); renderLivebar(); if (S.liveOpen) { const c = $('#capf'); if (c) c.focus(); } break;
    case 'settings': S.tab = S.tab === 'settings' ? (S.A ? 'summary' : 'summary') : 'settings'; if (S.tab === 'settings') { $('#empty').hidden = true; $('#app').hidden = false; } else if (!S.A) { $('#empty').hidden = false; $('#app').hidden = true; } S.liveOpen = false; renderLivebar(); render(); break;
    case 'ptentes': S.mode = 'adv'; try { localStorage.setItem('pl-mode', 'adv'); } catch (x) { /* yok say */ } S.tab = 'ptentes'; $('#empty').hidden = true; $('#app').hidden = false; S.liveOpen = false; renderLivebar(); render(); break;
    case 'lang': S.set.lang = v; saveSettings(); applySettings(false); render(); renderLivebar(); if (window.PLI) window.PLI.apply(document.body); break;
    case 'sample': loadSample(); break;
    case 'tab': S.tab = v; if ((S.tab === 'settings' || S.tab === 'ptentes') && !S.A) { $('#empty').hidden = true; $('#app').hidden = false; } render(); break;
    case 'clearq': setQuery(''); break;
    case 'try': setQuery(v); break;
    case 'clrflow': S.flowFilter = null; computeVisible(); render(); break;
    case 'clrset': S.pktSet = null; computeVisible(); render(); break;
    case 'copywire': try { navigator.clipboard.writeText(S.query.wire); toast('Filtre kopyalandı'); } catch (x) { toast('Kopyalanamadı'); } break;
    case 'quick':
      if (v === 'apps') { const s = $('#sec-apps'); s.scrollIntoView({ behavior: 'smooth', block: 'center' }); s.classList.remove('hl'); void s.offsetWidth; s.classList.add('hl'); }
      else if (v === 'top') { S.flowSort = 'bytes'; S.tab = 'flows'; render(); }
      else { S.tab = 'problems'; render(); }
      break;
    case 'flow': closeDrawer(); openFlow(+v); break;
    case 'probpk': openProbPk(+v); break;
    case 'setpk': setPktFilter(+v); break;
    case 'flowpk':
      if (S.mode !== 'adv') { S.mode = 'adv'; try { localStorage.setItem('pl-mode', 'adv'); } catch (x) { /* yok say */ } }
      S.flowFilter = +v; S.pktSet = null; S.tab = 'packets'; S.selPkt = null; computeVisible(); closeDrawer(); render(); break;
    case 'gopkt': closeDrawer(); S.tab = 'packets'; render(); selectPacket(+v, true); break;
    case 'expl': { const x = el.parentElement.querySelector('.expl'); if (x) x.hidden = !x.hidden; break; }
    case 'cleartime': S.timeRange = null; computeVisible(); render(); break;
    case 'probcat': S.probCat = v; render(); break;
    case 'clrdevprob': S._devProbIp = null; render(); break;
    case 'closedr': closeDrawer(); break;
    case 'livestart': liveStart(); break;
    case 'livestop': liveStop(); break;
  }
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeDrawer(); const m = $('#modal'); if (m) m.hidden = true; }
  else if (e.key === '/' && !/INPUT|SELECT|TEXTAREA/.test((e.target || {}).tagName || '')) { e.preventDefault(); $('#q').focus(); }
});
let qt; $('#q').addEventListener('input', e => { clearTimeout(qt); qt = setTimeout(() => setQuery(e.target.value), 160); });
let rz; window.addEventListener('resize', () => { clearTimeout(rz); rz = setTimeout(() => { if (S.A && S.tab === 'summary') render(); }, 200); });
$('#q').addEventListener('keydown', e => { if (e.key === 'Enter') { clearTimeout(qt); setQuery(e.target.value); } });
document.addEventListener('click', e => { const p = $('#menu-pop'); if (p && !p.hidden && !e.target.closest('#menu')) p.hidden = true; });
document.addEventListener('keydown', e => { if (e.key === 'Escape') { const p = $('#menu-pop'); if (p) p.hidden = true; } });
$('#file').addEventListener('change', e => { if (e.target.files[0]) loadFile(e.target.files[0]); e.target.value = ''; });
['dragover', 'dragenter'].forEach(t => document.addEventListener(t, e => { e.preventDefault(); const d = $('#drop'); if (d) d.classList.add('over'); }));
['dragleave', 'drop'].forEach(t => document.addEventListener(t, e => { e.preventDefault(); const d = $('#drop'); if (d) d.classList.remove('over'); }));
document.addEventListener('drop', e => { const f = e.dataTransfer && e.dataTransfer.files[0]; if (f) loadFile(f); });

applySettings(false);
renderChrome();
renderLivebar();
initServer();
window.PLApp = { S, PL, PLF, $, esc, fmtB, fmtD, fmtRate, rel, nm, toast, appColor, setQuery, render, renderChrome, computeVisible, openDrawer, closeDrawer, selectPacket, pSev, evtList, views: {}, extra: {},
  DEFAULTS, saveSettings, applySettings, reanalyze, ingest, loadBuffer, renderLivebar, L, tcol, drawRows, updatePacketList, probHTML, SEC, PERF, catOf, api,
  goPacket(no) { closeDrawer(); S.tab = 'packets'; render(); selectPacket(no, true); } };
window.__PL = { S, parseQuery };
})();
if (window.PLI) window.PLI.apply(document.body);
