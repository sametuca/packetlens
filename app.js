/* PacketLens arayüzü */
(function () {
'use strict';
const PLF = window.PLF;
function getPL() {
  const p = window.PL;
  return p && typeof p.analyze === 'function' && typeof p.dissect === 'function' ? p : null;
}
/** @deprecated use getPL() — parser yüklenince window.PL güncellenir */
const PL = window.PL;
const $ = (s, r) => (r || document).querySelector(s);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const S = { A: null, raw: [], pk: [], mode: 'simple', tab: 'summary', timeRange: null, visPre: [], logTab: 'dns', probCat: 'all', query: null, qtext: '', flowFilter: null, pktSet: null, pktSetLabel: '', vis: [], visFlows: new Set(), selPkt: null, flowSort: 'start', follow: true, srv: null, live: { running: false, since: 0, timer: null, iface: 'any', dirty: false }, appColors: new Map() };
let srvInit = 'pending', srvInitDetail = '', initServerSeq = 0, initServerRetryT = null;
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
  const pl = getPL(); if (!pl) return;
  const st = S.set, c = pl.cfg;
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
  const pl = getPL(); if (!pl) { toast(T('Analiz modülü yüklenemedi. Sayfayı Cmd+Shift+R ile yenileyin.')); return; }
  S.raw = rawList; S.pk = rawList.map((r, i) => pl.dissect(r, i + 1));
  S.live.name = name || ''; if (!S.live.running) S.live.since = 0; S.flowFilter = null; S.pktSet = null; S.selPkt = null; S.timeRange = null; S.appColors.clear();
  reanalyze(true);
  const after = $('#live-after'); if (after) after.hidden = true;
  S.find = null; S.liveOpen = false; syncScreen(); renderLivebar();
  if (S.tab === 'packets' && S.mode === 'simple') S.tab = 'summary';
  if (S.tab === 'settings') S.tab = 'summary';
  render();
}
function reanalyze(full) {
  const pl = getPL(); if (!pl) return;
  S.A = pl.analyze(S.pk);
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
  try {
    const pl = getPL(); if (!pl) throw new Error(T('Analiz modülü yüklenemedi.'));
    const raw = pl.parseCapture(buf); if (!raw.length) throw new Error('Dosyada paket bulunamadı.'); stopLiveUI(); ingest(raw, name); toast(`${raw.length} paket yüklendi`);
  }
  catch (e) { toast(e.message || 'Dosya okunamadı'); }
}
function loadFile(f) { const r = new FileReader(); r.onload = () => loadBuffer(r.result, f.name); r.readAsArrayBuffer(f); }
/* ---------- üst çubuk / mod / sekmeler ---------- */
function closeMenu() {
  const p = $('#menu-pop'), b = $('#b-menu');
  if (p) p.hidden = true;
  if (b) b.setAttribute('aria-expanded', 'false');
}
function renderChrome() {
  $('#m-simple').classList.toggle('on', S.mode === 'simple'); $('#m-adv').classList.toggle('on', S.mode === 'adv');
  $('#l-tr').classList.toggle('on', S.set.lang === 'tr'); $('#l-en').classList.toggle('on', S.set.lang === 'en');
  const A = S.A;
  $('#app').classList.toggle('nodata', !A);
  if (!A) {
    if (S.tab === 'ptentes') {
      $('#tabs').innerHTML = `<button class="tab on" data-act="tab" data-v="ptentes" role="tab">ptentes</button>`;
      $('#qmeta').innerHTML = `<span class="muted small">${T('Araya girme motoru — yakalama dosyası olmadan da çalışır.')}</span>`;
      return;
    }
    if (S.mode === 'adv') {
      $('#tabs').innerHTML = `<button class="tab" data-act="tab" data-v="ptentes" role="tab">ptentes</button>`;
      $('#qmeta').innerHTML = `<span class="muted small">${T('Gelişmiş mod: ptentes araya girme paneli.')}</span>`;
      return;
    }
    if (S.tab === 'settings') {
      $('#tabs').innerHTML = `<button class="tab on" data-act="tab" data-v="settings" role="tab">${T('Ayarlar')}</button>`;
      $('#qmeta').innerHTML = `<span class="muted small">${T('Paket yüklemeden dil, tema ve canlı yakalama tercihlerini düzenleyebilirsiniz.')}</span>`;
      return;
    }
    $('#tabs').innerHTML = ''; $('#qmeta').innerHTML = ''; return;
  }
  const tabs = [['summary', 'Özet'], ['problems', 'Sorunlar', A.problems.length], ['flows', 'Bağlantılar', A.flows.length], ['devices', 'Cihazlar'], ['sites', 'Siteler'], ['map', 'Harita'], ['charts', 'Grafik']];
  if (S.mode === 'adv') tabs.push(['packets', 'Paketler', A.packets.length], ['stats', 'İstatistik'], ['logs', 'Günlükler'], ['ptentes', 'ptentes']);
  tabs.push(['settings', 'Ayarlar']);
  if (!tabs.some(t => t[0] === S.tab)) S.tab = 'summary';
  $('#tabs').innerHTML = tabs.map(t => `<button class="tab ${S.tab === t[0] ? 'on' : ''}" data-act="tab" data-v="${t[0]}" role="tab">${t[1]}${t[2] != null ? `<span class="badge ${t[0] === 'problems' && A.stats.high ? 'bad' : ''}">${t[2]}</span>` : ''}</button>`).join('');
  const meta = [];
  if (S.query && S.query.test) { S.query.labels.forEach(l => meta.push(`<span class="chip on">${esc(l.label)}</span>`)); meta.push(`<span>→ ${S.vis.length} paket, ${S.visFlows.size} bağlantı</span>`); }
  if (S.query && S.query.error) meta.push(`<span class="chip err" title="Filtre ifadesi geçersiz">⚠ ${esc(S.query.error)}</span>`);
  if (S.timeRange) meta.push(`<button class="chip on" data-act="cleartime">Zaman: ${S.timeRange[0].toFixed(2)}–${S.timeRange[1].toFixed(2)} sn · temizle</button>`);
  if (S.flowFilter) meta.push(`<button class="chip on" data-act="clrflow">Bağlantı #${S.flowFilter} · temizle</button>`);
  if (S.pktSet) meta.push(`<button class="chip on" data-act="clrset">${esc(S.pktSetLabel)} · temizle</button>`);
  if (S.query && S.query.wire) meta.push(`<span>Wireshark filtresi:</span><span class="wire">${esc(S.query.wire)}</span><button class="btn sm ghost" data-act="copywire">Kopyala</button>`);
  if (!meta.length) { meta.push(['sorunlar', 'yavaş dns', 'tls', 'şifresiz', 'tcp.port == 443', 'dns.time > 0.1'].map(x => `<button class="chip" data-act="try" data-v="${esc(x)}">${esc(x)}</button>`).join(' '));
    if ((S.set.presets || []).length) meta.push('<span class="muted">|</span>', S.set.presets.map(x => `<button class="chip pre" data-act="try" data-v="${esc(x.f)}" title="${esc(x.f)}">${esc(x.n)}</button>`).join(' ')); }
  $('#qmeta').innerHTML = meta.join(' ');
  $('#clearq').hidden = !S.qtext;
}
function render() {
  renderChrome();
  if (!S.A && S.tab !== 'settings' && S.tab !== 'ptentes') return;
  const v = $('#view');
  if (!v) return;
  const sc = v.scrollTop;
  const views = (window.PLApp && window.PLApp.views) || {};
  const R = Object.assign({ summary: renderSummary, problems: renderProblems, flows: renderFlows, packets: renderPackets }, views);
  let fn = R[S.tab];
  if (!fn && S.tab === 'settings' && typeof window.__PL_renderSettings === 'function') fn = window.__PL_renderSettings;
  if (!fn && S.tab === 'ptentes' && typeof window.__PL_renderPtentes === 'function') fn = window.__PL_renderPtentes;
  if (!fn && (S.tab === 'settings' || S.tab === 'ptentes')) {
    v.innerHTML = `<div class="empty-note">${esc(T('Görünüm yüklenemedi. Sayfayı Ctrl+Shift+R (Mac: Cmd+Shift+R) ile yenileyin.'))}</div>`;
    return;
  }
  if (!fn) fn = renderSummary;
  try { fn(v); } catch (e) {
    v.innerHTML = `<div class="card"><p class="muted">${esc(e.message || String(e))}</p></div>`;
  }
  if (S.tab !== 'packets') v.scrollTop = sc;
  if ((S.tab === 'settings' || S.tab === 'ptentes') && window.PLI) window.PLI.apply(v);
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
  const devChip = S._devProbIp ? `<button class="chip on" data-act="clrdevprob">Cihaz: ${esc(S._devProbIp)} · temizle</button>` : '';
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
    <div class="muted small" style="padding:6px 10px;border-top:1px solid var(--line);display:flex;gap:12px;align-items:center;flex-wrap:wrap"><span id="pkcount"></span>${S.live.running ? '<label><input type="checkbox" id="follow" ' + (S.follow ? 'checked' : '') + '> Otomatik kaydır</label>' : ''}
    <label class="pk-goto">${T('Pakete git')} <input id="pkgoto" type="number" min="1" placeholder="#" style="width:72px" spellcheck="false"><button class="btn sm" type="button" data-act="pkgoto">${T('Git')}</button></label><span class="muted">↑↓ · ⌘G</span></div></div>
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
    <div class="small muted" style="margin-bottom:10px">Paket #${p.no} · ${rel(p)} sn · <a href="#" data-act="flowpk" data-v="${f.id}">${T('bu bağlantıdaki tüm paketler')}</a> · <a href="#" data-act="vfollow" data-v="${f.id}">${T('akışı takip et')}</a> · <a href="#" data-act="flowfilt" data-v="${f.id}">${T('tcp.stream filtresi')}</a></div>
    ${p.layers.map((l, i) => `<details class="layer" ${i > 0 ? 'open' : ''}><summary>${esc(l.name)}</summary><div class="fields">${l.fields.map(([k, val]) => `<div class="fld"><span class="k">${esc(k)}</span><span class="vv">${esc(val)}</span>${EXPLAIN[k] ? `<button class="q" data-act="expl" title="Bu ne demek?">?</button>` : '<span></span>'}${EXPLAIN[k] ? `<div class="expl" hidden>${esc(EXPLAIN[k])}</div>` : ''}</div>`).join('')}</div></details>`).join('')}
    <details class="layer"><summary>Ham veri (hex)</summary><pre class="hex">${hexdump(p.raw)}</pre></details>`;
}

/* ---------- Çekmece ---------- */
function openDrawer(html) { $('#drawer').innerHTML = `<button class="btn dr-close" data-act="closedr">Kapat</button>${html}`; $('#drawer').hidden = false; $('#drawer-bg').hidden = false; $('#drawer').scrollTop = 0; }
function closeDrawer() { $('#drawer').hidden = true; $('#drawer-bg').hidden = true; }
function evtList(pkts) {
  const A = S.A;
  return pkts.slice(0, 400).map(p => `<div class="evt ${p._s}"><span class="tm">${(p.ts - A.t0).toFixed(3)}s</span><span>${esc(S.mode === 'adv' ? p.info : PL.describePacket(p, A))}${S.mode === 'adv' ? ` <a href="#" data-act="gopkt" data-v="${p.no}">#${p.no}</a>` : ''}</span></div>`).join('') + (pkts.length > 400 ? `<p class="muted">… ve ${pkts.length - 400} paket daha</p>` : '');
}
function openFlow(id) {
  const A = S.A, f = A.flows[id - 1], pk = f.pnos.map(n => A.packets[n - 1]), X = window.PLApp.extra;
  openDrawer(`<h2>${esc(nm(f.client))} ↔ ${esc(nm(f.server))}</h2><p>${esc(PL.describeFlow(f, A))}</p>
    <div class="row" style="justify-content:flex-start;margin:10px 0;flex-wrap:wrap;gap:6px"><button class="btn sm primary" data-act="vfollow" data-v="${id}">${T('Akışı takip et')}</button><button class="btn sm" data-act="flowfilt" data-v="${id}">${T('Bu bağlantıya filtrele')}</button><button class="btn sm" data-act="flowexcl" data-v="${id}">${T('Bu bağlantıyı gizle')}</button><button class="btn sm" data-act="flowpk" data-v="${id}">${S.mode === 'adv' ? T('Paketler sekmesinde aç') : T('Gelişmiş modda paketleri aç')}</button></div>
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
function api(path, opt) {
  return fetch(path, Object.assign({ cache: 'no-store', headers: { Accept: 'application/json' } }, opt || {}))
    .then(r => r.text().then(t => {
      let j = {};
      try { j = t ? JSON.parse(t) : {}; } catch (e) { /* geçersiz json */ }
      return { ok: r.ok, status: r.status, j };
    }))
    .catch(() => ({ ok: false, status: 0, j: { error: T('Sunucuya ulaşılamadı') } }));
}
async function apiPollRunning(tries, gapMs) {
  for (let i = 0; i < tries; i++) {
    const chk = await api('/api/poll?since=0');
    if (chk.ok && chk.j && chk.j.running) return chk;
    if (chk.j && chk.j.error && !chk.j.running && i > 2) return chk;
    if (i + 1 < tries) await new Promise(r => setTimeout(r, gapMs));
  }
  return api('/api/poll?since=0');
}
function b64u8(s) { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
function maskBits(m) { return String(m).split('.').reduce((n, o) => n + (+o).toString(2).replace(/0/g, '').length, 0); }
async function loadNet() { try { const { ok, j } = await api('/api/net'); if (ok) S.net = j; } catch (e) { /* yok say */ } }
function liveConnectHint() {
  const h = location.hostname;
  if (h && h !== '127.0.0.1' && h !== 'localhost' && h !== '[::1]' && h !== '::1') {
    return ' Sunucu yalnızca <span class="mono">127.0.0.1</span> üzerinde dinler — sayfayı <b>Kali VM içindeki</b> tarayıcıda, terminalde yazan adresle açın (Mac/Windows’taki 127.0.0.1 sanal makineye gitmez).';
  }
  return '';
}
function httpGetJson(url) {
  return fetch(url, { cache: 'no-store', headers: { Accept: 'application/json' } })
    .then(r => r.text().then(t => {
      let j = {};
      try { j = t ? JSON.parse(t) : {}; } catch (e) { /* geçersiz json */ }
      return { ok: r.ok, status: r.status, j };
    }))
    .catch(() => new Promise((resolve, reject) => {
      const x = new XMLHttpRequest();
      x.open('GET', url, true);
      x.onload = () => {
        let j = {};
        try { j = x.responseText ? JSON.parse(x.responseText) : {}; } catch (e) { /* yok say */ }
        resolve({ ok: x.status >= 200 && x.status < 300, status: x.status, j });
      };
      x.onerror = () => reject(new Error('xhr'));
      x.send();
    }));
}
function scheduleInitServerRetry() {
  clearTimeout(initServerRetryT);
  if (srvInit !== 'fail' || location.protocol === 'file:' || !S.liveOpen) return;
  initServerRetryT = setTimeout(() => initServer().then(() => renderLivebar()), 2000);
}
async function initServer() {
  if (location.protocol === 'file:') { srvInit = 'file'; return; }
  const seq = ++initServerSeq;
  clearTimeout(initServerRetryT);
  srvInit = 'loading';
  srvInitDetail = '';
  renderLivebar();
  try {
    const { ok, status, j } = await httpGetJson(location.origin + '/api/info');
    if (seq !== initServerSeq) return;
    if (!ok) {
      srvInit = 'fail';
      S.srv = null;
      if (status === 401) srvInitDetail = 'stale';
      else if (status === 403) srvInitDetail = 'host';
      else if (status === 404) srvInitDetail = '404';
      else if (status >= 500) srvInitDetail = '500';
      else srvInitDetail = 'http';
      scheduleInitServerRetry();
      renderLivebar();
      return;
    }
    if (!j || !Array.isArray(j.interfaces)) {
      srvInit = 'fail';
      S.srv = null;
      srvInitDetail = 'badjson';
      scheduleInitServerRetry();
      renderLivebar();
      return;
    }
    S.srv = j;
    srvInit = 'ok';
    renderLivebar();
    try {
      await loadNet();
      if (PL && PL.loadOui) await Promise.resolve(PL.loadOui());
      if (!S.A && !S.live.running) renderLiveHome();
      if (window.PLApp && window.PLApp.checkUpdate) window.PLApp.checkUpdate(j.commit);
    } catch (e2) { /* yan etkiler sunucu bağlantısını bozmaz */ }
    renderLivebar();
    syncHeaderLiveBtn();
  } catch (e) {
    if (seq !== initServerSeq) return;
    srvInit = 'fail';
    S.srv = null;
    srvInitDetail = 'network';
    scheduleInitServerRetry();
    renderLivebar();
  }
}
function canPressLiveStart(s) {
  if (!s || !s.capture) return false;
  if (s.platform === 'darwin') return !!s.root;
  if (s.platform === 'win32') return true;
  return !!s.root;
}
function pickDefaultIface(ifaces, st, s) {
  const gw = S.net && S.net.gateway && S.net.gateway.iface;
  const defIf = (ifaces.find(i => i.default) || {}).name;
  let ifc = S.live.iface && S.live.iface !== 'any' ? S.live.iface : (st.iface || s.default_iface || defIf || 'any');
  if (ifc !== 'any' && s.platform === 'darwin' && /^ap\d/i.test(ifc)) {
    const alt = ifaces.find(i => i.name === gw && i.state === 'up')
      || ifaces.find(i => /^en\d/i.test(i.name) && i.ipv4 && i.state === 'up')
      || ifaces.find(i => /^en\d/i.test(i.name) && i.state === 'up');
    if (alt) ifc = alt.name;
  }
  if (ifc !== 'any' && !ifaces.some(i => i.name === ifc)) ifc = gw || defIf || 'any';
  return ifc;
}
function liveStartHint(s) {
  if (!s || s.root) return '';
  if (s.platform === 'darwin') return '<span class="muted small">macOS: sunucuyu <b>sudo</b> ile başlatın — <span class="mono">start.command</span> veya <span class="mono">sudo python3 packetlens.py --restart</span></span>';
  if (s.platform === 'win32') return '<span class="muted small">Windows: <span class="mono">start.bat</span> dosyasını Yönetici olarak çalıştırın.</span>';
  return `<span class="muted small">Root değilsiniz: canlı analiz için <span class="mono">sudo python3 packetlens.py</span></span>`;
}
function buildIfaceSelect(ifaces, ifc) {
  const kindTx = { ethernet: 'Ethernet', wifi: 'Wi-Fi', loopback: 'Loopback', virtual: 'Sanal', any: '' };
  let opts = `<option value="any"${ifc === 'any' ? ' selected' : ''}>${T('Tüm arayüzler')} (any)</option>`;
  for (const i of ifaces) {
    const bits = [i.label || i.name, T(kindTx[i.kind] || 'Ethernet'), i.state === 'up' ? T('bağlı') : T('kapalı')];
    if (/^ap\d/i.test(i.name)) bits.push(T('yakalama için önerilmez'));
    if (i.ipv4) bits.push(i.ipv4);
    if (i.default) bits.push(T('internet çıkışı'));
    opts += `<option value="${esc(i.name)}"${ifc === i.name ? ' selected' : ''}>${esc(bits.join(' · '))}</option>`;
  }
  return `<label class="live-lab">${T('Ağ adaptörü')}</label><select id="iface" class="ifsel">${opts}</select>`;
}
function isHomeScreen() {
  const home = $('#home');
  return !!(home && !home.hidden);
}
function syncScreen() {
  const aux = S.tab === 'settings' || S.tab === 'ptentes';
  const showApp = !!(S.A || S.live.running || aux);
  const home = $('#home'), app = $('#app');
  if (home) home.hidden = showApp;
  if (app) app.hidden = !showApp;
  if (!showApp) renderLiveHome();
  else syncHeaderLiveBtn();
}
function buildLivePanelBody(s) {
  const cmd = '<span class="mono">sudo python3 packetlens.py</span>';
  if (!s) {
    let msg;
    if (srvInit === 'file') msg = 'Sayfa dosyadan (file://) açılmış. Terminalde <span class="mono">sudo python3 packetlens.py</span> çalıştırıp <span class="mono">http://127.0.0.1:…</span> adresini açın.';
    else if (srvInit === 'loading') msg = T('Sunucuya bağlanılıyor…');
    else if (srvInit === 'fail' && srvInitDetail === 'stale') msg = 'Portta <b>eski</b> PacketLens çalışıyor. <span class="mono">pkill -f packetlens.py</span> → sunucuyu yeniden başlatın → <b>Ctrl+Shift+R</b>.';
    else if (srvInit === 'fail' && srvInitDetail === 'host') msg = 'Adres çubuğu <span class="mono">http://127.0.0.1:' + (location.port || '8765') + '</span> olmalı.';
    else if (srvInit === 'fail' && srvInitDetail === '404') msg = 'Bu adreste PacketLens API yok. Terminalde <span class="mono">sudo python3 packetlens.py</span> ile başlatın.';
    else if (srvInit === 'fail' && srvInitDetail === '500') msg = 'Sunucu hatası (/api/info). Terminal çıktısına bakın.';
    else if (srvInit === 'fail') msg = 'Tarayıcı API’ye ulaşamadı.' + liveConnectHint();
    else msg = `Sunucu bilinmiyor. Terminalde: ${cmd}`;
    return `<p class="live-home-msg">${msg}</p><div class="live-home-meta"><button class="btn sm" data-act="retry-srv">${T('Yeniden dene')}</button></div>`;
  }
  if (!s.capture && s.platform === 'darwin') {
    return `<p class="live-home-msg">Canlı yakalama için <span class="mono">start.command</span> (sudo) ile başlatın. Kayıtlı dosya için <b>Menü → Dosya aç</b>.</p>`;
  }
  if (!s.capture) {
    const plat = (s.platform === 'win32') ? ' Windows’ta Npcap kurulunca canlı yakalama açılır.' : '';
    return `<p class="live-home-msg">Canlı yakalama bu ortamda kapalı.${plat} Kayıtlı dosya için <b>Menü → Dosya aç</b>.</p>`;
  }
  const ifaces = s.interfaces || [], st = S.set, ifc = pickDefaultIface(ifaces, st, s);
  const opts = [st.duration ? T(st.duration + ' sn sonra otomatik durur') : T('süre sınırı yok'), T('en fazla ' + st.max.toLocaleString(L()) + ' paket'), st.promisc ? T('promiscuous açık') : T('promiscuous kapalı')].join(' · ');
  const gw = S.net && S.net.gateway && S.net.gateway.ip ? `<span class="muted small">${T('Ağ geçidi')}: <span class="mono">${esc(S.net.gateway.ip)}</span>${S.net.dns && S.net.dns.length ? ' · DNS: <span class="mono">' + esc(S.net.dns.slice(0, 2).join(', ')) + '</span>' : ''}</span>` : '';
  return `<div class="live-home-form">${buildIfaceSelect(ifaces, ifc)}${gw}
    <input id="capf" class="capf" value="${esc(S.live.filter != null && S.live.since ? S.live.filter : (S.live.filter || st.capfilter || ''))}" placeholder="${esc(T('Yakalama filtresi (isteğe bağlı): host 192.168.1.5 and port 443'))}" spellcheck="false" autocomplete="off">
    <button class="btn primary" data-act="livestart" ${canPressLiveStart(s) ? '' : 'disabled'}>${T('Başlat')}</button></div>
    <div class="live-home-meta"><span class="muted small">${opts} · <a href="#" data-act="settings">${T('değiştir')}</a></span>${liveStartHint(s)}</div>`;
}
function renderLiveHome() {
  const panel = $('#live-home'), idle = $('#home-idle'), after = $('#live-after');
  if (!panel) return;
  if (idle) idle.hidden = true;
  if (S.live.running) { panel.innerHTML = ''; return; }
  if (S.liveOpen && after) after.hidden = true;
  const fileHint = `${T('Kayıtlı dosya için')} <b>${T('Menü → Dosya aç')}</b>.`;
  if (!S.liveOpen) {
    panel.innerHTML = `<div class="card live-welcome-card">
      <p class="live-welcome-lead">${T('Ağ trafiğini gerçek zamanlı yakalayıp uygulamalara, bağlantılara ve sorunlara ayırın.')}</p>
      <p class="live-welcome-sub muted">${fileHint}</p>
      <div class="live-welcome-actions"><button type="button" class="btn primary" data-act="analyze">${T('Canlı analiz')}</button></div>
    </div>`;
    syncHeaderLiveBtn();
    return;
  }
  panel.innerHTML = `<div class="card live-home-card">
    <div class="live-home-head"><h2>${T('Canlı yakalama')}</h2><button type="button" class="btn sm" data-act="analyze">${T('Kapat')}</button></div>
    ${buildLivePanelBody(S.srv)}</div>`;
  syncHeaderLiveBtn();
}
function goHomeScreen(afterStop) {
  S.liveOpen = false;
  closeDrawer();
  const after = $('#live-after');
  if (after && afterStop && S.pk.length && S.A) {
    after.hidden = false;
    after.innerHTML = `${S.pk.length.toLocaleString(L())} paket yakalandı. <button type="button" class="btn sm primary" data-act="view-capture">${T('Yakalamayı incele')}</button>`;
  } else if (after) after.hidden = true;
  syncScreen();
  renderLivebar();
}
function syncHeaderLiveBtn() {
  const b = $('#b-live');
  if (!b) return;
  if (isHomeScreen() && !S.live.running) {
    b.hidden = true;
    return;
  }
  b.hidden = false;
  b.removeAttribute('title');
  if (S.live.running) {
    b.textContent = T('Durdur');
    b.className = 'btn danger';
    b.dataset.act = 'livestop';
    return;
  }
  if (S.liveOpen) {
    b.textContent = T('Kapat');
    b.className = 'btn';
    b.dataset.act = 'analyze';
  } else {
    b.textContent = T('Canlı analiz');
    b.className = 'btn primary';
    b.dataset.act = 'analyze';
  }
}
function renderLivebar() {
  const bar = $('#livebar'), b = $('#b-live');
  syncHeaderLiveBtn();
  if (!S.live.running) {
    if (bar) bar.hidden = true;
    renderLiveHome();
    return;
  }
  bar.hidden = false;
  bar.innerHTML = `<span class="rec">CANLI</span><span class="muted">${esc(S.live.iface)}${S.live.filter ? ' · filtre: <span class="mono">' + esc(S.live.filter) + '</span>' : ''} · <b id="livecount">${S.pk.length}</b> paket</span><button class="btn danger sm" data-act="livestop">Durdur</button><a class="btn sm" href="/api/save" download>.pcap olarak kaydet</a>`;
}
async function liveStart() {
  const s = S.srv;
  if (s && s.platform === 'darwin' && !s.root) {
    toast('Canlı yakalama için sunucuyu sudo ile başlatın (start.command veya sudo python3 packetlens.py --restart)');
    return;
  }
  if (liveStart.busy) return;
  liveStart.busy = true;
  const startBtn = document.querySelector('[data-act="livestart"]');
  const prevBtn = startBtn ? startBtn.textContent : '';
  if (startBtn) { startBtn.disabled = true; startBtn.textContent = T('Başlatılıyor…'); }
  try {
    const ifaceEl = $('#iface'), capEl = $('#capf');
    let iface = ifaceEl ? ifaceEl.value : 'any';
    if (s && s.platform === 'darwin' && /^ap\d/i.test(iface)) {
      const ifaces = s.interfaces || [];
      const gw = S.net && S.net.gateway && S.net.gateway.iface;
      const alt = ifaces.find(i => i.name === gw) || ifaces.find(i => /^en\d/i.test(i.name) && i.ipv4);
      if (alt) {
        iface = alt.name;
        toast(T('ap arayüzü yerine') + ' ' + iface + ' ' + T('kullanılıyor'));
        if (ifaceEl) ifaceEl.value = iface;
      }
    }
    const flt = (capEl && capEl.value ? capEl.value : '').trim();
    const st = S.set;
    const qs = `iface=${encodeURIComponent(iface)}&filter=${encodeURIComponent(flt)}&snap=${st.snap}&max=${st.max}&duration=${st.duration}&promisc=${st.promisc ? 1 : 0}`;
    const { ok, j } = await api('/api/start?' + qs, { method: 'POST' });
    if (!ok || j.ok === false) { toast(j.error || T('Başlatılamadı')); return; }
    const chk = await apiPollRunning(12, 120);
    if (!chk.ok || !chk.j || !chk.j.running) {
      toast((chk.j && chk.j.error) || T('Yakalama başlayamadı. Arayüzü (en0) ve sudo ile başlatmayı deneyin.'));
      await api('/api/stop', { method: 'POST' });
      return;
    }
    const pl = getPL();
    if (!pl) {
      toast(T('Analiz modülü yüklenemedi. Sayfayı Cmd+Shift+R ile yenileyin.'));
      await api('/api/stop', { method: 'POST' });
      return;
    }
    S.liveOpen = false;
    S.live.since = 0; S.live.iface = iface; S.live.filter = flt; S.timeRange = null; S.pk = []; S.raw = []; S.selPkt = null; S.flowFilter = null; S.pktSet = null; S.find = null; S.appColors.clear();
    S.A = pl.analyze([]); S.A.nm = ip => ip; S.vis = []; S.visFlows = new Set();
    S.live.running = true;
    syncScreen();
    if (S.tab === 'settings') S.tab = 'summary';
    if (S.mode === 'adv') S.tab = 'packets';
    renderLivebar(); render(); livePoll(); S.live.timer = setInterval(livePoll, 700);
  } catch (e) {
    toast(e && e.message ? e.message : T('Sunucuya ulaşılamadı'));
  } finally {
    liveStart.busy = false;
    if (startBtn) { startBtn.disabled = false; startBtn.textContent = prevBtn || T('Başlat'); }
    renderLivebar();
  }
}
async function livePoll() {
  if (livePoll.busy) return; livePoll.busy = true;
  try {
    const { ok, j } = await api('/api/poll?since=' + S.live.since); if (!ok) return;
    if (j.error) { toast(j.error); }
    if (j.packets && j.packets.length) {
      const pl = getPL(); if (!pl) return;
      for (const [ts, len, b] of j.packets) { const r = { ts, len, data: b64u8(b), link: 1 }; S.raw.push(r); S.pk.push(pl.dissect(r, S.pk.length + 1)); }
      S.live.since += j.packets.length;
      if (S.pk.length < 20000 || Date.now() - (S.live.last || 0) > 3000) { reanalyze(false); S.live.last = Date.now(); }
      const c = $('#livecount'); if (c) c.textContent = S.pk.length.toLocaleString(L());
      if (S.tab === 'packets' && $('#pkb')) { renderChrome(); updatePacketList(); } else render();
    }
    if (!j.running && S.live.running) {
      stopLiveUI();
      goHomeScreen(true);
      toast(j.error || T('Yakalama sona erdi'));
    }
  } catch (e) { /* ağ hatası: bir sonraki turda tekrar dener */ } finally { livePoll.busy = false; }
}
function stopLiveUI() { S.live.running = false; clearInterval(S.live.timer); S.live.timer = null; renderLivebar(); }
async function liveStop() {
  try { await api('/api/stop', { method: 'POST' }); } catch (e) { /* yok say */ }
  await livePoll();
  stopLiveUI();
  goHomeScreen(true);
  toast(T('Yakalama durduruldu'));
}

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
function flowDisplayFilter(id, exclude) {
  const f = S.A && S.A.flows[id - 1];
  const base = f && f.proto === 'TCP' ? `tcp.stream == ${id}` : `pl.flow == ${id}`;
  setQuery(exclude ? `!(${base})` : base);
}
function goToPacketNo(raw) {
  const no = typeof raw === 'number' ? raw : parseInt(String(raw || '').trim(), 10);
  if (!S.A || !no || no < 1 || no > S.A.packets.length) { toast(T('Geçersiz paket numarası')); return; }
  if (S.tab !== 'packets') { S.tab = 'packets'; render(); }
  selectPacket(no, true);
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
  switch (act) {
    case 'mode':
      S.mode = v;
      try { localStorage.setItem('pl-mode', v); } catch (x) { /* yok say */ }
      if (S.mode === 'simple' && ['packets', 'stats', 'logs', 'ptentes'].includes(S.tab)) S.tab = 'flows';
      else if (S.mode === 'adv' && !S.A && S.tab !== 'settings') { S.tab = 'ptentes'; syncScreen(); }
      render(); renderChrome();
      break;
    case 'menu': { const p = $('#menu-pop'); p.hidden = !p.hidden; $('#b-menu').setAttribute('aria-expanded', String(!p.hidden)); return; }
    case 'home':
      S.tab = 'summary';
      S.liveOpen = false;
      syncScreen();
      renderLivebar();
      render();
      break;
    case 'open': $('#file').click(); break;
    case 'pickif': { const c = $('#capf'); if (c) S.live.filter = c.value; S.live.iface = v; S.set.iface = v; renderLivebar(); return; }
    case 'retry-srv': initServer().then(() => renderLivebar()); break;
    case 'analyze':
      S.liveOpen = !S.liveOpen;
      if (!S.live.running && !S.A && (S.tab === 'settings' || S.tab === 'ptentes')) S.tab = 'summary';
      if (S.liveOpen) {
        if (!S.srv) initServer().then(() => renderLivebar());
        else loadNet().then(renderLivebar);
      }
      syncScreen();
      renderLivebar();
      if (S.liveOpen) { const c = $('#capf'); if (c) c.focus(); }
      break;
    case 'settings':
      S.tab = 'settings';
      S.liveOpen = false;
      syncScreen();
      renderLivebar();
      render();
      break;
    case 'ptentes': S.mode = 'adv'; try { localStorage.setItem('pl-mode', 'adv'); } catch (x) { /* yok say */ } S.tab = 'ptentes'; S.liveOpen = false; syncScreen(); renderLivebar(); render(); break;
    case 'lang': S.set.lang = v; saveSettings(); applySettings(false); render(); renderLivebar(); if (window.PLI) window.PLI.apply(document.body); break;
    case 'tab': S.tab = v; syncScreen(); render(); break;
    case 'clearq': setQuery(''); break;
    case 'try': setQuery(v); break;
    case 'conv': { const i = v.indexOf('|'); if (i > 0) setQuery(`(ip.addr == ${v.slice(0, i)} && ip.addr == ${v.slice(i + 1)})`); break; }
    case 'expert': setQuery(v); break;
    case 'flowfilt': closeDrawer(); flowDisplayFilter(+v, false); break;
    case 'flowexcl': closeDrawer(); flowDisplayFilter(+v, true); break;
    case 'pkgoto': goToPacketNo(($('#pkgoto') || {}).value); break;
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
    case 'view-capture': { const a = $('#live-after'); if (a) a.hidden = true; S.liveOpen = false; syncScreen(); render(); break; }
  }
  if (el.closest('#menu-pop') && act !== 'menu') closeMenu();
});
document.addEventListener('change', e => {
  if (e.target.id !== 'iface') return;
  const c = $('#capf');
  if (c) S.live.filter = c.value;
  S.live.iface = e.target.value;
  S.set.iface = e.target.value;
  saveSettings();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeDrawer(); const m = $('#modal'); if (m) m.hidden = true; }
  else if (e.key === '/' && !/INPUT|SELECT|TEXTAREA/.test((e.target || {}).tagName || '')) { e.preventDefault(); $('#q').focus(); }
  else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'g' && S.A && S.tab === 'packets') {
    e.preventDefault(); const inp = $('#pkgoto'); if (inp) { inp.focus(); inp.select(); }
  }
});
document.addEventListener('keydown', e => {
  if (e.key !== 'Enter' || (e.target || {}).id !== 'pkgoto') return;
  e.preventDefault(); goToPacketNo(e.target.value);
});
let qt; $('#q').addEventListener('input', e => { clearTimeout(qt); qt = setTimeout(() => setQuery(e.target.value), 160); });
let rz; window.addEventListener('resize', () => { clearTimeout(rz); rz = setTimeout(() => { if (S.A && S.tab === 'summary') render(); }, 200); });
$('#q').addEventListener('keydown', e => { if (e.key === 'Enter') { clearTimeout(qt); setQuery(e.target.value); } });
document.addEventListener('click', e => {
  if (e.target.closest('#menu')) return;
  closeMenu();
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeMenu(); });
$('#file').addEventListener('change', e => { if (e.target.files[0]) loadFile(e.target.files[0]); e.target.value = ''; });
['dragover', 'dragenter'].forEach(t => document.addEventListener(t, e => { e.preventDefault(); document.body.classList.add('pcap-drag'); }));
['dragleave', 'drop'].forEach(t => document.addEventListener(t, e => { e.preventDefault(); document.body.classList.remove('pcap-drag'); }));
document.addEventListener('drop', e => { const f = e.dataTransfer && e.dataTransfer.files[0]; if (f) loadFile(f); });

applySettings(false);
if (!getPL()) toast(T('Analiz modülü yüklenemedi. Sayfayı Cmd+Shift+R ile yenileyin.'));
renderChrome();
syncScreen();
renderLivebar();
initServer().then(() => syncHeaderLiveBtn());
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && S.liveOpen && !S.srv && srvInit === 'fail') initServer().then(() => renderLivebar());
});
const _plViews = (window.PLApp && window.PLApp.views) || {};
const _plExtra = (window.PLApp && window.PLApp.extra) || {};
Object.assign(window.PLApp || (window.PLApp = {}), {
  S, get PL() { return window.PL; }, PLF, getPL, $, esc, fmtB, fmtD, fmtRate, rel, nm, toast, appColor, setQuery, render, renderChrome, computeVisible, openDrawer, closeDrawer, selectPacket, pSev, evtList,
  views: _plViews, extra: _plExtra,
  DEFAULTS, saveSettings, applySettings, reanalyze, ingest, loadBuffer, syncScreen, renderLiveHome, renderLivebar, L, tcol, drawRows, updatePacketList, probHTML, SEC, PERF, catOf, api,
  goPacket(no) { closeDrawer(); goToPacketNo(no); },
  flowDisplayFilter,
  goToPacketNo,
});
if (window.__PL_renderSettings) window.PLApp.views.settings = window.__PL_renderSettings;
if (window.__PL_renderPtentes) window.PLApp.views.ptentes = window.__PL_renderPtentes;
window.__PL = { S, parseQuery };
})();
if (window.PLI) window.PLI.apply(document.body);
