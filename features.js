/* PacketLens - ek özellikler: Ayarlar, Siteler, HTTP dosyaları, dışa aktarma/rapor/anonimleştirme, filtre kütüphanesi, içerik arama, notlar */
(function () {
'use strict';
const X = window.PLApp;
if (!X || !X.S) return;
const { S, PL, esc, fmtB, fmtD, nm, toast, $ } = X;
const PLF = window.PLF;
const T = s => (window.PLI ? window.PLI.t(s) : s);
const short = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
const table = (heads, rows) => `<div class="tablewrap"><table class="t"><thead><tr>${heads.map(h => h[0] === '#' ? `<th class="num">${esc(h.slice(1))}</th>` : `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
function download(name, data, mime) {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mime || 'application/octet-stream' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500);
}
const filtering = () => !!(S.query && S.query.test) || !!S.flowFilter || !!S.pktSet || !!S.timeRange;
function openModal(title, html, cls) {
  const m = $('#modal');
  m.innerHTML = `<div class="modal-bg" data-act="fm-close"></div><div class="modal ${cls || 'auto'}" role="dialog" aria-label="${esc(title)}"><div class="modal-head"><b>${esc(title)}</b><button class="btn sm" data-act="fm-close">${T('Kapat')}</button></div><div class="modal-body">${html}</div></div>`;
  m.hidden = false;
}
const closeModal = () => { const m = $('#modal'); if (m) m.hidden = true; };

/* =============== AYARLAR =============== */
const DET = [
  ['Güvenlik', [['cred', 'Şifresiz kimlik bilgisi'], ['clear', 'Şifresiz protokol kullanımı'], ['scan', 'Port taraması'], ['sweep', 'Ping taraması'], ['arp', 'ARP sahteciliği'], ['dnstunnel', 'DNS tünelleme'], ['dga', 'DGA / NXDOMAIN yağmuru'], ['beacon', 'Beacon (düzenli aralıklı bağlantı)'], ['synflood', 'SYN seli'], ['weaktls', 'Zayıf / eski TLS']]],
  ['Performans', [['retrans', 'Yeniden iletim'], ['zerowin', 'Zero Window'], ['slowrtt', 'Yavaş bağlantı kurulumu'], ['dnsslow', 'Yavaş DNS']]],
  ['Ağ / bağlantı', [['nosyn', 'Bağlantı kurulamadı'], ['rst', 'RST ile kesilen bağlantı'], ['icmp', 'ICMP: hedefe ulaşılamadı'], ['refused', 'Reddedilen bağlantı'], ['dnserr', 'DNS sunucu hatası'], ['dnsno', 'Yanıtsız DNS sorgusu'], ['dnsnx', 'NXDOMAIN']]],
];
const ANALYSIS = new Set(['dnsSlow', 'rttSlow', 'retransMed', 'scanTargets', 'tunnelSubs', 'dgaNames', 'sweepHosts', 'names', 'detoff']);
const sel = (key, opts, val) => `<select data-set="${key}">${opts.map(([v, l]) => `<option value="${v}" ${String(val) === String(v) ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`;
const num = (key, min, max, unit, step) => `<input type="number" data-set="${key}" data-num="1" min="${min}" max="${max}" step="${step || 1}" value="${S.set[key]}"> <span class="muted small">${esc(unit || '')}</span>`;
const chk = (key, val) => `<label class="sw"><input type="checkbox" data-set="${key}" ${val ? 'checked' : ''}><span class="sl"></span></label>`;
const row = (label, hint, ctl) => `<div class="srow"><div><div class="sl-t">${esc(label)}</div>${hint ? `<div class="muted small">${esc(hint)}</div>` : ''}</div><div class="sctl">${ctl}</div></div>`;

function renderSettings(v) {
  const st = S.set, srv = S.srv;
  const ifs = srv && srv.interfaces ? `<select data-set="iface"><option value="">Otomatik</option><option value="any" ${st.iface === 'any' ? 'selected' : ''}>Tüm arayüzler</option>${srv.interfaces.map(i => `<option value="${esc(i.name)}" ${st.iface === i.name ? 'selected' : ''}>${esc(i.name)}</option>`).join('')}</select>` : '<input type="text" data-set="iface" value="' + esc(st.iface) + '" placeholder="eth0">';
  v.innerHTML = `
  <div class="set-head"><h2>Ayarlar</h2>${S.A ? '' : `<button class="btn" data-act="home">${T('Geri')}</button>`}<span class="muted small">Değişiklikler otomatik kaydedilir (bu tarayıcıda).</span></div>
  <div class="grid g2">
    <div class="card"><h3>Genel</h3>
      ${row('Dil', 'Arayüz dili', sel('lang', [['tr', 'Türkçe'], ['en', 'English']], st.lang))}
      ${row('Tema', '', sel('theme', [['auto', 'Sistemle aynı'], ['light', 'Açık'], ['dark', 'Koyu']], st.theme))}
      ${row('Mod', 'Basit: günlük kullanım · Gelişmiş: paket düzeyi ayrıntı', sel('mode', [['simple', 'Basit'], ['adv', 'Gelişmiş']], S.mode))}
      ${row('Paket listesi satır yüksekliği', '', sel('density', [['normal', 'Normal'], ['compact', 'Sıkışık']], st.density))}
      ${row('Zaman sütunu', 'Paket listesindeki zaman gösterimi', sel('timefmt', [['rel', 'Yakalama başından itibaren (sn)'], ['abs', 'Saat (yerel)'], ['delta', 'Önceki paketten fark (sn)']], st.timefmt))}
      ${row('Adları göster', 'IP adreslerini DNS / SNI / Host bilgisinden isme çevir; kapalıyken ham IP gösterilir', chk('names', st.names !== false))}
    </div>
    <div class="card"><h3>Canlı analiz</h3>
      ${row('Varsayılan arayüz', srv ? '' : 'Sunucu bağlı değil: ad elle yazılır', ifs)}
      ${row('Varsayılan yakalama filtresi', 'Örn. host 192.168.1.5 and port 443', `<input type="text" data-set="capfilter" class="wide" value="${esc(st.capfilter)}" placeholder="boş = hepsi" spellcheck="false">`)}
      ${row('Paket başına bayt (snaplen)', 'Başlıklar ve TLS hello için 1600 yeterli; içerik için artırın', num('snap', 64, 65535, 'bayt'))}
      ${row('En fazla paket sayısı', 'Bellek koruması', num('max', 1000, 2000000, 'paket', 1000))}
      ${row('Otomatik durdurma', '0 = elle durdurulana kadar', num('duration', 0, 86400, 'sn'))}
      ${row('Promiscuous mod', 'Arayüze gelen, başka cihazlara ait trafiği de yakala', chk('promisc', st.promisc))}
      ${row('Canlı listede otomatik kaydır', '', chk('follow', st.follow))}
    </div>
  </div>
  <div class="card" style="margin-top:14px"><h3>Tespit eşikleri <small>değişince analiz yeniden yapılır</small></h3>
    <div class="grid g3">
      ${row('Yavaş DNS', 'Bu süreden uzun yanıt sorun sayılır', num('dnsSlow', 10, 10000, 'ms'))}
      ${row('Yavaş bağlantı kurulumu', 'TCP el sıkışma süresi', num('rttSlow', 10, 10000, 'ms'))}
      ${row('Yeniden iletim (orta seviye)', 'Bu sayıdan çoksa “orta” sorun', num('retransMed', 1, 1000, 'paket'))}
      ${row('Port taraması', 'Kısa sürede denenen farklı hedef/port sayısı', num('scanTargets', 3, 1000, 'hedef'))}
      ${row('DNS tünelleme', 'Tek alan adı altındaki farklı alt alan adı sayısı', num('tunnelSubs', 3, 1000, 'adet'))}
      ${row('DGA / NXDOMAIN', 'Bir cihazın aldığı farklı geçersiz alan adı sayısı', num('dgaNames', 3, 1000, 'adet'))}
      ${row('Ping taraması', 'Aynı kaynaktan ping atılan farklı cihaz sayısı', num('sweepHosts', 3, 1000, 'cihaz'))}
    </div>
    <h3 style="margin-top:14px">Tespit türleri <small>kapatılan türler sorun listesinde gösterilmez</small></h3>
    ${DET.map(([cat, items]) => `<div class="dets"><b>${esc(cat)}</b>${items.map(([k, l]) => `<label class="chk"><input type="checkbox" data-set="detoff" data-type="${k}" ${(st.off || []).includes(k) ? '' : 'checked'}> ${esc(l)}</label>`).join('')}</div>`).join('')}
  </div>
  <div class="grid g2" style="margin-top:14px">
    <div class="card"><h3>Kayıtlı filtreler</h3>
      <div class="muted small" style="margin-bottom:8px">Arama kutusunun altında kayıtlı filtre olarak görünür. Sık kullandığınız filtreleri buraya ekleyin.</div>
      ${(st.presets || []).length ? table(['Ad', 'Filtre', ''], st.presets.map((p, i) => `<tr><td>${esc(p.n)}</td><td class="mono">${esc(p.f)}</td><td class="num"><button class="btn sm" data-act="fs-delpreset" data-v="${i}">Sil</button></td></tr>`)) : '<div class="empty-note" style="padding:10px">Henüz kayıtlı filtre yok.</div>'}
      <div class="toolbar" style="margin-top:10px"><input type="text" id="pn" placeholder="Ad (örn. Şüpheli DNS)" style="width:170px"><input type="text" id="pf" class="wide" placeholder="Filtre (örn. dns.time > 0.5)" spellcheck="false"><button class="btn sm primary" data-act="fs-addpreset">Ekle</button></div></div>
    <div class="card"><h3>Veri ve gizlilik</h3>
      <p class="muted small">Dosyalar tarayıcınızda işlenir, hiçbir yere gönderilmez. Ayarlar yalnızca bu tarayıcıda saklanır.</p>
      <div class="toolbar"><button class="btn" data-act="fs-export">Ayarları dışa aktar</button><button class="btn" data-act="fs-import">Ayarları içe aktar</button><button class="btn danger" data-act="fs-reset">Varsayılana sıfırla</button><input type="file" id="sfile" accept=".json" hidden></div>
    </div>
  </div>`;
}
function setCtl(e) {
  const el = e.target.closest('[data-set]'); if (!el) return;
  const k = el.dataset.set, st = S.set; let val;
  if (el.type === 'checkbox') val = el.checked;
  else if (el.dataset.num) { val = Number(el.value); const mn = +el.min, mx = +el.max; if (!isFinite(val)) val = X.DEFAULTS[k]; val = Math.min(mx, Math.max(mn, Math.round(val))); }
  else val = el.value;
  if (k === 'detoff') { const t = el.dataset.type, off = new Set(st.off || []); if (el.checked) off.delete(t); else off.add(t); st.off = [...off]; }
  else if (k === 'mode') { S.mode = val; try { localStorage.setItem('pl-mode', val); } catch (x) { /* yok say */ } if (val === 'simple' && ['packets', 'stats', 'logs'].includes(S.tab)) S.tab = 'flows'; }
  else st[k] = val;
  if (k === 'follow') S.follow = !!val;
  X.saveSettings(); X.applySettings(ANALYSIS.has(k));
  X.render(); X.renderLivebar(); if (window.PLI) window.PLI.apply(document.body);
}
document.addEventListener('change', setCtl);

/* =============== SİTELER =============== */
const SD = { dev: 'all' };
function renderSites(v) {
  try {
    const mt = sessionStorage.getItem('pl-mitm-targets');
    if (mt) {
      sessionStorage.removeItem('pl-mitm-targets');
      const ips = mt.split(/[,;\s]+/).map(s => s.trim()).filter(Boolean);
      if (ips.length === 1) SD.dev = ips[0];
    }
  } catch (x) { /* yok say */ }
  const A = S.A, f = filtering(), nos = f ? new Set(S.vis.map(p => p.no)) : null;
  let rows = PL.sites(A, { flows: f ? S.visFlows : null, nos });
  const devs = new Map(); rows.forEach(r => devs.set(r.client, (devs.get(r.client) || 0) + 1));
  if (SD.dev !== 'all' && !devs.has(SD.dev)) SD.dev = 'all';
  const shown = SD.dev === 'all' ? rows : rows.filter(r => r.client === SD.dev);
  const cleartext = shown.filter(r => r.clear).length;
  v.innerHTML = `<div class="toolbar"><label class="muted">Cihaz: <select id="sdev"><option value="all">Tüm cihazlar (${devs.size})</option>${[...devs.keys()].map(d => `<option value="${esc(d)}" ${SD.dev === d ? 'selected' : ''}>${esc(nm(d))}${nm(d) !== d ? ' (' + esc(d) + ')' : ''} – ${devs.get(d)}</option>`).join('')}</select></label>
    <span class="muted">${shown.length} site / sunucu</span>${cleartext ? `<span class="pill med">${cleartext} tanesine şifresiz (HTTP) bağlanıldı</span>` : ''}</div>
    <div class="muted small" style="margin-bottom:8px">Alan adları DNS sorgularından, TLS SNI alanından ve HTTP Host başlığından çıkarılır. İçerik şifreli olsa bile hangi siteye gidildiği görünür.</div>
    ${shown.length ? table(['Site / alan adı', 'Cihaz', 'Uygulama', '#Bağlantı', '#Veri', '#DNS sorgusu', 'Kaynak', '#İlk', '#Son'], shown.slice(0, 1500).map(r => `<tr data-act="try" data-v="${esc(r.domain)}"><td class="mono">${esc(short(r.domain, 54))} ${r.clear ? '<span class="pill med" title="Şifresiz HTTP ile bağlanıldı">şifresiz</span>' : ''}</td><td>${esc(nm(r.client))}</td><td>${esc(r.apps.join(', '))}</td><td class="num">${r.flows || ''}</td><td class="num">${r.bytes ? fmtB(r.bytes) : ''}</td><td class="num">${r.dnsQ || ''}</td><td class="muted">${esc(r.via.join(' · '))}</td><td class="num">${isFinite(r.first) ? (r.first - A.t0).toFixed(1) + ' sn' : ''}</td><td class="num">${r.last ? (r.last - A.t0).toFixed(1) + ' sn' : ''}</td></tr>`))
      : '<div class="empty-note">Bu görünümde site bilgisi bulunamadı.</div>'}`;
  $('#sdev').onchange = e => { SD.dev = e.target.value; renderSites(v); if (window.PLI) window.PLI.apply(v); };
}

/* =============== CİHAZLAR (YEREL AĞ) =============== */
const DEV = { view: 'cards', scanNote: '', compare: null, filterKind: 'all' };
function netCtx() {
  const live = S.live && (S.live.running || S.live.since > 0), n = live ? (S.net || {}) : {}, self = [];
  if (live && S.srv && S.srv.interfaces) S.srv.interfaces.forEach(i => { if (i.ipv4 && i.kind !== 'loopback') self.push(i.ipv4); });
  return { gateway: n.gateway, dns: n.dns, arp: n.arp, self, registry: S.deviceRegistry || [] };
}
function riskPill(r) {
  if (r >= 60) return '<span class="pill bad">risk ' + r + '</span>';
  if (r >= 25) return '<span class="pill med">risk ' + r + '</span>';
  if (r > 0) return '<span class="pill low">risk ' + r + '</span>';
  return '<span class="pill ok">risk 0</span>';
}
function portsLine(d) {
  const seen = new Set();
  const parts = [];
  for (const x of (d.portsOpen || []).concat(d.scanPorts || []).concat((d.portsOut || []).map(p => ({ port: p.port, svc: p.svc })))) {
    if (seen.has(x.port)) continue;
    seen.add(x.port);
    parts.push(x.port + (x.svc ? ' ' + x.svc : ''));
    if (parts.length >= 8) break;
  }
  return parts.length ? parts.join(', ') : '—';
}
function deviceCard(d, A) {
  const dn = (d.name && d.name !== d.ip) ? d.name : '';
  const title = dn || d.ip;
  return `<div class="dev-card" data-ip="${esc(d.ip)}">
    <div class="dev-head"><b>${esc(short(title, 28))}</b>${riskPill(d.risk || 0)}</div>
    <div class="mono muted small">${esc(d.ip)}${d.mac ? ' · ' + esc(d.mac) : ''}</div>
    <div class="dev-meta">${esc(d.vendor || '—')}${d.mobilePlatform ? ' · <span class="pill ok">' + esc(d.mobileKind || 'mobil') + ' · ' + esc(d.mobilePlatform) + '</span>' : ''}${d.os ? ' · ' + esc(d.os) : ''}${d.dhcpClass ? '<br><span class="muted">DHCP: ' + esc(short(d.dhcpClass, 36)) + '</span>' : ''}${d.mobileHint ? '<br><span class="muted">' + esc(d.mobileHint) + (d.mobileConf ? ' (' + esc(d.mobileConf) + ')' : '') + '</span>' : ''}</div>
    <div class="dev-roles">${d.roles.map(r => `<span class="pill ${r === 'Bu bilgisayar' ? 'ok' : r === 'Mobil cihaz' ? 'ok' : 'low'}">${esc(r)}</span>`).join(' ')}${d.silent ? ' <span class="pill low">sessiz</span>' : ''}</div>
    <div class="muted small">Portlar: <span class="mono">${esc(portsLine(d))}</span></div>
    ${d.riskTags && d.riskTags.length ? `<div class="muted small">${d.riskTags.map(t => '<span class="pill med">' + esc(t) + '</span>').join(' ')}</div>` : ''}
    <div class="toolbar dev-actions">
      <button class="btn sm" data-act="dev-watch" data-v="${esc(d.ip)}">Trafiği izle</button>
      <button class="btn sm" data-act="dev-pt" data-v="${esc(d.ip)}">ptentes</button>
      ${(d.problemIds && d.problemIds.length) ? `<button class="btn sm" data-act="dev-problems" data-v="${esc(d.ip)}">Sorunlar (${d.problemIds.length})</button>` : ''}
    </div>
    <div class="muted small">${d.flows ? d.flows + ' bağlantı · ' : ''}${d.last && A ? fmtD(d.last - A.t0) : ''}</div>
  </div>`;
}
async function refreshDeviceRegistry() {
  if (!X.api || location.protocol === 'file:') return;
  try {
    const { ok, j } = await X.api('/api/devices/registry');
    if (ok && j && j.devices) S.deviceRegistry = j.devices;
  } catch (e) { /* yok say */ }
}
function renderDevices(v) {
  const A = S.A, D = PL.devices(A, netCtx());
  const iso = (A && A.apIsolation) || (A && PL.detectApIsolation(A));
  let l = D.devices;
  if (DEV.filterKind === 'mobile') l = l.filter(d => d.mobile);
  else if (DEV.filterKind === 'other') l = l.filter(d => !d.mobile);
  const canScan = !!(S.srv && S.srv.root);
  const iface = S.set.iface || (S.srv && S.srv.default_iface) || 'any';
  v.innerHTML = `<div class="grid g3" style="margin-bottom:12px">
      <div class="kpi"><div class="v">${l.length}</div><div class="l">${T('yerel cihaz')}${D.mobileCount != null ? ' · ' + D.mobileCount + ' mobil' : ''}${D.subnet ? ' · ' + esc(D.subnet) : ''}</div></div>
      <div class="kpi"><div class="v mono" style="font-size:18px">${esc(D.gateway || '—')}</div><div class="l">${T('Ağ geçidi (router)')}${D.gatewayMac ? ' · ' + esc(D.gatewayMac) : ''}</div></div>
      <div class="kpi"><div class="v mono" style="font-size:18px">${esc(D.dns.slice(0, 2).join(', ') || '—')}</div><div class="l">${T('DNS sunucusu')}</div></div></div>
    <div class="toolbar" style="margin-bottom:10px">
      <button class="chip ${DEV.view === 'cards' ? 'on' : ''}" data-act="dev-view" data-v="cards">Kartlar</button>
      <button class="chip ${DEV.view === 'table' ? 'on' : ''}" data-act="dev-view" data-v="table">Tablo</button>
      <button class="chip ${DEV.filterKind === 'all' ? 'on' : ''}" data-act="dev-kind" data-v="all">Tümü</button>
      <button class="chip ${DEV.filterKind === 'mobile' ? 'on' : ''}" data-act="dev-kind" data-v="mobile">Yalnızca mobil</button>
      <button class="chip ${DEV.filterKind === 'other' ? 'on' : ''}" data-act="dev-kind" data-v="other">Mobil değil</button>
      <button class="btn sm" data-act="dev-scan" data-v="arp" ${canScan ? '' : 'disabled'}>ARP tara</button>
      <button class="btn sm" data-act="dev-scan" data-v="ping" ${canScan ? '' : 'disabled'}>Ping tara</button>
      <button class="btn sm" data-act="dev-scan" data-v="ports" ${canScan ? '' : 'disabled'}>Port tara</button>
      <button class="btn sm ghost" data-act="dev-refresh">Kayıt yenile</button>
      <button class="btn sm ghost" data-act="dev-compare">Taramaları karşılaştır</button>
      <span class="muted small">|</span>
      <button class="btn sm ghost" data-act="pb-newdev">Playbook: yeni cihaz</button>
      <button class="btn sm ghost" data-act="pb-suspicious">Playbook: şüpheli trafik</button>
      <button class="btn sm ghost" data-act="pb-mobile">Playbook: mobil cihazlar</button>
      <button class="btn sm ghost" data-act="dev-mobile-csv">Mobil rapor .csv</button>
      ${DEV.scanNote ? `<span class="muted small">${esc(DEV.scanNote)}</span>` : ''}
    </div>
    ${iso && iso.likely ? `<div class="card" style="margin-bottom:10px;border-left:4px solid #b54708"><b>Olası AP izolasyonu</b> (${esc(iso.confidence || '—')} güven)
      <p class="muted small" style="margin:6px 0 0">${esc(iso.hint || '')} <a href="#" data-act="pb-apiso">Sorunlar’da aç</a></p></div>` : ''}
    ${DEV.compare && DEV.compare.ok ? `<div class="card" style="margin-bottom:10px"><h3>Tarama farkı</h3>
      <div class="muted small">Yeni: ${esc((DEV.compare.new || []).join(', ') || '—')} · Kayboldu: ${esc((DEV.compare.gone || []).join(', ') || '—')}</div>
      ${(DEV.compare.changed || []).length ? `<ul class="muted small">${DEV.compare.changed.map(c => `<li>${esc(c.ip)} port +${esc((c.ports_added||[]).join(','))} −${esc((c.ports_removed||[]).join(','))}</li>`).join('')}</ul>` : ''}</div>` : ''}
    <div class="muted small" style="margin-bottom:8px">Mobil cihazlar genelde mDNS adı (<span class="mono">iPhone</span>, <span class="mono">Android</span>), DHCP sınıfı, Apple/Samsung/Google MAC üreticisi, QUIC trafiği ve gizli (rastgele) MAC ile tanınır. Çoğu uygulama trafiği HTTPS/QUIC olduğu için içerik okunmaz; <b>Siteler</b> sekmesinde hangi alan adlarına gidildiği görülür.</div>
    ${l.length ? (DEV.view === 'table' ? table(['Cihaz', 'MAC', 'Üretici', 'Risk', 'Portlar', 'Rol', 'OS', 'İşlem'], l.map(d => {
      const dn = d.name && d.name !== d.ip ? d.name : '';
      return `<tr><td><span class="mono">${esc(d.ip)}</span>${dn ? '<br><span class="muted small">' + esc(short(dn, 40)) + '</span>' : ''}</td><td class="mono">${esc(d.mac || '—')}</td><td>${esc(d.vendor || '—')}</td><td>${riskPill(d.risk || 0)}</td><td class="mono small">${esc(portsLine(d))}</td>
        <td>${d.roles.map(r => `<span class="pill low">${esc(r)}</span>`).join(' ') || '—'}</td><td>${esc(d.os || '—')}</td>
        <td><button class="btn sm" data-act="dev-watch" data-v="${esc(d.ip)}">İzle</button> <button class="btn sm" data-act="dev-pt" data-v="${esc(d.ip)}">ptentes</button></td></tr>`;
    })) : `<div class="dev-grid">${l.map(d => deviceCard(d, A)).join('')}</div>`)
      : '<div class="empty-note">Bu yakalamada yerel cihaz bulunamadı. Canlı modda ARP taraması deneyin.</div>'}`;
  if (canScan && !S.deviceRegistry.length) refreshDeviceRegistry().then(() => { if (S.tab === 'devices') renderDevices(v); });
  if (PL.loadOui) PL.loadOui();
  if (window.PLI) window.PLI.apply(v);
}

/* =============== HTTP DOSYALARI =============== */
let objCache = { A: null, list: [] };
function objects() { if (objCache.A !== S.A) { objCache = { A: S.A, list: PL.httpObjects(S.A).map((o, i) => (o.idx = i, o)) }; } return objCache.list; }
function filesHTML() {
  const l = objects().filter(o => !filtering() || S.visFlows.has(o.flow));
  if (!l.length) return '<div class="empty-note">Şifresiz HTTP üzerinden aktarılan dosya bulunamadı. (HTTPS içeriği şifreli olduğundan çıkarılamaz.)</div>';
  const A = S.A;
  return `<div class="muted small" style="margin-bottom:8px">Şifresiz HTTP yanıtlarından yeniden birleştirilen dosyalar. İndirilen dosyalar çalıştırılmaz; bilinmeyen dosyaları açmadan önce kontrol edin.</div>` +
    table(['Zaman', 'Dosya', 'Sunucu', 'Tür (başlık)', 'Gerçek tür', '#Boyut', 'Durum', ''], l.map(o => `<tr><td class="mono">${(o.t - A.t0).toFixed(3)}</td><td class="mono"><a href="#" data-act="flow" data-v="${o.flow}">${esc(short(o.name, 36))}</a></td><td>${esc(o.host)}</td><td>${esc(o.ctype || '–')}${o.enc ? ' <span class="muted">(' + esc(o.enc) + ')</span>' : ''}</td>
      <td>${o.exec ? `<span class="pill high" title="Çalıştırılabilir dosya türü">${esc(o.kind)} ⚠</span>` : esc(o.kind)}</td><td class="num">${fmtB(o.size)}</td><td>${o.complete ? o.status : '<span class="pill low" title="Yakalama eksik">eksik</span>'}</td><td class="num"><button class="btn sm" data-act="ff-dl" data-v="${o.idx}">İndir</button></td></tr>`));
}
const EXT = { PNG: '.png', JPEG: '.jpg', GIF: '.gif', PDF: '.pdf', ZIP: '.zip', GZIP: '.gz', HTML: '.html', JSON: '.json', 'PE/EXE': '.exe.bin', ELF: '.elf.bin', 'Mach-O': '.macho.bin', Script: '.sh.txt' };
async function downloadObject(i) {
  const o = objects()[i]; if (!o) return;
  let bytes = o.bytes, name = o.name;
  if (/gzip/i.test(o.enc) && typeof DecompressionStream !== 'undefined') {
    try { bytes = new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer()); } catch (e) { toast('Sıkıştırma açılamadı, ham veri indiriliyor'); }
  }
  if (!/\.[A-Za-z0-9]{1,8}$/.test(name) && EXT[o.kind]) name += EXT[o.kind]; else if (o.exec && !/\.bin$|\.txt$/.test(name)) name += '.bin';
  download(name, new Blob([bytes], { type: 'application/octet-stream' }));
}

/* =============== NOTLAR =============== */
function noteBox(id) { return `<div class="notebox"><label>📝 Not<textarea data-note="${id}" rows="2" placeholder="Bu bağlantı hakkında not… (rapora ve JSON çıktısına eklenir)">${esc(S.notes[id] || '')}</textarea></label></div>`; }
document.addEventListener('input', e => {
  const t = e.target; if (!t.matches || !t.matches('[data-note]')) return;
  const id = +t.dataset.note; if (t.value.trim()) S.notes[id] = t.value; else delete S.notes[id];
});

/* =============== İÇERİK ARAMA (paket baytlarında) =============== */
const FU = { q: '', mode: 'text', cs: false };
function findBar() {
  const n = S.find ? S.find.nos.length : 0;
  return `<div class="pk-find"><input id="fq" type="search" value="${esc(FU.q)}" placeholder="Paket içeriğinde ara (metin, hex veya regex)…" spellcheck="false" autocomplete="off"><select id="fmode"><option value="text" ${FU.mode === 'text' ? 'selected' : ''}>Metin</option><option value="hex" ${FU.mode === 'hex' ? 'selected' : ''}>Hex</option><option value="re" ${FU.mode === 're' ? 'selected' : ''}>Regex</option></select>
    <label class="chk" title="Büyük/küçük harf duyarlı"><input type="checkbox" id="fcs" ${FU.cs ? 'checked' : ''}> Aa</label><button class="btn sm" data-act="f-find">Ara</button><button class="btn sm" data-act="f-prev">Önceki</button><button class="btn sm" data-act="f-next">Sonraki</button><span class="muted small" id="fres">${S.find ? (n ? `${S.find.idx + 1} / ${n} eşleşme` : 'eşleşme yok') : ''}</span></div>`;
}
const latin1 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 8192) s += String.fromCharCode.apply(null, u8.subarray(i, i + 8192)); return s; };
function doFind() {
  const q = ($('#fq') || {}).value || ''; FU.q = q; FU.mode = ($('#fmode') || {}).value || 'text'; FU.cs = !!($('#fcs') || {}).checked;
  if (!q) { S.find = null; X.drawRows(); const r = $('#fres'); if (r) r.textContent = ''; return; }
  let test;
  try {
    if (FU.mode === 'hex') {
      const hex = q.replace(/[^0-9a-f]/gi, ''); if (hex.length < 2 || hex.length % 2) throw new Error('Hex değeri çift sayıda basamak olmalı (örn. 47 45 54)');
      const pat = []; for (let i = 0; i < hex.length; i += 2) pat.push(parseInt(hex.slice(i, i + 2), 16));
      test = p => { const d = p.raw, n = pat.length; outer: for (let i = 0; i + n <= d.length; i++) { for (let j = 0; j < n; j++) if (d[i + j] !== pat[j]) continue outer; return true; } return false; };
    } else if (FU.mode === 're') { const re = new RegExp(q, FU.cs ? '' : 'i'); test = p => re.test(latin1(p.raw)); }
    else { const w = FU.cs ? q : q.toLowerCase(); test = p => { const s = latin1(p.raw); return (FU.cs ? s : s.toLowerCase()).includes(w); }; }
  } catch (e) { toast(e.message || 'Geçersiz arama ifadesi'); return; }
  const nos = []; for (const p of S.vis) if (test(p)) nos.push(p.no);
  S.find = { nos, set: new Set(nos), idx: nos.length ? 0 : -1, q };
  const r = $('#fres'); if (r) r.textContent = nos.length ? `1 / ${nos.length} eşleşme` : 'eşleşme yok';
  if (nos.length) X.selectPacket(nos[0], true); else X.drawRows();
}
function stepFind(d) {
  if (!S.find || !S.find.nos.length) return doFind();
  const n = S.find.nos.length; S.find.idx = (S.find.idx + d + n) % n;
  const r = $('#fres'); if (r) r.textContent = `${S.find.idx + 1} / ${n} eşleşme`;
  X.selectPacket(S.find.nos[S.find.idx], true);
}
document.addEventListener('keydown', e => { if (e.target && e.target.id === 'fq' && e.key === 'Enter') { e.preventDefault(); if (S.find && S.find.q === e.target.value) stepFind(e.shiftKey ? -1 : 1); else doFind(); } });
document.addEventListener('change', e => { if (e.target && (e.target.id === 'fmode' || e.target.id === 'fcs')) { FU.mode = ($('#fmode') || {}).value; FU.cs = !!($('#fcs') || {}).checked; } });

/* =============== FİLTRE KÜTÜPHANESİ =============== */
function openFilterLib() {
  const cur = S.qtext || '';
  const pre = (S.set.presets || []);
  openModal('Filtre kütüphanesi', `
    <p class="muted small">Wireshark kullanıcılarının en çok aradığı filtreler. Tıklayınca uygulanır; IP adreslerini ve alan adlarını kendi verinize göre değiştirebilirsiniz. Doğal dille de arayabilirsiniz (örn. “yavaş dns”).</p>
    <div class="toolbar"><input type="text" id="fl-save-n" placeholder="Ad" style="width:160px"><input type="text" id="fl-save-f" class="wide" value="${esc(cur)}" placeholder="Kaydedilecek filtre" spellcheck="false"><button class="btn sm primary" data-act="fl-save">Filtreyi kaydet</button></div>
    ${pre.length ? `<h3>Kayıtlı filtrelerim</h3>${pre.map((p, i) => `<div class="libitem"><div><b>${esc(p.n)}</b><div class="mono small">${esc(p.f)}</div></div><div><button class="btn sm" data-act="fl-apply" data-v="${esc(p.f)}">Uygula</button> <button class="btn sm ghost" data-act="fs-delpreset" data-v="${i}" data-reopen="1">Sil</button></div></div>`).join('')}` : ''}
    ${PL.FILTER_LIB.map(g => `<h3>${esc(g.cat)}</h3>${g.items.map(([f, d]) => `<div class="libitem"><div><div>${esc(d)}</div><div class="mono small">${esc(f)}</div></div><div><button class="btn sm" data-act="fl-apply" data-v="${esc(f)}">Uygula</button></div></div>`).join('')}`).join('')}`, 'wide');
}

/* =============== DIŞA AKTARMA =============== */
const catName = t => (X.SEC.has(t) ? 'security' : X.PERF.has(t) ? 'performance' : 'network');
function visFlowsList() { return S.A.flows.filter(f => !filtering() || S.visFlows.has(f.id)); }
function csvData(kind) {
  const A = S.A, t0 = A.t0;
  if (kind === 'packets') return ['packets', ['no', 'time_epoch', 'time_rel_s', 'src', 'dst', 'src_port', 'dst_port', 'proto', 'app', 'length', 'flow', 'problem', 'info'],
    S.vis.map(p => [p.no, p.ts.toFixed(6), (p.ts - t0).toFixed(6), p.src, p.dst, p.sport, p.dport, p.proto, p.app, p.len, p.flow, p.anoms.join('|'), p.info])];
  if (kind === 'flows') return ['flows', ['id', 'app', 'client', 'server', 'proto', 'client_port', 'server_port', 'packets', 'bytes', 'start_s', 'duration_s', 'handshake_ms', 'retransmissions', 'status', 'problems', 'note'],
    visFlowsList().map(f => [f.id, f.app, f.client, f.server, f.proto, f.aPort, f.bPort, f.pkts, f.bytes, (f.start - t0).toFixed(3), (f.end - f.start).toFixed(3), f.rtt != null ? Math.round(f.rtt * 1000) : '', f.retrans || 0, f.status, f.probs.length, S.notes[f.id] || ''])];
  if (kind === 'problems') return ['problems', ['id', 'severity', 'category', 'type', 'title', 'description', 'advice', 'time_s', 'packets', 'flow'],
    A.problems.map(pr => [pr.id, pr.sev, catName(pr.type), pr.type, T(pr.title), T(pr.plain), T(pr.advice), (pr.ts - t0).toFixed(3), pr.pkts.length, pr.flow || ''])];
  if (kind === 'sites') return ['sites', ['domain', 'device', 'apps', 'flows', 'bytes', 'dns_queries', 'source', 'first_s', 'last_s', 'cleartext'],
    PL.sites(A, { flows: filtering() ? S.visFlows : null }).map(r => [r.domain, r.client, r.apps.join('|'), r.flows, r.bytes, r.dnsQ, r.via.join('|'), isFinite(r.first) ? (r.first - t0).toFixed(3) : '', r.last ? (r.last - t0).toFixed(3) : '', r.clear ? 'yes' : 'no'])];
  if (kind === 'dns') return ['dns', ['time_s', 'client', 'query', 'type', 'rcode', 'answers', 'latency_ms'], PL.dnsLog(A).map(e => [(e.t - t0).toFixed(3), e.client, e.name, PL.QTYPE[e.qtype] || e.qtype, e.rcode == null ? '' : e.rcode, e.answers.join('|'), e.latency != null ? Math.round(e.latency * 1000) : ''])];
  if (kind === 'http') return ['http', ['time_s', 'client', 'host', 'method', 'path', 'status', 'content_type', 'size'], PL.httpLog(A).map(e => [(e.t - t0).toFixed(3), e.client, e.host, e.method, e.path, e.status == null ? '' : e.status, e.ctype || '', e.size == null ? '' : e.size])];
  if (kind === 'tls') return ['tls', ['time_s', 'client', 'sni', 'quic', 'ech', 'ja3', 'ja4', 'version', 'cipher', 'alpn', 'cert_subject', 'cert_issuer', 'cert_sans'],
    PL.tlsLog(A).map(e => [(e.t - t0).toFixed(3), e.client, e.sni || '', e.quic ? 'yes' : 'no', e.ech ? 'yes' : 'no', e.ja3Hash || '', e.ja4 || '',
      e.version != null ? (PL.TLSV[e.version] || '') : '', e.cipher != null ? PL.cipherName(e.cipher) : '', e.alpn.join('|'),
      (e.cert && e.cert.subject) || '', (e.cert && e.cert.issuer) || '', (e.cert && e.cert.sans) ? e.cert.sans.join('|') : ''])];
  if (kind === 'devices') {
    const D = PL.devices(A, netCtx());
    return ['devices', ['ip', 'name', 'mac', 'vendor', 'mobile', 'mobile_kind', 'mobile_platform', 'mobile_confidence', 'os', 'roles', 'bytes_tx', 'bytes_rx', 'flows', 'risk', 'dhcp_class', 'user_agent'],
      D.devices.map(d => {
        const h = A.hosts.get(d.ip);
        return [d.ip, d.name, d.mac, d.vendor, d.mobile ? 'yes' : 'no', d.mobileKind, d.mobilePlatform, d.mobileConf, d.os, d.roles.join('|'), d.bytesTx, d.bytesRx, d.flows, d.risk, d.dhcpClass, (h && h.userAgent) || ''];
      })];
  }
  if (kind === 'mobile-report') {
    const R = PL.mobileDeviceReport(A, netCtx());
    return ['mobile-report', ['ip', 'name', 'mac', 'vendor', 'platform', 'kind', 'confidence', 'bytes_total', 'flows', 'user_agent', 'top_sites', 'site_count'],
      R.rows.map(r => {
        const d = r.device;
        return [d.ip, d.name, d.mac, d.vendor, d.mobilePlatform, d.mobileKind, d.mobileConf, d.bytesTx + d.bytesRx, d.flows, r.userAgent, r.siteSummary, r.topSites.length];
      })];
  }
  return null;
}
function exportMobileReport() { exportCSV('mobile-report'); }
function exportCSV(kind) { const d = csvData(kind); if (!d) return; download(`packetlens-${d[0]}-${stamp()}.csv`, PL.toCSV(d[1], d[2]), 'text/csv;charset=utf-8'); toast(`${d[2].length} satır dışa aktarıldı`); }
function exportJSON() {
  const A = S.A, t0 = A.t0, st = A.stats;
  const o = { tool: 'PacketLens', generated: new Date().toISOString(), source: S.live.name || 'canlı yakalama',
    summary: { packets: st.packets, bytes: st.bytes, duration_s: +st.duration.toFixed(3), flows: st.flows, hosts: st.hosts, problems: st.problems },
    problems: A.problems.map(pr => ({ id: pr.id, severity: pr.sev, category: catName(pr.type), type: pr.type, title: T(pr.title), description: T(pr.plain), advice: T(pr.advice), time_s: +(pr.ts - t0).toFixed(3), packets: pr.pkts.length, flow: pr.flow || null })),
    flows: visFlowsList().map(f => ({ id: f.id, app: f.app, client: f.client, server: f.server, proto: f.proto, client_port: f.aPort, server_port: f.bPort, packets: f.pkts, bytes: f.bytes, start_s: +(f.start - t0).toFixed(3), duration_s: +(f.end - f.start).toFixed(3), status: f.status, note: S.notes[f.id] || undefined })),
    sites: PL.sites(A, {}).map(r => ({ domain: r.domain, device: r.client, flows: r.flows, bytes: r.bytes, dns_queries: r.dnsQ, cleartext: r.clear })),
    notes: S.notes };
  download(`packetlens-analysis-${stamp()}.json`, JSON.stringify(o, null, 2), 'application/json');
}
function recordsOfVisible() { return S.vis.map(p => S.raw[p.no - 1]).filter(Boolean); }
function exportPcap(anon) {
  const recs = recordsOfVisible(); if (!recs.length) return toast('Dışa aktarılacak paket yok');
  if (!anon) { download(`packetlens-${stamp()}.pcap`, PL.pcapBytes(recs), 'application/vnd.tcpdump.pcap'); return toast(`${recs.length} paket kaydedildi`); }
  const opt = { addr: !!($('#an-addr') || {}).checked, payload: !!($('#an-pay') || {}).checked };
  if (!opt.addr && !opt.payload) return toast('En az bir anonimleştirme seçeneği işaretleyin');
  const r = PL.anonymize(recs, opt);
  download(`packetlens-anonymized-${stamp()}.pcap`, PL.pcapBytes(r.records), 'application/vnd.tcpdump.pcap');
  toast(`${recs.length} paket anonimleştirildi (${r.stats.macs} MAC, ${r.stats.ips + r.stats.ip6} IP maskelendi)`);
}
function reportHTML() {
  const A = S.A, st = A.stats, t0 = A.t0, e = esc;
  const hosts = [...A.hosts.values()].map(h => ({ ip: h.ip, b: h.bytesTx + h.bytesRx })).sort((a, b) => b.b - a.b).slice(0, 10);
  const sec = A.problems.filter(p => X.SEC.has(p.type)), oth = A.problems.filter(p => !X.SEC.has(p.type));
  const probs = l => l.length ? l.map(pr => `<div class="pr ${e(pr.sev)}"><b>[${e({ high: 'Ciddi', med: 'Orta', low: 'Düşük' }[pr.sev])}] ${e(pr.title)}</b><p>${e(pr.plain)}</p><p class="ad">${e(pr.advice)}</p><small>${(pr.ts - t0).toFixed(2)}. saniye · ${pr.pkts.length} paket${pr.flow ? ' · bağlantı #' + pr.flow : ''}${S.notes[pr.flow] ? ' · Not: ' + e(S.notes[pr.flow]) : ''}</small></div>`).join('') : '<p class="ok">✓ Sorun bulunamadı.</p>';
  const sites = PL.sites(A, {}).slice(0, 15);
  const notes = Object.keys(S.notes);
  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>PacketLens raporu</title><style>
body{font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1b2230;max-width:900px;margin:30px auto;padding:0 18px}h1{margin:0 0 4px}h2{margin:28px 0 8px;border-bottom:2px solid #e1e4ea;padding-bottom:4px}
.m{color:#667085}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #e1e4ea;padding:5px 8px;text-align:left;font-size:13px}td.n,th.n{text-align:right}
.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}.k div{border:1px solid #e1e4ea;border-radius:8px;padding:8px 12px}.k b{display:block;font-size:20px}
.pr{border-left:4px solid #98a2b3;background:#f6f7f9;padding:6px 12px;margin:8px 0;border-radius:4px}.pr.high{border-color:#d92d20}.pr.med{border-color:#b54708}.pr p{margin:4px 0}.pr .ad{color:#475467}.ok{color:#067647}
code{font-family:ui-monospace,Menlo,monospace}footer{margin-top:30px;color:#667085;font-size:12px}@media print{body{margin:0}}</style></head><body>
<h1>PacketLens raporu</h1><div class="m">${e(new Date().toLocaleString(X.L()))} · kaynak: ${e(S.live.name || 'canlı yakalama')}</div>
<h2>Özet</h2><div class="k"><div><b>${st.packets.toLocaleString(X.L())}</b>paket</div><div><b>${fmtB(st.bytes)}</b>toplam veri</div><div><b>${fmtD(st.duration)}</b>süre</div><div><b>${st.flows}</b>bağlantı</div><div><b>${st.hosts}</b>cihaz / adres</div><div><b>${st.problems}</b>sorun / uyarı</div></div>
<h2>Güvenlik bulguları (${sec.length})</h2>${probs(sec)}<h2>Performans ve ağ sorunları (${oth.length})</h2>${probs(oth)}
<h2>Uygulama başına trafik</h2><table><tr><th>Uygulama</th><th class="n">Bağlantı</th><th class="n">Paket</th><th class="n">Veri</th></tr>${A.apps.slice(0, 10).map(a => `<tr><td>${e(a.app)}</td><td class="n">${a.flows}</td><td class="n">${a.pkts}</td><td class="n">${fmtB(a.bytes)}</td></tr>`).join('')}</table>
<h2>En çok konuşan cihazlar</h2><table><tr><th>Cihaz</th><th>Adres</th><th class="n">Veri</th></tr>${hosts.map(h => `<tr><td>${e(nm(h.ip))}</td><td><code>${e(h.ip)}</code></td><td class="n">${fmtB(h.b)}</td></tr>`).join('')}</table>
${sites.length ? `<h2>Erişilen siteler</h2><table><tr><th>Site</th><th>Cihaz</th><th class="n">Bağlantı</th><th class="n">Veri</th></tr>${sites.map(r => `<tr><td><code>${e(r.domain)}</code>${r.clear ? ' (şifresiz)' : ''}</td><td>${e(nm(r.client))}</td><td class="n">${r.flows}</td><td class="n">${fmtB(r.bytes)}</td></tr>`).join('')}</table>` : ''}
${(A.creds || []).length ? `<h2>Şifresiz kimlik bilgileri (parolalar maskeli)</h2><table><tr><th>Protokol</th><th>Kullanıcı</th><th>Parola</th></tr>${A.creds.map(c => `<tr><td>${e(c.proto)}</td><td>${e(c.user)}</td><td><code>${e(c.pass)}</code></td></tr>`).join('')}</table>` : ''}
${notes.length ? `<h2>Notlar</h2>${notes.map(id => `<p><b>Bağlantı #${e(id)}</b> (${e(nm(A.flows[id - 1].client))} → ${e(nm(A.flows[id - 1].server))}): ${e(S.notes[id])}</p>`).join('')}` : ''}
<footer>PacketLens ile oluşturuldu. Otomatik analiz bir ipucudur; sonuçları kendiniz doğrulayın.</footer></body></html>`;
}
function exportReport() {
  const html = window.PLI ? window.PLI.translateHTML(reportHTML()) : reportHTML();
  download(`packetlens-report-${stamp()}.html`, html, 'text/html;charset=utf-8');
}
function openExport() {
  if (!S.A || !S.pk.length) return toast('Önce bir yakalama açın');
  const n = S.vis.length;
  openModal('Dışa aktar', `
    <div class="xrow"><div><b>HTML raporu</b><div class="muted small">Sorunlar, öneriler, güvenlik bulguları, siteler ve notlar. Yazdırılabilir, tek dosya.</div></div><button class="btn primary" data-act="fe-report">Raporu indir</button></div>
    <div class="xrow"><div><b>Yakalama (.pcap)</b><div class="muted small">${filtering() ? `Filtreye uyan ${n.toLocaleString(X.L())} paket kaydedilir.` : `Tüm ${n.toLocaleString(X.L())} paket kaydedilir.`} Wireshark ile açılır.</div></div><button class="btn" data-act="fe-pcap">.pcap kaydet</button></div>
    <div class="xrow col"><div><b>Anonimleştirilmiş yakalama</b><div class="muted small">Dosyayı paylaşmadan önce kimliği gizler. Aynı adres hep aynı takma adrese dönüşür, analiz bozulmaz. Sağlama toplamları yeniden hesaplanır.</div></div>
      <label class="chk"><input type="checkbox" id="an-addr" checked> IP ve MAC adreslerini maskele</label>
      <label class="chk"><input type="checkbox" id="an-pay" checked> Uygulama verisini (payload) sil: HTTP gövdesi, DNS adları, parolalar gider</label>
      <div class="muted small">Not: yalnızca adres maskelenirse DNS yanıtlarındaki IP’ler ve içerik olduğu gibi kalır. Gerçekten paylaşmak için ikisini de seçin.</div>
      <div><button class="btn" data-act="fe-anon">Anonim .pcap kaydet</button></div></div>
    <div class="xrow col"><div><b>Tablo (CSV) ve JSON</b><div class="muted small">Excel / betikler için. Parolalar dışa aktarılmaz.</div></div>
      <div class="toolbar">${[['packets', 'Paketler'], ['flows', 'Bağlantılar'], ['problems', 'Sorunlar'], ['devices', 'Cihazlar'], ['mobile-report', 'Mobil rapor'], ['sites', 'Siteler'], ['dns', 'DNS'], ['http', 'HTTP'], ['tls', 'TLS']].map(([k, l]) => `<button class="btn sm" data-act="fe-csv" data-v="${k}">${l} .csv</button>`).join('')}<button class="btn sm" data-act="fe-json">Tüm analiz .json</button></div></div>`);
}

/* =============== TIKLAMA OLAYLARI =============== */
document.addEventListener('click', e => {
  const el = e.target.closest('[data-act]'); if (!el) return;
  const act = el.dataset.act, v = el.dataset.v;
  if (el.tagName === 'A') e.preventDefault();
  switch (act) {
    case 'fm-close': closeModal(); break;
    case 'fl-lib': openFilterLib(); break;
    case 'fl-apply': closeModal(); X.setQuery(v); break;
    case 'fl-save': {
      const n = ($('#fl-save-n').value || '').trim(), f = ($('#fl-save-f').value || '').trim();
      if (!n || !f) return toast('Ad ve filtre gerekli');
      S.set.presets = (S.set.presets || []).concat([{ n: n.slice(0, 40), f: f.slice(0, 300) }]); X.saveSettings(); X.renderChrome(); openFilterLib(); toast('Filtre kaydedildi'); break;
    }
    case 'fl-export': case 'fl-exp': openExport(); break;
    case 'fe-report': exportReport(); break;
    case 'fe-pcap': exportPcap(false); break;
    case 'fe-anon': exportPcap(true); break;
    case 'fe-csv': exportCSV(v); break;
    case 'fe-json': exportJSON(); break;
    case 'ff-dl': downloadObject(+v); break;
    case 'f-find': doFind(); break;
    case 'f-next': stepFind(1); break;
    case 'f-prev': stepFind(-1); break;
    case 'fs-addpreset': {
      const n = ($('#pn').value || '').trim(), f = ($('#pf').value || '').trim();
      if (!n || !f) return toast('Ad ve filtre gerekli');
      if (PLF && PLF.looksLikeFilter(f)) { const c = PLF.compile(f); if (!c.ok) return toast(c.error); }
      S.set.presets = (S.set.presets || []).concat([{ n: n.slice(0, 40), f: f.slice(0, 300) }]); X.saveSettings(); X.render(); X.renderChrome(); if (window.PLI) window.PLI.apply(document.body); break;
    }
    case 'fs-delpreset': S.set.presets.splice(+v, 1); X.saveSettings(); X.renderChrome(); if (el.dataset.reopen) openFilterLib(); else { X.render(); if (window.PLI) window.PLI.apply(document.body); } break;
    case 'fs-export': download('packetlens-settings.json', JSON.stringify(S.set, null, 2), 'application/json'); break;
    case 'fs-import': $('#sfile').click(); break;
    case 'fs-reset': { const lang = S.set.lang; Object.keys(S.set).forEach(k => delete S.set[k]); Object.assign(S.set, X.DEFAULTS, { lang, presets: [] }); S.follow = true; X.saveSettings(); X.applySettings(true); X.render(); X.renderLivebar(); if (window.PLI) window.PLI.apply(document.body); toast('Ayarlar sıfırlandı'); break; }
  }
});
document.addEventListener('change', e => {
  if (e.target.id !== 'sfile' || !e.target.files[0]) return;
  const r = new FileReader();
  r.onload = () => {
    try {
      const j = JSON.parse(r.result); if (!j || typeof j !== 'object') throw new Error('x');
      for (const k of Object.keys(X.DEFAULTS)) if (k in j && typeof j[k] === typeof X.DEFAULTS[k]) S.set[k] = j[k];
      X.saveSettings(); X.applySettings(true); X.render(); X.renderLivebar(); if (window.PLI) window.PLI.apply(document.body); toast('Ayarlar içe aktarıldı');
    } catch (x) { toast('Geçersiz ayar dosyası'); }
  };
  r.readAsText(e.target.files[0]); e.target.value = '';
});

async function runDeviceScan(mode) {
  if (!X.api) { toast('Sunucu gerekli'); return; }
  const iface = S.set.iface || (S.srv && S.srv.default_iface) || '';
  if (!iface || iface === 'any') { toast('Ayarlar’dan yakalama arayüzü seçin'); return; }
  DEV.scanNote = 'Taranıyor…'; if (S.tab === 'devices') renderDevices($('#view'));
  const modes = mode === 'arp' ? ['arp'] : mode === 'ping' ? ['arp', 'ping'] : ['arp', 'ports'];
  try {
    const { ok, j } = await X.api('/api/devices/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ iface, modes }) });
    if (!ok) { DEV.scanNote = j.error || 'Tarama başarısız'; toast(DEV.scanNote); }
    else {
      S.deviceRegistry = (j.registry && j.registry.devices) || j.found || [];
      if (j.compare) DEV.compare = j.compare;
      DEV.scanNote = (j.found || []).length + ' cihaz · ' + modes.join('+');
      toast('Tarama tamam');
      try { const { ok, j } = await X.api('/api/net'); if (ok) S.net = j; } catch (e2) { /* yok say */ }
    }
  } catch (e) { DEV.scanNote = 'Ağ hatası'; }
  if (S.tab === 'devices') renderDevices($('#view'));
}

document.addEventListener('click', e => {
  const el = e.target.closest('[data-act]'); if (!el) return;
  const act = el.dataset.act;
  if (act === 'dev-view') { DEV.view = el.dataset.v || 'cards'; if (S.tab === 'devices') renderDevices($('#view')); return; }
  if (act === 'dev-kind') { DEV.filterKind = el.dataset.v || 'all'; if (S.tab === 'devices') renderDevices($('#view')); return; }
  if (act === 'dev-scan') { e.preventDefault(); runDeviceScan(el.dataset.v); return; }
  if (act === 'dev-refresh') { e.preventDefault(); refreshDeviceRegistry().then(() => { if (S.tab === 'devices') renderDevices($('#view')); toast('Kayıt güncellendi'); }); return; }
  if (act === 'dev-watch') { e.preventDefault(); X.setQuery('ip.addr == ' + el.dataset.v); return; }
  if (act === 'dev-pt') {
    e.preventDefault();
    try { sessionStorage.setItem('pl-pt-targets', el.dataset.v || ''); } catch (x) { /* yok say */ }
    S.mode = 'adv'; try { localStorage.setItem('pl-mode', 'adv'); } catch (x) { /* yok say */ }
    S.tab = 'ptentes'; if (X.syncScreen) X.syncScreen(); X.render(); return;
  }
  if (act === 'dev-problems') {
    e.preventDefault();
    const ip = el.dataset.v;
    S.tab = 'problems'; S.probCat = 'all';
    S._devProbIp = ip;
    X.render();
    return;
  }
  if (act === 'dev-compare') {
    e.preventDefault();
    if (!X.api) return;
    X.api('/api/devices/compare?a=-2&b=-1').then(({ ok, j }) => {
      DEV.compare = ok ? j : { ok: false, error: j.error };
      if (S.tab === 'devices') renderDevices($('#view'));
    });
    return;
  }
  if (act === 'pb-newdev') { e.preventDefault(); runDeviceScan('arp'); return; }
  if (act === 'pb-suspicious') {
    e.preventDefault();
    X.setQuery('pl.problem');
    S.tab = 'problems';
    X.render();
    return;
  }
  if (act === 'pb-mobile') {
    e.preventDefault();
    DEV.filterKind = 'mobile';
    S.tab = 'devices';
    if (!S.A) { toast('Önce yakalama veya canlı analiz başlatın'); return; }
    X.render();
    return;
  }
  if (act === 'dev-mobile-csv') {
    e.preventDefault();
    if (!S.A || !S.pk.length) { toast('Önce bir yakalama açın'); return; }
    exportCSV('mobile-report');
    return;
  }
  if (act === 'pb-apiso') {
    e.preventDefault();
    S.tab = 'problems';
    S.probCat = 'net';
    S._devProbIp = null;
    X.render();
    toast('AP izolasyonu ve captive portal uyarıları “Ağ / bağlantı” listesinde');
    return;
  }
});

window.__PL_renderSettings = renderSettings;
Object.assign(X.views, { settings: renderSettings, sites: renderSites, devices: renderDevices });
if (window.PLApp && window.PLApp.views) window.PLApp.views.settings = renderSettings;
Object.assign(X.extra, { findBar, noteBox, filesHTML, openExport, openFilterLib, reportHTML, csvData, exportCSV });
})();
