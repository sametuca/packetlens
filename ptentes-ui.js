/* ptentes - araya girme (MITM) kontrol paneli.
 * Sunucu tarafındaki motora (/api/ptentes/*) bağlanır; durum, DNS eşlemesi,
 * yakalanan kimlik bilgileri ve olay akışını gösterir. */
(function () {
'use strict';
const X = window.PLApp; if (!X) return;
const { S, esc, toast, $ } = X;
const api = (path, opt) => fetch(path, opt)
  .then(r => r.json().then(j => ({ ok: r.ok, j })).catch(() => ({ ok: r.ok, j: {} })));

const PT = { st: null, timer: null, busy: false, pane: 'live', reveal: false, err: '', note: '', lastCfg: null,
  discovered: [], filter: '', sig: '', focusIp: '' };
const fmtB = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1073741824).toFixed(2) + ' GB';
const fmtT = t => new Date(t * 1000).toLocaleTimeString();
const canRun = () => !!(S.srv && S.srv.root);

function ifaceOptions() {
  const list = (S.srv && S.srv.interfaces) || [];
  const def = (PT.lastCfg && PT.lastCfg.iface) || (list.find(i => i.default) || list.find(i => i.kind === 'ethernet') || {}).name || '';
  return list.filter(i => i.kind !== 'loopback').map(i =>
    `<option value="${esc(i.name)}" ${i.name === def ? 'selected' : ''}>${esc(i.name)}${i.default ? ' · internet çıkışı' : ''}${i.ipv4 ? ' · ' + esc(i.ipv4) : ''}</option>`).join('');
}

function parseMap(text) {
  const map = {};
  String(text || '').split('\n').forEach(line => {
    line = line.trim();
    if (!line || line[0] === '#') return;
    const m = line.split(/[=\s]+/);
    if (m.length >= 2 && /^\d+\.\d+\.\d+\.\d+$/.test(m[1])) map[m[0].toLowerCase()] = m[1];
  });
  return map;
}

function hostOptions() {
  const seen = new Set();
  const out = [];
  const add = (ip, mac) => {
    if (!ip || seen.has(ip)) return;
    seen.add(ip);
    out.push(`<option value="${esc(ip)}">${esc(mac || ip)}</option>`);
  };
  (PT.discovered || []).forEach(h => add(h.ip, h.mac));
  const net = S.net || {};
  (net.arp || []).filter(a => a.ip !== (net.gateway || {}).ip).forEach(a => add(a.ip, a.mac));
  return out.join('');
}

function kpis(st) {
  const s = st.stats || {};
  const cell = (v, l, cls) => `<div class="kpi ${cls || ''}"><div class="v">${v}</div><div class="l">${l}</div></div>`;
  return `<div class="kpis" id="pt-kpis">
    ${cell((s.packets || 0).toLocaleString('tr-TR'), 'paket')}
    ${cell(fmtB(s.bytes || 0), 'trafik')}
    ${cell(s.http || 0, 'HTTP isteği')}
    ${cell(s.tls || 0, 'TLS / SNI')}
    ${cell(s.quic || 0, 'QUIC SNI', s.quic ? 'ok' : '')}
    ${cell(s.ech || 0, 'ECH', s.ech ? 'med' : '')}
    ${cell(s.dns || 0, 'DNS sorgusu')}
    ${cell(s.spoofed || 0, 'yönlendirilen DNS', s.spoofed ? 'bad' : '')}
    ${cell(s.creds || 0, 'kimlik bilgisi', s.creds ? 'bad' : '')}
    ${cell(s.cookies || 0, 'çerez', s.cookies ? 'med' : '')}
    ${cell(s.arp_warn || 0, 'ARP uyarısı', s.arp_warn ? 'med' : '')}
    ${cell(st.uptime ? st.uptime.toFixed(0) + ' sn' : '—', 'süre')}
  </div>`;
}

function paneTabs(st) {
  const c = (st.creds || []).length, ck = (st.cookies || []).length, d = (st.dns || []).length;
  const e = (st.events || []).length, h = (st.hosts || []).length;
  const sitesN = ptSites(st).length;
  const items = [['live', 'Trafik'], ['sites', 'Siteler', sitesN], ['creds', 'Kimlik bilgileri', c], ['cookies', 'Çerezler', ck],
    ['dns', 'DNS', d], ['events', 'Olaylar', e], ['hosts', 'Cihazlar', h]];
  return `<div class="toolbar" id="pt-tabs">${items.map(([k, l, n]) => `<button class="chip ${PT.pane === k ? 'on' : ''}" data-act="pt-pane" data-v="${k}">${l}${n != null ? ' (' + n + ')' : ''}</button>`).join('')}
    <input type="search" class="inp sm" id="pt-filter" placeholder="Olaylarda filtre…" value="${esc(PT.filter)}" spellcheck="false">
    <button class="btn sm" data-act="pt-watch">Yakalamada izle</button>
    <button class="btn sm ghost" data-act="pt-open-sites">Ana Siteler</button>
    <a class="btn sm" href="/api/ptentes/report" download>Raporu indir</a></div>`;
}

function eventFilter(list) {
  let l = list;
  if (PT.focusIp) l = l.filter(e => e.src === PT.focusIp || e.dst === PT.focusIp || String(e.detail || '').includes(PT.focusIp));
  const q = (PT.filter || '').trim().toLowerCase();
  if (!q) return l;
  return l.filter(e => [e.kind, e.src, e.dst, e.detail].some(x => String(x || '').toLowerCase().includes(q)));
}

function targetIps(st) {
  const ips = (st && st.target_ips && st.target_ips.length) ? st.target_ips.slice() : (st && st.target ? [st.target] : []);
  if (PT.focusIp && ips.includes(PT.focusIp)) return [PT.focusIp];
  return ips.filter(Boolean);
}

function ptSites(st) {
  const targets = new Set(targetIps(st));
  const onlyTarget = targets.size > 0;
  const rows = new Map();
  const add = (client, domain, via) => {
    if (!domain) return;
    domain = String(domain).toLowerCase().replace(/\.$/, '');
    if (!domain || domain.includes(' ')) return;
    if (onlyTarget && client && !targets.has(client)) return;
    const k = (client || '?') + '|' + domain;
    let r = rows.get(k);
    if (!r) rows.set(k, r = { client: client || '—', domain, via: new Set(), n: 0 });
    r.via.add(via);
    r.n++;
  };
  for (const d of (st.dns || [])) add(d.client, d.name, d.spoofed ? 'DNS (yönlendirildi)' : 'DNS');
  for (const e of (st.events || [])) {
    if (e.kind === 'tls') add(e.src, e.dst, 'TLS SNI');
    else if (e.kind === 'http') add(e.src, e.dst, 'HTTP Host');
    else if (e.kind === 'quic') add(e.src, e.dst, 'QUIC SNI');
  }
  return [...rows.values()].sort((a, b) => b.n - a.n || a.domain.localeCompare(b.domain));
}

function mitmReadiness() {
  const items = [];
  if (canRun()) items.push({ ok: true, t: 'Root: araya girme kullanılabilir' });
  else items.push({ ok: false, t: 'Root yok — sudo python3 packetlens.py gerekir' });
  const gw = ((S.net || {}).gateway || {}).ip;
  if (gw) items.push({ ok: true, t: 'Ağ geçidi: ' + gw });
  else items.push({ ok: false, t: 'Ağ geçidi bilinmiyor (canlı analiz veya Cihazlar → ARP tara)' });
  const iso = S.A && S.A.apIsolation && S.A.apIsolation.likely;
  if (iso) items.push({ ok: false, t: 'Olası AP izolasyonu — hedef trafiği araya alınamayabilir' });
  else if (S.A && S.A.stats && S.A.stats.packets > 100) items.push({ ok: true, t: 'Yakalamada cihazlar arası trafik görüldü (izolasyon belirtisi zayıf)' });
  const live = S.live && S.live.running;
  if (live) items.push({ ok: true, t: 'Canlı yakalama açık — hedef trafiği PacketLens’te de görünür' });
  else items.push({ ok: false, t: 'Canlı yakalama kapalı — MITM sırasında ptentes paneli + “Yakalamada izle” önerilir' });
  return items;
}

function watchQuery(ips) {
  if (!ips.length) return '';
  if (ips.length === 1) return 'ip.addr == ' + ips[0];
  return ips.map(ip => 'ip.addr == ' + ip).join(' || ');
}

function paneBody(st) {
  if (PT.pane === 'creds') {
    const l = (st.creds || []).slice().reverse();
    if (!l.length) return '<div class="empty-note">Henüz kimlik bilgisi yakalanmadı. Şifresiz HTTP (form, Basic auth, JSON gövde, sorgu dizisi) okunur; HTTPS içeriği şifreli kalır.</div>';
    return `<div class="tablewrap"><table class="t"><thead><tr><th>Zaman</th><th>Hedef</th><th>Tür</th><th>Kullanıcı</th><th>Parola</th></tr></thead><tbody>
      ${l.map(c => `<tr><td class="mono">${fmtT(c.t)}</td><td class="mono">${esc(c.host)}</td><td>${esc(c.proto)}</td><td class="mono">${esc(c.user || '—')}</td><td class="mono">${PT.reveal ? esc(c.pass || '—') : '•'.repeat(Math.min(14, Math.max(4, (c.pass || '').length)))}</td></tr>`).join('')}
    </tbody></table></div><div class="toolbar"><button class="btn sm ghost" data-act="pt-reveal">${PT.reveal ? 'Parolaları gizle' : 'Parolaları göster'}</button><button class="btn sm ghost" data-act="pt-copy-creds">Panoya kopyala</button><span class="muted small">Yalnızca yetkili olduğunuz ağlarda kullanın.</span></div>`;
  }
  if (PT.pane === 'cookies') {
    const l = (st.cookies || []).slice().reverse();
    if (!l.length) return '<div class="empty-note">Set-Cookie başlığı yakalanmadı. Sunucu yanıtları şifresiz HTTP üzerindeyse oturum çerezleri burada görünür.</div>';
    return `<div class="tablewrap"><table class="t"><thead><tr><th>Zaman</th><th>Sunucu</th><th>Ad</th><th>Değer</th><th>İstemci</th></tr></thead><tbody>
      ${l.map(c => `<tr><td class="mono">${fmtT(c.t)}</td><td class="mono">${esc(c.host)}</td><td class="mono">${esc(c.name)}</td><td class="mono">${PT.reveal ? esc(c.value || '—') : (c.value ? esc(c.value.slice(0, 8)) + '…' : '—')}</td><td class="mono">${esc(c.src || '')}</td></tr>`).join('')}
    </tbody></table></div><div class="toolbar"><button class="btn sm ghost" data-act="pt-reveal">${PT.reveal ? 'Değerleri gizle' : 'Değerleri göster'}</button></div>`;
  }
  if (PT.pane === 'dns') {
    const l = (st.dns || []).slice().reverse().slice(0, 500);
    if (!l.length) return '<div class="empty-note">DNS sorgusu görülmedi.</div>';
    return `<div class="tablewrap"><table class="t"><thead><tr><th>Zaman</th><th>İstemci</th><th>Alan adı</th><th>Tür</th><th>Durum</th></tr></thead><tbody>
      ${l.map(d => `<tr><td class="mono">${fmtT(d.t)}</td><td class="mono">${esc(d.client)}</td><td class="mono">${esc(d.name)}</td><td>${d.qtype === 28 ? 'AAAA' : d.qtype === 1 ? 'A' : '#' + d.qtype}</td><td>${d.rcode === 3 ? '<span class="pill med">NXDOMAIN</span>' : d.response ? '<span class="muted">yanıt</span>' : d.spoofed ? '<span class="pill bad">yönlendirildi → ' + esc(d.answer || '') + '</span>' : '<span class="muted">sorgu</span>'}</td></tr>`).join('')}
    </tbody></table></div>`;
  }
  if (PT.pane === 'events') {
    const l = eventFilter((st.events || []).slice().reverse().slice(0, 500));
    if (!l.length) return '<div class="empty-note">Olay yok veya filtre eşleşmedi.</div>';
    const sev = { bad: 'bad', warn: 'med', ok: 'ok', info: 'low' };
    return `<div class="tablewrap"><table class="t"><thead><tr><th>Zaman</th><th>Tür</th><th>Kaynak</th><th>Hedef / ayrıntı</th><th>Açıklama</th></tr></thead><tbody>
      ${l.map(e => `<tr><td class="mono">${fmtT(e.t)}</td><td><span class="pill ${sev[e.sev] || 'low'}">${esc(e.kind)}</span></td><td class="mono">${esc(e.src || '')}</td><td class="mono">${esc(e.dst || '')}</td><td>${esc(e.detail || '')}</td></tr>`).join('')}
    </tbody></table></div>`;
  }
  if (PT.pane === 'hosts') {
    const l = (st.hosts || []);
    if (!l.length) return '<div class="empty-note">Cihaz görülmedi.</div>';
    return `<div class="tablewrap"><table class="t"><thead><tr><th>Adres</th><th>MAC</th><th class="num">#Paket</th><th class="num">Veri</th><th>Son görülme</th></tr></thead><tbody>
      ${l.map(h => `<tr><td class="mono">${esc(h.ip)}</td><td class="mono">${esc(h.mac || '—')}</td><td class="num">${h.packets || 0}</td><td class="num">${fmtB(h.bytes || 0)}</td><td class="mono">${fmtT(h.last)}</td></tr>`).join('')}
    </tbody></table></div>`;
  }
  if (PT.pane === 'sites') {
    const l = ptSites(st);
    if (!l.length) return '<div class="empty-note">Henüz alan adı yok. Hedef cihazda tarayıcı veya uygulama açın; DNS ve TLS SNI burada birikir. HTTPS içeriği şifrelidir.</div>';
    return `<div class="tablewrap"><table class="t"><thead><tr><th>Alan adı</th><th>İstemci</th><th>Kaynak</th><th class="num">#</th></tr></thead><tbody>
      ${l.slice(0, 300).map(r => `<tr><td class="mono">${esc(r.domain)}</td><td class="mono">${esc(r.client)}</td><td>${[...r.via].map(v => esc(v)).join(', ')}</td><td class="num">${r.n}</td></tr>`).join('')}
    </tbody></table></div><div class="muted small">Mobil uygulamaların çoğu QUIC/HTTPS kullanır; görünen çoğunlukla SNI ve DNS olur.</div>`;
  }
  const l = eventFilter((st.events || []).slice(-120).reverse());
  return `<div class="card"><h3>Canlı akış <small>en yeni üstte</small></h3>
    <div class="pt-feed">${l.length ? l.map(e => `<div class="pt-line ${e.sev === 'bad' ? 'bad' : e.sev === 'warn' ? 'warn' : ''}"><span class="mono muted">${fmtT(e.t)}</span><span class="pill ${e.sev === 'bad' ? 'bad' : e.sev === 'warn' ? 'med' : 'low'}">${esc(e.kind)}</span><span class="mono">${esc(e.src || '')}</span><span>→</span><span class="mono">${esc(e.dst || '')}</span><span class="pt-detail">${esc(e.detail || '')}</span></div>`).join('') : '<div class="empty-note">Trafik bekleniyor…</div>'}</div></div>`;
}

function dnsMapBlock(st, running) {
  const mapText = PT.lastCfg && PT.lastCfg.dns_map != null ? PT.lastCfg.dns_map
    : (st && st.dns_map ? Object.entries(st.dns_map).map(([k, v]) => k + '=' + v).join('\n') : '');
  if (running) {
    return `<div class="card" style="margin-top:14px"><h3>DNS eşlemesi <small>oturum açıkken güncellenebilir</small></h3>
      <textarea id="pt-dnsmap-live" rows="4" spellcheck="false" placeholder="ornek.com=192.168.1.50">${esc(mapText)}</textarea>
      <div class="toolbar" style="margin-top:8px"><button class="btn sm" data-act="pt-dns-apply">Eşlemeyi uygula</button></div></div>`;
  }
  return '';
}

function form() {
  const st = PT.st;
  let ptTargets = '';
  try { ptTargets = sessionStorage.getItem('pl-pt-targets') || ''; if (ptTargets) sessionStorage.removeItem('pl-pt-targets'); } catch (x) { /* yok say */ }
  const cfg = PT.lastCfg || {
    iface: (S.srv && S.srv.default_iface && S.srv.default_iface !== 'any') ? S.srv.default_iface : ((S.srv && (S.srv.interfaces || []).find(i => i.default) || {}).name || ''),
    target: ptTargets || '', gateway: ((S.net || {}).gateway || {}).ip || '', dns: true, forward: true,
    dns_map: st && st.dns_map ? Object.entries(st.dns_map).map(([k, v]) => k + '=' + v).join('\n') : ''
  };
  return `<div class="grid g2">
    <div class="card"><h3>Oturum</h3>
      <div class="pt-row"><label>Arayüz</label><div><select id="pt-iface">${ifaceOptions()}</select></div></div>
      <div class="pt-row"><label>Hedef cihaz</label><div><input id="pt-target" list="pt-hosts" value="${esc(cfg.target || '')}" placeholder="192.168.1.42 veya virgülle çoklu" spellcheck="false"><datalist id="pt-hosts">${hostOptions()}</datalist><div class="muted small">Tek IP veya en fazla 8 cihaz (virgülle). Trafiği araya alınacak yerel hedefler.</div></div></div>
      <div class="pt-row"><label>Ağ geçidi</label><div><input id="pt-gateway" value="${esc(cfg.gateway || '')}" placeholder="192.168.1.1" spellcheck="false"></div></div>
      <div class="pt-row"><label>Oturum etiketi</label><div><input id="pt-label" value="${esc(cfg.session_label || '')}" placeholder="Lab-3 / hedef telefon" spellcheck="false"></div></div>
      <div class="pt-row"><label>Not</label><div><textarea id="pt-note" rows="2" spellcheck="false" placeholder="Yetki kapsamı, tarih…">${esc(cfg.session_note || '')}</textarea></div></div>
      <div class="pt-row"><label>Seçenekler</label><div class="pt-checks">
        <label class="chk"><input type="checkbox" id="pt-forward" ${cfg.forward !== false ? 'checked' : ''}> IP yönlendirmeyi aç <span class="muted small">(trafik akmaya devam eder)</span></label>
        <label class="chk"><input type="checkbox" id="pt-dns" ${cfg.dns !== false ? 'checked' : ''}> DNS yanıtlarını yönlendir</label>
      </div></div>
      <div class="pt-row"><label>DNS eşlemesi</label><div><textarea id="pt-dnsmap" rows="4" spellcheck="false" placeholder="ornek.com=192.168.1.50&#10;*.test.local=192.168.1.50">${esc(cfg.dns_map || '')}</textarea><div class="muted small">Her satır <span class="mono">alanadi=ip</span>. Eşleşen sorgulara sahte yanıt gönderilir.</div></div></div>
      <div class="toolbar" style="margin-top:10px">
        <button class="btn primary" data-act="pt-start" ${canRun() ? '' : 'disabled'}>▶ Araya gir</button>
        <button class="btn" data-act="pt-discover" ${canRun() ? '' : 'disabled'}>Cihazları tara</button>
        ${PT.note ? `<span class="muted small">${esc(PT.note)}</span>` : ''}
      </div>
      ${canRun() ? '' : `<div class="muted small">Araya girme için sunucunun root olarak çalışması gerekir: <span class="mono">sudo python3 packetlens.py</span></div>`}
      ${PT.err ? `<div class="banner bad" style="margin-top:10px"><b>Hata</b><span class="muted">${esc(PT.err)}</span></div>` : ''}
    </div>
    <div class="card"><h3>Nasıl çalışır</h3>
      <ol class="pt-steps">
        <li>Hedef ve ağ geçidine <b>ARP yanıtları</b> gönderilir; iki taraf da birbirini bu makinenin MAC adresi sanır.</li>
        <li><b>IP yönlendirme</b> açıksa trafik kesintisiz akmaya devam eder; motor aradan yalnızca kopya okur.</li>
        <li>HTTP istekleri, TLS <b>SNI</b>, DNS ve <b>Set-Cookie</b> yanıtları çözümlenir. Rakip ARP uyarıları izolasyon veya DAI işaret edebilir.</li>
        <li>Durdurulduğunda doğru ARP eşlemeleri geri gönderilir ve <span class="mono">ip_forward</span> eski değerine döner.</li>
      </ol>
      <div class="muted small">Hedef ve ağ geçidi aynı yerel ağda olmalıdır. HTTPS içeriği şifreli kalır; yalnızca bağlantı hedefi görünür. Yalnızca izinli olduğunuz ağlarda kullanın.</div>
      <h4 style="margin-top:14px">MITM hazırlık</h4>
      <ul class="muted small" style="margin:6px 0 0;padding-left:18px">${mitmReadiness().map(i => `<li style="color:${i.ok ? 'inherit' : '#b54708'}">${esc(i.t)}</li>`).join('')}</ul>
    </div>
  </div>`;
}

function running(st) {
  const tgtLabel = (st.targets && st.targets.length > 1) ? st.targets.map(t => t.ip).join(', ') : st.target;
  const chips = (st.target_ips || [st.target]).map(ip => `<button class="chip ${PT.focusIp === ip ? 'on' : ''}" data-act="pt-focus" data-v="${esc(ip)}">${esc(ip)}</button>`).join('');
  const arpBad = (st.stats && st.stats.arp_warn) > 0;
  return `<div id="pt-running"><div class="banner bad"><span style="font-size:22px">◉</span><div><b>Araya girme etkin</b>
    <span class="muted">${esc(st.session_label || tgtLabel)} ↔ ${esc(st.gateway)} · ${esc(st.iface)}</span></div>
    <button class="btn danger" style="margin-left:auto" data-act="pt-stop">■ Durdur ve geri al</button></div>
  ${arpBad ? `<div class="banner med" style="margin-top:8px"><b>ARP uyarısı</b> <span class="muted">Ağ gerçek MAC adreslerini duyuruyor — izolasyon veya DAI olabilir; trafik sizden geçmiyor olabilir.</span></div>` : ''}
  <div class="toolbar">${chips}<button class="chip ${PT.focusIp ? '' : 'on'}" data-act="pt-focus" data-v="">Tüm hedefler</button></div>
  ${st.session_note ? `<div class="muted small" style="margin:6px 0">${esc(st.session_note)}</div>` : ''}
  ${kpis(st)}${paneTabs(st)}<div id="pt-pane">${paneBody(st)}</div>${dnsMapBlock(st, true)}</div>`;
}

function statusSig(st) {
  if (!st) return '';
  const s = st.stats || {};
  return [st.running, s.packets, s.creds, s.cookies, s.arp_warn, (st.events || []).length, (st.dns || []).length, PT.pane, PT.filter].join('|');
}

function patchRunning(st) {
  const k = $('#pt-kpis'), t = $('#pt-tabs'), p = $('#pt-pane');
  if (!k || !p) return false;
  k.outerHTML = kpis(st);
  if (t) t.outerHTML = paneTabs(st);
  p.innerHTML = paneBody(st);
  const ff = $('#pt-filter');
  if (ff) ff.value = PT.filter;
  return true;
}

function render(v) {
  const st = PT.st;
  if (location.protocol === 'file:') {
    v.innerHTML = `<div class="card"><h2>ptentes</h2><p class="muted">Bu panel sunucu üzerinden çalışır. Programı çalıştırıp arayüzü <span class="mono">http://127.0.0.1:8765</span> adresinden açın.</p></div>`;
    return;
  }
  const head = `<div class="set-head"><h2>ptentes <span class="muted small">araya girme motoru</span></h2>
    <button class="btn sm" data-act="pt-refresh">↻ Yenile</button></div>`;
  v.innerHTML = head + (st && st.running ? running(st) : form() + (st && (st.events || []).length ? `<div class="card" style="margin-top:14px"><h3>Son oturum</h3>${kpis(st)}${paneTabs(st)}${paneBody(st)}</div>` : ''));
  PT.sig = statusSig(st);
  if (window.PLI) window.PLI.apply(v);
}

async function poll() {
  if (PT.busy) return;
  if (S.tab !== 'ptentes') { clearInterval(PT.timer); PT.timer = null; return; }
  PT.busy = true;
  try {
    const { ok, j } = await api('/api/ptentes/status');
    if (ok && j) {
      const wasRunning = PT.st && PT.st.running;
      PT.st = j;
      const sig = statusSig(j);
      const view = $('#view');
      if (!view) return;
      if (j.running) {
        if (!wasRunning || !$('#pt-running')) render(view);
        else if (sig !== PT.sig) {
          if (!patchRunning(j)) render(view);
          PT.sig = sig;
          if (window.PLI) window.PLI.apply($('#pt-running') || view);
        }
      } else if (wasRunning && !j.running) render(view);
    }
  } catch (e) { /* sunucu yok */ } finally { PT.busy = false; }
}

function startPolling() {
  clearInterval(PT.timer);
  PT.timer = setInterval(poll, 1200);
  poll();
}

async function start() {
  PT.err = ''; PT.note = '';
  const rawTarget = (($('#pt-target') || {}).value || '').trim();
  const targets = rawTarget.split(/[,;\s]+/).map(s => s.trim()).filter(Boolean);
  const cfg = {
    iface: ($('#pt-iface') || {}).value || '',
    target: targets[0] || '',
    targets,
    gateway: (($('#pt-gateway') || {}).value || '').trim(),
    forward: !!($('#pt-forward') && $('#pt-forward').checked),
    dns_spoof: !!($('#pt-dns') && $('#pt-dns').checked),
    dns_map: parseMap(($('#pt-dnsmap') || {}).value || ''),
    session_label: (($('#pt-label') || {}).value || '').trim(),
    session_note: (($('#pt-note') || {}).value || '').trim()
  };
  PT.lastCfg = { iface: cfg.iface, target: cfg.target, gateway: cfg.gateway, forward: cfg.forward, dns: cfg.dns_spoof,
    dns_map: Object.entries(cfg.dns_map).map(([k, v]) => k + '=' + v).join('\n'),
    session_label: cfg.session_label, session_note: cfg.session_note };
  if (!targets.length) { PT.err = 'Hedef IP girin.'; render($('#view')); return; }
  if (targets.length > 8) { PT.err = 'En fazla 8 hedef seçilebilir.'; render($('#view')); return; }
  const { ok, j } = await api('/api/ptentes/start', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cfg)
  });
  if (!ok) { PT.err = j.error || 'Araya girilemedi.'; render($('#view')); return; }
  toast('ptentes etkin: ' + (targets.length > 1 ? targets.join(', ') : cfg.target));
  startPolling();
}

async function stop() {
  const { ok, j } = await api('/api/ptentes/stop', { method: 'POST' });
  if (!ok) toast(j.error || 'Durdurulamadı');
  await poll();
  render($('#view'));
  toast('Durduruldu, ARP geri alındı');
  clearInterval(PT.timer); PT.timer = null;
}

async function discover() {
  const iface = ($('#pt-iface') || {}).value || '';
  PT.note = 'Taranıyor…'; render($('#view'));
  const { ok, j } = await api('/api/ptentes/discover', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ iface })
  });
  PT.note = ok ? `${(j.found || []).length} cihaz bulundu (${j.subnet || ''})` : (j.error || 'Tarama başarısız');
  if (ok && j.found && j.found.length) {
    PT.discovered = j.found;
    PT.lastCfg = PT.lastCfg || {};
    PT.lastCfg.iface = iface;
    if (!($('#pt-target') || {}).value && j.found.length) PT.lastCfg.target = j.found[0].ip;
  }
  render($('#view'));
}

async function applyDns() {
  const el = $('#pt-dnsmap-live') || $('#pt-dnsmap');
  const map = parseMap((el && el.value) || '');
  const { ok, j } = await api('/api/ptentes/dnsmap', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ map })
  });
  if (ok) {
    toast('DNS eşlemesi güncellendi (' + Object.keys(map).length + ' kayıt)');
    PT.lastCfg = PT.lastCfg || {};
    PT.lastCfg.dns_map = Object.entries(map).map(([k, v]) => k + '=' + v).join('\n');
  } else toast(j.error || 'Güncellenemedi');
}

function copyCreds() {
  const l = (PT.st && PT.st.creds) || [];
  if (!l.length) { toast('Kopyalanacak kayıt yok'); return; }
  const text = l.map(c => [fmtT(c.t), c.host, c.proto, c.user || '', c.pass || ''].join('\t')).join('\n');
  navigator.clipboard.writeText(text).then(() => toast('Kimlik bilgileri panoya kopyalandı')).catch(() => toast('Panoya kopyalanamadı'));
}

document.addEventListener('click', e => {
  const el = e.target.closest('[data-act]'); if (!el) return;
  const act = el.dataset.act;
  if (!act || act.indexOf('pt-') !== 0) return;
  e.preventDefault();
  switch (act) {
    case 'pt-start': start(); break;
    case 'pt-stop': stop(); break;
    case 'pt-discover': discover(); break;
    case 'pt-refresh': poll(); if (PT.st) render($('#view')); break;
    case 'pt-pane': PT.pane = el.dataset.v; render($('#view')); break;
    case 'pt-reveal': PT.reveal = !PT.reveal; render($('#view')); break;
    case 'pt-dns-apply': applyDns(); break;
    case 'pt-copy-creds': copyCreds(); break;
    case 'pt-focus': PT.focusIp = el.dataset.v || ''; render($('#view')); break;
    case 'pt-watch': {
      const st = PT.st;
      const ips = targetIps(st);
      if (!ips.length) { toast('Hedef IP yok'); break; }
      const q = watchQuery(ips);
      try { sessionStorage.setItem('pl-mitm-targets', ips.join(',')); } catch (x) { /* yok say */ }
      if (!S.live.running) toast('İpucu: canlı yakalama açık değil — Ayarlardan arayüz seçip canlı analiz başlatın');
      X.setQuery(q);
      S.tab = 'packets';
      $('#empty').hidden = true; $('#app').hidden = false;
      X.render();
      toast('Filtre: hedef trafiği');
      break;
    }
    case 'pt-open-sites': {
      const st = PT.st;
      const ips = targetIps(st);
      if (ips.length) try { sessionStorage.setItem('pl-mitm-targets', ips.join(',')); } catch (x) { /* yok say */ }
      S.tab = 'sites';
      $('#empty').hidden = true; $('#app').hidden = false;
      X.render();
      toast('Siteler sekmesi — cihaz filtresini hedef IP yapın');
      break;
    }
  }
});

document.addEventListener('input', e => {
  if (e.target && e.target.id === 'pt-filter') {
    PT.filter = e.target.value;
    if (PT.st && PT.st.running) patchRunning(PT.st);
    else if (PT.st) render($('#view'));
  }
});

Object.assign(X.views, {
  ptentes: function (v) {
    render(v);
    if (PT.st && PT.st.running) startPolling();
    else {
      api('/api/ptentes/status').then(({ ok, j }) => {
        if (ok && j) { PT.st = j; if (S.tab === 'ptentes') render($('#view')); if (j.running) startPolling(); }
      }).catch(() => {});
    }
  }
});
})();
