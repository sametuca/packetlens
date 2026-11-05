/* ptentes - araya girme (MITM) kontrol paneli.
 * Sunucu tarafındaki motora (/api/ptentes/*) bağlanır; durum, DNS eşlemesi,
 * yakalanan kimlik bilgileri ve olay akışını gösterir. */
(function () {
'use strict';
const X = window.PLApp; if (!X) return;
const { S, esc, toast, $ } = X;
const TOKEN = new URLSearchParams(location.search).get('t');
const api = (path, opt) => fetch(path + (path.includes('?') ? '&' : '?') + 't=' + encodeURIComponent(TOKEN), opt)
  .then(r => r.json().then(j => ({ ok: r.ok, j })).catch(() => ({ ok: r.ok, j: {} })));

const PT = { st: null, timer: null, busy: false, pane: 'live', reveal: false, err: '', note: '', lastCfg: null };
const fmtB = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1073741824).toFixed(2) + ' GB';
const fmtT = t => new Date(t * 1000).toLocaleTimeString();
const canRun = () => !!(S.srv && S.srv.root);

function ifaceOptions() {
  const list = (S.srv && S.srv.interfaces) || [];
  const def = (list.find(i => i.default) || list.find(i => i.kind === 'ethernet') || {}).name || '';
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

function kpis(st) {
  const s = st.stats || {};
  const cell = (v, l, cls) => `<div class="kpi ${cls || ''}"><div class="v">${v}</div><div class="l">${l}</div></div>`;
  return `<div class="kpis">
    ${cell((s.packets || 0).toLocaleString('tr-TR'), 'paket')}
    ${cell(fmtB(s.bytes || 0), 'trafik')}
    ${cell(s.http || 0, 'HTTP isteği')}
    ${cell(s.tls || 0, 'TLS / SNI')}
    ${cell(s.dns || 0, 'DNS sorgusu')}
    ${cell(s.spoofed || 0, 'yönlendirilen DNS', s.spoofed ? 'bad' : '')}
    ${cell(s.creds || 0, 'kimlik bilgisi', s.creds ? 'bad' : '')}
    ${cell(st.uptime ? st.uptime.toFixed(0) + ' sn' : '—', 'süre')}
  </div>`;
}

function paneTabs(st) {
  const c = (st.creds || []).length, d = (st.dns || []).length, e = (st.events || []).length, h = (st.hosts || []).length;
  const items = [['live', 'Trafik'], ['creds', 'Kimlik bilgileri', c], ['dns', 'DNS', d], ['events', 'Olaylar', e], ['hosts', 'Cihazlar', h]];
  return `<div class="toolbar">${items.map(([k, l, n]) => `<button class="chip ${PT.pane === k ? 'on' : ''}" data-act="pt-pane" data-v="${k}">${l}${n != null ? ' (' + n + ')' : ''}</button>`).join('')}
    <a class="btn sm" href="/api/ptentes/report?t=${encodeURIComponent(TOKEN)}" download>Raporu indir</a></div>`;
}

function paneBody(st) {
  if (PT.pane === 'creds') {
    const l = (st.creds || []).slice().reverse();
    if (!l.length) return '<div class="empty-note">Henüz kimlik bilgisi yakalanmadı. Yalnızca şifresiz HTTP formları ve Basic auth okunur; HTTPS içeriği şifreli kalır.</div>';
    return `<div class="tablewrap"><table class="t"><thead><tr><th>Zaman</th><th>Hedef</th><th>Tür</th><th>Kullanıcı</th><th>Parola</th></tr></thead><tbody>
      ${l.map(c => `<tr><td class="mono">${fmtT(c.t)}</td><td class="mono">${esc(c.host)}</td><td>${esc(c.proto)}</td><td class="mono">${esc(c.user || '—')}</td><td class="mono">${PT.reveal ? esc(c.pass || '—') : '•'.repeat(Math.min(14, Math.max(4, (c.pass || '').length)))}</td></tr>`).join('')}
    </tbody></table></div><div class="toolbar"><button class="btn sm ghost" data-act="pt-reveal">${PT.reveal ? 'Parolaları gizle' : 'Parolaları göster'}</button><span class="muted small">Yalnızca yetkili olduğunuz ağlarda kullanın.</span></div>`;
  }
  if (PT.pane === 'dns') {
    const l = (st.dns || []).slice().reverse().slice(0, 500);
    if (!l.length) return '<div class="empty-note">DNS sorgusu görülmedi.</div>';
    return `<div class="tablewrap"><table class="t"><thead><tr><th>Zaman</th><th>İstemci</th><th>Alan adı</th><th>Tür</th><th>Durum</th></tr></thead><tbody>
      ${l.map(d => `<tr><td class="mono">${fmtT(d.t)}</td><td class="mono">${esc(d.client)}</td><td class="mono">${esc(d.name)}</td><td>${d.qtype === 28 ? 'AAAA' : d.qtype === 1 ? 'A' : '#' + d.qtype}</td><td>${d.spoofed ? '<span class="pill bad">yönlendirildi → ' + esc(d.answer || '') + '</span>' : '<span class="muted">geçti</span>'}</td></tr>`).join('')}
    </tbody></table></div>`;
  }
  if (PT.pane === 'events') {
    const l = (st.events || []).slice().reverse().slice(0, 500);
    if (!l.length) return '<div class="empty-note">Olay yok.</div>';
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
  // Canlı akış
  const l = (st.events || []).slice(-120).reverse();
  return `<div class="card"><h3>Canlı akış <small>en yeni üstte</small></h3>
    <div class="pt-feed">${l.length ? l.map(e => `<div class="pt-line ${e.sev === 'bad' ? 'bad' : ''}"><span class="mono muted">${fmtT(e.t)}</span><span class="pill ${e.sev === 'bad' ? 'bad' : e.sev === 'warn' ? 'med' : 'low'}">${esc(e.kind)}</span><span class="mono">${esc(e.src || '')}</span><span>→</span><span class="mono">${esc(e.dst || '')}</span><span class="pt-detail">${esc(e.detail || '')}</span></div>`).join('') : '<div class="empty-note">Trafik bekleniyor…</div>'}</div></div>`;
}

function form() {
  const st = PT.st, net = S.net || {}, arp = (net.arp || []).filter(a => a.ip !== (net.gateway || {}).ip);
  const cfg = PT.lastCfg || {
    iface: (S.srv && S.srv.default_iface && S.srv.default_iface !== 'any') ? S.srv.default_iface : ((S.srv && (S.srv.interfaces || []).find(i => i.default) || {}).name || ''),
    target: '', gateway: (net.gateway || {}).ip || '', dns: true, forward: true,
    dns_map: st && st.dns_map ? Object.entries(st.dns_map).map(([k, v]) => k + '=' + v).join('\n') : ''
  };
  const targetList = arp.map(a => `<option value="${esc(a.ip)}">${esc(a.mac)}</option>`).join('');
  return `<div class="grid g2">
    <div class="card"><h3>Oturum</h3>
      <div class="pt-row"><label>Arayüz</label><div><select id="pt-iface">${ifaceOptions()}</select></div></div>
      <div class="pt-row"><label>Hedef cihaz</label><div><input id="pt-target" list="pt-hosts" value="${esc(cfg.target || '')}" placeholder="192.168.1.42" spellcheck="false"><datalist id="pt-hosts">${targetList}</datalist><div class="muted small">Trafiği araya alınacak yerel cihaz.</div></div></div>
      <div class="pt-row"><label>Ağ geçidi</label><div><input id="pt-gateway" value="${esc(cfg.gateway || '')}" placeholder="192.168.1.1" spellcheck="false"></div></div>
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
        <li>HTTP istekleri, TLS <b>SNI</b> alanı ve DNS sorguları çözümlenir. DNS eşlemesi doluysa sahte yanıt öne geçer.</li>
        <li>Durdurulduğunda doğru ARP eşlemeleri geri gönderilir ve <span class="mono">ip_forward</span> eski değerine döner.</li>
      </ol>
      <div class="muted small">Hedef ve ağ geçidi aynı yerel ağda olmalıdır. HTTPS içeriği şifreli kalır; yalnızca bağlantı hedefi görünür. Yalnızca izinli olduğunuz ağlarda kullanın.</div>
    </div>
  </div>`;
}

function running(st) {
  return `<div class="banner bad"><span style="font-size:22px">◉</span><div><b>Araya girme etkin</b>
    <span class="muted">${esc(st.target)} ↔ ${esc(st.gateway)} · arayüz ${esc(st.iface)} · ${esc(st.target_mac)} / ${esc(st.gateway_mac)}</span></div>
    <button class="btn danger" style="margin-left:auto" data-act="pt-stop">■ Durdur ve geri al</button></div>
  ${kpis(st)}${paneTabs(st)}${paneBody(st)}`;
}

function render(v) {
  const st = PT.st;
  if (!TOKEN || location.protocol === 'file:') {
    v.innerHTML = `<div class="card"><h2>ptentes</h2><p class="muted">Bu panel sunucu üzerinden çalışır. Programı çalıştırıp arayüzü <span class="mono">http://127.0.0.1:8765</span> adresinden açın.</p></div>`;
    return;
  }
  const head = `<div class="set-head"><h2>ptentes <span class="muted small">araya girme motoru</span></h2>
    <button class="btn sm" data-act="pt-refresh">↻ Yenile</button></div>`;
  v.innerHTML = head + (st && st.running ? running(st) : form() + (st && (st.events || []).length ? `<div class="card" style="margin-top:14px"><h3>Son oturum</h3>${kpis(st)}${paneTabs(st)}${paneBody(st)}</div>` : ''));
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
      if (j.running && (!$('#pt-status'))) render($('#view'));
      else if (wasRunning && !j.running) render($('#view'));
      else if (j.running) {
        // Yalnızca gövdeyi yenile: form alanlarına dokunma.
        const head = $('#view .set-head');
        const body = $('#view');
        if (body) render(body);
      }
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
  const cfg = {
    iface: ($('#pt-iface') || {}).value || '',
    target: (($('#pt-target') || {}).value || '').trim(),
    gateway: (($('#pt-gateway') || {}).value || '').trim(),
    forward: !!($('#pt-forward') && $('#pt-forward').checked),
    dns_spoof: !!($('#pt-dns') && $('#pt-dns').checked),
    dns_map: parseMap(($('#pt-dnsmap') || {}).value || '')
  };
  PT.lastCfg = { iface: cfg.iface, target: cfg.target, gateway: cfg.gateway, forward: cfg.forward, dns: cfg.dns_spoof,
    dns_map: Object.entries(cfg.dns_map).map(([k, v]) => k + '=' + v).join('\n') };
  if (!cfg.target) { PT.err = 'Hedef IP girin.'; render($('#view')); return; }
  const { ok, j } = await api('/api/ptentes/start', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cfg)
  });
  if (!ok) { PT.err = j.error || 'Araya girilemedi.'; render($('#view')); return; }
  toast('ptentes etkin: ' + cfg.target);
  startPolling();
}

async function stop() {
  const { ok, j } = await api('/api/ptentes/stop', { method: 'POST' });
  if (!ok) toast(j.error || 'Durdurulamadı');
  PT.st = j.ok ? PT.st : PT.st;
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
    PT.lastCfg = PT.lastCfg || {};
    PT.lastCfg.iface = iface;
    if (!PT.lastCfg.target && j.found.length) PT.lastCfg.target = j.found[0].ip;
  }
  render($('#view'));
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
  }
});

Object.assign(X.views, {
  ptentes: function (v) {
    render(v);
    if (PT.st && PT.st.running) startPolling();
    else {
      // İlk açılışta sunucudan durumu bir kez al.
      api('/api/ptentes/status').then(({ ok, j }) => {
        if (ok && j) { PT.st = j; if (S.tab === 'ptentes') render($('#view')); if (j.running) startPolling(); }
      }).catch(() => {});
    }
  }
});
})();
