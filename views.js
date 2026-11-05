/* PacketLens - ek görünümler: Grafik, Harita, İstatistik, Günlükler, akış takibi, sıra diyagramı */
(function () {
'use strict';
const X = window.PLApp; if (!X) return;
const T = s => (window.PLI ? window.PLI.t(s) : s);
const { S, PL, esc, fmtB, fmtD, nm, appColor, toast, $ } = X;
const fmtT = s => s < 0.001 ? '0' : s < 1 ? (s * 1000).toFixed(s < 0.01 ? 1 : 0) + ' ms' : s < 60 ? s.toFixed(s < 10 ? 2 : 1) + ' sn' : Math.floor(s / 60) + ' dk ' + Math.round(s % 60) + ' sn';
const short = (s, n) => { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
const pct = (a, b) => b ? (a / b * 100).toFixed(1) + '%' : '0%';
const table = (head, rows, cls) => `<div class="tablewrap" style="max-height:none"><table class="t ${cls || ''}"><thead><tr>${head.map(h => `<th${h[0] === '#' ? ' class="num"' : ''}>${esc(h.replace(/^#/, ''))}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
const visNos = () => (S.query && S.query.test || S.flowFilter || S.pktSet || S.timeRange) ? new Set(S.vis.map(p => p.no)) : null;

/* =============== GRAFİK =============== */
const CH = { metric: 'bytes', bucket: 'auto', stack: true };
const METRICS = {
  bytes: { label: 'Veri (bayt/sn)', f: p => p.len, fmt: v => fmtB(v) + '/sn' },
  pkts: { label: 'Paket/sn', f: () => 1, fmt: v => (v < 10 ? v.toFixed(1) : Math.round(v)) + ' paket/sn' },
  probs: { label: 'Sorun belirtisi/sn', f: p => p.anoms.filter(a => a !== 'dns-nx').length, fmt: v => v.toFixed(1) + '/sn' },
  retrans: { label: 'Yeniden iletim/sn', f: p => p.anoms.includes('retrans') ? 1 : 0, fmt: v => v.toFixed(1) + '/sn' },
};
function niceBucket(dur) { const c = [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 300, 600]; return c.find(x => x >= dur / 70) || 600; }
function renderCharts(v) {
  const A = S.A, pk = S.visPre, dur = Math.max(A.t1 - A.t0, 1e-6), M = METRICS[CH.metric];
  let bs = CH.bucket === 'auto' ? niceBucket(dur) : +CH.bucket; if (dur / bs > 500) bs = niceBucket(dur);
  const nb = Math.max(1, Math.ceil(dur / bs));
  const top = A.apps.slice(0, 6).map(a => a.app), keys = CH.stack ? top.concat(A.apps.length > 6 ? ['Diğer'] : []) : ['Toplam'];
  const ser = {}; keys.forEach(k => ser[k] = new Array(nb).fill(0)); const tot = new Array(nb).fill(0);
  for (const p of pk) {
    const i = Math.min(nb - 1, Math.floor((p.ts - A.t0) / bs)), val = M.f(p); if (!val) continue;
    const app = A.flows[p.flow - 1].app, key = CH.stack ? (top.includes(app) ? app : 'Diğer') : 'Toplam';
    ser[key][i] += val; tot[i] += val;
  }
  const W = Math.max(360, Math.round(v.clientWidth - 34)), H = 300, l = 64, rm = 10, tp = 14, bt = 34, pw = W - l - rm, ph = H - tp - bt;
  const max = Math.max(1e-9, ...tot) / bs, bw = pw / nb;
  const yAt = val => tp + ph - (val / max) * ph, xT = t => l + t / dur * pw;
  let g = '';
  for (let k = 0; k <= 4; k++) { const val = max * k / 4, y = yAt(val); g += `<line x1="${l}" x2="${W - rm}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${l - 6}" y="${y + 3}" text-anchor="end">${esc(M.fmt(val).replace(/\/sn$/, ''))}</text>`; }
  const acc = new Array(nb).fill(0);
  keys.forEach(k => ser[k].forEach((val, i) => {
    if (!val) return; const h = val / bs / max * ph, y = tp + ph - acc[i] - h; acc[i] += h;
    g += `<rect x="${(l + i * bw + 0.5).toFixed(1)}" y="${y.toFixed(1)}" width="${Math.max(1, bw - 1).toFixed(1)}" height="${Math.max(0.8, h).toFixed(1)}" fill="${CH.stack ? appColor(k) : 'var(--c0)'}"/>`;
  }));
  for (let k = 0; k <= 6; k++) { const t = dur * k / 6; g += `<text x="${xT(t)}" y="${H - 12}" text-anchor="${k === 0 ? 'start' : k === 6 ? 'end' : 'middle'}">${fmtT(t)}</text>`; }
  const sel = S.timeRange ? `<rect x="${xT(S.timeRange[0])}" y="${tp}" width="${Math.max(2, xT(S.timeRange[1]) - xT(S.timeRange[0]))}" height="${ph}" fill="var(--accent)" opacity=".16" stroke="var(--accent)"/>` : '';
  v.innerHTML = `<div class="toolbar">
    <label class="muted">Ölçü <select id="chm">${Object.entries(METRICS).map(([k, m]) => `<option value="${k}" ${CH.metric === k ? 'selected' : ''}>${m.label}</option>`).join('')}</select></label>
    <label class="muted">Aralık <select id="chb"><option value="auto">Otomatik (${fmtT(bs)})</option>${[0.1, 1, 5, 10, 60].map(x => `<option value="${x}" ${String(CH.bucket) === String(x) ? 'selected' : ''}>${fmtT(x)}</option>`).join('')}</select></label>
    <label class="muted"><input type="checkbox" id="chs" ${CH.stack ? 'checked' : ''}> Uygulamaya göre renklendir</label>
    ${S.timeRange ? '<button class="btn sm" data-act="cleartime">Aralık seçimini temizle</button><button class="btn sm primary" data-act="vgoflows">Seçili aralıktaki bağlantıları gör</button>' : ''}</div>
  <div class="card" style="position:relative"><div class="muted small" style="margin-bottom:6px">Grafik üzerinde <b>sürükleyerek</b> bir zaman aralığı seçin: tüm sekmeler o aralığa göre filtrelenir. ${pk.length.toLocaleString('tr')} paket gösteriliyor.</div>
    <svg id="chsvg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="display:block;touch-action:none;cursor:crosshair" role="img" aria-label="Zamana göre ${esc(M.label)}"><g style="font-size:10px;fill:var(--muted)">${g}</g>${sel}<rect id="chsel" x="0" y="${tp}" width="0" height="${ph}" fill="var(--accent)" opacity=".2"/><line id="chcur" y1="${tp}" y2="${tp + ph}" stroke="var(--text)" opacity=".4" visibility="hidden"/></svg>
    <div id="chtip" class="tip" hidden></div>
    ${CH.stack ? `<div class="legend">${keys.map(k => `<span><i class="dot" style="background:${appColor(k)}"></i>${esc(k)}</span>`).join('')}</div>` : ''}</div>`;
  $('#chm').onchange = e => { CH.metric = e.target.value; renderCharts(v); };
  $('#chb').onchange = e => { CH.bucket = e.target.value; renderCharts(v); };
  $('#chs').onchange = e => { CH.stack = e.target.checked; renderCharts(v); };
  const svg = $('#chsvg'), tip = $('#chtip'), selr = $('#chsel'), cur = $('#chcur');
  let drag = null; const xOf = e => { const b = svg.getBoundingClientRect(); return Math.max(l, Math.min(W - rm, e.clientX - b.left)); };
  const tOf = x => Math.max(0, Math.min(dur, (x - l) / pw * dur));
  svg.addEventListener('pointermove', e => {
    const x = xOf(e), t = tOf(x), i = Math.min(nb - 1, Math.floor(t / bs));
    cur.setAttribute('x1', x); cur.setAttribute('x2', x); cur.setAttribute('visibility', 'visible');
    const parts = CH.stack ? keys.filter(k => ser[k][i]).map(k => `<i class="dot" style="background:${appColor(k)}"></i>${esc(k)}: ${esc(M.fmt(ser[k][i] / bs))}`).join('<br>') : '';
    tip.hidden = false; tip.innerHTML = `<b>${fmtT(i * bs)} – ${fmtT((i + 1) * bs)}</b><br>${esc(M.fmt(tot[i] / bs))}${parts ? '<br>' + parts : ''}`;
    tip.style.left = Math.max(0, Math.min(x + 12, W - 200)) + 'px'; tip.style.top = '40px';
    if (drag) { drag.x1 = x; const a = Math.min(drag.x0, x), b = Math.max(drag.x0, x); selr.setAttribute('x', a); selr.setAttribute('width', b - a); }
  });
  svg.addEventListener('pointerdown', e => { const x = xOf(e); drag = { x0: x, x1: x }; svg.setPointerCapture(e.pointerId); });
  svg.addEventListener('pointerup', e => {
    if (drag && Math.abs(drag.x1 - drag.x0) > 4) { const a = tOf(Math.min(drag.x0, drag.x1)), b = tOf(Math.max(drag.x0, drag.x1)); S.timeRange = [a, b]; X.computeVisible(); X.render(); }
    else if (drag) { selr.setAttribute('width', 0); }
    drag = null;
  });
  svg.addEventListener('pointerleave', () => { tip.hidden = true; cur.setAttribute('visibility', 'hidden'); });
}

/* =============== HARİTA =============== */
const MP = { n: 30, localOnly: false };
function forceLayout(nodes, edges, W, H) {
  const n = nodes.length; if (!n) return;
  const k = Math.sqrt(W * H / n) * 0.9, idx = new Map(nodes.map((d, i) => [d.id, i]));
  nodes.forEach((d, i) => { const a = 2 * Math.PI * i / n; d.x = W / 2 + Math.cos(a) * W * 0.3; d.y = H / 2 + Math.sin(a) * H * 0.3; });
  for (let it = 0; it < 300; it++) {
    const t = 1 - it / 300, step = (W / 10) * t + 1, dx = new Float64Array(n), dy = new Float64Array(n);
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
      const ex = nodes[i].x - nodes[j].x, ey = nodes[i].y - nodes[j].y, d = Math.hypot(ex, ey) || 0.01, f = (k * k) / d;
      dx[i] += ex / d * f; dy[i] += ey / d * f; dx[j] -= ex / d * f; dy[j] -= ey / d * f;
    }
    for (const e of edges) {
      const i = idx.get(e.a), j = idx.get(e.b), ex = nodes[i].x - nodes[j].x, ey = nodes[i].y - nodes[j].y, d = Math.hypot(ex, ey) || 0.01, f = (d * d) / k * (0.2 + e.w * 0.8);
      dx[i] -= ex / d * f; dy[i] -= ey / d * f; dx[j] += ex / d * f; dy[j] += ey / d * f;
    }
    for (let i = 0; i < n; i++) {
      dx[i] -= (nodes[i].x - W / 2) * 0.08; dy[i] -= (nodes[i].y - H / 2) * 0.08;
      const d = Math.hypot(dx[i], dy[i]) || 1, m = Math.min(d, step), px = nodes[i].r + 46, py = nodes[i].r + 18;
      nodes[i].x = Math.max(px, Math.min(W - px, nodes[i].x + dx[i] / d * m)); nodes[i].y = Math.max(py, Math.min(H - py - 22, nodes[i].y + dy[i] / d * m));
    }
  }
}
function renderMap(v) {
  const A = S.A, hosts = new Map(), edges = new Map(), isIP = s => /^\d+\.\d+\.\d+\.\d+$/.test(s) || (s.includes(':') && !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s));
  for (const p of S.vis) {
    if (!isIP(p.src) || !isIP(p.dst)) continue;
    for (const ip of [p.src, p.dst]) { let h = hosts.get(ip); if (!h) hosts.set(ip, h = { id: ip, bytes: 0, pk: 0 }); h.bytes += p.len; h.pk++; }
    const k = p.src < p.dst ? p.src + '|' + p.dst : p.dst + '|' + p.src; let e = edges.get(k); if (!e) edges.set(k, e = { a: p.src < p.dst ? p.src : p.dst, b: p.src < p.dst ? p.dst : p.src, bytes: 0, bad: 0 }); e.bytes += p.len; if (p._s === 'bad') e.bad++;
  }
  const bad = new Set();
  for (const pr of A.problems) if (pr.sev !== 'low') { if (pr.flow) { const f = A.flows[pr.flow - 1]; bad.add(f.a); bad.add(f.b); } else if (pr.pkts.length) { const p = A.packets[pr.pkts[0] - 1]; if (p) bad.add(p.src); } }
  let list = [...hosts.values()]; if (MP.localOnly) list = list.filter(h => PL.isPrivate(h.id));
  list.sort((a, b) => b.bytes - a.bytes); list = list.slice(0, MP.n);
  const keep = new Set(list.map(h => h.id)), el = [...edges.values()].filter(e => keep.has(e.a) && keep.has(e.b));
  const W = Math.max(360, Math.min(1100, Math.round(v.clientWidth - 34))), H = 620, maxB = Math.max(1, ...list.map(h => h.bytes)), maxE = Math.max(2, ...el.map(e => e.bytes));
  list.forEach(h => { h.r = 7 + Math.sqrt(h.bytes / maxB) * 20; });
  el.forEach(e => { e.w = Math.log(e.bytes + 1) / Math.log(maxE + 1); });
  forceLayout(list, el, W, H);
  const pos = new Map(list.map(h => [h.id, h]));
  const lines = el.map(e => { const a = pos.get(e.a), b = pos.get(e.b); return `<line x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}" stroke="${e.bad ? 'var(--high)' : 'var(--cx)'}" stroke-width="${(1 + e.w * 4).toFixed(1)}" opacity="${e.bad ? .75 : .45}"><title>${esc(nm(e.a))} ↔ ${esc(nm(e.b))}: ${fmtB(e.bytes)}</title></line>`; }).join('');
  const placed = [], hit = (b) => placed.some(q => b.x1 < q.x2 && b.x2 > q.x1 && b.y1 < q.y2 && b.y2 > q.y1);
  const dots = list.map(h => {
    const loc = PL.isPrivate(h.id), host = A.hosts.get(h.id), fl = host ? host.flows.size : 0, label = short(nm(h.id), 22), w = label.length * 6.1 / 2;
    let ly = h.y + h.r + 12, box = { x1: h.x - w, x2: h.x + w, y1: ly - 10, y2: ly + 3 };
    if (hit(box)) { ly = h.y - h.r - 6; box = { x1: h.x - w, x2: h.x + w, y1: ly - 10, y2: ly + 3 }; }
    const show = !hit(box); if (show) placed.push(box);
    return `<g class="mapnode" data-act="vnode" data-v="${esc(h.id)}" style="cursor:pointer"><circle cx="${h.x.toFixed(1)}" cy="${h.y.toFixed(1)}" r="${h.r.toFixed(1)}" fill="${loc ? 'var(--c0)' : 'var(--cx)'}" opacity=".9" stroke="${bad.has(h.id) ? 'var(--high)' : 'var(--surface)'}" stroke-width="${bad.has(h.id) ? 4 : 2}"/>
      ${show ? `<text x="${h.x.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="middle" style="font-size:11px;fill:var(--text);paint-order:stroke;stroke:var(--surface);stroke-width:3px">${esc(label)}</text>` : ''}
      <title>${esc(nm(h.id))}${nm(h.id) !== h.id ? ' (' + esc(h.id) + ')' : ''}\n${loc ? T('yerel ağ') : 'internet'}${host && host.os ? ' · ' + T('tahmini:') + ' ' + esc(T(host.os)) : ''}\n${fmtB(h.bytes)} · ${h.pk} ${T('paket')} · ${fl} ${T('bağlantı')}${bad.has(h.id) ? '\n⚠ ' + T('sorunlu') : ''}</title></g>`;
  }).join('');
  v.innerHTML = `<div class="toolbar"><label class="muted">Gösterilen cihaz <select id="mpn">${[15, 30, 60, 100].map(n => `<option ${MP.n === n ? 'selected' : ''}>${n}</option>`).join('')}</select></label>
    <label class="muted"><input type="checkbox" id="mpl" ${MP.localOnly ? 'checked' : ''}> Sadece yerel ağ</label><span class="muted small">${list.length} cihaz, ${el.length} bağlantı. Bir cihaza tıklayarak o cihazın trafiğine odaklanın.</span></div>
  <div class="card" style="overflow:auto">${list.length ? `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="display:block;margin:auto" role="img" aria-label="Cihazlar arası ağ haritası">${lines}${dots}</svg>
  <div class="legend"><span><i class="dot" style="background:var(--c0)"></i>yerel cihaz</span><span><i class="dot" style="background:var(--cx)"></i>internet</span><span><i class="dot" style="background:var(--high)"></i>kırmızı halka / çizgi: sorunlu</span><span>daire boyutu = veri miktarı, çizgi kalınlığı = trafik</span></div>` : '<div class="empty-note">Bu filtreyle gösterilecek cihaz yok.</div>'}</div>`;
  $('#mpn').onchange = e => { MP.n = +e.target.value; renderMap(v); };
  $('#mpl').onchange = e => { MP.localOnly = e.target.checked; renderMap(v); };
}

/* =============== İSTATİSTİK =============== */
function renderStats(v) {
  const A = S.A, st = PL.stats(A), hosts = [...A.hosts.values()].filter(h => /^\d|:/.test(h.ip) && !/^([0-9a-f]{2}:){5}/i.test(h.ip)).sort((a, b) => (b.bytesTx + b.bytesRx) - (a.bytesTx + a.bytesRx)).slice(0, 12);
  const maxL = Math.max(1, ...st.lenHist.map(b => b.pkts)), tcp = st.tcp, dns = st.dns, http = st.http;
  v.innerHTML = `<div class="grid g2">
  <div class="card"><h3>Protokol hiyerarşisi <small>paketlerin hangi katmanlardan oluştuğu</small></h3>${table(['Protokol', '#Paket', '#Veri', '#Oran'], st.hier.map(r => `<tr><td style="padding-left:${10 + r.d * 18}px">${esc(r.name)}</td><td class="num">${r.pkts}</td><td class="num">${fmtB(r.bytes)}</td><td class="num">${pct(r.bytes, st.total.bytes)}</td></tr>`))}</div>
  <div class="card"><h3>Paket boyutu dağılımı</h3><div class="bars">${st.lenHist.map(b => `<div class="bar"><span class="nm">${b.lo}–${b.hi === Infinity ? '…' : b.hi} B</span><span class="track"><span class="fill" style="display:block;width:${b.pkts / maxL * 100}%;background:var(--c0)"></span></span><span class="val">${b.pkts}</span></div>`).join('')}</div>
    <h3 style="margin-top:18px">TCP sağlığı</h3><div class="muted">El sıkışma süresi: ${tcp.n ? `en az <b>${tcp.min.toFixed(0)} ms</b>, ortanca <b>${tcp.med.toFixed(0)} ms</b>, %95 <b>${tcp.p95.toFixed(0)} ms</b>, en çok <b>${tcp.max.toFixed(0)} ms</b> (${tcp.n} bağlantı)` : 'veri yok'}<br>Yeniden iletim: <b>${tcp.retrans}</b> · Sıfırlanan (RST) bağlantı: <b>${tcp.resets}</b></div></div>
  </div>
  <div class="card" style="margin-top:14px"><h3>En çok veri taşıyan konuşmalar <small>iki cihaz arasındaki toplam trafik</small></h3>${table(['Cihaz A', 'Cihaz B', '#Bağlantı', '#Paket', '#Veri', 'Sorun'], st.convs.slice(0, 12).map(c => `<tr data-act="try" data-v="${esc(c.a)}"><td>${esc(nm(c.a))}</td><td>${esc(nm(c.b))}</td><td class="num">${c.flows}</td><td class="num">${c.pkts}</td><td class="num">${fmtB(c.bytes)}</td><td>${c.probs ? `<span class="pill med">${c.probs}</span>` : ''}</td></tr>`))}</div>
  <div class="card" style="margin-top:14px"><h3>Cihazlar <small>işletim sistemi tahmini TTL ve TCP ayarlarına dayanır, kesin değildir</small></h3>${table(['Cihaz', 'Adres', 'Tahmini sistem', '#Gönderilen', '#Alınan', '#Bağlantı'], hosts.map(h => `<tr data-act="try" data-v="${esc(h.ip)}"><td>${esc(nm(h.ip))}</td><td class="mono">${esc(h.ip)}</td><td>${esc(h.os || '–')}</td><td class="num">${fmtB(h.bytesTx)}</td><td class="num">${fmtB(h.bytesRx)}</td><td class="num">${h.flows.size}</td></tr>`))}</div>
  <div class="grid g2" style="margin-top:14px">
    <div class="card"><h3>DNS özeti</h3><div class="muted">${dns.n} sorgu, ${dns.answered} yanıtlandı${dns.avg != null ? ` · ortalama <b>${dns.avg.toFixed(0)} ms</b>, en yavaş <b>${dns.max.toFixed(0)} ms</b>` : ''} · NXDOMAIN: <b>${dns.nx}</b></div>
      ${dns.top.length ? '<h3 style="margin-top:12px">En çok sorgulananlar</h3>' + table(['Alan adı', '#Sorgu'], dns.top.map(([n, c]) => `<tr><td class="mono">${esc(short(n, 48))}</td><td class="num">${c}</td></tr>`)) : ''}</div>
    <div class="card"><h3>HTTP özeti</h3>${http.n ? `<div class="muted">${http.n} istek, ${http.hosts} farklı sunucu</div>${table(['Durum kodu', '#Adet'], http.codes.map(([c, n]) => `<tr><td>${c}</td><td class="num">${n}</td></tr>`))}` : '<div class="muted">Şifresiz HTTP trafiği yok.</div>'}</div>
  </div>`;
}

/* =============== GÜNLÜKLER =============== */
function renderLogs(v) {
  const A = S.A, vn = visNos(), keep = n => !vn || vn.has(n);
  const tabs = [['dns', 'DNS'], ['http', 'HTTP'], ['tls', 'TLS'], ['files', 'Dosyalar'], ['cred', 'Şifresiz oturumlar']];
  const t0 = A.t0, rc = { 0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };
  let body = '';
  if (S.logTab === 'dns') {
    const l = PL.dnsLog(A).filter(e => keep(e.no));
    body = l.length ? table(['Zaman', 'İstemci', 'Sorgu', 'Tür', 'Sonuç', 'Yanıt', '#Süre'], l.slice(0, 1500).map(e => `<tr data-act="vpkt" data-v="${e.no}"><td class="mono">${(e.t - t0).toFixed(3)}</td><td>${esc(nm(e.client))}</td><td class="mono">${esc(short(e.name, 52))}</td><td>${esc(PL.QTYPE[e.qtype] || e.qtype)}</td>
      <td>${e.answered ? `<span class="pill ${e.rcode === 0 ? 'ok' : e.rcode === 3 ? 'low' : 'high'}">${rc[e.rcode] || e.rcode}</span>` : (e.app === 'mDNS' ? '<span class="muted">yayın</span>' : '<span class="pill high">yanıtsız</span>')}</td><td class="mono">${esc(short(e.answers.join(', '), 40))}</td><td class="num">${e.latency != null ? `<span class="${e.latency > 0.25 ? 'slow' : ''}">${Math.round(e.latency * 1000)} ms</span>` : ''}</td></tr>`)) : '<div class="empty-note">DNS kaydı yok.</div>';
  } else if (S.logTab === 'http') {
    const l = PL.httpLog(A).filter(e => keep(e.no));
    body = l.length ? table(['Zaman', 'İstemci', 'Sunucu', 'Yöntem', 'Yol', 'Durum', 'Tür', '#Boyut', '#Süre'], l.map(e => `<tr data-act="vpkt" data-v="${e.no}"><td class="mono">${(e.t - t0).toFixed(3)}</td><td>${esc(nm(e.client))}</td><td>${esc(e.host)}</td><td><b>${esc(e.method)}</b></td><td class="mono">${esc(short(e.path, 40))}</td>
      <td>${e.status != null ? `<span class="pill ${e.status < 300 ? 'ok' : e.status < 400 ? 'low' : 'high'}">${e.status}</span>` : ''}</td><td>${esc(short(e.ctype || '', 24))}</td><td class="num">${e.size != null ? fmtB(e.size) : ''}</td><td class="num">${e.latency != null ? Math.round(e.latency * 1000) + ' ms' : ''}</td></tr>`)) : '<div class="empty-note">Şifresiz HTTP isteği yok (HTTPS içeriği görünmez).</div>';
  } else if (S.logTab === 'tls') {
    const l = PL.tlsLog(A).filter(e => keep(e.no));
    body = l.length ? table(['Zaman', 'İstemci', 'Site (SNI)', 'QUIC', 'ECH', 'JA3/JA4', 'Sürüm', 'Şifre', 'ALPN', 'Sertifika', '#El sık.', 'Not'], l.map(e => `<tr data-act="flow" data-v="${e.flow}"><td class="mono">${(e.t - t0).toFixed(3)}</td><td>${esc(nm(e.client))}</td><td>${esc(e.sni || nm(e.server))}</td>
      <td>${e.quic ? '<span class="pill ok">QUIC</span>' : ''}</td><td>${e.ech ? '<span class="pill low">ECH</span>' : ''}</td>
      <td class="mono small">${esc((e.ja4 || e.ja3Hash || '').slice(0, 22))}</td>
      <td>${e.version != null ? esc(PL.TLSV[e.version] || '?') : '<span class="muted">?</span>'}</td><td class="mono">${e.cipher != null ? esc(PL.cipherName(e.cipher)) : ''}</td><td>${esc(e.alpn.join(', '))}</td>
      <td class="small">${e.cert ? esc(short(e.cert.subject, 24)) + (e.cert.issuer ? '<br><span class="muted">' + esc(short(e.cert.issuer, 24)) + '</span>' : '') : ''}</td><td class="num">${e.hsMs != null ? Math.round(e.hsMs) + ' ms' : ''}</td><td>${e.weak.length ? `<span class="pill med" title="${esc(e.weak.join('; '))}">!</span>` : ''}</td></tr>`)) : '<div class="empty-note">TLS el sıkışması yakalanmadı.</div>';
  } else if (S.logTab === 'files') {
    body = X.extra.filesHTML ? X.extra.filesHTML() : '';
  } else {
    const l = (A.creds || []).filter(c => keep(c.no));
    body = `<div class="banner warn" style="margin-bottom:12px"><span style="font-size:20px">!</span><div><b>Parolalar maskelenir</b><span class="muted">Yalnızca şifresiz gönderildiği tespit edilir; tam parola saklanmaz ve gösterilmez.</span></div></div>` +
      (l.length ? table(['Protokol', 'Kullanıcı', 'Parola (maskeli)', 'Bağlantı'], l.map(c => `<tr data-act="vpkt" data-v="${c.no}"><td><span class="pill high">${esc(c.proto)}</span></td><td>${esc(c.user)}</td><td class="mono">${esc(c.pass)}</td><td>${esc(nm(A.flows[c.flow - 1].client))} → ${esc(nm(A.flows[c.flow - 1].server))}</td></tr>`)) : '<div class="empty-note">✓ Şifresiz kimlik bilgisi tespit edilmedi.</div>');
  }
  v.innerHTML = `<div class="toolbar">${tabs.map(([k, t]) => `<button class="chip ${S.logTab === k ? 'on' : ''}" data-act="vlog" data-v="${k}">${t}</button>`).join('')}</div>${body}`;
}

/* =============== AKIŞ TAKİBİ =============== */
const ST = { r: null, mode: 'ascii', dir: 'all' };
const printable = u8 => { let s = ''; for (let i = 0; i < u8.length; i++) { const c = u8[i]; s += (c >= 32 && c < 127) || c === 10 || c === 9 ? String.fromCharCode(c) : c === 13 ? '' : '.'; } return s; };
function hexLines(u8) { const n = Math.min(u8.length, 8192), out = []; for (let o = 0; o < n; o += 16) { let h = '', a = ''; for (let i = 0; i < 16; i++) { if (o + i < n) { const c = u8[o + i]; h += c.toString(16).padStart(2, '0') + ' '; a += c >= 32 && c < 127 ? String.fromCharCode(c) : '.'; } else h += '   '; if (i === 7) h += ' '; } out.push(o.toString(16).padStart(4, '0') + '  ' + h + ' ' + a); } return out.join('\n') + (u8.length > n ? `\n… (${u8.length - n} bayt daha)` : ''); }
function streamText(seg) { return ST.mode === 'hex' ? hexLines(seg.bytes) : ST.mode === 'raw' ? Array.from(seg.bytes.subarray(0, 8192)).map(b => b.toString(16).padStart(2, '0')).join('') : printable(seg.bytes); }
function openStream(id) {
  ST.r = PL.followStream(S.A, id); ST.mode = 'ascii'; ST.dir = 'all';
  let m = $('#modal'); if (!m) { m = document.createElement('div'); m.id = 'modal'; document.body.appendChild(m); }
  m.hidden = false; renderStream();
}
function renderStream() {
  const r = ST.r, f = r.flow, m = $('#modal'), t0 = S.A.t0;
  const segs = r.segs.filter(s => s.gap || ST.dir === 'all' || s.dir === ST.dir);
  const blocks = segs.map(s => s.gap ? `<div class="gapseg">[… ${s.gap} bayt eksik: paket kaybı veya yakalanmadı]</div>` :
    `<div class="sseg ${s.dir}"><div class="seghead">${s.dir === 'AB' ? '→ istemciden sunucuya' : '← sunucudan istemciye'} · ${(s.t - t0).toFixed(3)} sn · paket #${s.no} · ${fmtB(s.bytes.length)}</div><pre>${esc(streamText(s))}</pre></div>`).join('');
  m.innerHTML = `<div class="modal-bg" data-act="vclose"></div><div class="modal" role="dialog" aria-label="Akışı takip et"><div class="modal-head"><div><b>${esc(nm(f.client))}${f.aPort != null ? ':' + f.aPort : ''} ⇄ ${esc(nm(f.server))}${f.bPort != null ? ':' + f.bPort : ''}</b>
    <div class="muted small">${f.app} · <span class="cl">istemci → sunucu ${fmtB(r.bytes.AB)}</span> · <span class="sv">sunucu → istemci ${fmtB(r.bytes.BA)}</span>${r.truncated ? ' · <b>çok büyük, kısaltıldı</b>' : ''}</div></div><button class="btn sm" data-act="vclose">${T('Kapat')}</button></div>
    <div class="toolbar" style="margin:0;padding:8px 14px"><label class="muted">Görünüm <select id="stm"><option value="ascii" ${ST.mode === 'ascii' ? 'selected' : ''}>ASCII</option><option value="hex" ${ST.mode === 'hex' ? 'selected' : ''}>Hex dökümü</option><option value="raw" ${ST.mode === 'raw' ? 'selected' : ''}>Ham hex</option></select></label>
    <label class="muted">Yön <select id="std"><option value="all" ${ST.dir === 'all' ? 'selected' : ''}>İki yön</option><option value="AB" ${ST.dir === 'AB' ? 'selected' : ''}>Sadece istemci →</option><option value="BA" ${ST.dir === 'BA' ? 'selected' : ''}>Sadece sunucu →</option></select></label>
    <button class="btn sm" data-act="vcopy">Kopyala</button><button class="btn sm" data-act="vsave">İndir (.txt)</button></div>
    <div class="modal-body">${blocks || '<div class="empty-note">Bu akışta uygulama verisi yok.</div>'}</div></div>`;
  $('#stm').onchange = e => { ST.mode = e.target.value; renderStream(); };
  $('#std').onchange = e => { ST.dir = e.target.value; renderStream(); };
}
const streamPlain = () => ST.r.segs.filter(s => s.gap || ST.dir === 'all' || s.dir === ST.dir).map(s => s.gap ? `[… ${s.gap} bayt eksik]` : `${s.dir === 'AB' ? '>>>' : '<<<'} ${streamText(s)}`).join('\n');

/* =============== SIRA DİYAGRAMI + TLS PANELİ =============== */
function seqLabel(p) {
  if (p.proto === 'TCP') {
    const fl = p.flags; if ((fl & 2) && (fl & 16)) return 'SYN-ACK'; if (fl & 2) return 'SYN'; if (fl & 4) return 'RST'; if (fl & 1) return 'FIN';
    if (p.payloadLen) return p.tls ? short(p.info.replace(/^TLS\s*/, ''), 26) : p.http ? short(p.http.first, 26) : p.payloadLen + ' B';
    return 'ACK';
  }
  if (p.dns) return (p.dns.qr ? 'Yanıt ' : 'Sorgu ') + short(p.dns.questions[0] ? p.dns.questions[0].name : '', 18);
  return short(p.info, 26);
}
function seqSVG(f) {
  const A = S.A, MAXR = 40, W = 500, x1 = 120, x2 = 380, y0 = 54, RH = 24, pk = f.pnos.slice(0, MAXR).map(n => A.packets[n - 1]), H = y0 + pk.length * RH + 28;
  let g = `<defs><marker id="ah" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L8,4 L0,8 z" fill="context-stroke"/></marker></defs>
    <text x="${x1}" y="16" text-anchor="middle" style="font-weight:600">${esc(short(nm(f.client), 20))}</text><text x="${x2}" y="16" text-anchor="middle" style="font-weight:600">${esc(short(nm(f.server), 20))}</text>
    <text x="${x1}" y="29" text-anchor="middle" class="sm">istemci</text><text x="${x2}" y="29" text-anchor="middle" class="sm">sunucu</text>
    <line x1="${x1}" x2="${x1}" y1="36" y2="${H - 10}" stroke="var(--line)" stroke-width="2"/><line x1="${x2}" x2="${x2}" y1="36" y2="${H - 10}" stroke="var(--line)" stroke-width="2"/>`;
  pk.forEach((p, i) => {
    const y = y0 + i * RH, ab = (p.src === f.a && p.sport === f.aPort), sa = ab ? x1 : x2, sb = ab ? x2 : x1, col = p._s === 'bad' ? 'var(--high)' : p._s === 'warn' ? 'var(--med)' : 'var(--text)';
    g += `<text x="4" y="${y + 4}" class="sm">+${(p.ts - f.start).toFixed(3)}</text><line x1="${sa + (ab ? 2 : -2)}" y1="${y}" x2="${sb + (ab ? -4 : 4)}" y2="${y}" stroke="${col}" stroke-width="1.5" ${p.anoms.includes('retrans') ? 'stroke-dasharray="4 3"' : ''} marker-end="url(#ah)"/>
      <text x="${(x1 + x2) / 2}" y="${y - 4}" text-anchor="middle" style="fill:${col}">${esc(seqLabel(p))}</text>`;
  });
  if (f.pnos.length > MAXR) g += `<text x="${W / 2}" y="${H - 4}" text-anchor="middle" class="sm">… ${f.pnos.length - MAXR} paket daha</text>`;
  return `<div class="seq"><svg width="100%" viewBox="0 0 ${W} ${H}" style="max-width:${W}px" role="img" aria-label="Paket sıra diyagramı"><g style="font-size:11px;fill:var(--text)">${g}</g></svg></div>`;
}
function tlsHTML(f) {
  const e = PL.tlsLog(S.A).find(x => x.flow === f.id); if (!e) return '';
  const row = (k, val) => val ? `<tr><td class="muted">${k}</td><td>${val}</td></tr>` : '';
  return `<h3>TLS ayrıntıları</h3><div class="card" style="padding:8px 12px;margin-bottom:12px"><table class="t kv"><tbody>
    ${row('Site (SNI)', esc(e.sni || ''))}${row('Sürüm', e.version != null ? esc(PL.TLSV[e.version] || '?') : '')}${row('Önerilen sürümler', e.offered.map(x => esc(PL.TLSV[x] || '?')).join(', '))}
    ${row('Şifre takımı', e.cipher != null ? '<span class="mono">' + esc(PL.cipherName(e.cipher)) + '</span>' : '')}${row('Önerilen şifre sayısı', e.ciphers.length ? String(e.ciphers.length) : '')}${row('ALPN', esc(e.alpn.join(', ')))}
    ${row('Sertifika sahibi', e.cert ? esc(e.cert.subject) : '')}${row('Sertifikayı veren', e.cert ? esc(e.cert.issuer) : '')}${e.cert && e.cert.sans && e.cert.sans.length ? row('SAN', esc(e.cert.sans.slice(0, 6).join(', '))) : ''}${e.cert && e.cert.notAfter ? row('Geçerlilik bitiş', esc(e.cert.notAfter)) : ''}
    ${row('JA3', esc(e.ja3Hash || ''))}${row('JA4', esc(e.ja4 || ''))}${row('ECH', e.ech ? 'evet' : 'hayır')}${row('QUIC', e.quic ? 'evet' : 'hayır')}${row('El sıkışma süresi', e.hsMs != null ? Math.round(e.hsMs) + ' ms' : '')}
    ${row('Uyarı', e.weak.length ? '<span class="pill med">' + esc(e.weak.join('; ')) + '</span>' : '')}</tbody></table></div>`;
}

/* =============== OLAYLAR =============== */
document.addEventListener('click', ev => {
  const el = ev.target.closest('[data-act]'); if (!el || !/^v/.test(el.dataset.act)) return;
  const act = el.dataset.act, val = el.dataset.v;
  if (el.tagName === 'A') ev.preventDefault();
  if (act === 'vfollow') { X.closeDrawer(); openStream(+val); }
  else if (act === 'vclose') { $('#modal').hidden = true; }
  else if (act === 'vcopy') { try { navigator.clipboard.writeText(streamPlain()); toast('Kopyalandı'); } catch (e) { toast('Kopyalanamadı'); } }
  else if (act === 'vsave') { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([streamPlain()], { type: 'text/plain' })); a.download = `akis-${ST.r.flow.id}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }
  else if (act === 'vlog') { S.logTab = val; X.render(); }
  else if (act === 'vnode') { X.setQuery(val); }
  else if (act === 'vpkt') { if (S.mode === 'adv') X.goPacket(+val); }
  else if (act === 'vgoflows') { S.tab = 'flows'; X.render(); }
});

Object.assign(X.views, { charts: renderCharts, map: renderMap, stats: renderStats, logs: renderLogs });
Object.assign(X.extra, { seqSVG, tlsHTML, openStream });
})();
