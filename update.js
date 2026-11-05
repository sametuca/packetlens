/* PacketLens - güncelleme kontrolü: GitHub'daki main dalında yeni commit varsa üstte bir bant gösterir. */
(function () {
'use strict';
const X = window.PLApp; if (!X) return;
const { $, toast, S, api } = X;
const T = s => (window.PLI ? window.PLI.t(s) : s);
const REPO = 'sametuca/packetlens';
const DISMISS_KEY = 'pl-update-dismiss';

let installing = false;
let progressTimer = null;

function setProgress(mode, pct) {
  const bar = $('#update-bar-progress'), fill = $('#update-bar-progress-fill');
  if (!bar || !fill) return;
  bar.hidden = false;
  if (mode === 'indeterminate') {
    bar.classList.add('indeterminate');
    fill.style.width = '';
    bar.setAttribute('aria-valuenow', '0');
    return;
  }
  bar.classList.remove('indeterminate');
  const p = Math.max(0, Math.min(100, pct || 0));
  fill.style.width = p + '%';
  bar.setAttribute('aria-valuenow', String(Math.round(p)));
}

function hideProgress() {
  const bar = $('#update-bar-progress'), st = $('#update-bar-status');
  if (bar) { bar.hidden = true; bar.classList.remove('indeterminate'); }
  if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
  if (st) st.hidden = true;
}

function setStatus(msg) {
  const st = $('#update-bar-status');
  if (!st) return;
  if (msg) { st.textContent = msg; st.hidden = false; }
  else st.hidden = true;
}

function show(localSha, remoteSha) {
  const bar = $('#update-bar'); if (!bar) return;
  bar.dataset.local = localSha;
  bar.dataset.sha = remoteSha;
  const txt = $('#update-bar-text');
  if (txt) txt.textContent = `🔔 ${T('Yeni bir PacketLens güncellemesi var')} (${localSha.slice(0, 7)} → ${remoteSha.slice(0, 7)})`;
  const a = $('#update-bar-link'); if (a) a.href = `https://github.com/${REPO}/compare/${localSha}...main`;
  const btn = $('#update-bar-install');
  if (btn) { btn.hidden = false; btn.disabled = false; btn.textContent = T('Güncelle'); }
  hideProgress();
  bar.hidden = false;
}

async function check(localCommit) {
  if (!localCommit || typeof localCommit !== 'string') return;
  let dismissed = ''; try { dismissed = localStorage.getItem(DISMISS_KEY) || ''; } catch (e) { /* yok say */ }
  try {
    const ctrl = new AbortController(); const tm = setTimeout(() => ctrl.abort(), 6000);
    const r = await fetch(`https://api.github.com/repos/${REPO}/commits/main`, { headers: { Accept: 'application/vnd.github+json' }, signal: ctrl.signal });
    clearTimeout(tm);
    if (!r.ok) return;
    const j = await r.json();
    const sha = j && j.sha;
    if (!sha || sha === localCommit || sha === dismissed) return;
    show(localCommit, sha);
  } catch (e) { /* internet yok ya da GitHub'a ulaşılamadı: sessizce geç */ }
}

async function installUpdate() {
  if (installing) return;
  const bar = $('#update-bar'), btn = $('#update-bar-install');
  if (!bar || bar.hidden) return;
  if (S && S.live && S.live.running) { toast(T('Canlı yakalama açıkken güncelleme yapılamaz.')); return; }
  installing = true;
  if (btn) { btn.disabled = true; btn.textContent = T('Güncelleniyor…'); }
  setStatus(T('Depodan indiriliyor…'));
  setProgress('indeterminate');
  let fake = 8;
  progressTimer = setInterval(() => {
    if (fake < 88) fake += Math.random() * 6;
  }, 400);
  try {
    const { ok, j } = await api('/api/update/pull', { method: 'POST' });
    clearInterval(progressTimer); progressTimer = null;
    if (!ok || !j || j.ok === false) {
      const err = (j && j.error) ? j.error : T('Güncelleme başarısız.');
      setProgress('done', 0);
      hideProgress();
      setStatus('');
      if (btn) { btn.disabled = false; btn.textContent = T('Güncelle'); }
      toast(err);
      installing = false;
      return;
    }
    setProgress('done', 100);
    const nc = j.commit ? j.commit.slice(0, 7) : '—';
    setStatus(`${T('Güncelleme tamamlandı')} (${nc}) — ${T('sayfa yenileniyor…')}`);
    if (btn) btn.hidden = true;
    try { localStorage.removeItem(DISMISS_KEY); } catch (x) { /* yok say */ }
    if (S && S.srv) S.srv.commit = j.commit;
    toast(T('Güncelleme tamamlandı'));
    setTimeout(() => { location.reload(); }, 900);
  } catch (e) {
    clearInterval(progressTimer); progressTimer = null;
    hideProgress();
    setStatus('');
    if (btn) { btn.disabled = false; btn.textContent = T('Güncelle'); }
    toast(T('Sunucuya ulaşılamadı'));
    installing = false;
  }
}

document.addEventListener('click', e => {
  const el = e.target.closest('[data-act]'); if (!el) return;
  if (el.dataset.act === 'update-install') {
    e.preventDefault();
    installUpdate();
    return;
  }
  if (el.dataset.act !== 'update-dismiss') return;
  const bar = $('#update-bar'); if (!bar) return;
  try { localStorage.setItem(DISMISS_KEY, bar.dataset.sha || '1'); } catch (x) { /* yok say */ }
  bar.hidden = true;
  hideProgress();
  installing = false;
});

X.checkUpdate = check;
})();
