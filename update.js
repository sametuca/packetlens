/* PacketLens - güncelleme kontrolü: GitHub'daki main dalında yeni commit varsa üstte bir bant gösterir. */
(function () {
'use strict';
const X = window.PLApp; if (!X) return;
const { $ } = X;
const T = s => (window.PLI ? window.PLI.t(s) : s);
const REPO = 'sametuca/packetlens';
const DISMISS_KEY = 'pl-update-dismiss';

function show(localSha, remoteSha) {
  const bar = $('#update-bar'); if (!bar) return;
  bar.dataset.sha = remoteSha;
  const txt = $('#update-bar-text'); if (txt) txt.textContent = `🔔 ${T('Yeni bir PacketLens güncellemesi var')} (${localSha.slice(0, 7)} → ${remoteSha.slice(0, 7)})`;
  const a = $('#update-bar-link'); if (a) a.href = `https://github.com/${REPO}/compare/${localSha}...main`;
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

document.addEventListener('click', e => {
  if (!e.target.closest('[data-act="update-dismiss"]')) return;
  const bar = $('#update-bar'); if (!bar) return;
  try { localStorage.setItem(DISMISS_KEY, bar.dataset.sha || '1'); } catch (x) { /* yok say */ }
  bar.hidden = true;
});

X.checkUpdate = check;
})();
