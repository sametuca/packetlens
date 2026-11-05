/* PackageLens - dil desteği (i18n)
 *
 * Kaynak metinler Türkçedir. Başka bir dil seçilince ekrana basılan metinler sözlükle çevrilir
 * (lang-en.js). Çeviri iki yolla yapılır:
 *   1) birebir eşleşme:  'Sorunlar' -> 'Problems'
 *   2) kalıp eşleşmesi:  'Yeniden iletim ({} paket)' -> 'Retransmission ({1} packets)'
 *      {} sayıyı/adı yakalar, çeviride {1}, {2} … olarak yeniden kullanılır (sıra değişebilir).
 * Sayfadaki metin düğümleri ve title/placeholder/aria-label öznitelikleri otomatik çevrilir;
 * arayüz yeniden çizildiğinde MutationObserver yeni düğümleri çevirir. Türkçeye dönünce orijinaller geri yüklenir.
 */
(function (root) {
'use strict';
const PLI = { lang: 'tr', dict: new Map(), pats: [], tokens: [], cache: new Map(), langs: { tr: 'Türkçe', en: 'English' } };
const norm = s => String(s).replace(/\s+/g, ' ').trim();
const reEsc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

PLI.add = function (obj) {
  for (const k of Object.keys(obj)) {
    const key = norm(k), v = obj[k];
    if (key.includes('{}')) {
      const parts = key.split('{}');
      const re = new RegExp('^' + parts.map(reEsc).join('(.+?)') + '$', 's');
      PLI.pats.push({ re, en: v, lit: parts.join('').length, key });
    } else PLI.dict.set(key, v);
  }
  PLI.pats.sort((a, b) => b.lit - a.lit);
  PLI.cache.clear();
};
PLI.addTokens = function (list) { PLI.tokens = PLI.tokens.concat(list); PLI.cache.clear(); };

function tx(raw, depth) {
  const k = norm(raw);
  if (!k) return raw;
  let r = PLI.cache.get(k);
  if (r !== undefined) return r;
  r = PLI.dict.get(k);
  if (r === undefined && (depth || 0) < 4) {
    for (const p of PLI.pats) {
      const m = p.re.exec(k);
      if (m) { r = p.en.replace(/\{(\d+)\}/g, (_, i) => sub(m[+i] || '', (depth || 0) + 1)); break; }
    }
  }
  if (r === undefined && (depth || 0) < 3 && k.length > 20) { // cümle cümle çevir
    const parts = k.split(/(?<=[.!?…)]) +(?=[A-ZÇĞİÖŞÜ⚠"(0-9])/);
    if (parts.length > 1) { const tr = parts.map(x => tx(x, (depth || 0) + 1)); if (tr.some((x, i) => x !== norm(parts[i]))) r = tr.join(' '); }
  }
  if (r === undefined) { r = k; for (const [re, to] of PLI.tokens) r = r.replace(re, to); }
  if (PLI.cache.size > 30000) PLI.cache.clear();
  PLI.cache.set(k, r);
  return r;
}
/* yakalanan parçayı çevir, çevrilmediyse olduğu gibi (boşluklarıyla) bırak */
function sub(g, depth) {
  const t = tx(g, depth); if (t === norm(g)) return g;
  return g.match(/^\s*/)[0] + t + g.match(/\s*$/)[0];
}
/* boşlukları koruyarak çevir */
function txWS(v) {
  const t = tx(v);
  if (t === norm(v)) return v;
  const lead = v.match(/^\s*/)[0], trail = v.match(/\s*$/)[0];
  return lead + t + trail;
}
PLI.t = function (s) { return PLI.lang === 'tr' ? s : tx(s); };

const ATTRS = ['title', 'placeholder', 'aria-label', 'alt'];
const SKIP = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'PRE']);
function trText(n) {
  const v = n.nodeValue; if (!v || !v.trim()) return;
  const t = txWS(v); if (t !== v) { if (n.__o === undefined) n.__o = v; n.nodeValue = t; }
}
function trAttr(el, a) {
  const v = el.getAttribute(a); if (!v) return;
  const t = txWS(v); if (t !== v) { (el.__oa || (el.__oa = {}))[a] = (el.__oa && el.__oa[a]) !== undefined ? el.__oa[a] : v; el.setAttribute(a, t); }
}
function walk(n) {
  if (n.nodeType === 3) return trText(n);
  if (n.nodeType !== 1 || SKIP.has(n.nodeName)) { if (n.nodeType === 1 && n.nodeName === 'PRE') return; return; }
  for (const a of ATTRS) if (n.hasAttribute && n.hasAttribute(a)) trAttr(n, a);
  for (let c = n.firstChild; c; c = c.nextSibling) walk(c);
}
function restore(n) {
  if (n.nodeType === 3) { if (n.__o !== undefined) { n.nodeValue = n.__o; n.__o = undefined; } return; }
  if (n.nodeType !== 1) return;
  if (n.__oa) { for (const a in n.__oa) n.setAttribute(a, n.__oa[a]); n.__oa = null; }
  for (let c = n.firstChild; c; c = c.nextSibling) restore(c);
}
PLI.apply = function (el) { if (PLI.lang !== 'tr' && el) walk(el); };
PLI.setLang = function (l, doApply) {
  if (!PLI.langs[l]) l = 'tr';
  const was = PLI.lang; PLI.lang = l;
  if (typeof document === 'undefined') return;
  if (l === 'tr' && was !== 'tr') restore(document.body);
  if (l !== 'tr' && doApply !== false) walk(document.body);
};
PLI.translateHTML = function (html) {
  if (PLI.lang === 'tr' || typeof DOMParser === 'undefined') return html;
  const d = new DOMParser().parseFromString(html, 'text/html');
  walk(d.body); const t = d.querySelector('title'); if (t) t.textContent = tx(t.textContent);
  return '<!doctype html>\n' + d.documentElement.outerHTML;
};

if (typeof MutationObserver !== 'undefined' && typeof document !== 'undefined') {
  const start = () => {
    new MutationObserver(ms => {
      if (PLI.lang === 'tr') return;
      for (const m of ms) {
        if (m.type === 'childList') m.addedNodes.forEach(walk);
        else if (m.type === 'characterData') trText(m.target);
        else if (m.type === 'attributes') trAttr(m.target, m.attributeName);
      }
    }).observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });
  };
  start();
}

if (typeof module !== 'undefined' && module.exports) module.exports = PLI; else root.PLI = PLI;
})(typeof window !== 'undefined' ? window : globalThis);
