/* PacketLens — paylaşılan PLApp kabuğu (app.js yenilense bile views kaydı kalır) */
(function () {
  'use strict';
  var p = window.PLApp;
  if (!p || typeof p !== 'object') p = window.PLApp = {};
  if (!p.views || typeof p.views !== 'object') p.views = {};
  if (!p.extra || typeof p.extra !== 'object') p.extra = {};
})();
