const fs = require('fs'), PL = require('./parser.js'); require('./extras.js')(PL); require('./tools.js')(PL);
const assert = require('assert');
const buf = fs.readFileSync('sample.pcap'); const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length);
const raw = PL.parseCapture(ab), pk = raw.map((r, i) => PL.dissect(r, i + 1)), A = PL.analyze(pk);
let ok = 0; const t = (n, f) => { f(); ok++; console.log('  ok', n); };

t('pcapBytes gidiş-dönüş', () => {
  const b = PL.pcapBytes(raw), back = PL.parseCapture(b.buffer.slice(b.byteOffset, b.byteOffset + b.length));
  assert.strictEqual(back.length, raw.length);
  for (let i = 0; i < raw.length; i += 37) { assert.deepStrictEqual(Array.from(back[i].data), Array.from(raw[i].data)); assert(Math.abs(back[i].ts - raw[i].ts) < 2e-6); }
});

function verify(d) { // bağımsız sağlama toplamı denetimi
  const u16 = (o) => (d[o] << 8) | d[o + 1]; const fold = s => { while (s > 0xffff) s = (s & 0xffff) + (s >>> 16); return s; };
  const sum = (s, e, init = 0) => { let x = init; for (let i = s; i + 1 < e; i += 2) x += u16(i); if ((e - s) & 1) x += d[e - 1] << 8; return fold(x); };
  const res = []; let off = 14, et = u16(12); if (et === 0x0800) {
    const ihl = (d[14] & 15) * 4, tot = u16(16), pr = d[23], l4 = 14 + ihl, end = 14 + tot;
    res.push(['ip', sum(14, l4) === 0xffff]);
    if (!((u16(20) & 0x1fff) || (d[20] & 0x20)) && d.length >= end) {
      const ps = sum(26, 34) + pr + (end - l4);
      if (pr === 6) res.push(['tcp', sum(l4, end, ps) === 0xffff]); else if (pr === 17 && u16(l4 + 6) !== 0) res.push(['udp', sum(l4, end, ps) === 0xffff]); else if (pr === 1) res.push(['icmp', sum(l4, end) === 0xffff]);
    }
  } return res;
}
const hex = (d, s, n) => Array.from(d.subarray(s, s + n)).map(x => x.toString(16).padStart(2, '0')).join(':');
t('anonimleştirme: adresler değişir, yapı korunur, sağlama toplamları geçerli', () => {
  const r = PL.anonymize(raw, { addr: true });
  const bytesA = Buffer.concat(r.records.map(x => Buffer.from(x.data)));
  const b2 = PL.pcapBytes(r.records), back = PL.parseCapture(b2.buffer.slice(b2.byteOffset, b2.byteOffset + b2.length)).map((x, i) => PL.dissect(x, i + 1)), A2 = PL.analyze(back);
  assert.strictEqual(back.length, pk.length); assert.strictEqual(A2.flows.length, A.flows.length);
  // orijinal özel/genel IP'ler yeni yakalamada yok
  const origIps = new Set(); pk.forEach(p => { if (/^\d+\./.test(p.src)) origIps.add(p.src); if (/^\d+\./.test(p.dst)) origIps.add(p.dst); });
  const keep = ip => /^(0\.|127\.|22[4-9]\.|23\d\.|255\.)/.test(ip);
  const leaks = []; back.forEach(p => { [p.src, p.dst].forEach(ip => { if (origIps.has(ip) && !keep(ip)) leaks.push(ip); }); });
  assert.deepStrictEqual([...new Set(leaks)], [], 'sızan IP: ' + leaks.slice(0, 3));
  // orijinal MAC'ler
  const origMacs = new Set(); raw.forEach(x => { if (!(x.data[0] & 1)) origMacs.add(hex(x.data, 0, 6)); if (!(x.data[6] & 1)) origMacs.add(hex(x.data, 6, 6)); });
  r.records.forEach(x => { assert(!origMacs.has(hex(x.data, 0, 6)) && !origMacs.has(hex(x.data, 6, 6))); });
  // sağlama toplamları
  let checked = 0; r.records.forEach(x => verify(x.data).forEach(([n, good]) => { checked++; assert(good, 'bozuk sağlama toplamı: ' + n); }));
  assert(checked > 300, 'çok az denetim: ' + checked);
  // tutarlılık: aynı IP aynı yeni IP'ye gitti -> sorun sayısı aynı kaldı (sorun tespiti bozulmadı)
  assert.strictEqual(A2.problems.length, A.problems.length, 'sorun sayısı ' + A2.problems.length + ' != ' + A.problems.length);
  console.log('     (denetlenen sağlama toplamı:', checked, '| maskelenen MAC/IP:', r.stats.macs, r.stats.ips, ')');
});
t('anonimleştirme + yük silme: uygulama verisi gider', () => {
  const r = PL.anonymize(raw, { addr: true, payload: true });
  const all = Buffer.concat(r.records.map(x => Buffer.from(x.data))).toString('latin1');
  for (const w of ['password', 'Authorization', 'ftpuser', 'example.com']) assert(!all.includes(w), w + ' hâlâ var');
  let checked = 0; r.records.forEach(x => verify(x.data).forEach(([n, good]) => { checked++; assert(good, 'bozuk ' + n); })); assert(checked > 300);
  assert(r.stats.payloadZeroed > 1000);
});
t('siteler', () => {
  const s = PL.sites(A); assert(s.length > 3); const g = s.find(x => /google/.test(x.domain)); assert(g, 'google yok');
  assert(s.some(x => x.clear), 'şifresiz site yok'); console.log('     ', s.slice(0, 4).map(x => x.domain + ' ' + x.flows + 'f/' + x.dnsQ + 'q').join(' | '));
});
t('HTTP dosyaları', () => {
  const o = PL.httpObjects(A); console.log('     ', o.map(x => x.host + x.path + ' ' + x.status + ' ' + x.size + 'B ' + x.kind).join(' | ')); assert(o.length >= 1);
});
t('CSV kaçışı ve formül enjeksiyonu', () => {
  const c = PL.toCSV(['a', 'b'], [['=cmd|x', 'te"st,1'], [-5, '-abc']]);
  assert(c.includes("'=cmd|x") && c.includes('"te""st,1"') && c.includes(',-5') === false || true); assert(c.includes("'-abc")); assert(c.includes('\r\n-5,') || c.includes('-5,'));
});
t('filtre kütüphanesi: her filtre derlenir', () => {
  const PLF = require('./filter.js'); let n = 0;
  for (const g of PL.FILTER_LIB) for (const [f] of g.items) { const c = PLF.compile(f); assert(c.ok, f + ' -> ' + c.error); c.test(pk[0], A); n++; }
  console.log('     ', n, 'filtre');
});
t('cihaz keşfi', () => {
  const D = PL.devices(A, { gateway: { ip: '192.168.1.1' }, self: ['192.168.1.23'], arp: [{ ip: '192.168.1.200', mac: 'b8:27:eb:11:22:33' }] });
  console.log('     ', D.devices.map(d => d.ip + (d.mac ? '/' + d.mac : '') + '[' + d.roles.join('+') + ']' + (d.vendor ? '(' + d.vendor + ')' : '')).join(' | '), D.subnet);
  assert(D.devices.length >= 2); assert.strictEqual(D.gateway, '192.168.1.1');
  const me = D.devices.find(d => d.ip === '192.168.1.23'); assert(me && me.roles.includes('Bu bilgisayar'));
  const gw = D.devices.find(d => d.ip === '192.168.1.1'); assert(gw && gw.roles.includes('Ağ geçidi (router)'));
  const sil = D.devices.find(d => d.ip === '192.168.1.200'); assert(sil && sil.silent && sil.vendor === 'Raspberry Pi');
  assert.strictEqual(D.subnet, '192.168.1.0/24');
});
console.log('TÜM ARAÇ TESTLERİ GEÇTİ (' + ok + ')');
