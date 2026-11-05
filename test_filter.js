// Display filter motoru testi: node test_filter.js
const fs = require('fs');
const PL = require('./parser.js');
const PLF = require('./filter.js');
const b = fs.readFileSync(__dirname + '/sample.pcap');
const raw = PL.parseCapture(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
const A = PL.analyze(raw.map((r, i) => PL.dissect(r, i + 1)));
let fail = 0;
const count = q => { const c = PLF.compile(q); if (!c.ok) throw new Error(q + ' -> ' + c.error); return A.packets.filter(p => c.test(p, A)).length; };
const eq = (q, n) => { let got; try { got = count(q); } catch (e) { got = e.message; } const ok = got === n; if (!ok) fail++; console.log(ok ? 'ok  ' : 'FAIL', q, '=>', got, ok ? '' : '(beklenen ' + n + ')'); };
const err = (q, re) => { const c = PLF.compile(q); const ok = !c.ok && re.test(c.error); if (!ok) fail++; console.log(ok ? 'ok  ' : 'FAIL', 'hata:', q, '=>', c.ok ? 'derlendi' : c.error); };
const manual = f => A.packets.filter(f).length;

eq('arp', manual(p => p.arp));
eq('dns', manual(p => p.dns && p.app === 'DNS'));
eq('tcp.port == 443', manual(p => p.proto === 'TCP' && (p.sport === 443 || p.dport === 443)));
eq('tcp.dstport == 80 && http', manual(p => p.proto === 'TCP' && p.dport === 80 && p.http));
eq('ip.addr == 192.168.1.23 && udp', manual(p => p.ipv === 4 && (p.src === '192.168.1.23' || p.dst === '192.168.1.23') && p.proto === 'UDP'));
eq('ip.src == 192.168.1.0/24 && ip.dst == 142.250.74.46', manual(p => p.ipv === 4 && p.src.startsWith('192.168.1.') && p.dst === '142.250.74.46'));
eq('!(tcp || udp || icmp || arp)', manual(p => !['TCP', 'UDP', 'ICMP'].includes(p.proto) && !p.arp));
eq('tcp.flags.syn == 1 && tcp.flags.ack == 0', manual(p => p.proto === 'TCP' && (p.flags & 18) === 2));
eq('tcp.flags.reset', manual(p => p.proto === 'TCP' && p.flags & 4));
eq('tcp.analysis.retransmission', manual(p => p.anoms.includes('retrans')));
eq('frame.len >= 1400', manual(p => p.len >= 1400));
eq('dns.qry.name contains "GOOGLE"', 3); // sorgu + yanıt + mDNS _googlecast
eq('dns.flags.rcode == 3', manual(p => p.dns && p.dns.rcode === 3));
eq('dns.time > 0.25', 1);
eq('http.request.method == "GET"', manual(p => p.http && p.http.method === 'GET'));
eq('tls.handshake.extensions_server_name == "www.google.com"', 1);
eq('tls.handshake.type == 1', manual(p => p.tls && p.tls.ht === 1));
eq('eth.src == aa:bb:cc:00:00:99', manual(p => p.macSrc === 'aa:bb:cc:00:00:99'));
eq('pl.host contains "slow-service"', manual(p => A.nm(p.src).includes('slow-service') || A.nm(p.dst).includes('slow-service')));
eq('pl.problem and tcp', manual(p => p.anoms.length && p.proto === 'TCP'));
eq('icmp.type == 3', 1);
eq('http.host matches "^exam"', manual(p => p.http && /^exam/i.test(p.http.host || '')));
eq('frame contains "SSH-2.0"', manual(p => p.info.startsWith('SSH sürüm')));
err('tcp.prt == 1', /Bilinmeyen alan/);
err('tcp.port ==', /değer bekleniyordu/);
err('(tcp.port == 80', /parantezi/);
err('tcp.port == 80 tcp', /Beklenmeyen ifade/);
err('frame.len == "abc"', /sayı/);
err('frame == "x"', /contains/);
err('dns.qry.name matches "("', /düzenli ifade/);
err('ip.addr == 1.2.3.4 @', /Beklenmeyen karakter/);
// arayüzdeki doğal dil sorgularının Wireshark karşılıkları geçerli mi?
for (const w of ['ip.addr == 1.2.3.4', '(tcp.port == 443 || udp.port == 443)', 'dns && (dns.time > 0.25 || tcp.analysis.retransmission || tcp.analysis.zero_window)',
  'tcp.analysis.flags || dns.flags.rcode > 0 || icmp.type == 3 || tcp.flags.reset == 1', 'frame.len >= 1000', 'tcp.flags.syn == 1 && tcp.flags.ack == 0', 'http || ftp || telnet || pop', 'frame contains "x"', 'icmp || icmpv6', 'tls', 'quic'])
  { const c = PLF.compile(w); if (!c.ok) { fail++; console.log('FAIL wire', w, c.error); } }
console.log('looksLikeFilter:', ['google.com', 'yavaş dns', 'port 443', 'tcp.port == 443', 'dns.qry.name contains x', 'ip.addr==1.2.3.4'].map(t => t + '=' + PLF.looksLikeFilter(t)).join(' | '));
console.log(fail ? `\n${fail} HATA` : '\nTÜM FİLTRE TESTLERİ GEÇTİ');
process.exit(fail ? 1 : 0);
