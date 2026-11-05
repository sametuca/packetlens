"""Yakalama filtresi testi: python3 test_capfilter.py"""
import struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capfilter import compile_filter, FilterError


def read_pcap(path):
    d = open(path, 'rb').read()
    o, out = 24, []
    while o + 16 <= len(d):
        _, _, n, _ = struct.unpack('<IIII', d[o:o + 16])
        out.append(d[o + 16:o + 16 + n])
        o += 16 + n
    return out


pk = read_pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sample.pcap'))
bad = 0


def count(expr):
    f = compile_filter(expr)
    return sum(1 for x in pk if f(x))


def check(expr, expect):
    global bad
    got = count(expr)
    ok = got == expect
    bad += not ok
    print('ok  ' if ok else 'FAIL', expr, '=>', got, '' if ok else '(beklenen %s)' % expect)


def raises(expr, frag):
    global bad
    try:
        compile_filter(expr)
        print('FAIL', expr, 'hata vermedi')
        bad += 1
    except FilterError as e:
        ok = frag in str(e)
        bad += not ok
        print('ok  ' if ok else 'FAIL', 'hata:', expr, '=>', e)


total = len(pk)

# Çapraz doğrulama: aynı paketleri JS tarafındaki bağımsız display filter motoruyla say
import json, subprocess
PAIRS = [
    ('arp', 'arp'), ('icmp', 'icmp'), ('tcp port 443', 'tcp.port == 443'), ('udp port 53', 'udp.port == 53'),
    ('host 192.168.1.1', 'ip.addr == 192.168.1.1'), ('src host 192.168.1.99 and tcp', 'ip.src == 192.168.1.99 && tcp'),
    ('dst net 192.168.1.0/24 and udp port 5000', 'ip.dst == 192.168.1.0/24 && udp.port == 5000'),
    ('tcp or udp', 'tcp || udp'), ('not (tcp or udp or icmp or arp)', '!(tcp || udp || icmp || arp)'),
    ('greater 1400', 'frame.len >= 1400'), ('ip and not port 53 and not icmp', 'ip && !(udp.port == 53 || tcp.port == 53) && !icmp'),
    ('src port 443', 'tcp.srcport == 443 || udp.srcport == 443'), ('dst portrange 80-81 and tcp', 'tcp.dstport >= 80 && tcp.dstport <= 81'),
    ('net 142.250.0.0/16 || host 203.0.113.9', 'ip.addr == 142.250.0.0/16 || ip.addr == 203.0.113.9'),
]
js = """const fs=require('fs');const PL=require('./parser.js');const PLF=require('./filter.js');
const b=fs.readFileSync('sample.pcap');const A=PL.analyze(PL.parseCapture(b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength)).map((r,i)=>PL.dissect(r,i+1)));
console.log(JSON.stringify(JSON.parse(process.argv[1]).map(q=>{const c=PLF.compile(q);return A.packets.filter(p=>c.test(p,A)).length})));"""
try:
    ref = json.loads(subprocess.check_output(['node', '-e', js, json.dumps([p[1] for p in PAIRS])], cwd=os.path.dirname(os.path.abspath(__file__))))
except (OSError, subprocess.CalledProcessError) as e:
    ref = None
    print('Uyarı: node bulunamadı, çapraz doğrulama atlandı:', e)
if ref:
    for (bpf, disp), want in zip(PAIRS, ref):
        check(bpf, want)
check('src host 192.168.1.99 and tcp', 26)   # sabit, elle doğrulanmış (26 SYN)

assert compile_filter('') is None and compile_filter('   ') is None
raises('host', 'Değer eksik')
raises('host evil.com', 'Alan adı desteklenmiyor')
raises('port 99999', '0-65535')
raises('tcp port 80 udp', 'Beklenmeyen ifade')
raises('(tcp', 'parantezi')
raises('src', 'bekleniyordu')
raises('foo bar', 'Anlaşılmayan ifade')
print('\n%s' % ('%d HATA' % bad if bad else 'TÜM YAKALAMA FİLTRESİ TESTLERİ GEÇTİ'))
sys.exit(1 if bad else 0)
