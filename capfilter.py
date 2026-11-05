"""PacketLens - yakalama filtresi (tcpdump/BPF sözdiziminin yaygın alt kümesi).

Desteklenen: host, net, port, portrange, src/dst, tcp/udp/icmp/icmp6/arp/ip/ip6,
             less/greater N, and/or/not (&&, ||, !) ve parantez.
Örnekler:    host 192.168.1.5 and port 443
             not port 22
             (tcp or udp) and net 10.0.0.0/8
             udp port 53
Yalnızca standart kütüphane kullanır; filtre kullanıcı alanında (Python) uygulanır.
"""
import ipaddress
import re


class FilterError(ValueError):
    pass


_TOKEN = re.compile(r'\s*(\(|\)|&&|\|\||!(?!=)|[^\s()!&|]+)')
_PROTOS = ('tcp', 'udp', 'icmp', 'icmp6', 'arp', 'ip', 'ip6')
_TYPES = ('host', 'net', 'port', 'portrange')


def _tokenize(text):
    out, pos = [], 0
    while pos < len(text):
        if not text[pos:].strip():
            break
        m = _TOKEN.match(text, pos)
        if not m:
            raise FilterError('Anlaşılmayan karakter: %r' % text[pos:pos + 8].strip())
        out.append(m.group(1))
        pos = m.end()
    return out


def decode(d):
    """Ham Ethernet çerçevesinden filtre için gereken alanları çıkarır."""
    n = len(d)
    pk = {'len': n, 'ip': None, 'arp': False, 'l4': None, 'src': None, 'dst': None, 'sp': None, 'dp': None}
    if n < 14:
        return pk
    et, o = (d[12] << 8) | d[13], 14
    while et in (0x8100, 0x88a8) and n >= o + 4:
        et = (d[o + 2] << 8) | d[o + 3]
        o += 4
    if et == 0x0800 and n >= o + 20:
        ihl, proto = (d[o] & 15) * 4, d[o + 9]
        pk['ip'] = 4
        pk['src'] = (4, int.from_bytes(d[o + 12:o + 16], 'big'))
        pk['dst'] = (4, int.from_bytes(d[o + 16:o + 20], 'big'))
        frag = ((d[o + 6] & 0x1f) << 8) | d[o + 7]
        pk['l4'] = {6: 'tcp', 17: 'udp', 1: 'icmp'}.get(proto)
        if pk['l4'] in ('tcp', 'udp') and frag == 0 and n >= o + ihl + 4:
            pk['sp'], pk['dp'] = (d[o + ihl] << 8) | d[o + ihl + 1], (d[o + ihl + 2] << 8) | d[o + ihl + 3]
    elif et == 0x86dd and n >= o + 40:
        nh = d[o + 6]
        pk['ip'] = 6
        pk['src'] = (6, int.from_bytes(d[o + 8:o + 24], 'big'))
        pk['dst'] = (6, int.from_bytes(d[o + 24:o + 40], 'big'))
        q = o + 40
        while nh in (0, 43, 60) and n >= q + 8:
            nh, q = d[q], q + (d[q + 1] + 1) * 8
        pk['l4'] = {6: 'tcp', 17: 'udp', 58: 'icmp6'}.get(nh)
        if pk['l4'] in ('tcp', 'udp') and n >= q + 4:
            pk['sp'], pk['dp'] = (d[q] << 8) | d[q + 1], (d[q + 2] << 8) | d[q + 3]
    elif et == 0x0806:
        pk['arp'] = True
    return pk


def _proto_ok(pk, proto):
    if proto is None:
        return True
    if proto == 'ip':
        return pk['ip'] == 4
    if proto == 'ip6':
        return pk['ip'] == 6
    if proto == 'arp':
        return pk['arp']
    return pk['l4'] == proto


def _parse(tokens):
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        t = peek()
        pos += 1
        return t

    def or_expr():
        left = and_expr()
        while peek() in ('or', '||'):
            take()
            a, b = left, and_expr()
            left = (lambda a, b: lambda pk: a(pk) or b(pk))(a, b)
        return left

    def and_expr():
        left = not_expr()
        while peek() in ('and', '&&'):
            take()
            a, b = left, not_expr()
            left = (lambda a, b: lambda pk: a(pk) and b(pk))(a, b)
        return left

    def not_expr():
        if peek() in ('not', '!'):
            take()
            a = not_expr()
            return lambda pk: not a(pk)
        return primary()

    def primary():
        if peek() == '(':
            take()
            e = or_expr()
            if take() != ')':
                raise FilterError('Kapanış parantezi ")" eksik')
            return e
        return prim()

    def value():
        v = take()
        if v is None:
            raise FilterError('Değer eksik')
        return v

    def prim():
        t = peek()
        if t is None:
            raise FilterError('İfade eksik: bir koşul bekleniyordu')
        if t in ('less', 'greater'):
            take()
            try:
                n = int(value())
            except ValueError:
                raise FilterError('"%s" sonrasında bir sayı bekleniyordu' % t)
            return (lambda pk: pk['len'] <= n) if t == 'less' else (lambda pk: pk['len'] >= n)
        direction = None
        if t in ('src', 'dst'):
            direction = take()
            t = peek()
        proto = None
        if t in _PROTOS:
            proto = take()
            t = peek()
        if t in _TYPES:
            ptype = take()
            return make(direction, proto, ptype, value())
        if direction:
            raise FilterError('"%s" sonrasında host, net, port veya portrange bekleniyordu' % direction)
        if proto is None:
            raise FilterError('Anlaşılmayan ifade: "%s"' % t)
        return lambda pk: _proto_ok(pk, proto)

    def make(direction, proto, ptype, val):
        if ptype in ('host', 'net'):
            try:
                if ptype == 'host':
                    a = ipaddress.ip_address(val)
                    key = (a.version, int(a))
                    test = lambda x: x == key
                else:
                    net = ipaddress.ip_network(val, strict=False)
                    ver, base, mask = net.version, int(net.network_address), int(net.netmask)
                    test = lambda x: x[0] == ver and (x[1] & mask) == base
            except ValueError:
                if re.match(r'^[A-Za-z]', val):
                    raise FilterError('Alan adı desteklenmiyor: "%s" yerine IP adresi yazın' % val)
                raise FilterError('Geçersiz %s değeri: "%s"' % (ptype, val))

            def f(pk):
                if pk['src'] is None or not _proto_ok(pk, proto):
                    return False
                if direction == 'src':
                    return test(pk['src'])
                if direction == 'dst':
                    return test(pk['dst'])
                return test(pk['src']) or test(pk['dst'])
            return f
        try:
            lo, hi = (int(x) for x in val.split('-', 1)) if ptype == 'portrange' else (int(val), int(val))
        except ValueError:
            raise FilterError('Geçersiz %s değeri: "%s"' % (ptype, val))
        if not (0 <= lo <= hi <= 65535):
            raise FilterError('Port 0-65535 arasında olmalı: "%s"' % val)

        def g(pk):
            if pk['l4'] not in ('tcp', 'udp') or pk['sp'] is None or not _proto_ok(pk, proto):
                return False
            ok = lambda p: lo <= p <= hi
            if direction == 'src':
                return ok(pk['sp'])
            if direction == 'dst':
                return ok(pk['dp'])
            return ok(pk['sp']) or ok(pk['dp'])
        return g

    expr = or_expr()
    if pos < len(tokens):
        raise FilterError('Beklenmeyen ifade: "%s" (and/or eksik olabilir)' % tokens[pos])
    return expr


def compile_filter(text):
    """Metni derler; boşsa None döner. Hata durumunda FilterError fırlatır."""
    text = (text or '').strip()
    if not text:
        return None
    expr = _parse(_tokenize(text))
    return lambda data: expr(decode(data))
