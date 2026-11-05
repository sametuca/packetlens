#!/usr/bin/env python3
"""IEEE OUI listesini indirip oui.json üretir (opsiyonel: ağ gerekir).

    python3 scripts/update_oui.py
"""
import json
import os
import re
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'oui.json')
URL = 'https://standards-oui.ieee.org/oui/oui.csv'


def main():
    print('İndiriliyor:', URL)
    with urllib.request.urlopen(URL, timeout=120) as r:
        text = r.read().decode('utf-8', 'replace')
    out = {}
    for line in text.splitlines()[1:]:
        parts = line.split(',')
        if len(parts) < 2:
            continue
        mac = re.sub(r'[^0-9A-Fa-f]', '', parts[1])[:6].lower()
        name = (parts[2] if len(parts) > 2 else parts[0]).strip().strip('"')
        if len(mac) == 6 and name:
            out[mac] = name[:80]
    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=0)
    print('Yazıldı:', OUT, '(%d kayıt)' % len(out))


if __name__ == '__main__':
    main()
