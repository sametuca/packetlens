# PackageLens

Wireshark tarzı ama daha kolay: paketleri uygulamalara, bağlantılara ve **sorunlara** ayırır, düz Türkçe ile anlatır.
Kali Linux için hazırlandı; **bağımlılık yok** (sadece Python 3). Wireshark, tshark veya libpcap gerekmez.

## Çalıştırma

```bash
cd packagelens
sudo python3 packagelens.py          # canlı yakalama + arayüz (tarayıcı otomatik açılır)
python3 packagelens.py --no-capture  # root olmadan, sadece .pcap dosyası analizi (macOS'ta da çalışır)
```

Tarayıcı açılmazsa terminalde yazan `http://127.0.0.1:8765/?t=...` adresini açın.
Seçenekler: `-i eth0` (varsayılan arayüz), `--port 9000`, `--no-browser`.
Canlı yakalama olmadan sadece `index.html` dosyasını tarayıcıda açıp `.pcap` yüklemek de mümkündür.

## Özellikler

**Kolay kullanım**
- **Basit / Gelişmiş mod** (sağ üst): Basit modda Özet, Sorunlar, Bağlantılar, Harita, Grafik; Gelişmiş modda ayrıca Paketler, İstatistik, Günlükler.
- **Doğal dil arama:** `yavaş dns`, `192.168.1.23 hata`, `port 443`, `google.com`, `şifresiz`. Altında Wireshark karşılığı gösterilir. `/` tuşu aramaya odaklanır.
- Her sorun için nedeni ve "ne yapmalı?" önerisi; her paket için düz dille "ne oluyor?" açıklaması; alan başına (?) açıklamaları.
- IP adresleri DNS yanıtlarından ve TLS SNI / HTTP Host bilgisinden isme çevrilir.

**Wireshark çekirdeği**
- **Display filter dili:** `ip.addr == 192.168.1.0/24 && tcp.port == 443`, `dns.qry.name contains "google"`, `tcp.analysis.retransmission`, `!(…)`, `matches`, parantez. Hatalarda Türkçe açıklama ve benzer alan önerisi. (`ip`, `tcp`, `udp`, `dns`, `http`, `tls`, `arp`, `icmp`, `frame`, `eth`, `pl` alanları)
- **BPF yakalama filtresi** (canlı yakalamada): `host 192.168.1.5 and port 443`, `not port 22`, `tcp or udp`, `net 10.0.0.0/8`, `portrange 20-25`, `less/greater N`.
- **TCP/UDP akışını takip et** (istemci mavi, sunucu kırmızı; ASCII/Hex; kopyala/indir; kayıp veri işaretlenir).
- **Grafik:** bayt/sn, paket/sn, sorun, yeniden iletim; uygulamaya göre renkli; **sürükleyerek zaman aralığı seçimi** tüm sekmeleri filtreler.
- **İstatistik:** protokol hiyerarşisi, paket boyutu dağılımı, konuşmalar, cihazlar, TCP el sıkışma süreleri, DNS ve HTTP özetleri.
- **Günlükler:** DNS (süre, sonuç), HTTP (istek/yanıt eşleşmeli), TLS (sürüm, şifre, ALPN, sertifika), şifresiz oturumlar.
- Paket listesi, katman ağacı, hex görünümü, `.pcap` / `.pcapng` okuma ve `.pcap` kaydetme.

**Görselleştirme**
- **Ağ haritası:** cihazlar arası konuşmalar (daire boyutu = veri, kırmızı = sorunlu); cihaza tıklayınca o cihaza odaklanır.
- **Sıra diyagramı** (bağlantı ayrıntısında) ve **TLS ayrıntı paneli**.

**Güvenlik (Kali)**
- Şifresiz kimlik bilgisi: HTTP Basic/form, FTP, POP3, IMAP, SMTP AUTH, Telnet. **Parolalar maskelenir**, tam parola saklanmaz.
- ARP sahteciliği, DNS tünelleme, DGA benzeri NXDOMAIN yağmuru, beacon (düzenli aralıklı bağlantı), port/ping taraması, SYN seli, zayıf/eski TLS, şifresiz protokol kullanımı.
- TTL ve TCP ayarlarından işletim sistemi tahmini (kesin değildir).
- Sorunlar **Güvenlik / Performans / Ağ** olarak ayrı listelenir.

## Güvenlik notları

Sunucu yalnızca `127.0.0.1` üzerinde dinler, rastgele bir erişim anahtarı (token) ister ve `Host` başlığını doğrular
(DNS rebinding koruması). Yakalama root ile çalışır; **yalnızca yetkili olduğunuz ağlarda** kullanın.

## Dosyalar

| Dosya | Görev |
|---|---|
| `packagelens.py` | Yerel sunucu + canlı yakalama (AF_PACKET) |
| `capfilter.py` | BPF yakalama filtresi (host/net/port/proto, and/or/not) |
| `parser.js` | pcap/pcapng okuma, protokol çözme, akış ve sorun analizi |
| `filter.js` | Wireshark tarzı display filter dili |
| `extras.js` | Akış takibi, günlükler, istatistikler, güvenlik tespitleri |
| `app.js`, `views.js`, `index.html`, `style.css` | Arayüz |
| `gen_sample.py` | `sample.pcap` / `sample.js` üretir (örnek senaryolar) |

## Testler

```bash
python3 gen_sample.py        # örnek yakalamayı yeniden üretir
node test_parser.js          # çözümleyici
node test_filter.js          # display filter (36 test)
python3 test_capfilter.py    # BPF filtresi (JS motoruyla çapraz doğrulama)
```

## Bilinen sınırlar

- Şifreli (TLS/QUIC) içerik çözülmez; kim kiminle konuşuyor, hangi siteye (SNI), ne kadar ve hangi sorunlarla görülür.
- TLS 1.3'te sertifika şifreli olduğundan sertifika bilgisi yalnızca TLS 1.2 ve öncesinde görünür.
- Canlı yakalama paket başına ilk 1600 bayt ve en fazla 300 bin paket saklar (bellek koruması).
- Yakalama filtresi tcpdump/BPF sözdiziminin yaygın alt kümesidir (alan adı çözümleme ve `ether`, `vlan` gibi ifadeler yok).
- Canlı yakalama yalnızca Linux'ta çalışır.
