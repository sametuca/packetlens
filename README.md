# PaketLens

Wireshark tarzı ama daha kolay: paketleri uygulamalara, bağlantılara ve **sorunlara** ayırır, düz Türkçe ile anlatır.
Kali Linux için hazırlandı; **bağımlılık yok** (sadece Python 3). Wireshark, tshark veya libpcap gerekmez.

## Çalıştırma

```bash
cd paketlens
sudo python3 paketlens.py          # canlı yakalama + arayüz (tarayıcı otomatik açılır)
python3 paketlens.py --no-capture  # root olmadan, sadece .pcap dosyası analizi
```

Tarayıcı açılmazsa terminalde yazan `http://127.0.0.1:8765/?t=...` adresini açın.
Seçenekler: `-i eth0` (varsayılan arayüz), `--port 9000`, `--no-browser`.

## Özellikler

- **Basit / Gelişmiş mod** (sağ üst): Basit modda özet, sorunlar ve bağlantılar; Gelişmiş modda paket listesi, katman ağacı, alan açıklamaları (?) ve hex görünümü.
- **Canlı yakalama** (AF_PACKET): arayüz seç, başlat/durdur, `.pcap` olarak kaydet (Wireshark ile de açılır).
- **Doğal dil arama:** `yavaş dns`, `192.168.1.23 hata`, `port 443`, `google.com`, `şifresiz`. Altında **Wireshark filtre karşılığı** gösterilir.
- **Otomatik sorun tespiti:** yeniden iletim, RST, zero window, yanıtsız SYN, yavaş/hatalı DNS, ICMP "ulaşılamadı", olası port taraması. Her biri nedeni ve önerisiyle.
- **Hızlı görünümler:** uygulama başına trafik, en çok veri kullananlar, hata özeti.
- IP adresleri DNS yanıtlarından ve TLS SNI / HTTP Host bilgisinden isme çevrilir.
- Protokoller: Ethernet/VLAN, ARP, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, DNS/mDNS, TLS (SNI), HTTP; QUIC, SSH, NTP vb. port ile tanınır.
- `.pcap` ve `.pcapng` dosyalarını sürükle-bırak ile açar.

## Güvenlik

Sunucu yalnızca `127.0.0.1` üzerinde dinler, rastgele bir erişim anahtarı (token) ister ve `Host` başlığını doğrular
(DNS rebinding koruması). Yakalama root ile çalışır; yalnızca yetkili olduğunuz ağlarda kullanın.

## Dosyalar

| Dosya | Görev |
|---|---|
| `paketlens.py` | Yerel sunucu + canlı yakalama |
| `parser.js` | pcap/pcapng okuma, protokol çözme, akış ve sorun analizi |
| `app.js`, `index.html`, `style.css` | Arayüz |
| `gen_sample.py` | `sample.pcap` / `sample.js` üretir (örnek senaryolar) |
| `test_parser.js` | `node test_parser.js dosya.pcap` ile hızlı çözümleyici testi |

## Bilinen sınırlar

- Şifreli (TLS/QUIC) içerik çözülmez; sadece kim kiminle konuşuyor, hangi siteye (SNI), ne kadar ve hangi sorunlarla görülür.
- Canlı yakalama paket başına ilk 1600 bayt ve en fazla 300 bin paket saklar (bellek koruması).
- BPF yakalama filtresi yok; filtreleme yakalamadan sonra arama kutusuyla yapılır.
