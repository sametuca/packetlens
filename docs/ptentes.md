# ptentes — araya girme motoru

`ptentes`, PacketLens'in ARP sahteciliğine dayalı araya girme (MITM) modülüdür.
Amaç, kendi laboratuvarınızda ya da yetkili olduğunuz bir ağda trafiğin
şifresiz kısmını gözlemlemek ve DNS yanıtlarını kontrollü biçimde
yönlendirmektir.

## Gereksinimler

- Linux (AF_PACKET; Kali/Ubuntu/Debian)
- root: `sudo python3 packetlens.py`
- Hedef cihaz ve ağ geçidi aynı yerel alt ağda olmalı
- Arayüzün promiscuous modu desteklemesi (Ethernet/Wi-Fi)

## Kullanım

1. `sudo python3 packetlens.py`
2. Üst çubuktaki **ptentes** düğmesine basın.
3. Arayüzü, hedef cihazı ve ağ geçidini seçin.
4. (İsteğe bağlı) DNS eşlemesi girin: her satır `alanadi=ip`.
5. **▶ Araya gir** düğmesine basın.

Durdurduğunuzda motor doğru ARP eşlemelerini geri gönderir ve
`/proc/sys/net/ipv4/ip_forward` değerini eski hâline döndürür.

## Ne yapar

| Bileşen | Açıklama |
|---|---|
| ARP zehirleme | Hedefe "ağ geçidi benim", ağ geçidine "hedef benim" yanıtları gönderilir; 1,8 sn'de bir yenilenir. |
| IP yönlendirme | `ip_forward=1` iken trafik kesintisiz akar; motor yalnızca kopyayı okur. |
| HTTP gözlemi | İstek satırı, `Host`, `User-Agent`, Basic auth ve form alanları çözümlenir. |
| TLS SNI | Şifreli trafikte bile bağlantı kurulan alan adı okunur. |
| DNS | Sorgular kaydedilir; eşlemede karşılığı olan alan adlarına sahte A yanıtı gönderilir. |
| Cihaz keşfi | Yerel alt ağda ARP taraması yapıp MAC/IP listesi çıkarır. |
| Rapor | Oturumun tamamı JSON olarak indirilebilir. |

## Sınırlar

- HTTPS **içeriği** çözülmez; sertifika değiştirme (SSL stripping / sahte CA)
  bu modülde yoktur. Yalnızca SNI görünür.
- QUIC/HTTP3 trafiği UDP olduğu için HTTP gözlemi kapsamaz.
- Paket parçalanması ve TCP segmentasyonu nedeniyle çok büyük isteklerde
  başlık/gövde alanları eksik okunabilir (snap uzunluğu 1600 bayttır).
- Wi-Fi istemci izolasyonu açıksa ARP zehirleme çalışmaz.

## Erişim ve güvenlik

Sunucu yalnızca `127.0.0.1` üzerinde dinler ve rastgele bir token ister.
ptentes yalnızca yerel alt ağdaki bir hedefi kabul eder (internet üzerinden
rastgele hedef verilemez). Yalnızca sahibi olduğunuz veya yazılı izinle
test yaptığınız ağlarda kullanın.

## API

| Yol | Yöntem | Gövde |
|---|---|---|
| `/api/ptentes/status` | GET | — |
| `/api/ptentes/start` | POST | `{iface,target,gateway,dns_spoof,forward,dns_map}` |
| `/api/ptentes/stop` | POST | — |
| `/api/ptentes/dnsmap` | POST | `{map:{host:ip}}` |
| `/api/ptentes/discover` | POST | `{iface}` |
| `/api/ptentes/report` | GET | JSON indirme |

Tüm çağrılar `?t=<token>` ister.
