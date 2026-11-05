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
| HTTP gözlemi | İstek satırı, `Host`, Basic auth, form/JSON gövdesi ve sorgu dizisindeki kullanıcı/parola alanları. |
| Çerezler | Şifresiz HTTP yanıtlarındaki `Set-Cookie` başlıkları kaydedilir. |
| TLS SNI | 443/8443/4443/9443 portlarında ClientHello içinden alan adı okunur. |
| ARP uyarısı | Hedef veya ağ geçidi gerçek MAC ile geri bildirilirse (izolasyon, DAI) olay günlüğüne düşer. |
| DNS | Sorgular kaydedilir; eşlemede karşılığı olan alan adlarına sahte A yanıtı gönderilir. |
| Cihaz keşfi | Yerel alt ağda ARP taraması yapıp MAC/IP listesi çıkarır. |
| Rapor | Oturumun tamamı JSON olarak indirilebilir. |

## Mobil / Wi‑Fi MITM akışı

1. Canlı analizi aynı Wi‑Fi arayüzünde başlatın (promiscuous).
2. **Cihazlar** → hedef telefon → **ptentes** veya keşif + hedef IP.
3. **▶ Araya gir** → **Siteler** sekmesinde DNS/SNI birikir; **Yakalamada izle** ile ana pencerede hedef filtresi uygulanır.
4. **ARP uyarısı** artıyorsa izolasyon veya DAI vardır — MITM tutmuyor olabilir.

## Sınırlar

- HTTPS **içeriği** çözülmez; sertifika değiştirme (SSL stripping / sahte CA)
  bu modülde yoktur. Yalnızca SNI görünür.
- QUIC/HTTP3 trafiği UDP olduğu için HTTP gözlemi kapsamaz (SNI QUIC için ayrı geliştirme gerekir).
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
| `/api/ptentes/start` | POST | `{iface,target,targets[],gateway,dns_spoof,forward,dns_map}` |
| `/api/devices/scan` | POST | `{iface,modes:[arp,ping,ports],ports?,ips?}` |
| `/api/devices/registry` | GET | Birleşik cihaz kaydı |
| `/api/ptentes/stop` | POST | — |
| `/api/ptentes/dnsmap` | POST | `{map:{host:ip}}` |
| `/api/ptentes/discover` | POST | `{iface}` |
| `/api/ptentes/report` | GET | JSON indirme |

Tüm çağrılar `?t=<token>` ister.
