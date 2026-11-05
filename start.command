#!/bin/bash
# PacketLens başlatıcı / launcher.
#
# TR: Bu dosyaya Finder'da çift tıklayın: sunucuyu başlatır ve tarayıcıyı
#     doğru adres (oturum anahtarı dahil) ile otomatik açar. index.html
#     dosyasını doğrudan çift tıklayıp AÇMAYIN: o zaman sayfa sunucusuz
#     (file://) açılır ve "Canlı analiz" çalışmaz. Her zaman bu dosyayı
#     kullanın.
# EN: Double-click this file in Finder: it starts the server and opens
#     your browser at the correct URL (with the session token). Do NOT
#     open index.html directly — that loads the page without a server
#     (file://) and live analysis will not work. Always use this file.
cd "$(dirname "$0")" || exit 1

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "Python 3 bulunamadı / Python 3 not found."
  echo "Kurulum / install: https://www.python.org/downloads/"
  read -n 1 -s -r -p "Kapatmak için bir tuşa basın / press any key to exit..."
  exit 1
fi

echo "PacketLens başlatılıyor / starting (${PY})..."
echo "Tarayıcı birazdan otomatik açılacak. Durdurmak için bu pencerede Ctrl+C'ye basın."
echo "Your browser will open automatically. Press Ctrl+C in this window to stop."
echo

"$PY" packetlens.py "$@"

echo
read -n 1 -s -r -p "Sunucu durdu / server stopped. Kapatmak için bir tuşa basın / press any key to exit..."
