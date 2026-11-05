#!/bin/bash
# PacketLens başlatıcı / launcher (Linux).
#
# TR: Dosya yöneticinizde (Nautilus/Thunar/Dolphin…) bu dosyaya çift
#     tıklayın ve "Çalıştır" / "Run" / "Run in Terminal" seçin: sunucuyu
#     başlatır ve tarayıcıyı doğru adreste (oturum anahtarı dahil)
#     otomatik açar. Canlı yakalama root ister; parolanız terminalde
#     sorulur. index.html dosyasını doğrudan çift tıklayıp AÇMAYIN: o
#     zaman sayfa sunucusuz (file://) açılır ve canlı analiz çalışmaz.
#
# EN: Double-click this file in your file manager (Nautilus/Thunar/
#     Dolphin…) and choose "Run" / "Run in Terminal": it starts the
#     server and opens your browser at the correct URL (with the
#     session token). Live capture needs root — you'll be asked for
#     your password in the terminal. Do NOT open index.html directly:
#     that loads the page without a server (file://) and live analysis
#     will not work.
#
# Bir simge / menü girdisi istiyorsanız: ./install-desktop-launcher.sh
# For a desktop icon / app-menu entry: ./install-desktop-launcher.sh
set -u
cd "$(dirname "$0")" || exit 1

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "Python 3 bulunamadı / Python 3 not found."
  echo "Kurulum / install: sudo apt install python3  (Kali/Debian/Ubuntu)"
  read -n 1 -s -r -p "Kapatmak için bir tuşa basın / press any key to exit..."
  exit 1
fi

echo "PacketLens başlatılıyor / starting (${PY})..."
echo "Tarayıcı birazdan otomatik açılacak. Durdurmak için bu pencerede Ctrl+C'ye basın."
echo "Your browser will open automatically. Press Ctrl+C in this window to stop."
echo

if [ "$(id -u)" -eq 0 ]; then
  "$PY" packetlens.py "$@"
elif command -v sudo >/dev/null 2>&1; then
  echo "Canlı yakalama için parolanız istenecek (iptal ederseniz yalnızca dosya analizi çalışır)."
  echo "You'll be asked for your password for live capture (cancel to fall back to file analysis only)."
  sudo "$PY" packetlens.py "$@"
  rc=$?
  if [ $rc -ne 0 ]; then
    echo
    echo "sudo ile başlatılamadı; yalnızca dosya analizi modunda deneniyor."
    echo "Could not start with sudo; retrying in file-analysis-only mode."
    "$PY" packetlens.py --no-capture "$@"
  fi
else
  "$PY" packetlens.py --no-capture "$@"
fi

echo
read -n 1 -s -r -p "Sunucu durdu / server stopped. Kapatmak için bir tuşa basın / press any key to exit..."
