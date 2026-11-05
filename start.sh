#!/bin/bash
# PacketLens başlatıcı / launcher (Linux).
#
# TR: Dosya yöneticinizde (Nautilus/Thunar/Dolphin…) bu dosyaya çift
#     tıklayın ve "Çalıştır" / "Run" / "Run in Terminal" seçin: sunucuyu
#     başlatır ve tarayıcıyı doğru adreste (oturum anahtarı dahil)
#     otomatik açar (http://127.0.0.1:8765). Eski arka plan sürecini
#     kapatıp yeniden başlatır (--restart). Canlı yakalama root ister.
#     index.html dosyasını doğrudan çift tıklayıp AÇMAYIN (file://).
#
# EN: Starts the server and opens http://127.0.0.1:8765 (restarts any
#     stale background process). Live capture needs root. Do NOT open
#     index.html directly (file://).
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

PL_ARGS=(--restart)
for a in "$@"; do
  case "$a" in
    --attach|--no-restart) PL_ARGS=() ;;
  esac
done
# --attach / --no-restart dışındaki argümanları python'a ilet
PY_EXTRA=()
for a in "$@"; do
  case "$a" in
    --no-restart) PY_EXTRA+=(--keep-running) ;;
    --attach) PY_EXTRA+=(--attach) ;;
    *) PY_EXTRA+=("$a") ;;
  esac
done

run_pl() {
  "$PY" packetlens.py "${PL_ARGS[@]}" "${PY_EXTRA[@]}"
}

if [ "$(id -u)" -eq 0 ]; then
  run_pl
  rc=$?
elif command -v sudo >/dev/null 2>&1; then
  echo "Canlı yakalama için parolanız istenecek (iptal ederseniz yalnızca dosya analizi çalışır)."
  echo "You'll be asked for your password for live capture (cancel to fall back to file analysis only)."
  sudo "$PY" packetlens.py "${PL_ARGS[@]}" "${PY_EXTRA[@]}"
  rc=$?
  if [ $rc -ne 0 ] && [ $rc -ne 10 ]; then
    echo
    echo "sudo ile başlatılamadı; yalnızca dosya analizi modunda deneniyor."
    echo "Could not start with sudo; retrying in file-analysis-only mode."
    "$PY" packetlens.py --no-capture "${PL_ARGS[@]}" "${PY_EXTRA[@]}"
    rc=$?
  fi
else
  "$PY" packetlens.py --no-capture "${PL_ARGS[@]}" "${PY_EXTRA[@]}"
  rc=$?
fi

echo
if [ "${rc:-0}" -eq 10 ]; then
  read -n 1 -s -r -p "Tarayıcı açıldı; arka plandaki sunucu çalışıyor. Kapatmak için bir tuşa basın / press any key..."
else
  read -n 1 -s -r -p "Sunucu durdu / server stopped. Kapatmak için bir tuşa basın / press any key..."
fi
