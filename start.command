#!/bin/bash
# PacketLens — macOS başlatıcı (canlı yakalama: tcpdump, sudo).
cd "$(dirname "$0")" || exit 1

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "Python 3 bulunamadı. https://www.python.org/downloads/"
  read -n 1 -s -r -p "Kapatmak için bir tuşa basın..."
  exit 1
fi

PL_ARGS=(--restart)
PY_EXTRA=()
for a in "$@"; do
  case "$a" in
    --no-restart) PL_ARGS=() ;;
    --attach|--keep-running) PL_ARGS=(); PY_EXTRA+=(--keep-running) ;;
    *) PY_EXTRA+=("$a") ;;
  esac
done

echo "PacketLens başlatılıyor (${PY})..."
echo "Canlı yakalama için parola istenebilir (tcpdump). Durdurmak: Ctrl+C"
echo

if [ "$(id -u)" -eq 0 ]; then
  "$PY" packetlens.py "${PL_ARGS[@]}" "${PY_EXTRA[@]}"
elif command -v sudo >/dev/null 2>&1; then
  sudo "$PY" packetlens.py "${PL_ARGS[@]}" "${PY_EXTRA[@]}"
  rc=$?
  if [ $rc -ne 0 ] && [ $rc -ne 10 ]; then
    echo
    echo "sudo başarısız; yalnızca dosya analizi modu."
    "$PY" packetlens.py --no-capture "${PL_ARGS[@]}" "${PY_EXTRA[@]}"
  fi
else
  "$PY" packetlens.py --no-capture "${PL_ARGS[@]}" "${PY_EXTRA[@]}"
fi

echo
read -n 1 -s -r -p "Sunucu durdu. Kapatmak için bir tuşa basın..."
