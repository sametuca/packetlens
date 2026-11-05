#!/bin/bash
# TR: Uygulamalar menüsüne ve (varsa) Masaüstüne "PacketLens" simgesi ekler,
#     böylece her seferinde komut yazmadan, simgeye çift tıklayarak başlatabilirsiniz.
# EN: Adds a "PacketLens" icon to your Applications menu and (if present) your
#     Desktop, so you can start it by double-clicking instead of typing commands.
set -e
cd "$(dirname "$0")"
HERE="$(pwd)"
chmod +x start.sh packetlens.py 2>/dev/null || true

APPDIR="$HOME/.local/share/applications"
mkdir -p "$APPDIR"
DESK="$APPDIR/packetlens.desktop"

cat > "$DESK" <<EOF
[Desktop Entry]
Type=Application
Name=PacketLens
GenericName=Packet Analyzer
Comment=Kolay paket analizörü (Wireshark benzeri) / Easy packet analyzer
Exec=$HERE/start.sh
Path=$HERE
Icon=utilities-system-monitor
Terminal=true
Categories=Network;System;Security;
EOF
chmod +x "$DESK"
command -v gio >/dev/null 2>&1 && gio set "$DESK" metadata::trusted true 2>/dev/null || true

echo "Uygulamalar menüsüne eklendi / added to the Applications menu: PacketLens"

if [ -d "$HOME/Desktop" ]; then
  cp "$DESK" "$HOME/Desktop/PacketLens.desktop"
  chmod +x "$HOME/Desktop/PacketLens.desktop"
  command -v gio >/dev/null 2>&1 && gio set "$HOME/Desktop/PacketLens.desktop" metadata::trusted true 2>/dev/null || true
  echo "Masaüstüne kısayol eklendi / desktop shortcut added: $HOME/Desktop/PacketLens.desktop"
fi

echo
echo "Artık Uygulamalar menüsünden ya da masaüstündeki simgeden PacketLens'i açabilirsiniz."
echo "You can now launch PacketLens from the Applications menu or the desktop icon."
