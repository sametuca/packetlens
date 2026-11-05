@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>&1 && set PY=python
if not defined PY where py >nul 2>&1 && set PY=py -3
if not defined PY (
  echo Python 3 bulunamadi. https://www.python.org/downloads/
  pause
  exit /b 1
)

echo PacketLens baslatiliyor...
echo Npcap yoksa otomatik kurulur ^(winget veya resmi kurulum; UAC istenebilir^).
echo Durdurmak icin bu pencerede Ctrl+C
echo.

%PY% packetlens.py --restart %*
echo.
pause
endlocal
