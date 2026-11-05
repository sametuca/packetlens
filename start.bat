@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

:: Yonetici degilsek UAC ile bu betigi yeniden ac (__elevated__ = sonsuz dongu onlemi)
net session >nul 2>&1
if errorlevel 1 (
  if /i not "%~1"=="__elevated__" (
    echo.
    echo PacketLens canli yakalama icin yonetici izni onerilir.
    echo Windows guvenlik penceresinde EVET'e basin ^(UAC^).
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "Start-Process -FilePath '%~f0' -ArgumentList '__elevated__ %*' -Verb RunAs -WorkingDirectory '%~dp0'"
    if errorlevel 1 (
      echo UAC reddedildi veya basarisiz. Dosya analizi icin normal mod deneniyor...
      goto :user
    )
    exit /b 0
  )
)

if /i "%~1"=="__elevated__" shift

where python >nul 2>&1 && set "PY=python"
if not defined PY where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
  echo Python 3 bulunamadi. https://www.python.org/downloads/
  pause
  exit /b 1
)

echo PacketLens baslatiliyor...
net session >nul 2>&1 && (
  echo Mod: Yonetici ^(Npcap / canli yakalama^)
) || (
  echo Mod: Normal kullanici ^(.pcap analizi; canli yakalama sinirli olabilir^)
)
echo Npcap yoksa otomatik kurulabilir. Durdurmak icin bu pencerede Ctrl+C
echo.

%PY% packetlens.py --restart %*
goto :end

:user
%PY% packetlens.py --restart --no-capture %*
goto :end

:end
echo.
pause
endlocal
