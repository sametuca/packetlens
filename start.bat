@echo off
cd /d "%~dp0"
rem Konsol yok: cift tik PacketLens.vbs veya masaustu kisayolu. Bu dosya da oraya gider.
start "" wscript.exe //nologo "%~dp0PacketLens.vbs"
exit /b 0
