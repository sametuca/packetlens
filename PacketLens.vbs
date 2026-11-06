' Çift tık: konsol yok, UAC bir kez, ardından tarayıcı arayüzü.
' Double-click: no console, one UAC prompt, then the browser UI.
Option Explicit

Dim fso, sh, here, http, lnk, sc
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
here = fso.GetParentFolderName(WScript.ScriptFullName)

lnk = sh.SpecialFolders("Desktop") & "\PacketLens.lnk"
Set sc = sh.CreateShortcut(lnk)
sc.TargetPath = "wscript.exe"
sc.Arguments = "//nologo """ & WScript.ScriptFullName & """"
sc.WorkingDirectory = here
sc.WindowStyle = 7
sc.Description = "PacketLens"
sc.IconLocation = sh.ExpandEnvironmentStrings("%SystemRoot%\System32\shell32.dll,13")
sc.Save

sh.CurrentDirectory = here
sh.Run "powershell.exe -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File """ & here & "\pl_launch_win.ps1""", 0, False
