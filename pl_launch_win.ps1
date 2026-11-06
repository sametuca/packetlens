# PacketLens Windows başlatıcı: küçük pencere, gizli sunucu, tarayıcı arayüzü.
param([switch]$NoCapture)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$tr = [Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'tr'
function L([string]$turkish, [string]$english) {
    if ($tr) { return $turkish }
    return $english
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PacketLens {
    try {
        $req = [Net.HttpWebRequest]::Create('http://127.0.0.1:8765/api/info')
        $req.Timeout = 8000
        $req.Proxy = $null
        $res = $req.GetResponse()
        $ok = [int]$res.StatusCode -eq 200
        $res.Close()
        return $ok
    } catch {
        return $false
    }
}

function Open-WhenReady {
    $deadline = (Get-Date).AddMinutes(3)
    while ((Get-Date) -lt $deadline) {
        if (Test-PacketLens) {
            Start-Process 'http://127.0.0.1:8765/'
            return
        }
        Start-Sleep -Milliseconds 700
    }
}

if (-not $NoCapture -and -not (Test-Admin)) {
    $arg = '-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
    try {
        Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arg -Verb RunAs -ErrorAction Stop
        Open-WhenReady
        exit 0
    } catch {
        $NoCapture = $true
    }
}

function Resolve-Python {
    $list = New-Object System.Collections.Generic.List[string]
    $bin = Join-Path $env:LocalAppData 'Python\bin\python.exe'
    if (Test-Path $bin) { $list.Add($bin) }
    foreach ($root in @(
        (Join-Path $env:LocalAppData 'Python'),
        (Join-Path $env:LocalAppData 'Programs\Python')
    )) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root -Recurse -Filter python.exe -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.FullName -notmatch 'WindowsApps' -and -not $list.Contains($_.FullName)) { $list.Add($_.FullName) }
        }
    }
    return $list | Select-Object -First 1
}

function Stop-OldListener {
    Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -gt 0 } |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^(python|python3|py)\.exe$' -and $_.CommandLine -like '*packetlens.py*'
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

$here = $PSScriptRoot
$log = Join-Path $env:TEMP 'packetlens-launch.log'
if (Test-Path $log) { Remove-Item $log -Force -ErrorAction SilentlyContinue }
$pythonExe = Resolve-Python

$form = New-Object System.Windows.Forms.Form
$form.Text = 'PacketLens'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.StartPosition = 'CenterScreen'
$form.ClientSize = New-Object System.Drawing.Size(460, 128)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$form.TopMost = $false

$label = New-Object System.Windows.Forms.Label
$label.Dock = 'Fill'
$label.Padding = New-Object System.Windows.Forms.Padding(16, 16, 16, 8)
$label.Text = L 'PacketLens açılıyor. İlk seferde Wireshark indirilebilir; Npcap penceresi gelirse İleri ve Kur düğmelerine basın.' 'Starting PacketLens. The first launch may download Wireshark; if an Npcap window appears, click Next and Install.'
$form.Controls.Add($label)

if (-not $pythonExe) {
    [System.Windows.Forms.MessageBox]::Show(
        (L "Python 3 bulunamadı.`nhttps://www.python.org/downloads/" "Python 3 was not found.`nhttps://www.python.org/downloads/"),
        'PacketLens') | Out-Null
    exit 1
}
$script:previousPid = 0
if (-not $NoCapture) {
    $previous = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -gt 0 } | Select-Object -First 1
    if ($previous) { $script:previousPid = [int]$previous.OwningProcess }
    Stop-OldListener
}

$captureFlag = ''
if ($NoCapture) {
    $captureFlag = ' --no-capture'
    $label.Text = L 'Yönetici onayı verilmedi. Yalnızca dosya analizi açılıyor.' 'Administrator approval was declined. Opening file analysis only.'
}

$env:PYTHONUNBUFFERED = '1'
$env:PYTHONIOENCODING = 'utf-8'
$cmd = "chcp 65001>nul & set PYTHONUNBUFFERED=1& set PYTHONIOENCODING=utf-8& `"$pythonExe`" packetlens.py --restart$captureFlag > `"$log`" 2>&1"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "$env:SystemRoot\System32\cmd.exe"
$psi.Arguments = '/c ' + $cmd
$psi.WorkingDirectory = $here
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$script:log = $log
$script:label = $label
$script:form = $form
$script:readyText = L 'Arayüz tarayıcıda açıldı.' 'The interface is open in the browser.'
$script:failText = L 'PacketLens başlatılamadı.' 'PacketLens could not start.'
$script:proc = [Diagnostics.Process]::Start($psi)

function Read-LastLine([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    $reader = $null
    try {
        $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        $reader = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
        $text = $reader.ReadToEnd()
        $lines = @($text -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
        if ($lines.Count -gt 0) { return $lines[-1] }
    } catch {
        return $null
    } finally {
        if ($reader) { $reader.Dispose() }
    }
    return $null
}

function Test-Server {
    try {
        $req = [Net.HttpWebRequest]::Create('http://127.0.0.1:8765/api/info')
        $req.Timeout = 8000
        $req.Proxy = $null
        $res = $req.GetResponse()
        $ok = [int]$res.StatusCode -eq 200
        $res.Close()
        return $ok
    } catch {
        return $false
    }
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 400
$script:ticks = 0
$script:timer = $timer
$timer.Add_Tick({
    $script:ticks++
    $line = Read-LastLine $script:log
    if ($line) {
        if ($line.Length -gt 180) { $line = $line.Substring(0, 180) }
        $script:label.Text = $line
    }
    if (Test-Server) {
        $listen = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.OwningProcess -gt 0 } | Select-Object -First 1
        if ($script:previousPid -and $listen -and [int]$listen.OwningProcess -eq $script:previousPid) { return }
        $script:timer.Stop()
        $script:label.Text = $script:readyText
        Start-Process 'http://127.0.0.1:8765/'
        $script:form.Close()
        return
    }
    $dead = $false
    try { $dead = $script:proc.HasExited } catch { $dead = $true }
    if ($dead -or $script:ticks -gt 2250) {
        $script:timer.Stop()
        $tail = ''
        if (Test-Path $script:log) {
            try {
                $fs = [IO.File]::Open($script:log, 'Open', 'Read', 'ReadWrite')
                $reader = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
                $raw = $reader.ReadToEnd()
                $reader.Close()
                $chunk = @($raw -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
                if ($chunk.Count -gt 12) { $chunk = $chunk[($chunk.Count - 12)..($chunk.Count - 1)] }
                $tail = ($chunk -join "`r`n")
            } catch {
                $tail = ''
            }
        }
        if (-not $tail) { $tail = $script:failText }
        [System.Windows.Forms.MessageBox]::Show($tail, 'PacketLens') | Out-Null
        $script:form.Close()
    }
})
$timer.Start()
[void]$form.ShowDialog()
$timer.Stop()
$timer.Dispose()
