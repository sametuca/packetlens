"""Windows: Wireshark (dumpcap) ve Npcap kurulumu.

winget kaynak hatası (0x8a15000f) kurulumun önüne geçmez: paketler
resmi siteden indirilir. Wireshark sessiz kurulur. Npcap ücretsiz
sürümü sessiz kurulumu desteklemez; kurulum penceresi açılır ve
kullanıcı bitirene kadar beklenir.
"""
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

from pl_capture_win import find_dumpcap
from pl_platform import is_privileged

_NOWINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
_UA = {'User-Agent': 'PacketLens/1.0'}

# İndeks okunamazsa kullanılan kararlı adresler.
_NPCAP_FALLBACK = 'https://npcap.com/dist/npcap-1.90.exe'
_WS_FALLBACK = {
    'x64': 'Wireshark-4.6.9-x64.exe',
    'arm64': 'Wireshark-4.6.9-arm64.exe',
}
# Ücretsiz Npcap'te /S yoktur (yalnızca OEM). Seçenekler GUI'de önceden işaretlenir.
_NPCAP_GUI_ARGS = ['/winpcap_mode=yes', '/loopback_support=yes', '/admin_only=no']
_WS_SILENT_ARGS = ['/S', '/desktopicon=no']

_NPCAP_EXE = re.compile(r'npcap-(\d+)\.(\d+)\.exe', re.I)
_WS_STABLE = {
    'x64': re.compile(r'Wireshark-(\d+)\.(\d+)\.(\d+)-x64\.exe'),
    'arm64': re.compile(r'Wireshark-(\d+)\.(\d+)\.(\d+)-arm64\.exe'),
}

_WINGET_SOURCE = None


def windows_arch():
    machine = platform.machine().lower()
    if machine in ('arm64', 'aarch64'):
        return 'arm64'
    return 'x64'


def pick_npcap_name(html):
    versions = {(int(a), int(b)) for a, b in _NPCAP_EXE.findall(html or '')}
    if not versions:
        return None
    major, minor = max(versions)
    return 'npcap-%d.%d.exe' % (major, minor)


def pick_wireshark_name(html, arch):
    pattern = _WS_STABLE.get(arch) or _WS_STABLE['x64']
    stables = []
    for major, minor, patch in pattern.findall(html or ''):
        major, minor, patch = int(major), int(minor), int(patch)
        if minor % 2 == 0:
            stables.append((major, minor, patch))
    if not stables:
        return None
    major, minor, patch = max(stables)
    suffix = 'arm64' if arch == 'arm64' else 'x64'
    return 'Wireshark-%d.%d.%d-%s.exe' % (major, minor, patch, suffix)


def _hidden():
    if sys.platform == 'win32' and _NOWINDOW:
        return {'creationflags': _NOWINDOW}
    return {}


def _fetch_text(url):
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode('utf-8', 'replace')


def npcap_installer_urls():
    name = None
    try:
        name = pick_npcap_name(_fetch_text('https://npcap.com/dist/'))
    except Exception:
        name = None
    urls = []
    if name:
        urls.append('https://npcap.com/dist/' + name)
    if _NPCAP_FALLBACK not in urls:
        urls.append(_NPCAP_FALLBACK)
    return urls


def wireshark_installer_urls():
    arch = windows_arch()
    name = None
    try:
        name = pick_wireshark_name(_fetch_text('https://www.wireshark.org/download/win64/'), arch)
    except Exception:
        name = None
    if not name:
        name = _WS_FALLBACK.get(arch) or _WS_FALLBACK['x64']
    return [
        'https://www.wireshark.org/download/win64/' + name,
        'https://2.na.dl.wireshark.org/win64/' + name,
    ]


def _winget_ok():
    try:
        r = subprocess.run(
            ['winget', '--version'],
            capture_output=True, timeout=15, **_hidden(),
        )
        return r.returncode == 0
    except Exception:
        return False


def winget_source_ok():
    """Paket kaynağı gerçekten arama yapabiliyor mu? Sürüm komutu yetmez."""
    global _WINGET_SOURCE
    if _WINGET_SOURCE is not None:
        return _WINGET_SOURCE
    if not _winget_ok():
        _WINGET_SOURCE = False
        return False
    try:
        r = subprocess.run(
            [
                'winget', 'search', '--id', 'WiresharkFoundation.Wireshark', '-e',
                '-n', '1', '--accept-source-agreements', '--disable-interactivity',
            ],
            capture_output=True, text=True, timeout=45, **_hidden(),
        )
    except Exception:
        _WINGET_SOURCE = False
        return False
    blob = ((r.stdout or '') + '\n' + (r.stderr or '')).lower()
    broken = (
        r.returncode != 0
        or '0x8a15000f' in blob
        or 'failed when searching source' in blob
        or 'data required by the source is missing' in blob
    )
    if broken:
        print('winget paket kaynağı kullanılamıyor; kurulum dosyası doğrudan indirilecek.')
    _WINGET_SOURCE = not broken
    return _WINGET_SOURCE


def npcap_installed():
    if sys.platform != 'win32':
        return False
    try:
        import winreg
        for hive in (winreg.HKEY_LOCAL_MACHINE,):
            for sub in (r'SOFTWARE\Npcap', r'SOFTWARE\WOW6432Node\Npcap'):
                try:
                    winreg.OpenKey(hive, sub)
                    return True
                except OSError:
                    pass
    except ImportError:
        pass
    sysroot = os.environ.get('SystemRoot', r'C:\Windows')
    npcap_dir = os.path.join(sysroot, 'System32', 'Npcap')
    if os.path.isdir(npcap_dir):
        return True
    try:
        r = subprocess.run(
            ['sc', 'query', 'npcap'],
            capture_output=True, text=True, timeout=10, **_hidden(),
        )
        if r.returncode == 0 and 'STATE' in (r.stdout or '').upper():
            return True
    except Exception:
        pass
    return False


def relaunch_as_admin():
    """Yönetici olarak yeniden başlat; başarılıysa mevcut süreç çıkar."""
    if sys.platform != 'win32' or is_privileged():
        return False
    try:
        import ctypes
        exe = sys.executable
        script = os.path.abspath(sys.argv[0])
        args = ' '.join('"%s"' % a.replace('"', '') for a in sys.argv[1:])
        if script.lower().endswith('.py'):
            params = '"%s" %s %s' % (script, args, '--elevated-child').strip()
        else:
            params = (args + ' --elevated-child').strip()
        rc = ctypes.windll.shell32.ShellExecuteW(None, 'runas', exe, params, None, 1)
        if rc <= 32:
            return False
        sys.exit(0)
    except Exception:
        return False


def _run_winget(package_id, label):
    if not winget_source_ok():
        return False
    print('winget ile %s kuruluyor…' % label, flush=True)
    try:
        r = subprocess.run(
            [
                'winget', 'install', '--id', package_id, '-e',
                '--accept-package-agreements', '--accept-source-agreements',
                '--disable-interactivity',
            ],
            capture_output=True, text=True, timeout=900, **_hidden(),
        )
    except Exception:
        print('winget %s kurulumunu başlatamadı.' % label)
        return False
    if r.returncode == 0:
        return True
    print('winget %s kurulumunu tamamlayamadı.' % label)
    return False


def _looks_like_installer(path, min_size):
    try:
        if os.path.getsize(path) < min_size:
            return False
        with open(path, 'rb') as handle:
            return handle.read(2) == b'MZ'
    except OSError:
        return False


def _unblock(path):
    try:
        os.remove(path + ':Zone.Identifier')
    except OSError:
        pass


def _download(urls, dest, label, min_size):
    last_error = ''
    for url in urls:
        try:
            print('%s indiriliyor…' % label, flush=True)
            req = urllib.request.Request(url, headers=_UA)
            with urllib.request.urlopen(req, timeout=180) as resp, open(dest, 'wb') as handle:
                total = int(resp.headers.get('Content-Length') or 0)
                got = 0
                next_mark = 25
                while True:
                    chunk = resp.read(256 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    got += len(chunk)
                    if total and got * 100 // total >= next_mark:
                        print('  %d%%' % min(100, got * 100 // total), flush=True)
                        next_mark += 25
            if _looks_like_installer(dest, min_size):
                _unblock(dest)
                return True
            last_error = 'indirilen dosya kurulum paketi değil'
        except Exception as exc:
            last_error = exc.__class__.__name__
            try:
                os.remove(dest)
            except OSError:
                pass
    if last_error:
        print('%s indirilemedi (%s).' % (label, last_error))
    return False


def _wait_installer(path, args):
    """Kurulum bitene kadar bekle. NSIS üst süreci erken çıktığı için Start-Process -Wait."""
    path_lit = path.replace("'", "''")
    if args:
        arg_lit = ','.join("'" + item.replace("'", "''") + "'" for item in args)
        command = (
            "$p = Start-Process -FilePath '%s' -ArgumentList @(%s) -Wait -PassThru; "
            "if ($null -eq $p.ExitCode) { exit 0 } else { exit $p.ExitCode }"
        ) % (path_lit, arg_lit)
    else:
        command = (
            "$p = Start-Process -FilePath '%s' -Wait -PassThru; "
            "if ($null -eq $p.ExitCode) { exit 0 } else { exit $p.ExitCode }"
        ) % path_lit
    try:
        completed = subprocess.run(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command],
            timeout=1200, **_hidden(),
        )
    except subprocess.TimeoutExpired:
        print('Kurulum penceresi zaman aşımına uğradı.')
        return None
    except Exception as exc:
        print('Kurulum başlatılamadı (%s).' % exc.__class__.__name__)
        return None
    return completed.returncode


def _npcap_exit_message(code):
    messages = {
        1: 'Npcap kurulumu iptal edildi.',
        2: 'Npcap kurulumu yarıda kesildi.',
        350: 'Npcap kurulumu başarısız. Bilgisayarı yeniden başlatıp PacketLens uygulamasını tekrar açın.',
        1618: 'Başka bir kurulum sürüyor. O bitince PacketLens uygulamasını tekrar açın.',
        1633: 'Bu Windows sürümünde Npcap desteklenmiyor.',
        3010: 'Npcap kuruldu. Canlı yakalama için bilgisayarı yeniden başlatmanız gerekebilir.',
    }
    return messages.get(code)


def install_npcap():
    if npcap_installed():
        return True
    dest = os.path.join(tempfile.gettempdir(), 'npcap-setup.exe')
    try:
        if not _download(npcap_installer_urls(), dest, 'Npcap', 500000):
            return False
        print('Npcap penceresi açılıyor. Ücretsiz sürüm sessiz kurulamaz; İleri ve Kur düğmelerine basın.', flush=True)
        code = _wait_installer(dest, _NPCAP_GUI_ARGS)
        time.sleep(2)
        if npcap_installed() or code == 3010:
            note = _npcap_exit_message(code) if code == 3010 else None
            if note:
                print(note)
            return True
        note = _npcap_exit_message(code)
        if note:
            print(note)
        elif code not in (0, None):
            print('Npcap kurulumu tamamlanmadı (çıkış kodu %s).' % code)
        else:
            print('Npcap kurulumu doğrulanamadı.')
        return False
    finally:
        try:
            os.remove(dest)
        except OSError:
            pass


def install_wireshark():
    if find_dumpcap():
        return True
    dest = os.path.join(tempfile.gettempdir(), 'wireshark-setup.exe')
    try:
        if _download(wireshark_installer_urls(), dest, 'Wireshark', 20000000):
            print('Wireshark sessiz kuruluyor (dumpcap)…', flush=True)
            _wait_installer(dest, _WS_SILENT_ARGS)
            time.sleep(2)
            if find_dumpcap():
                return True
            print('Wireshark kurulumu dumpcap dosyasını yerleştirmedi.')
    finally:
        try:
            os.remove(dest)
        except OSError:
            pass
    if _run_winget('WiresharkFoundation.Wireshark', 'Wireshark'):
        time.sleep(2)
        if find_dumpcap():
            return True
    return False


def ensure_capture_ready(elevated_child=False):
    """Npcap + dumpcap hazır değilse kurmayı dener. Başarı: True."""
    if sys.platform != 'win32':
        return False
    if find_dumpcap() and npcap_installed():
        return True
    if not is_privileged():
        if elevated_child:
            print('Yönetici izni gerekli. start.bat dosyasına sağ tık → Yönetici olarak çalıştır.')
            return False
        print('Kurulum için yönetici onayı isteniyor…')
        if not relaunch_as_admin():
            print('Yönetici onayı verilmedi. Canlı yakalama için start.bat dosyasına sağ tık → Yönetici olarak çalıştır.')
        return False

    print('PacketLens: canlı yakalama için Wireshark (dumpcap) ve Npcap hazırlanıyor…')
    ok_cap = bool(find_dumpcap()) or install_wireshark()
    ok_npcap = npcap_installed() or install_npcap()
    if ok_npcap and ok_cap:
        print('Npcap ve dumpcap hazır.')
        return True
    if not ok_cap:
        print('Wireshark kurulamadı: https://www.wireshark.org/download.html')
    if not ok_npcap:
        print('Npcap kurulamadı: https://npcap.com/#download')
    return False
