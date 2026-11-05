"""Windows: Npcap + Wireshark (dumpcap) otomatik kurulum."""
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

from pl_platform import is_privileged

# Resmi dağıtım; güncel sürüm: https://npcap.com/#download
NPCAP_INSTALLER_URL = 'https://npcap.com/dist/npcap-1.79.exe'
NPCAP_SILENT = ['/S', '/winpcap_mode=yes', '/loopback_support=yes', '/admin_only=no']


def _winget_ok():
    try:
        r = subprocess.run(['winget', '--version'], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


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
    return os.path.isdir(os.path.join(sysroot, 'System32', 'Npcap'))


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
    print('winget ile %s kuruluyor (birkaç dakika sürebilir)…' % label)
    try:
        r = subprocess.run([
            'winget', 'install', '--id', package_id, '-e',
            '--accept-package-agreements', '--accept-source-agreements',
            '--disable-interactivity',
        ], timeout=900)
        return r.returncode == 0
    except Exception as e:
        print('winget hatası: %s' % e)
        return False


def _download_npcap_installer(dest):
    print('Npcap indiriliyor…')
    req = urllib.request.Request(NPCAP_INSTALLER_URL, headers={'User-Agent': 'PacketLens/1.0'})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, 'wb') as f:
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            f.write(chunk)
    return os.path.getsize(dest) > 100000


def _install_npcap_exe(installer_path):
    print('Npcap sessiz kurulum…')
    try:
        r = subprocess.run([installer_path] + NPCAP_SILENT, timeout=600)
        return r.returncode == 0
    except Exception as e:
        print('Npcap kurulum hatası: %s' % e)
        return False


def install_npcap():
    if npcap_installed():
        return True
    if _winget_ok() and _run_winget('Insecure.Npcap', 'Npcap'):
        time.sleep(2)
        if npcap_installed():
            return True
    td = tempfile.gettempdir()
    dest = os.path.join(td, 'npcap-setup.exe')
    try:
        if not _download_npcap_installer(dest):
            return False
        ok = _install_npcap_exe(dest)
        time.sleep(2)
        return ok and npcap_installed()
    finally:
        try:
            os.remove(dest)
        except OSError:
            pass


def install_wireshark():
    from pl_capture_win import find_dumpcap
    if find_dumpcap():
        return True
    if _winget_ok() and _run_winget('WiresharkFoundation.Wireshark', 'Wireshark (dumpcap)'):
        time.sleep(3)
        if find_dumpcap():
            return True
    print('Wireshark bulunamadı. winget yoksa: https://www.wireshark.org/download.html')
    return bool(find_dumpcap())


def ensure_capture_ready(elevated_child=False):
    """Npcap + dumpcap hazır değilse kurmayı dener. Başarı: True."""
    if sys.platform != 'win32':
        return False
    from pl_capture_win import find_dumpcap
    if find_dumpcap() and npcap_installed():
        return True
    if find_dumpcap() and not npcap_installed():
        # dumpcap var, sürücü eksik olabilir
        pass
    if not is_privileged():
        if elevated_child:
            print('Yönetici izni gerekli. start.bat dosyasına sağ tık → Yönetici olarak çalıştır.')
            return False
        print('Npcap kurulumu için yönetici onayı isteniyor…')
        relaunch_as_admin()
        return False

    print('PacketLens: canlı yakalama için Npcap (ve gerekirse Wireshark) kuruluyor…')
    ok_npcap = npcap_installed() or install_npcap()
    ok_cap = find_dumpcap() or install_wireshark()
    if ok_npcap and ok_cap:
        print('Npcap + dumpcap hazır.')
        return True
    if ok_cap:
        print('dumpcap var; Npcap doğrulanamadı — yine de deneyebilirsiniz.')
        return True
    print('Otomatik kurulum tamamlanamadı. Manuel: winget install Insecure.Npcap && winget install WiresharkFoundation.Wireshark')
    return False
