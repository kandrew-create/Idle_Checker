import ctypes as C
from ctypes import wintypes as W
import json, os, subprocess, sys, tempfile, time
from pathlib import Path
import pefile

exe = Path(sys.argv[1]).resolve()
assert pefile.PE(str(exe)).OPTIONAL_HEADER.Subsystem == 2, 'Must use Windows GUI subsystem'
u = C.WinDLL('user32', use_last_error=True)
callback = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
u.EnumWindows.argtypes = [callback, W.LPARAM]
u.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
u.GetClassNameW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
u.GetWindowTextW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
u.IsWindowVisible.argtypes = [W.HWND]
u.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
with tempfile.TemporaryDirectory(prefix='idle-packaged-') as folder:
    env = dict(os.environ, APPDATA=folder)
    diagnostic = subprocess.run([str(exe), '--check-idle'], env=env, timeout=20)
    assert diagnostic.returncode == 0
    orphan_pid = 0
    if len(sys.argv) > 2: orphan_pid = int(sys.argv[2])
    process = subprocess.Popen([str(exe)], env=env)
    try:
        deadline = time.monotonic() + 20
        tray, settings = [], []
        while time.monotonic() < deadline:
            lock = Path(folder) / 'idle-monitor' / 'idle_monitor.lock'
            if lock.exists():
                tray.clear(); settings.clear()
                @callback
                def visit(hwnd, _):
                    owner = W.DWORD()
                    u.GetWindowThreadProcessId(hwnd, C.byref(owner))
                    if owner.value in child_pids:
                        cls, title = C.create_unicode_buffer(256), C.create_unicode_buffer(256)
                        u.GetClassNameW(hwnd, cls, 256)
                        u.GetWindowTextW(hwnd, title, 256)
                        if cls.value.startswith('idle-monitor') and cls.value.endswith('SystemTrayIcon'):
                            tray.append(hwnd)
                        if cls.value == 'TkTopLevel' and u.IsWindowVisible(hwnd): settings.append(hwnd)
                    return True
                child_pids = {process.pid, orphan_pid}
                listing = subprocess.check_output(['powershell', '-NoProfile', '-Command', "Get-CimInstance Win32_Process -Filter \"Name = 'Idle Monitor.exe'\" | Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress"], text=True)
                entries = json.loads(listing or '[]')
                if isinstance(entries, dict): entries = [entries]
                child_pids.update(item['ProcessId'] for item in entries if item['ParentProcessId'] == process.pid)
                u.EnumWindows(visit, 0)
                assert not settings, 'Startup must not show a dashboard'
                if tray: break
            assert process.poll() is None, 'Packaged application exited early'
            time.sleep(.1)
        assert tray and not settings, 'Startup must initialize only the tray'
        for hwnd in tray: u.PostMessageW(hwnd, 0x40A, 0, 0)
        assert process.wait(timeout=15) == 0
        assert not lock.exists(), 'Clean shutdown must remove the lock'
        print('PASS: GUI subsystem, idle diagnostic, tray-only startup, shutdown and lock cleanup')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
