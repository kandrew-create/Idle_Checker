"""Gracefully stop only the specified installed app processes during this update."""
import ctypes as C
from ctypes import wintypes as W
import sys

pids = {int(value) for value in sys.argv[1:]}
user = C.WinDLL('user32', use_last_error=True)
callback_type = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
user.EnumWindows.argtypes = [callback_type, W.LPARAM]
user.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
user.GetClassNameW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
user.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
count = 0

@callback_type
def visit(hwnd, _):
    global count
    pid = W.DWORD()
    user.GetWindowThreadProcessId(hwnd, C.byref(pid))
    if pid.value in pids:
        cls = C.create_unicode_buffer(256)
        user.GetClassNameW(hwnd, cls, len(cls))
        if cls.value.startswith('idle-monitor') and cls.value.endswith('SystemTrayIcon'):
            user.PostMessageW(hwnd, 0x40A, 0, 0)
            count += 1
    return True

user.EnumWindows(visit, 0)
print('Sent graceful tray shutdown to', count, 'app windows')
