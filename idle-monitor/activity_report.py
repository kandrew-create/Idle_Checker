"""Read window metadata and best-effort document save status without changing apps."""
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess

UNKNOWN = 'Unknown - application does not expose save status'
OFFICE = {'winword.exe', 'excel.exe', 'powerpnt.exe'}


def normalize_whitelist(value):
    if not isinstance(value, list):
        raise ValueError('App whitelist must be a list of executable names.')
    names = set()
    for name in value:
        if not isinstance(name, str):
            raise ValueError('App whitelist entries must be executable names, such as chrome.exe.')
        name = name.strip().casefold()
        if not name.endswith('.exe') or len(name) <= 4 or any(ch in name for ch in '\\/:*?"<>|\r\n\t'):
            raise ValueError('Use executable names such as chrome.exe, without paths or wildcards.')
        names.add(name)
    return sorted(names)


def monitored_windows(rows, whitelist):
    excluded = {name.casefold() for name in whitelist}
    return [row for row in rows if row['application'].casefold() not in excluded]


def title_save_status(title):
    # These are indications only: an asterisk may be part of a filename/title.
    if title.lstrip().startswith(('*', '\u25cf', '\u2022')):
        return 'Possible unsaved changes - title indicator'
    return UNKNOWN


def open_windows():
    user = C.WinDLL('user32', use_last_error=True)
    kernel = C.WinDLL('kernel32', use_last_error=True)
    callback_type = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    user.EnumWindows.argtypes = [callback_type, W.LPARAM]
    user.EnumWindows.restype = W.BOOL
    user.GetForegroundWindow.restype = W.HWND
    user.IsWindowVisible.argtypes = [W.HWND]
    user.GetWindowTextW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
    user.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
    kernel.CloseHandle.argtypes = [W.HANDLE]
    foreground = user.GetForegroundWindow()
    rows = []

    @callback_type
    def visit(hwnd, _):
        try:
            if not user.IsWindowVisible(hwnd): return True
            title = C.create_unicode_buffer(2048)
            if not user.GetWindowTextW(hwnd, title, len(title)): return True
            pid = W.DWORD()
            user.GetWindowThreadProcessId(hwnd, C.byref(pid))
            if pid.value == os.getpid() or title.value == 'Program Manager': return True
            process = kernel.OpenProcess(0x1000, False, pid.value)
            name = f'Unavailable (PID {pid.value})'
            if process:
                try:
                    path, length = C.create_unicode_buffer(32768), W.DWORD(32768)
                    if kernel.QueryFullProcessImageNameW(process, 0, path, C.byref(length)):
                        name = Path(path.value).name
                finally:
                    kernel.CloseHandle(process)
            rows.append(dict(hwnd=int(hwnd), pid=pid.value, application=name,
                             title=title.value, active=hwnd == foreground,
                             save_status=title_save_status(title.value)))
        except Exception:
            # A window may close or become inaccessible during enumeration.
            pass
        return True

    if not user.EnumWindows(visit, 0): raise C.WinError(C.get_last_error())
    return sorted(rows, key=lambda row: (not row['active'], row['application'].casefold(), row['title'].casefold()))


def office_status(rows):
    applications = sorted({row['application'].lower() for row in rows} & OFFICE)
    if not applications: return []
    script = Path(__file__).resolve().with_name('document_status.ps1')
    powershell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run(
        [str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
         '-File', str(script), '-Applications', ','.join(applications)],
        capture_output=True, timeout=4, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode: return []
    # Windows PowerShell writes redirected output using its console encoding.
    # Only numeric HWND and boolean properties are used for matching.
    return json.loads(result.stdout.decode('utf-8', errors='replace').lstrip('\ufeff'))


def apply_document_status(rows, documents):
    by_window = {}
    for doc in documents:
        by_window.setdefault(int(doc['hwnd']) & 0xFFFFFFFF, []).append(doc)
    for row in rows:
        matches = by_window.get(row['hwnd'] & 0xFFFFFFFF, [])
        if not matches: continue
        if len({(doc['has_path'], doc['saved']) for doc in matches}) > 1:
            row['save_status'] = 'Unknown - multiple documents share this window with different save states'
            continue
        doc = matches[0]
        if not doc['has_path']:
            row['save_status'] = 'Never saved to a file'
        elif doc['saved']:
            row['save_status'] = 'Saved - application reports no unsaved changes'
        else:
            row['save_status'] = 'Unsaved changes - application reports modified document'
    return rows


def collect_report(whitelist=()):
    report = dict(captured_at=datetime.now().astimezone().isoformat(timespec='seconds'),
                  windows=[], error='')
    try:
        report['windows'] = monitored_windows(open_windows(), whitelist)
    except Exception:
        report['error'] = 'Open application windows could not be read in this session.'
        return report
    try:
        apply_document_status(report['windows'], office_status(report['windows']))
    except Exception:
        # Failed inspection must never turn Unknown into Saved or block an idle email.
        pass
    return report


def format_report(report):
    lines = ['OPEN APPLICATION REPORT', f"Captured: {report['captured_at']}",
             'Visible application windows (including minimized windows); background services and hidden tabs are not listed.', '']
    if report.get('error'): lines.append(report['error'])
    elif not report['windows']: lines.append('No monitored application windows were found (whitelisted apps are excluded).')
    for row in report['windows']:
        marker = ' [ACTIVE AT CAPTURE]' if row['active'] else ''
        title = row['title'].replace('\r', ' ').replace('\n', ' ')
        lines.extend([f"{row['application']} (PID {row['pid']}){marker}",
                      f'  Window: {title}', f"  Save status: {row['save_status']}", ''])
    lines.extend(['Unknown means save status could not be determined; it does not mean saved.',
                  'Title indicators are hints only. Office status is read from an accessible running Word, Excel, or PowerPoint instance.',
                  'Saved reflects the application state at capture; it does not verify cloud sync or backups.'])
    return '\n'.join(lines)
