# Build a standalone Windows tray app with no console window.
a = Analysis(
    ['idle_monitor.py'],
    pathex=[], binaries=[], datas=[('document_status.ps1', '.')],
    hiddenimports=['pystray._win32'],
    hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='Idle Monitor',
    debug=False, bootloader_ignore_signals=False,
    strip=False, upx=False,
    console=False,
)
