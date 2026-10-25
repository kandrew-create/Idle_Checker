"""Windows integration check; uses real Tk/tray windows and mocked SMTP.

Run with a Python installation containing requirements.txt. No email is sent and
all configuration is isolated in a temporary directory.
"""
import importlib.util
import json
import logging
from pathlib import Path
import tempfile
import threading
import tkinter as tk
from tkinter import ttk
import weakref
import sys

source = Path(__file__).resolve().parents[1] / 'idle_monitor.py'
sys.path.insert(0, str(source.parent))
spec = importlib.util.spec_from_file_location('idle_monitor', source)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.smtp_action = lambda *args: None
# Authorization is isolated here; test_admin_policy.py exercises rejected writes.
m.is_admin = lambda: True
m.collect_report = lambda whitelist=(): dict(captured_at='test snapshot', error='', windows=m.monitored_windows([dict(
    hwnd=123, pid=456, application='editor.exe', title='Example unsaved document',
    active=True, save_status='Unknown - application does not expose save status')], whitelist))
original_tk = tk.Tk
errors = []
roots = []
original_thread_hook = threading.excepthook
threading.excepthook = lambda args: errors.append(args.exc_value)

with tempfile.TemporaryDirectory(prefix='idle-tray-test-') as folder:
    folder = Path(folder)
    config = dict(m.DEFAULTS, email='test@example.com', email_password='mock',
                  check_interval_seconds=0.1)
    (folder / 'config.json').write_text(json.dumps(config), encoding='utf-8')
    app = m.App(config, folder / 'config.json', folder)

    def check(callback):
        def run():
            try:
                callback()
            except BaseException as exc:
                import traceback
                traceback.print_exc()
                errors.append(exc)
                app.quit()
        return run

    def later(callback):
        roots[0].after(350, check(callback))

    def active():
        assert app.signed_in and not app.paused and not app.stop.is_set()
        assert app.last_tick is not None, 'Monitoring must continue'

    def minimize():
        active()
        roots[0].iconify()
        later(minimized)

    def minimized():
        active()
        assert roots[0].state() == 'withdrawn', 'Minimize must hide the taskbar window'
        app.show_monitor()
        later(restored)

    def restored():
        active()
        assert len(roots) == 1 and roots[0].state() == 'normal'
        notebook = next(widget for widget in roots[0].winfo_children() if isinstance(widget, ttk.Notebook))
        assert notebook.tab(notebook.select(), 'text') == 'Monitoring'
        dashboard = notebook.nametowidget(notebook.select())
        table_frame = next(widget for widget in dashboard.winfo_children()
                           if any(isinstance(child, ttk.Treeview) for child in widget.winfo_children()))
        table = next(widget for widget in table_frame.winfo_children() if isinstance(widget, ttk.Treeview))
        assert table.item('123', 'values')[0] == 'editor.exe'
        assert 'Unknown' in table.item('123', 'values')[3]
        labels = [widget for widget in dashboard.winfo_children() if isinstance(widget, ttk.Label)]
        assert any('Idle ' in str(widget.getvar(widget.cget('textvariable')))
                   for widget in labels if widget.cget('textvariable'))
        import os
        if os.environ.get('IDLE_MONITOR_PREVIEW'):
            from PIL import ImageGrab
            ImageGrab.grab(window=roots[0].winfo_id()).save(os.environ['IDLE_MONITOR_PREVIEW'])
        app.pause()
        later(paused)

    def paused():
        assert app.paused and not app.stop.is_set()
        app.pause()
        later(resumed)

    def resumed():
        active()
        roots[0].tk.call(roots[0].protocol('WM_DELETE_WINDOW'))
        later(closed)

    def closed():
        active()
        assert roots[0].state() == 'withdrawn', 'X must hide Settings'
        app.open_window('monitor')
        later(button)

    def button():
        active()
        assert roots[0].state() == 'normal' and len(roots) == 1
        app.show_monitor()
        later(whitelist_app)

    def whitelist_app():
        notebook = next(widget for widget in roots[0].winfo_children() if isinstance(widget, ttk.Notebook))
        assert notebook.tab(1, 'state') == 'hidden'
        assert notebook.tab(2, 'state') == 'hidden'
        dashboard = notebook.nametowidget(notebook.tabs()[0])
        buttons = [child for group in dashboard.winfo_children() for child in group.winfo_children()
                   if isinstance(child, ttk.Button) and child.cget('text') == 'Whitelist selected app']
        assert len(buttons) == 1 and str(buttons[0].cget('state')) == 'disabled'
        buttons[0].invoke()
        assert app.snapshot()['app_whitelist'] == []
        later(finish)

    def finish():
        active()
        app.quit()

    def create_root(*args, **kwargs):
        root = original_tk(*args, **kwargs)
        roots.append(weakref.proxy(root))
        root.after(400, check(minimize))
        return root

    tk.Tk = create_root
    timer = threading.Timer(0.3, app.show_monitor)
    watchdog = threading.Timer(12, app.quit)
    try:
        timer.start()
        watchdog.start()
        app.run()
        assert roots and app.last_tick is not None
        assert not errors, errors
        assert not app.window_thread.is_alive(), 'Quit must close hidden Settings'
        assert not watchdog.finished.is_set(), 'Test timed out'
        print('PASS: employee dashboard, hidden settings/whitelist tabs, disabled whitelist action, pause/resume, minimize, X, tray restore, continued monitoring and Quit')
    finally:
        watchdog.cancel()
        timer.cancel()
        tk.Tk = original_tk
        threading.excepthook = original_thread_hook
        logging.shutdown()
