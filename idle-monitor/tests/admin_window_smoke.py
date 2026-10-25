"""Real Tk admin editor, mocked elevation and SMTP; no machine writes."""
import json
from pathlib import Path
import sys
import tempfile
import tkinter as tk
from tkinter import ttk
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import idle_monitor as monitor

errors = []
original_tk = tk.Tk
def snapshot(whitelist):
    windows = monitor.monitored_windows([dict(hwnd=123, pid=456, application='editor.exe',
        title='Example document', active=True, save_status='Unknown')], whitelist)
    return dict(captured_at='test snapshot', error='', windows=windows)

with tempfile.TemporaryDirectory() as folder, patch.object(monitor, 'is_admin', return_value=True), \
     patch.object(monitor, 'smtp_action', return_value=None) as smtp, \
     patch.object(monitor, 'collect_report', side_effect=snapshot):
    folder = Path(folder)
    config = dict(monitor.DEFAULTS, email='it@example.com', email_password='mock')
    app = monitor.App(config, folder / 'config.json', folder, editor=True)
    app.settings_lock.save_password('original settings password', 'original settings password')
    app.settings_lock.lock()

    def check(root, callback):
        try: callback()
        except BaseException as exc:
            errors.append(exc)
            root.destroy()

    def create_root():
        root = original_tk()
        root.after(10000, lambda: (errors.append(RuntimeError('Admin editor timed out')), root.destroy()))

        def save():
            notebook = next(widget for widget in root.winfo_children() if isinstance(widget, ttk.Notebook))
            form = notebook.nametowidget(notebook.tabs()[1])
            assert notebook.tab(notebook.select(), 'text') == 'Sign in & Settings'
            button = next(widget for widget in form.winfo_children()
                          if isinstance(widget, tk.Button) and widget.cget('text') == 'Sign in & Save')
            button.invoke()
            root.after(1200, lambda: check(root, choose_running_app))

        def choose_running_app():
            assert app.signed_in
            notebook = next(widget for widget in root.winfo_children() if isinstance(widget, ttk.Notebook))
            whitelist_tab = notebook.nametowidget(notebook.tabs()[2])
            notebook.select(whitelist_tab)
            next(widget for widget in whitelist_tab.winfo_children()
                 if isinstance(widget, ttk.Button) and widget.cget('text') == 'Choose from running apps').invoke()
            assert notebook.tab(notebook.select(), 'text') == 'Monitoring'
            dashboard = notebook.nametowidget(notebook.select())
            table = next(child for widget in dashboard.winfo_children() for child in widget.winfo_children()
                         if isinstance(child, ttk.Treeview))
            assert table.item('123', 'values')[0] == 'editor.exe', 'Standalone editor must collect running apps'
            table.selection_set('123')
            next(child for widget in dashboard.winfo_children() for child in widget.winfo_children()
                 if isinstance(child, ttk.Button) and child.cget('text') == 'Whitelist selected app').invoke()
            assert json.loads(app.path.read_text())['app_whitelist'] == ['editor.exe']
            # Already-collected rows must disappear as soon as the whitelist changes.
            root.after(1200, lambda: check(root, whitelist))

        def whitelist():
            assert app.signed_in
            assert json.loads(app.path.read_text())['email'] == 'it@example.com'
            notebook = next(widget for widget in root.winfo_children() if isinstance(widget, ttk.Notebook))
            dashboard = notebook.nametowidget(notebook.tabs()[0])
            table = next(child for widget in dashboard.winfo_children() for child in widget.winfo_children()
                         if isinstance(child, ttk.Treeview))
            assert not table.get_children(), 'Whitelisted apps must leave the preview'
            tab = notebook.nametowidget(notebook.tabs()[2])
            notebook.select(tab)
            editor = next(widget for widget in tab.winfo_children() if isinstance(widget, tk.Text))
            assert editor.get('1.0', 'end').strip() == 'editor.exe'
            editor.delete('1.0', 'end')
            editor.insert('1.0', 'chrome.exe')
            next(widget for widget in tab.winfo_children()
                 if isinstance(widget, ttk.Button) and widget.cget('text') == 'Save whitelist').invoke()
            assert json.loads(app.path.read_text())['app_whitelist'] == ['chrome.exe']
            root.tk.call(root.protocol('WM_DELETE_WINDOW'))

        def unlock():
            assert not any(isinstance(widget, ttk.Notebook) for widget in root.winfo_children()), 'Settings must not be constructed before unlock'
            dialog = next(widget for widget in root.winfo_children() if isinstance(widget, tk.Toplevel))
            frame = next(widget for widget in dialog.winfo_children() if isinstance(widget, ttk.Frame))
            entry = next(widget for widget in frame.winfo_children() if isinstance(widget, ttk.Entry))
            button = next(widget for widget in frame.winfo_children()
                          if isinstance(widget, ttk.Button) and widget.cget('text') == 'Unlock settings')
            entry.insert(0, 'incorrect password')
            button.invoke()
            assert not any(isinstance(widget, ttk.Notebook) for widget in root.winfo_children())
            entry.insert(0, 'original settings password')
            button.invoke()
            root.after(250, lambda: check(root, change_password))

        def change_password():
            notebook = next(widget for widget in root.winfo_children() if isinstance(widget, ttk.Notebook))
            tab = notebook.nametowidget(notebook.tabs()[3])
            notebook.select(tab)
            entries = [widget for widget in tab.winfo_children() if isinstance(widget, ttk.Entry)]
            for entry, value in zip(entries, ('original settings password', 'replacement settings password', 'replacement settings password')):
                entry.insert(0, value)
            next(widget for widget in tab.winfo_children()
                 if isinstance(widget, ttk.Button) and widget.cget('text') == 'Change settings password').invoke()
            assert all(not entry.get() for entry in entries)
            app.settings_lock.lock()
            app.settings_lock.unlock('replacement settings password')
            notebook.select(notebook.tabs()[1])
            save()

        root.after(250, lambda: check(root, unlock))
        return root

    with patch.object(tk, 'Tk', side_effect=create_root):
        app.run_editor()
    smtp.assert_called_once()  # Only explicit Sign in & Save, no automatic alerts.
    assert app.stop.is_set()
    assert app.settings_lock.session_record is None, 'Closing settings must lock them'
    assert not errors, errors
print('PASS: standalone admin editor collects apps, whitelists a selected app, refreshes preview, saves manual whitelist, and closes without automatic email')
