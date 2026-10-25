"""Additional settings lock. Windows elevation and file ACLs remain mandatory."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile


def password_record(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise ValueError('Use a settings password with 12 to 1024 characters.')
    salt = os.urandom(32)
    digest = derive(password, salt)
    return dict(version=1, salt=salt.hex(), digest=digest.hex())


def derive(password, salt):
    return hashlib.scrypt(password.encode('utf-8'), salt=salt, n=32768, r=8, p=1,
                          dklen=32, maxmem=64 * 1024 * 1024)


def matches(password, record):
    if not isinstance(password, str) or not 1 <= len(password) <= 1024:
        return False
    return hmac.compare_digest(derive(password, bytes.fromhex(record['salt'])).hex(), record['digest'])


class SettingsLock:
    def __init__(self, path, require_admin):
        self.path = Path(path)
        self.require_admin = require_admin
        self.session_record = None
        self.attempts = 0

    def read(self):
        try:
            record = json.loads(self.path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise ValueError('Settings password data is unreadable. Use Windows administrator recovery.') from exc
        if (not isinstance(record, dict) or record.get('version') != 1
                or not isinstance(record.get('salt'), str) or len(record['salt']) != 64
                or not isinstance(record.get('digest'), str) or len(record['digest']) != 64):
            raise ValueError('Settings password data is invalid. Use Windows administrator recovery.')
        try:
            bytes.fromhex(record['salt'])
            bytes.fromhex(record['digest'])
        except ValueError as exc:
            raise ValueError('Settings password data is invalid. Use Windows administrator recovery.') from exc
        return record

    def lock(self):
        self.session_record = None

    def authorize(self):
        self.require_admin()
        if self.session_record is None or self.read() != self.session_record:
            self.lock()
            raise PermissionError('Settings are locked. Close and reopen IT Admin Settings to unlock them.')

    def unlock(self, password):
        self.require_admin()
        self.lock()
        if self.attempts >= 5:
            raise PermissionError('Too many incorrect attempts. Close and reopen IT Admin Settings, or use administrator recovery.')
        record = self.read()
        if record is None or not matches(password, record):
            self.attempts += 1
            raise PermissionError('Incorrect settings password.')
        self.session_record = record
        self.attempts = 0

    def save_password(self, password, confirmation, current=None, recovery=False):
        self.require_admin()
        if not recovery:
            record = self.read()
            if record is not None:
                self.authorize()
                if not matches(current, record): raise PermissionError('Current settings password is incorrect.')
        if password != confirmation: raise ValueError('The new settings passwords do not match.')
        record = password_record(password)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.path.parent,
                                             prefix='settings-password-', suffix='.tmp', delete=False) as temp:
                temp_path = Path(temp.name)
                json.dump(record, temp)
                temp.write('\n')
            os.replace(temp_path, self.path)
        finally:
            if temp_path is not None: temp_path.unlink(missing_ok=True)
        self.session_record = record
        self.attempts = 0


def unlock_dialog(parent, lock):
    """Do not construct editable settings until this modal gate succeeds."""
    import tkinter as tk
    from tkinter import messagebox, simpledialog, ttk

    def setup(recovery=False):
        if recovery and not messagebox.askyesno('Windows administrator recovery',
                'You are running as a Windows administrator. Replace the forgotten settings password?\n'
                'Other open settings windows will need to unlock again.', parent=parent):
            return False
        password = simpledialog.askstring('Set settings password',
            'Enter a new settings password (at least 12 characters).\nThis is separate from your Gmail App Password.',
            show='*', parent=parent)
        if password is None: return False
        confirmation = simpledialog.askstring('Confirm settings password', 'Enter the new settings password again:',
                                              show='*', parent=parent)
        if confirmation is None: return False
        try:
            lock.save_password(password, confirmation, recovery=recovery)
            return True
        except (ValueError, PermissionError, OSError) as exc:
            messagebox.showerror('Settings password', str(exc), parent=parent)
            return False

    try:
        if lock.read() is None:
            return setup()
        initial_error = ''
    except ValueError as exc:
        initial_error = str(exc)
    dialog = tk.Toplevel(parent)
    dialog.title('Unlock IT Admin Settings')
    dialog.resizable(False, False)
    frame = ttk.Frame(dialog, padding=20)
    frame.pack(fill='both', expand=True)
    ttk.Label(frame, text='Enter the settings password to continue.').pack(anchor='w')
    value, feedback = tk.StringVar(dialog), tk.StringVar(dialog, initial_error)
    entry = ttk.Entry(frame, textvariable=value, show='*', width=40)
    entry.pack(fill='x', pady=10)
    ttk.Label(frame, textvariable=feedback, wraplength=380).pack(anchor='w')
    unlocked = False

    def submit():
        nonlocal unlocked
        try:
            lock.unlock(value.get())
            unlocked = True
            dialog.destroy()
        except (ValueError, PermissionError, OSError) as exc:
            feedback.set(str(exc))
            value.set('')

    def recover():
        nonlocal unlocked
        if setup(recovery=True):
            unlocked = True
            dialog.destroy()

    ttk.Button(frame, text='Unlock settings', command=submit).pack(fill='x', pady=(10, 0))
    ttk.Button(frame, text='Forgot password? Windows admin recovery', command=recover).pack(fill='x', pady=8)
    ttk.Button(frame, text='Cancel', command=dialog.destroy).pack(fill='x')
    dialog.bind('<Return>', lambda event: submit())
    dialog.grab_set()
    entry.focus_force()
    parent.wait_window(dialog)
    value.set('')
    return unlocked
