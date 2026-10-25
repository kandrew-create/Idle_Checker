"""Windows interactive-session idle alert. Only pystray and Pillow are external."""
import argparse, ctypes as C, gc, getpass, json, logging, math, msvcrt, os, queue, re, signal
import smtplib, socket, ssl, sys, threading, time
from functools import partial
from ctypes import wintypes as W
from datetime import datetime, timedelta
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler
from pathlib import Path
from activity_report import collect_report, format_report, monitored_windows, normalize_whitelist
from settings_security import SettingsLock, unlock_dialog

DEFAULTS = dict(idle_threshold_minutes=30, check_interval_seconds=30,
                smtp_host="smtp.gmail.com", smtp_port=587, use_ssl=False,
                email="", email_password="", log_file="idle_monitor.log", app_whitelist=[])
AUTH_FIELDS = {"email", "email_password", "smtp_host", "smtp_port", "use_ssl"}
LOG = logging.getLogger("idle-monitor")

def is_admin():
    return sys.platform == 'win32' and bool(S.IsUserAnAdmin())

def require_admin():
    if not is_admin():
        raise PermissionError('Only IT administrators can change settings. Run IT Admin Settings as administrator.')

def machine_config_path():
    # Read the Windows known folder, not a user-overridable environment variable.
    buffer = C.create_unicode_buffer(32768)
    if S.SHGetFolderPathW(None, 35, None, 0, buffer) != 0:
        raise RuntimeError('Cannot locate machine settings. Contact IT.')
    return Path(buffer.value) / 'Idle Monitor' / 'config.json'

def launch_admin_settings():
    import subprocess
    arguments = ['--admin-settings']
    if not getattr(sys, 'frozen', False): arguments.insert(0, str(Path(__file__).resolve()))
    result = S.ShellExecuteW(None, 'runas', sys.executable, subprocess.list2cmdline(arguments), None, 1)
    if not result or result <= 32:
        raise PermissionError('Administrator approval is required to open IT Admin Settings.')

def read_machine_config(path):
    try:
        loaded = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(loaded, dict): raise ValueError('Expected an object')
        return validate({key: loaded.get(key, value) for key, value in DEFAULTS.items()}, require_email=False)
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError('IT-managed settings are missing, unreadable, or invalid. Ask IT to run install-managed.ps1 or repair the configuration.') from exc

if sys.platform == "win32":
    K, U, S = (C.WinDLL(n, use_last_error=True) for n in ("kernel32", "user32", "shell32"))
    # Explicit signatures prevent handle truncation on 64-bit Python.
    signatures = [(K.GetTickCount, [], W.DWORD),
                  (K.OpenProcess, [W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
                  (K.CloseHandle, [W.HANDLE], W.BOOL),
                  (K.GetExitCodeProcess, [W.HANDLE, C.POINTER(W.DWORD)], W.BOOL),
                  (K.ProcessIdToSessionId, [W.DWORD, C.POINTER(W.DWORD)], W.BOOL),
                  (K.CreateFileW, [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE], W.HANDLE),
                  (K.SetFileInformationByHandle, [W.HANDLE, C.c_int, W.LPVOID, W.DWORD], W.BOOL),
                  (U.MessageBoxW, [W.HWND, W.LPCWSTR, W.LPCWSTR, W.UINT], C.c_int)]
    for func, args, result in signatures:
        func.argtypes, func.restype = args, result
    S.ShellExecuteW.argtypes = [W.HWND, W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, C.c_int]
    S.ShellExecuteW.restype = W.HINSTANCE
    S.SHGetFolderPathW.argtypes = [W.HWND, C.c_int, W.HANDLE, W.DWORD, W.LPWSTR]
    S.SHGetFolderPathW.restype = C.c_long

class LASTINPUTINFO(C.Structure):
    _fields_ = [("cbSize", W.UINT), ("dwTime", W.DWORD)]

if sys.platform == "win32":
    U.GetLastInputInfo.argtypes, U.GetLastInputInfo.restype = [C.POINTER(LASTINPUTINFO)], W.BOOL

def get_idle_seconds() -> float:
    info = LASTINPUTINFO(C.sizeof(LASTINPUTINFO), 0)
    if not U.GetLastInputInfo(C.byref(info)):
        LOG.warning("GetLastInputInfo failed; skipping cycle")
        raise OSError("Unable to read last input")
    get_idle_seconds.last_tick = info.dwTime  # Monitor uses this to detect actual input.
    return ((K.GetTickCount() - info.dwTime) & 0xFFFFFFFF) / 1000.0

def validate(config, require_email=True):
    c = dict(config)
    c['app_whitelist'] = normalize_whitelist(c.get('app_whitelist', []))
    try:
        for key in ("idle_threshold_minutes", "check_interval_seconds"):
            if isinstance(c[key], bool): raise ValueError()
            c[key] = float(c[key])
            if not math.isfinite(c[key]) or c[key] <= 0: raise ValueError()
        c["smtp_port"] = int(str(c["smtp_port"]))
        if not 1 <= c["smtp_port"] <= 65535: raise ValueError()
    except (ValueError, TypeError, OverflowError):
        raise ValueError("Threshold and interval must be positive numbers; port must be 1–65535.")
    if c["check_interval_seconds"] >= c["idle_threshold_minutes"] * 60:
        raise ValueError("Check interval must be less than the threshold in seconds.")
    if not isinstance(c["use_ssl"], bool):
        raise ValueError("Use SSL must be true or false.")
    for key in ("smtp_host", "email", "email_password", "log_file"):
        if not isinstance(c[key], str) or "\n" in c[key] or "\r" in c[key]:
            raise ValueError("Text fields must be single-line strings.")
    c["email"], c["smtp_host"] = c["email"].strip(), c["smtp_host"].strip()
    if c["email"] and not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", c["email"]):
        raise ValueError("Enter one valid email address, for example name@example.com.")
    if c["email"] and (".." in c["email"] or c["email"].startswith(".") or ".@" in c["email"]):
        raise ValueError("Email address has an invalid dot placement.")
    if require_email and (not c["email"] or not c["smtp_host"]):
        raise ValueError("Email address and SMTP host are required.")
    if require_email and not c["email_password"]:
        raise ValueError("IT must configure an email App Password.")
    if not c["log_file"] or Path(c["log_file"]).name != c["log_file"]:
        raise ValueError("log_file must be a filename, without folders.")
    return c

def write_config(path, config):
    require_admin()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)  # Atomic replacement avoids half-written JSON.

def acquire_lock(path):
    # Deny competing writers/deleters while retaining a readable PID file.
    handle = K.CreateFileW(str(path), 0xC0010000, 1, None, 4, 0x80, None)
    if handle == C.c_void_p(-1).value:
        if C.get_last_error() in (32, 33): raise RuntimeError("Already running.")
        raise C.WinError(C.get_last_error())
    lock = os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDWR), "r+", encoding="ascii")
    try:
        try:
            pid = int(lock.read().strip())
        except (ValueError, OSError):
            pid = 0
        if pid > 0:
            process = K.OpenProcess(0x1000, False, pid)
            alive = C.get_last_error() == 5 if not process else True
            if process:
                code = W.DWORD()
                alive = not K.GetExitCodeProcess(process, C.byref(code)) or code.value == 259
                K.CloseHandle(process)
            if alive: raise RuntimeError("Already running.")
            LOG.info("Replacing stale PID lock")
        lock.seek(0)
        lock.truncate()
        lock.write(str(os.getpid()))
        lock.flush()
        return lock
    except BaseException:
        lock.close()
        raise

def smtp_action(config, idle=None):
    """Authenticate first. None verifies sign-in without sending a message."""
    c = validate(config)
    context = ssl.create_default_context()
    client = smtplib.SMTP_SSL if c["use_ssl"] else smtplib.SMTP
    kwargs = {"context": context} if c["use_ssl"] else {}
    smtp, stage = None, "server greeting"
    try:
        smtp = client(c["smtp_host"], c["smtp_port"], timeout=15, **kwargs)
        stage = "TLS setup"
        if not c["use_ssl"]: smtp.starttls(context=context)
        stage = "authentication"
        smtp.login(c["email"], c["email_password"])
        if idle is not None:
            stage = "message delivery"
            now, host = datetime.now().astimezone(), socket.gethostname()
            msg = EmailMessage()
            msg["From"] = msg["To"] = c["email"]
            msg["Subject"] = f"{host} - Idle Check Report"
            report = collect_report(c['app_whitelist'])
            report_text = format_report(report)
            msg.set_content(f"Hostname: {host}\nUsername: {getpass.getuser()}\nIdle: {idle / 60:.1f} minutes\n"
                            f"Idle began: {(now - timedelta(seconds=idle)).isoformat()}\nEmail time: {now.isoformat()}\n\n"
                            + report_text)
            msg.add_attachment(report_text, subtype='plain', filename='idle-application-report.txt')
            smtp.send_message(msg)
            return report
    except Exception as exc:
        exc.smtp_stage = stage
        LOG.warning("SMTP %s failed (%s)", stage, type(exc).__name__)
        raise
    finally:
        if smtp is not None: smtp.close()  # A failed QUIT must not cause duplicate retries.


def save_email_report(folder, report):
    """An archive failure must not retry an email already accepted by SMTP."""
    if report is None: return
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=folder,
                                         prefix='report-', suffix='.tmp', delete=False) as temp:
            temp.write(format_report(report))
        os.replace(temp.name, folder / 'latest-email-report.txt')
    except OSError:
        LOG.warning('Email sent, but local report could not be saved')
        if 'temp' in locals():
            try: Path(temp.name).unlink(missing_ok=True)
            except OSError: pass

def error_reason(exc):
    # Do not expose server text: it can echo credentials or authentication data.
    if isinstance(exc, smtplib.SMTPAuthenticationError): return "Sign-in rejected. Check the email and App Password."
    if isinstance(exc, smtplib.SMTPServerDisconnected) and getattr(exc, "smtp_stage", "") == "authentication":
        return "SMTP connection closed during sign-in. Check Workspace access policy, App Password, or mail-security filtering."
    if isinstance(exc, (TimeoutError, smtplib.SMTPServerDisconnected)): return "SMTP connection timed out or closed. Check network/firewall."
    if isinstance(exc, ssl.SSLError): return "TLS failed. Check the SSL checkbox, port, and certificates."
    if type(exc) in (ValueError, RuntimeError, PermissionError): return str(exc)
    return f"SMTP operation failed ({type(exc).__name__}). Check host, port, and network."

class App:
    def __init__(self, config, path, folder, recovery=False, override=None, editor=False):
        import pystray
        from PIL import Image, ImageDraw
        self.config, self.path, self.folder, self.recovery = dict(config), path, folder, recovery
        self.editor = editor
        if editor: require_admin()
        self.settings_lock = SettingsLock(path.parent / 'settings-password.json', require_admin)
        self.policy_stamp = path.stat().st_mtime_ns if path.exists() else None
        self.saved_threshold = config["idle_threshold_minutes"]
        if override is not None: self.config["idle_threshold_minutes"] = override
        self.guard, self.window_guard = threading.Lock(), threading.Lock()
        self.icon_guard = threading.Lock()
        self.stop, self.changed = threading.Event(), threading.Event()
        self.restore_settings = threading.Event()
        self.requested_page = 'settings'
        self.activity = dict(captured_at='', windows=[], error='Collecting application windows...')
        self.last_email_at, self.last_send_error = '', ''
        self.jobs, self.window_thread = [], None
        self.paused = self.notified = self.signed_in = False
        self.idle, self.last_tick, self.retry_at, self.epoch = 0.0, None, 0.0, 0
        try: validate(self.config); self.verify_pending = True
        except ValueError: self.verify_pending = False
        self.images = {}
        for color in ("green", "yellow", "red", "grey"):
            img = Image.new("RGBA", (64, 64))
            ImageDraw.Draw(img).ellipse((6, 6, 58, 58), fill=color, outline="white", width=3)
            self.images[color] = img
        I, M = pystray.MenuItem, pystray.Menu
        self.icon = pystray.Icon("idle-monitor", self.images["grey"], "Idle Monitor", M(
            I("Live monitoring...", self.show_monitor, default=True),
            I(lambda item: self.status(), None, enabled=False),
            I(lambda item: "Alerts go to " + self.snapshot()["email"], None, enabled=False, visible=lambda item: self.signed_in),
            I("IT Admin Settings...", self.settings),
            I(lambda item: "Resume monitoring" if self.paused else "Pause monitoring", self.pause),
            I("Send test email", lambda: self.start_job(self.send_current, notify=True), enabled=lambda item: self.signed_in),
            I("Open log file", lambda: os.startfile(str(folder / self.snapshot()["log_file"]))),
            I("Open config folder", lambda: os.startfile(str(path.parent))),
            I("Quit", self.quit)))
    def snapshot(self):
        with self.guard: return dict(self.config)
    def status(self):
        with self.guard:
            return "IT setup required" if not self.signed_in else "Paused" if self.paused else "Email sent" if self.notified else "Monitoring"
    def refresh(self):
        if self.editor: return
        with self.icon_guard:
            if self.stop.is_set(): return
            c = self.snapshot()
            self.icon.icon = self.images[{"IT setup required": "grey", "Paused": "yellow", "Email sent": "red"}.get(self.status(), "green")]
            self.icon.title = f"Idle {self.idle / 60:.0f} min / {c['idle_threshold_minutes']:g} min"
            self.icon.update_menu()
    def notice(self, message):
        try: self.icon.notify(message, "Idle Monitor")
        except Exception: LOG.warning("Tray notification unavailable")
    def commit(self, updates, verified=False, expected=None, cancel=None):
        require_admin()
        if not self.editor: raise PermissionError('Open IT Admin Settings to change settings.')
        self.settings_lock.authorize()
        with self.guard:
            if self.stop.is_set() or (cancel and cancel.is_set()): raise RuntimeError("Sign-in canceled.")
            if expected is not None and expected != self.epoch: raise RuntimeError("Account changed; please sign in again.")
            c = validate(dict(self.config, **updates), require_email=False)
            saved = dict(c, idle_threshold_minutes=updates.get("idle_threshold_minutes", self.saved_threshold))
            write_config(self.path, saved)
            fields = [k for k in c if c[k] != self.config[k]]
            self.config, self.saved_threshold = c, saved["idle_threshold_minutes"]
            if verified or AUTH_FIELDS.intersection(updates):
                self.signed_in, self.verify_pending, self.notified = verified, False, False
                self.epoch, self.retry_at = self.epoch + 1, 0.0
        LOG.info("Settings changed: %s", ", ".join(fields) or "none")
        self.changed.set()
        self.refresh()
    def sign_in(self, updates, cancel=None):
        require_admin()
        if not self.editor: raise PermissionError('Open IT Admin Settings to change settings.')
        self.settings_lock.authorize()
        with self.guard: c, epoch = validate(dict(self.config, **updates)), self.epoch
        LOG.info("Sign-in verification started")
        smtp_action(c)  # No settings are saved and no email is sent during verification.
        self.commit(updates, verified=True, expected=epoch, cancel=cancel)
        LOG.info("Signed in")
    def sign_out(self):
        try:
            self.commit({"email": "", "email_password": ""})
            LOG.info("Signed out")
        except Exception as exc: self.notice(error_reason(exc))
    def auth_required(self, epoch):
        with self.guard:
            if epoch != self.epoch: return
            self.signed_in = self.verify_pending = self.notified = False
            self.epoch += 1  # In-flight results for the old account must be discarded.
        LOG.info("Sign in required: SMTP authentication rejected")
        self.notice("Sign-in rejected. Ask IT to check the managed email settings.")
        self.refresh()
    def verify_saved(self):
        with self.guard: c, epoch = dict(self.config), self.epoch
        try:
            smtp_action(c)
            with self.guard:
                if epoch != self.epoch or self.stop.is_set(): return
                self.signed_in, self.verify_pending, self.retry_at = True, False, 0.0
            LOG.info("Saved sign-in verified")
        except smtplib.SMTPAuthenticationError: self.auth_required(epoch)
        except Exception as exc:
            with self.guard:
                if epoch != self.epoch: return
                self.retry_at = time.monotonic() + 300
            LOG.warning("Saved sign-in verification failed: %s", type(exc).__name__)
            self.notice(error_reason(exc) + " Saved sign-in kept; retrying in 5 minutes.")
    def send_current(self, idle=None):
        if self.editor: self.settings_lock.authorize()
        if not self.editor: self.reload_policy()
        with self.guard:
            if not self.signed_in or self.stop.is_set(): raise RuntimeError("Sign in successfully before sending a test email.")
            c, epoch = dict(self.config), self.epoch
            if idle is None: idle = self.idle
        try: report = smtp_action(c, idle)
        except smtplib.SMTPAuthenticationError:
            self.auth_required(epoch)
            raise
        except Exception as exc:
            with self.guard: self.last_send_error = error_reason(exc)
            raise
        save_email_report(self.folder, report)
        with self.guard:
            self.last_email_at = datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')
            self.last_send_error = ''
        LOG.info("Email sent to signed-in address")
        return epoch
    def start_job(self, function, notify=False):
        results = queue.Queue()
        def work():
            try: function(); ok, message = True, "Completed successfully."
            except Exception as exc:
                LOG.warning("SMTP/settings operation failed: %s", type(exc).__name__)
                ok, message = False, error_reason(exc)
            results.put((ok, message))  # Only plain values cross into the Tk thread.
            if notify: self.notice("Test email sent." if ok else message)
        with self.guard:
            if self.stop.is_set(): return results
            self.jobs = [t for t in self.jobs if t.is_alive()]
            worker = threading.Thread(target=work)
            self.jobs.append(worker)
            worker.start()
        return results
    def set_threshold(self, n):
        try: self.commit({"idle_threshold_minutes": n})
        except Exception as exc: self.notice(error_reason(exc))
    def pause(self):
        with self.guard: self.paused, self.notified = not self.paused, False
        LOG.info("Monitoring %s", "paused" if self.paused else "resumed")
        self.changed.set()
        self.refresh()
    def settings(self):
        if self.editor:
            self.open_window('settings')
            return
        try: launch_admin_settings()
        except PermissionError as exc: self.notice(str(exc))
    def show_monitor(self):
        self.open_window('monitor')
    def open_window(self, page):
        if self.stop.is_set(): return
        with self.guard: self.requested_page = page
        if self.window_guard.acquire(False):
            self.restore_settings.clear()
            self.window_thread = threading.Thread(target=self.settings_window)
            self.window_thread.start()
        else:
            self.restore_settings.set()  # Restore on the Tk thread, including hidden windows.
    def settings_window(self):
        try: self.build_settings()
        finally:
            gc.collect()  # Collect Tk cycles on their owning thread, after UI locals expire.
            self.window_guard.release()
    def build_settings(self):
        import tkinter as tk
        from tkinter import messagebox, ttk
        root, cancel = tk.Tk(), threading.Event()
        try:
            if self.editor:
                root.withdraw()
                if not unlock_dialog(root, self.settings_lock):
                    root.destroy()
                    return
                root.deiconify()
            root.title('Idle Monitor - IT Admin Settings' if self.editor else 'Idle Monitor - Monitoring (managed by IT)')
            def close():
                cancel.set()
                root.destroy()
            def hide():
                if self.editor: close()
                else: root.withdraw()
            def minimized(event):
                if event.widget is root and root.state() == 'iconic':
                    root.after_idle(hide)
            root.protocol("WM_DELETE_WINDOW", hide)
            root.bind('<Unmap>', minimized)
            root.geometry('1020x650')
            root.minsize(800, 560)
            notebook = ttk.Notebook(root)
            notebook.pack(fill='both', expand=True, padx=12, pady=12)
            dashboard, form = ttk.Frame(notebook, padding=12), ttk.Frame(notebook, padding=12)
            notebook.add(dashboard, text='Monitoring')
            notebook.add(form, text='Sign in & Settings')
            whitelist_tab = ttk.Frame(notebook, padding=12)
            notebook.add(whitelist_tab, text='App whitelist')
            if self.editor:
                security_tab = ttk.Frame(notebook, padding=12)
                notebook.add(security_tab, text='Settings security')
                ttk.Label(security_tab, text='Change settings password', font=('Segoe UI', 18, 'bold')).pack(anchor='w')
                ttk.Label(security_tab, text='Windows administrator approval is still required.\nUse at least 12 characters. This password is separate from the Gmail App Password.').pack(anchor='w', pady=10)
                password_fields = []
                for label in ('Current settings password', 'New settings password', 'Confirm new settings password'):
                    ttk.Label(security_tab, text=label).pack(anchor='w')
                    value = tk.StringVar(root)
                    ttk.Entry(security_tab, textvariable=value, show='*', width=45).pack(anchor='w', pady=(2, 10))
                    password_fields.append(value)
                password_feedback = tk.StringVar(root)
                def change_password():
                    try:
                        current, password, confirmation = [value.get() for value in password_fields]
                        self.settings_lock.save_password(password, confirmation, current=current)
                        password_feedback.set('Settings password changed. Use the new password the next time settings open.')
                    except (ValueError, PermissionError, OSError) as exc:
                        messagebox.showerror('Settings password', str(exc), parent=root)
                    finally:
                        for value in password_fields: value.set('')
                ttk.Button(security_tab, text='Change settings password', command=change_password).pack(anchor='w', pady=10)
                ttk.Label(security_tab, textvariable=password_feedback, wraplength=900).pack(anchor='w')
            ttk.Label(whitelist_tab, text='Apps excluded from monitoring', font=('Segoe UI', 18, 'bold')).pack(anchor='w')
            ttk.Label(whitelist_tab, text='Enter one executable name per line, for example chrome.exe or Spotify.exe.\nAll windows of these apps are excluded from the dashboard, document checks, and future email reports.\nKeyboard and mouse inactivity still controls idle alerts.', wraplength=940).pack(anchor='w', pady=10)
            whitelist_text = tk.Text(whitelist_tab, height=12, width=50)
            whitelist_text.pack(fill='both', expand=True)
            whitelist_feedback = tk.StringVar(root)
            def load_whitelist():
                whitelist_text.delete('1.0', 'end')
                whitelist_text.insert('1.0', '\n'.join(self.snapshot()['app_whitelist']))
            load_whitelist()
            if not self.editor: whitelist_text.configure(state='disabled')
            def save_whitelist():
                try:
                    names = [line.strip() for line in whitelist_text.get('1.0', 'end').splitlines() if line.strip()]
                    self.commit({'app_whitelist': names})
                    load_whitelist()
                    whitelist_feedback.set('Whitelist saved. Remove a name and save to monitor that app again.')
                except Exception as exc:
                    messagebox.showerror('App whitelist', error_reason(exc), parent=root)
            ttk.Button(whitelist_tab, text='Save whitelist', command=save_whitelist, state='normal' if self.editor else 'disabled').pack(anchor='w', pady=10)
            ttk.Label(whitelist_tab, textvariable=whitelist_feedback, wraplength=940).pack(anchor='w')
            def select_page():
                with self.guard: page = self.requested_page
                notebook.select(form if self.editor and page != 'monitor' else dashboard)
            if self.editor:
                ttk.Button(whitelist_tab, text='Choose from running apps',
                           command=lambda: notebook.select(dashboard)).pack(anchor='w', pady=(8, 0))
            select_page()
            ttk.Label(dashboard, text='Live monitoring', font=('Segoe UI', 18, 'bold')).pack(anchor='w')
            live_status, live_idle, live_detail, live_report = (tk.StringVar(root) for _ in range(4))
            ttk.Label(dashboard, textvariable=live_status, font=('Segoe UI', 11)).pack(anchor='w', pady=(6, 0))
            ttk.Label(dashboard, textvariable=live_idle, font=('Segoe UI', 25, 'bold')).pack(anchor='w', pady=6)
            progress = ttk.Progressbar(dashboard)
            progress.pack(fill='x', pady=(0, 6))
            ttk.Label(dashboard, textvariable=live_detail, wraplength=940).pack(anchor='w')
            controls = ttk.Frame(dashboard)
            controls.pack(fill='x', pady=10)
            pause_button = ttk.Button(controls, text='Pause monitoring', command=self.pause)
            pause_button.pack(side='left')
            ttk.Button(controls, text='IT Admin Settings', command=(lambda: notebook.select(form)) if self.editor else self.settings).pack(side='left', padx=8)
            test_button = ttk.Button(controls, text='Send test email', command=lambda: self.start_job(self.send_current, notify=True))
            test_button.pack(side='left')
            def open_report():
                report_path = self.folder / 'latest-email-report.txt'
                if report_path.exists(): os.startfile(str(report_path))
                else: messagebox.showinfo('Email report', 'No email report has been saved yet. Reports are saved after an email is sent successfully.', parent=root)
            ttk.Button(controls, text='Last email report', command=open_report).pack(side='left', padx=8)
            ttk.Label(dashboard, textvariable=live_report, wraplength=940).pack(anchor='w', pady=(0, 6))
            table_frame = ttk.Frame(dashboard)
            table_frame.pack(fill='both', expand=True)
            windows = ttk.Treeview(table_frame, columns=('application', 'window', 'active', 'saved'), show='headings', height=9)
            for key, label, width in [('application', 'Application', 140), ('window', 'Window / document', 330),
                                      ('active', 'Active', 65), ('saved', 'Save status', 360)]:
                windows.heading(key, text=label)
                windows.column(key, width=width, minwidth=50, stretch=key in ('window', 'saved'))
            scroll = ttk.Scrollbar(table_frame, orient='vertical', command=windows.yview)
            windows.configure(yscrollcommand=scroll.set)
            windows.pack(side='left', fill='both', expand=True)
            scroll.pack(side='right', fill='y')
            selected = tk.StringVar(root, 'Select a window to see its complete title and save status.')
            def show_selected(event):
                if windows.selection():
                    values = windows.item(windows.selection()[0], 'values')
                    selected.set(f'{values[0]} | {values[1]} | {values[3]}')
            windows.bind('<<TreeviewSelect>>', show_selected)
            def whitelist_selected():
                if not windows.selection():
                    messagebox.showinfo('App whitelist', 'Select an application window first.', parent=root)
                    return
                name = windows.item(windows.selection()[0], 'values')[0]
                try:
                    self.commit({'app_whitelist': self.snapshot()['app_whitelist'] + [name]})
                    load_whitelist()
                    selected.set(f'{name} added to the whitelist.')
                except Exception as exc:
                    messagebox.showerror('App whitelist', error_reason(exc), parent=root)
            ttk.Button(controls, text='Whitelist selected app', command=whitelist_selected, state='normal' if self.editor else 'disabled').pack(side='left')
            ttk.Label(dashboard, textvariable=selected, wraplength=940).pack(anchor='w', pady=(8, 0))
            ttk.Label(dashboard, text='Idle updates every second; application snapshots about every 5 seconds. Unknown does not mean saved.', wraplength=940).pack(anchor='w', pady=(6, 0))
            dashboard_at, rendered_at = 0.0, None
            def update_dashboard():
                nonlocal dashboard_at, rendered_at
                now = time.monotonic()
                if now - dashboard_at < 1: return
                dashboard_at = now
                c = self.snapshot()
                with self.guard:
                    activity, last_email, last_error, paused = self.activity, self.last_email_at, self.last_send_error, self.paused
                status = self.status()
                try:
                    idle = get_idle_seconds()
                    seconds = int(idle)
                    live_idle.set(f'Idle {seconds // 3600:02d}:{seconds // 60 % 60:02d}:{seconds % 60:02d}')
                    progress.configure(maximum=c['idle_threshold_minutes'] * 60, value=min(idle, c['idle_threshold_minutes'] * 60))
                    last_input = (datetime.now().astimezone() - timedelta(seconds=idle)).strftime('%H:%M:%S')
                    detail = f"Threshold: {c['idle_threshold_minutes']:g} min   |   Alert checks: every {c['check_interval_seconds']:g} sec   |   Last input: {last_input}"
                except OSError:
                    live_idle.set('Idle time unavailable')
                    detail = 'Windows could not read input activity in this session.'
                live_status.set(f"{status}   |   Alerts to: {c['email'] if self.signed_in else 'Contact IT'}")
                live_detail.set(detail + f"\nLast email: {last_email or 'None sent this session'}" + (f'\nEmail error: {last_error}' if last_error else ''))
                pause_button.configure(text='Resume monitoring' if paused else 'Pause monitoring')
                test_button.configure(state='normal' if self.signed_in else 'disabled')
                rows = monitored_windows(activity['windows'], c['app_whitelist'])
                live_report.set(activity.get('error') or f"Monitored windows: {len(rows)}   |   Whitelisted apps: {len(c['app_whitelist'])}   |   Captured: {activity['captured_at']}")
                render_key = (activity['captured_at'], tuple(c['app_whitelist']))
                if render_key != rendered_at:
                    rendered_at = render_key
                    chosen = windows.selection()
                    for item in windows.get_children(): windows.delete(item)
                    for row in rows:
                        windows.insert('', 'end', iid=str(row['hwnd']), values=(row['application'], row['title'], 'Yes' if row['active'] else '', row['save_status']))
                    if chosen and windows.exists(chosen[0]): windows.selection_set(chosen)
                    elif chosen: selected.set('Select a window to see its complete title and save status.')
            initial, fields = self.snapshot(), {}
            keys = ("email", "email_password", "idle_threshold_minutes", "check_interval_seconds", "smtp_host", "smtp_port", "use_ssl")
            for row, key in enumerate(keys):
                tk.Label(form, text=key.replace("_", " ").capitalize()).grid(row=row, column=0, sticky="w")
                value = initial[key] if self.editor or key != 'email_password' else ''
                var = tk.BooleanVar(root, value) if key == "use_ssl" else tk.StringVar(root, str(value))
                fields[key] = var
                widget = tk.Checkbutton(form, variable=var) if key == "use_ssl" else tk.Entry(form, textvariable=var, width=38, show="*" if key == "email_password" else "")
                widget.grid(row=row, column=1, padx=8, pady=4)
                if not self.editor: widget.configure(state='disabled')
            job, saving = None, False
            feedback = tk.StringVar(root, 'Settings are managed by IT. Use IT Admin Settings to request administrator access.' if not self.editor else 'Gmail / Workspace: use an App Password. Changes apply to all Windows users.')
            tk.Label(form, textvariable=feedback).grid(row=8, column=0, columnspan=3, padx=8)
            def action(save):
                nonlocal job, saving
                if job is not None: return
                try:
                    c = validate(dict(self.snapshot(), **{k: v.get() for k, v in fields.items()}))
                    updates = {k: c[k] for k in fields if c[k] != initial[k]}
                    if not save and AUTH_FIELDS.intersection(updates): raise ValueError("Sign in & Save account changes before testing.")
                    saving = save
                    job = self.start_job(partial(self.sign_in, updates, cancel) if save else self.send_current)
                    feedback.set("Signing in..." if save else "Sending test email...")
                except Exception as exc: messagebox.showerror("Check settings", error_reason(exc), parent=root)
            for col, (label, callback) in enumerate((("Sign in & Save", lambda: action(True)), ("Send test email", lambda: action(False)), ("Cancel", close))):
                tk.Button(form, text=label, command=callback, state='disabled' if not self.editor and col == 0 else 'normal').grid(row=9, column=col, pady=10)
            if not self.editor:
                notebook.hide(form)
                notebook.hide(whitelist_tab)
            tk.Button(root, text='Close' if self.editor else 'Minimize to tray', command=hide).pack(pady=(0, 10))
            def poll():
                nonlocal job
                if self.stop.is_set(): close(); return
                if self.restore_settings.is_set():
                    self.restore_settings.clear()
                    root.deiconify()
                    root.lift()
                    root.focus_force()
                    select_page()
                if root.state() != 'withdrawn': update_dashboard()
                if job is not None:
                    try: ok, message = job.get_nowait()
                    except queue.Empty: pass
                    else:
                        job = None
                        if ok and saving:
                            initial.update(self.snapshot())
                            for key, var in fields.items(): var.set(initial[key])
                            notebook.select(dashboard)
                            feedback.set('Signed in. Monitoring is active.')
                            root.after(100, poll)
                            return
                        feedback.set("Test email sent." if ok else "Sign-in or test failed.")
                        if not ok: messagebox.showerror("Idle Monitor", message, parent=root)
                root.after(100, poll)
            root.after(100, poll)
            root.mainloop()
        finally:
            cancel.set()  # Cancel/Quit prevents a late sign-in result from saving.
            if self.editor: self.settings_lock.lock()
    def cycle(self):
        with self.guard:
            if self.paused:
                self.notified = False
                LOG.debug("Paused; skipping cycle")
                return
            verify = self.verify_pending and time.monotonic() >= self.retry_at
        if verify: self.verify_saved()
        try: idle = get_idle_seconds()
        except OSError: return
        with self.guard:
            self.idle, tick = idle, get_idle_seconds.last_tick
            if self.last_tick is not None and tick != self.last_tick:
                self.notified = False
                LOG.info("Activity resumed, monitoring re-armed")
            self.last_tick, c = tick, dict(self.config)
            due = self.signed_in and not self.paused and not self.notified and idle >= c["idle_threshold_minutes"] * 60
        LOG.info("Idle: %.1f min (threshold %g min).", idle / 60, c["idle_threshold_minutes"])
        if due and time.monotonic() >= self.retry_at:
            try:
                epoch = self.send_current(idle)
                with self.guard:
                    if epoch == self.epoch and self.signed_in and not self.paused: self.notified = True
            except Exception as exc:
                LOG.warning("Email failed: %s", type(exc).__name__)
                self.notice(error_reason(exc))
                with self.guard: self.retry_at = time.monotonic() + 300
        self.refresh()
    def monitor(self):
        previous = time.time()
        while not self.stop.is_set():
            self.changed.clear()
            interval, now = self.snapshot()["check_interval_seconds"], time.time()
            if now - previous > 3 * interval: LOG.info("Wake or delayed cycle; reading fresh idle time")
            previous = now
            self.cycle()
            self.changed.wait(interval)
    def report_worker(self):
        while not self.stop.is_set():
            self.reload_policy()
            report = collect_report(self.snapshot()['app_whitelist'])
            with self.guard: self.activity = report
            self.stop.wait(5)
    def reload_policy(self):
        if self.editor: return
        try:
            stamp = self.path.stat().st_mtime_ns
            config = read_machine_config(self.path)
        except (RuntimeError, OSError):
            with self.guard:
                self.signed_in, self.verify_pending = False, False
                if not getattr(self, 'policy_failed', False): self.epoch += 1
                self.policy_failed = True
                self.last_send_error = 'IT settings unavailable. Contact IT.'
            return
        with self.guard:
            if config == self.config and stamp == self.policy_stamp and not getattr(self, 'policy_failed', False):
                return
            auth_changed = any(config[key] != self.config[key] for key in AUTH_FIELDS)
            self.config, self.saved_threshold = config, config['idle_threshold_minutes']
            self.policy_stamp = stamp
            self.policy_failed = False
            if auth_changed or not self.signed_in:
                self.signed_in = False
                try: validate(config); self.verify_pending = True
                except ValueError: self.verify_pending = False
                self.epoch += 1
                self.retry_at = 0.0
            self.last_send_error = ''
        self.changed.set()
    def quit(self):
        self.stop.set()
        self.changed.set()
        with self.icon_guard: self.icon.stop()
    def run_editor(self):
        require_admin()
        if not self.editor: raise PermissionError('Open IT Admin Settings to change settings.')
        # The standalone editor needs snapshots, but must not run a second alert loop.
        reporter = threading.Thread(target=self.report_worker, name='admin-application-report')
        reporter.start()
        try:
            self.build_settings()
        finally:
            self.stop.set()
            reporter.join()
            with self.guard: jobs = list(self.jobs)
            for job in jobs: job.join()
    def run(self):
        worker = threading.Thread(target=self.monitor, name="idle-monitor")
        reporter = threading.Thread(target=self.report_worker, name='application-report')
        def ready(icon):
            icon.visible = True
            self.refresh()
            if self.recovery: self.notice("Missing or corrupt config: defaults created; old config kept as .bad.")
            self.show_monitor()
            worker.start()
            reporter.start()
        try: self.icon.run(setup=ready)
        finally:
            self.quit()
            if worker.ident: worker.join()
            if reporter.ident: reporter.join()
            if self.window_thread: self.window_thread.join()
            with self.guard: jobs = list(self.jobs)
            for job in jobs: job.join()  # Release PID lock only after all SMTP work finishes.

def main():
    if sys.platform != "win32": raise RuntimeError("Windows only.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--test-email", action="store_true")
    modes.add_argument("--check-idle", action="store_true")
    parser.add_argument("--threshold-minutes", type=float)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument('--admin-settings', action='store_true', help='Open IT settings; requires Windows administrator elevation')
    args = parser.parse_args()
    if args.admin_settings and not is_admin():
        launch_admin_settings()
        return
    if args.config is not None or args.threshold_minutes is not None:
        raise PermissionError('Configuration and threshold overrides are disabled. Use IT Admin Settings.')
    if args.test_email: require_admin()
    if args.check_idle: return print(f"{get_idle_seconds():.3f}")
    folder = Path(os.environ["APPDATA"]) / "idle-monitor"
    folder.mkdir(parents=True, exist_ok=True)
    path = machine_config_path()
    recovery = False
    c = read_machine_config(path)
    handlers = [RotatingFileHandler(folder / c["log_file"], maxBytes=1048576, backupCount=3, encoding="utf-8")]
    if sys.stderr is not None: handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    session = W.DWORD()
    if not K.ProcessIdToSessionId(os.getpid(), C.byref(session)):
        raise C.WinError(C.get_last_error())
    LOG.info("User=%s session=%d elevated=%s", getpass.getuser(), session.value, bool(S.IsUserAnAdmin()))
    if session.value == 0:
        raise RuntimeError("Running in Session 0, idle detection will not work. Run as a logged-in user task instead.")
    LOG.info("Threshold=%g min interval=%g sec recipient=%s", args.threshold_minutes or c["idle_threshold_minutes"],
             c["check_interval_seconds"], c["email"])
    if args.test_email:
        report = smtp_action(c, get_idle_seconds())
        save_email_report(folder, report)
        LOG.info("Test email sent")
        return
    if args.admin_settings:
        app = App(c, path, folder, editor=True)
        app.run_editor()
        return
    lock = acquire_lock(folder / "idle_monitor.lock")
    handler = None
    try:
        app = App(c, path, folder, recovery, args.threshold_minutes)
        # Native console callbacks also wake the tray's blocking Windows message loop.
        handler = C.WINFUNCTYPE(W.BOOL, W.DWORD)(lambda event: (app.quit() or True) if event in (0, 1) else False)
        K.SetConsoleCtrlHandler(handler, True)
        for sig in (signal.SIGINT, signal.SIGBREAK): signal.signal(sig, lambda *_: app.quit())
        app.run()
    finally:
        if handler is not None: K.SetConsoleCtrlHandler(handler, False)
        delete = C.c_ubyte(1)  # FILE_DISPOSITION_INFO; delete atomically when handle closes.
        if not K.SetFileInformationByHandle(msvcrt.get_osfhandle(lock.fileno()), 4, C.byref(delete), 1):
            LOG.warning("Could not remove PID lock; it will be recovered next startup")
        lock.close()
        LOG.info("Stopped")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        message = error_reason(exc)
        LOG.error("%s", message)
        if sys.platform == "win32":
            U.MessageBoxW(None, message, "Idle Monitor", 0x10)
        sys.exit(1)
