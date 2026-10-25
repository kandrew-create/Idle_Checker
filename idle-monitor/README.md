# Idle Monitor — IT-managed Windows app

Monitors keyboard/mouse inactivity in each interactive Windows session and emails
an application/window snapshot after the configured idle threshold. Runs in the tray.

Email subjects automatically use the computer's hostname:
`<hostname> - Idle Check Report` for automatic alerts and manual tests. For example,
a computer named `STATION3` sends `STATION3 - Idle Check Report`. The body also
includes the computer name, Windows username, and idle details.

## IT-managed settings

Only an elevated Windows administrator can change the email account, SMTP server,
idle threshold, check interval, application whitelist, or log filename. Employees
see the monitoring dashboard; editable settings and whitelist tabs are hidden.
**IT Admin Settings** opens a separate process through Windows UAC. Canceling UAC
leaves the running monitor unchanged. Running the monitor elevated does not itself
unlock settings: use the separate editor.

### Settings password

After Windows administrator approval, IT Admin Settings also requires a separate
settings password. On first open after this update, IT is prompted to create and
confirm a password of at least 12 characters. Canceling leaves settings locked.
This password is separate from both Windows credentials and the Gmail App Password.

To change it, unlock the editor, open **Settings security**, enter the current
password and the new password twice, then click **Change settings password**.
Closing the editor locks it again. Five incorrect unlock attempts require closing
and reopening the editor or using recovery. A password change invalidates other
open editors' authorization to save; those editors must reopen and unlock again.

If forgotten, open IT Admin Settings with Windows administrator approval and click
**Forgot password? Windows admin recovery** on the unlock screen. Confirm recovery
and set a new password. Recovery does not change email or monitoring settings.
This is an extra app lock, not a restriction on the Windows administrator's ability
to repair local files or reset the password.

Only a random salt and a scrypt password verifier are stored in
`%ProgramData%\Idle Monitor\settings-password.json`; the settings password itself is
not stored or logged. Existing installations keep their monitoring configuration;
the installer preserves the verifier on ordinary updates. IT should retain this
file when backing up machine settings. Direct file repair or deliberate config
replacement by a Windows administrator remains an administrative recovery route.

The authority is the local Windows Administrators group, not a Google Workspace
admin role. Give administrator credentials only to IT. Users who already have
Windows administrator rights can manage the settings too.

All Windows users on a machine read the same configuration:
`%ProgramData%\Idle Monitor\config.json`. Windows known-folder lookup determines
the location; user environment variables cannot redirect it. The installer grants
Administrators and SYSTEM full control and ordinary Users read/execute access on
the policy directory and installed executable. It removes inherited write access.
Application saves also require an elevated admin editor. User profile configurations,
`--config`, `--threshold-minutes`, and `IDLE_MONITOR_PASSWORD` overrides are no longer
used. Missing/invalid machine policy stops email delivery and never creates a
user-writable fallback or silently resets the policy.

Running monitors reload policy about every five seconds. Credentials changed by IT
must pass SMTP verification before sending resumes. Reports/whitelist changes apply
to future captures; an email already in flight may finish using the prior settings.
An invalid policy disables sending until IT repairs it. Restart after changing the
log filename to change the active log destination.

This controls persistent settings. Employees can still pause/resume or quit their
tray app; it is not a tamper-resistant endpoint agent. It must run in the employee's
interactive session, not SYSTEM or Session 0.

## Install for all users

### Setup executable

Run `dist\setup.exe` and approve Windows administrator access. The setup wizard
installs the existing standalone app for all users, creates the two Start menu
shortcuts, enables startup at login, and registers an uninstall entry. Python is
not needed on the target computer. Close Idle Monitor in every Windows session
before upgrading. Setup preserves existing machine configuration and settings
passwords. It does not launch monitoring automatically in the elevated installer
session: open **Idle Monitor - IT Admin Settings** to configure email, then open
**Idle Monitor**, or sign out and back in.

Uninstall through Windows **Settings > Apps > Installed apps > Idle Monitor**
(**Apps & features** on Windows 10). Uninstall removes the app, shortcuts, and login
startup entry, while retaining machine settings and per-user logs/reports.
The setup executable is unsigned; a signing certificate is needed for a verified
publisher signature. This installer packages the current app; it does not implement
the additional behavior changes discussed in the requirements review.

To rebuild the installer after building the app, use Inno Setup 6 from
[the official download page](https://jrsoftware.org/isdl.php):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-installer.ps1
```

If the compiler is elsewhere, pass `-Compiler 'C:\path\to\ISCC.exe'`.
Use `-Version '1.0.2'` to set the installer version for a subsequent release.
Installer output is `dist\setup.exe`. The compiler is a build-only tool.
Use the compiler under its applicable license for your deployment.

### PowerShell installation alternative

1. Quit old Idle Monitor copies. Build first if using source (instructions below).
2. Open PowerShell **as administrator**, change to this directory, and run:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\install-managed.ps1
   ```

3. Open **Idle Monitor - IT Admin Settings** from Start, approve UAC with IT
   administrator credentials, enter the SMTP account and settings, then select
   **Sign in & Save**. This verifies SMTP without sending a message.
4. Start **Idle Monitor** from Start, or sign out of Windows and back in.
   The machine-wide startup entry starts it in each user's session at logon.

Installed executable: `%ProgramFiles%\Idle Monitor\Idle Monitor.exe`.
The compatibility `install-desktop.ps1` entry point now calls the managed installer
and also requires elevation. Python is not needed on employee machines.

To intentionally import an existing configuration during installation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-managed.ps1 -ConfigFile 'C:\path\to\config.json'
```

Review it first: the same email account/settings will apply to every Windows user
on this PC. Otherwise reinstalling preserves the existing machine configuration.
The installer refuses existing managed directories owned by non-administrators,
subdirectories, and links. IT must inspect/repair those cases instead of accepting
an untrusted directory. If the installed executable is in use, quit it before updating.
Old per-user executables/shortcuts/tasks are not removed automatically: retire them
and distribute the new managed build to every target PC. An old executable still
has its old behavior. Copying just the new EXE does not perform machine setup.

## Google Workspace / email

This app authenticates with SMTP, not Google browser sign-in. Use the full Gmail
or Workspace email address and an App Password permitted by your organization's
policy. Usual settings: `smtp.gmail.com`, port 587, SSL unchecked (STARTTLS), or
port 465 with SSL checked. TLS certificates are verified. There is no OAuth, Google
Workspace account discovery, central dashboard, or separate report-recipient field.
From and To both equal the IT-configured email address. Each report includes the
Windows username and hostname, so reports from multiple sessions can be distinguished.
Employee Google sign-in is not required to run the configured monitor.

**Credential limitation:** this desktop SMTP design needs the configured password
in each user's process. The machine configuration is readable by local users and
contains the App Password in plain text. Its ACL protects changes, not secrecy.
Use a dedicated reporting account; do not put an IT administrator's primary mailbox
credentials here. Keeping mail credentials secret from endpoint users requires a
separate reporting/mail backend, which this version does not provide.

## Monitoring and reports

Open the app or double-click its tray icon for Monitoring. Closing/minimizing this
window leaves monitoring in the tray. The dashboard shows idle time, threshold,
status, latest email time/error, and visible application windows (including minimized
ones). Background services, hidden windows, and inactive browser/editor tabs are
outside the snapshot. Application titles can contain document or website names.

The IT-only whitelist accepts executable names such as `chrome.exe`, one per line.
It excludes all matching windows, case-insensitively, from future snapshots and email
reports. Paths/wildcards are rejected. It does not change the keyboard/mouse idle timer.
In **IT Admin Settings**, open **Monitoring** to see applications in the current
Windows session, select a row, and click **Whitelist selected app**. Alternatively,
open **App whitelist** and click **Choose from running apps** to reach that list.
The admin window collects fresh snapshots about every five seconds without running
an additional automatic email loop. Selecting an app saves its exclusion immediately
and updates the manual whitelist editor. Whitelisted apps disappear from the list;
remove their executable names in **App whitelist** and save to monitor them again.

Word, Excel, and PowerPoint save status is probed read-only through existing Office
instances with a four-second timeout. Unsupported/inaccessible or ambiguous windows
remain Unknown. Title markers provide only a possible-unsaved hint. Saved does not
verify cloud sync or disk durability. No documents are saved, closed, or activated.

One automatic email is sent per continuous idle period; input re-arms it. Manual
tests are independent. Network failures retry at most every five minutes. SMTP
cannot guarantee exactly-once delivery if the acceptance response is lost. No mail
is sent while asleep/offline. Pause/resume starts monitoring afresh.

Logs, the per-profile instance lock, and `latest-email-report.txt` stay in
`%APPDATA%\idle-monitor`. The latest successful report contains the emailed snapshot;
older reports are not retained locally. Logs rotate at 1 MiB with three backups.
Credentials and raw SMTP errors are not logged. Existing personal configurations
are ignored and remain on disk; IT can remove them according to local policy.

## Build and verification

Use a full Windows Python 3.9+ installation with Tcl/Tk and pip:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Python 'C:\path\to\python.exe'
```

The standalone output is `dist\Idle Monitor.exe`. To run source after machine setup:

```powershell
python -m pip install -r requirements.txt
python idle_monitor.py
python idle_monitor.py --admin-settings
python idle_monitor.py --check-idle
```

`--admin-settings` requests elevation if needed. `--test-email` requires an already
elevated process. `--debug` enables diagnostic logging. Windows 10/11 only.

Verification with mocked SMTP/Office and isolated temporary files:

```powershell
python -m unittest discover -s tests -p 'test_*.py' -v
python tests/tray_window_smoke.py
python tests/admin_window_smoke.py
```

The authorization suite covers blocked standard-user writes/sign-in, admin editor
requirements, live reload, credential invalidation, invalid/missing-policy recovery,
and blocked configuration/password overrides. Real Tk checks cover the employee
read-only dashboard/tray lifecycle and the separate admin editor's save/close behavior.
No test email is sent. Elevated installation, actual file ACL enforcement across
Windows accounts, UAC, logon startup, and real Workspace delivery need deployment
verification on a test PC with IT credentials.

## Uninstall

IT should quit the app in every session, remove the `Idle Monitor` value from
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, remove the two Start menu
shortcuts, then remove `%ProgramFiles%\Idle Monitor`. Machine settings and each
user's logs/reports remain unless IT explicitly removes those directories too.
