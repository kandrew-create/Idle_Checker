; Build with build-installer.ps1. Packages the existing application executable.
#ifndef AppVersion
  #define AppVersion "1.0.1"
#endif

[Setup]
AppId={{F7E5869D-7DA9-477A-A5A2-6EA3622A8466}
AppName=Idle Monitor
AppVersion={#AppVersion}
DefaultDirName={autopf}\Idle Monitor
DisableDirPage=yes
UsePreviousAppDir=no
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=dist
OutputBaseFilename=setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\Idle Monitor.exe
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
DisableWelcomePage=no

[Messages]
WelcomeLabel2=This will install Idle Monitor for all Windows users.%n%nClose Idle Monitor in every Windows session before upgrading. Existing IT settings and passwords will be preserved.
FinishedLabelNoIcons=Idle Monitor is installed.%n%nOpen Idle Monitor - IT Admin Settings from Start to configure email. Start Idle Monitor to begin monitoring, or sign out and back in. Monitoring starts automatically at future logins.

[Files]
Source: "dist\Idle Monitor.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
; Never overwrite or remove the machine's configured SMTP account on upgrade/uninstall.
Source: "config.example.json"; DestDir: "{commonappdata}\Idle Monitor"; DestName: "config.json"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "install-managed.ps1"; Flags: dontcopy
Source: "config.example.json"; Flags: dontcopy

[Dirs]
Name: "{commonappdata}\Idle Monitor"; Flags: uninsneveruninstall

[Icons]
Name: "{commonprograms}\Idle Monitor"; Filename: "{app}\Idle Monitor.exe"; WorkingDir: "{app}"
Name: "{commonprograms}\Idle Monitor - IT Admin Settings"; Filename: "{app}\Idle Monitor.exe"; Parameters: "--admin-settings"; WorkingDir: "{app}"

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Idle Monitor"; ValueData: """{app}\Idle Monitor.exe"""; Flags: uninsdeletevalue

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ExitCode: Integer;
  Arguments: String;
begin
  Result := '';
  ExtractTemporaryFile('install-managed.ps1');
  ExtractTemporaryFile('config.example.json');
  Arguments := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
    ExpandConstant('{tmp}\install-managed.ps1') + '" -PrepareOnly';
  { Use the same directory ownership checks and ACLs as the existing installer.
    This happens before any application/configuration files are copied. }
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      Arguments, '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    Result := 'Cannot start Windows PowerShell to prepare installation folders.'
  else if ExitCode <> 0 then
    Result := 'Cannot prepare protected installation folders. IT must check the ownership and permissions of Program Files\Idle Monitor and ProgramData\Idle Monitor, and remove unexpected links or subdirectories. Existing settings have not been replaced.';
end;
