# Run from an elevated PowerShell window. Installs for every Windows user.
param(
    [string]$Executable = (Join-Path $PSScriptRoot 'dist\Idle Monitor.exe'),
    [string]$ConfigFile,
    # Used by setup.exe before Inno Setup copies files into the managed folders.
    [switch]$PrepareOnly
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'IT administrator elevation is required. Run PowerShell as administrator, then run this installer again.'
}
if (-not $PrepareOnly -and -not (Test-Path -LiteralPath $Executable -PathType Leaf)) { throw 'Build the executable first.' }
$installFolder = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Idle Monitor'
$policyFolder = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Idle Monitor'
$admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')

function Protect-ManagedDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Unsafe managed directory: $Path"
        }
        $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier])
        if ($owner -ne $admins -and $owner -ne $system) {
            throw "Existing directory is not owned by Administrators or SYSTEM: $Path. IT must inspect and remove or repair it before installation."
        }
    } else {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($admins, $system)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl -LiteralPath $Path -AclObject $acl
    foreach ($entry in Get-ChildItem -LiteralPath $Path -Force) {
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Unexpected directory or link in managed folder: $($entry.FullName)"
        }
        $fileAcl = New-Object Security.AccessControl.FileSecurity
        $fileAcl.SetOwner($admins)
        $fileAcl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($admins, $system)) {
            $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')))
        }
        $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users, 'ReadAndExecute', 'Allow')))
        Set-Acl -LiteralPath $entry.FullName -AclObject $fileAcl
    }
}

$sourceConfig = if ($ConfigFile) { $ConfigFile } else { Join-Path $PSScriptRoot 'config.example.json' }
$configText = Get-Content -LiteralPath $sourceConfig -Raw
$parsed = ConvertFrom-Json -InputObject $configText
if ($null -eq $parsed -or $parsed -isnot [PSCustomObject]) { throw 'Configuration must be a JSON object.' }
Protect-ManagedDirectory $installFolder
Protect-ManagedDirectory $policyFolder
if ($PrepareOnly) { return }
$installedExe = Join-Path $installFolder 'Idle Monitor.exe'
if ([IO.Path]::GetFullPath($Executable) -ne [IO.Path]::GetFullPath($installedExe)) {
    Copy-Item -LiteralPath $Executable -Destination $installedExe -Force
}
$policyPath = Join-Path $policyFolder 'config.json'
if ($ConfigFile -or -not (Test-Path -LiteralPath $policyPath)) {
    [IO.File]::WriteAllText($policyPath, $configText, (New-Object Text.UTF8Encoding($false)))
}
$runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $runKey -Force | Out-Null
New-ItemProperty -Path $runKey -Name 'Idle Monitor' -Value ('"' + $installedExe + '"') -PropertyType String -Force | Out-Null
$shell = New-Object -ComObject WScript.Shell
foreach ($name in @('Idle Monitor', 'Idle Monitor - IT Admin Settings')) {
    $link = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonPrograms')) ($name + '.lnk')))
    $link.TargetPath = $installedExe
    $link.WorkingDirectory = $installFolder
    if ($name -like '*IT Admin*') { $link.Arguments = '--admin-settings' }
    $link.Save()
}
Write-Host "Installed for all users: $installedExe"
Write-Host "IT settings: $policyPath"
Write-Host 'Open Idle Monitor - IT Admin Settings from Start to configure email and monitoring.'
Write-Host 'The app starts in each Windows user session at the next logon. Restart running copies after upgrading.'
