param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & $Python -m pip install -r requirements-build.txt
    if ($LASTEXITCODE -ne 0) { throw 'Build dependencies could not be installed.' }
    & $Python -m PyInstaller --noconfirm 'Idle Monitor.spec'
    if ($LASTEXITCODE -ne 0) { throw 'Executable build failed.' }
    Write-Host "Built: $PSScriptRoot\dist\Idle Monitor.exe"
    Write-Host 'Run install-desktop.ps1 to install it and create a desktop shortcut.'
} finally {
    Pop-Location
}
