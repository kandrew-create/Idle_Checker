param(
    [string]$Compiler,
    [ValidatePattern('^\d+\.\d+\.\d+(\.\d+)?$')]
    [string]$Version = '1.0.2'
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path -LiteralPath 'dist\Idle Monitor.exe' -PathType Leaf)) {
        throw 'Build the application first with build.ps1.'
    }
    if (-not $Compiler) {
        $candidates = @(
            (Join-Path $PSScriptRoot 'build\installer-tools\Inno Setup 6\ISCC.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
        )
        $Compiler = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if (-not $Compiler) {
            $found = Get-Command ISCC.exe -ErrorAction SilentlyContinue
            if ($found) { $Compiler = $found.Source }
        }
    }
    if (-not $Compiler) { throw 'Install Inno Setup 6, or pass -Compiler with the full path to ISCC.exe.' }
    & $Compiler "/DAppVersion=$Version" 'installer.iss'
    if ($LASTEXITCODE -ne 0) { throw "Installer build failed: $LASTEXITCODE" }
    Get-Item -LiteralPath 'dist\setup.exe' | Select-Object FullName,Length
    $checksum = Get-FileHash -LiteralPath 'dist\setup.exe' -Algorithm SHA256
    ($checksum.Hash.ToLowerInvariant() + '  setup.exe') | Set-Content -LiteralPath 'dist\setup.exe.sha256' -Encoding ASCII
    Write-Host "SHA256: $($checksum.Hash)"
} finally {
    Pop-Location
}
