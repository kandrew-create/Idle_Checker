# Compatibility entry point: installations now use IT-managed machine settings.
param([string]$Executable = (Join-Path $PSScriptRoot 'dist\Idle Monitor.exe'), [string]$ConfigFile)
& (Join-Path $PSScriptRoot 'install-managed.ps1') @PSBoundParameters
