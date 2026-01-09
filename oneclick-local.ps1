param()

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$launcher = Join-Path $root 'D-Gen\launcher.ps1'

if (-not (Test-Path $powershellExe)) {
    throw "powershell.exe not found: $powershellExe"
}
if (-not (Test-Path $launcher)) {
    throw "D-Gen launcher not found: $launcher"
}

# Start the GUI launcher with no visible console window.
$launcherArgs = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-STA',
    '-WindowStyle', 'Hidden',
    '-File', "`"$launcher`""
)

Start-Process -FilePath $powershellExe -ArgumentList $launcherArgs -WorkingDirectory $root -WindowStyle Hidden | Out-Null
