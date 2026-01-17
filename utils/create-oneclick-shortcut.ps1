param(
    [string]$Destination = "",
    [switch]$Desktop
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$vbsPath = Join-Path $root 'oneclick-local.vbs'
$wscriptPath = Join-Path $env:SystemRoot 'System32\wscript.exe'
$iconPath = Join-Path $root 'utils\Disappear_gen_windows_icon.ico'

if (-not (Test-Path -LiteralPath $vbsPath)) {
    throw "oneclick-local.vbs not found: $vbsPath"
}
if (-not (Test-Path -LiteralPath $wscriptPath)) {
    throw "wscript.exe not found: $wscriptPath"
}
if (-not (Test-Path -LiteralPath $iconPath)) {
    throw "Icon not found: $iconPath"
}

if (-not $Destination) {
    if ($Desktop) {
        $desktop = [Environment]::GetFolderPath('Desktop')
        $Destination = Join-Path $desktop 'NoDPI-D-Gen.lnk'
    } else {
        # Put it next to the repo so it looks like a "real" one-click file with a custom icon.
        $Destination = Join-Path $root 'oneclick-local.lnk'
    }
}

$wsh = New-Object -ComObject WScript.Shell
$sc = $wsh.CreateShortcut($Destination)
$sc.TargetPath = $wscriptPath
$sc.Arguments = "//nologo `"$vbsPath`""
$sc.WorkingDirectory = $root
$sc.IconLocation = $iconPath
$sc.Description = 'NoDPI-D-Gen'
$sc.Save()

Write-Host "Created shortcut: $Destination"