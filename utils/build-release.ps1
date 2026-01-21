# D-Gen | https://t.me/DisappearGen
param(
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$BinSource,
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if (-not $OutDir) {
    $OutDir = Join-Path $root 'dist'
}

if (-not $Version) {
    $verPath = Join-Path $root '.service\version.txt'
    if (-not (Test-Path -LiteralPath $verPath)) {
        throw "Version not provided and version file not found: $verPath"
    }
    $Version = (Get-Content -LiteralPath $verPath -Raw -ErrorAction Stop).Trim()
}

if (-not (Test-Path -LiteralPath $BinSource)) {
    throw "BinSource not found: $BinSource"
}

$stage = Join-Path $OutDir ("NoDPI-D-Gen-{0}" -f $Version)
$zipPath = Join-Path $OutDir ("NoDPI-D-Gen-{0}.zip" -f $Version)

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$items = @(
    'D-Gen',
    'assets',
    'lists',
    'strategies',
    'utils',
    'oneclick-local.bat',
    'oneclick-local.ps1',
    'oneclick-local.vbs',
    'service.bat',
    'README.md',
    'LICENSE'
)

foreach ($it in $items) {
    $src = Join-Path $root $it
    if (-not (Test-Path -LiteralPath $src)) {
        throw "Missing required path for release: $src"
    }

    $dst = Join-Path $stage $it

    if (Test-Path -LiteralPath $src -PathType Container) {
        Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force
    } else {
        Copy-Item -LiteralPath $src -Destination $dst -Force
    }
}

# --- Release hygiene: avoid shipping developer artifacts ---

# 1) Drop legacy strategies from the release bundle (ship only the 6 current strategies)
$legacyStrategies = Join-Path $stage 'strategies\legacy'
if (Test-Path -LiteralPath $legacyStrategies) {
    Remove-Item -LiteralPath $legacyStrategies -Recurse -Force
}

# 2) Keep logs empty (ship only .gitkeep to preserve folder structure)
$logsDir = Join-Path $stage 'D-Gen\logs'
if (Test-Path -LiteralPath $logsDir) {
    Get-ChildItem -LiteralPath $logsDir -Force |
        Where-Object { $_.Name -ne '.gitkeep' } |
        Remove-Item -Recurse -Force
}

# 3) Don't ship local bot-state from the developer machine; reset to an empty state file
$botStatePath = Join-Path $stage 'D-Gen\bot-state.json'
$cleanBotState = @{ Profiles = @{}; Version = 2 } | ConvertTo-Json -Depth 10
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($botStatePath, $cleanBotState + [Environment]::NewLine, $utf8NoBom)

$dstBin = Join-Path $stage 'bin'
New-Item -ItemType Directory -Path $dstBin -Force | Out-Null

# Copy BinSource payload but exclude developer backup artifacts like DGen.exe.bak-*
$binSourceItems = Get-ChildItem -LiteralPath $BinSource -Force
foreach ($item in $binSourceItems) {
    if ($item.Name -like 'DGen.exe.bak*') {
        continue
    }
    Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $dstBin $item.Name) -Recurse -Force
}

# Fail-fast: ensure no backup artifacts slipped into the release bin
$bakItems = @(Get-ChildItem -LiteralPath $dstBin -Filter 'DGen.exe.bak*' -File -ErrorAction SilentlyContinue)
if ($bakItems.Count -gt 0) {
    throw ("Release bin contains backup artifacts: {0}" -f (($bakItems | Select-Object -ExpandProperty Name) -join ', '))
}

# 4) Don't ship machine-local autopick cache/state
$autopickState = Join-Path $dstBin 'dgen-autopick.state'
if (Test-Path -LiteralPath $autopickState) {
    Remove-Item -LiteralPath $autopickState -Force
}

$dgenExe = Join-Path $dstBin 'DGen.exe'
$unexpectedExeNames = @(
    Get-ChildItem -LiteralPath $dstBin -Filter '*.exe' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'DGen.exe' } |
        Select-Object -ExpandProperty Name
)

if ($unexpectedExeNames -and $unexpectedExeNames.Count -gt 0) {
    throw ("Release bin contains unexpected .exe files: {0}. Only DGen.exe should be present." -f ($unexpectedExeNames -join ', '))
}

if (-not (Test-Path -LiteralPath $dgenExe)) {
    throw "Release bin is missing DGen.exe. Provide BinSource that already contains DGen.exe."
}

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -Force

Write-Host "OK: built release zip: $zipPath"
Write-Host "Stage folder: $stage"
Write-Host "BinSource: $BinSource"