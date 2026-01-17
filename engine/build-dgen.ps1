param(
  [string]$CygwinRoot = "E:\\NoDpi\\_tools\\cygwin64",
  [switch]$CopyToRepoBin
)

$ErrorActionPreference = 'Stop'

function Convert-ToCygPath([string]$winPath) {
  if (-not $winPath) { throw "Convert-ToCygPath: empty path" }
  $p = $winPath
  if ($p.Length -lt 3 -or $p[1] -ne ':') {
    throw "Convert-ToCygPath: expected absolute Windows path, got: $winPath"
  }
  $drive = $p.Substring(0, 1).ToLowerInvariant()
  $rest = $p.Substring(2) # starts with \
  $rest = $rest -replace '\\', '/'
  return "/cygdrive/$drive$rest"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$engineSrc = Join-Path $repoRoot 'engine\\src\\nfq'
$engineOutDir = Join-Path $repoRoot 'engine\\out'
$engineOutExe = Join-Path $engineOutDir 'DGen.exe'

if (-not (Test-Path $engineSrc)) {
  throw "Engine sources not found: $engineSrc (expected private sources under engine/src; it is gitignored by design)."
}

$makefile = Join-Path $engineSrc 'Makefile'
if (-not (Test-Path $makefile)) {
  throw "Makefile not found: $makefile"
}

$bash = Join-Path $CygwinRoot 'bin\\bash.exe'
if (-not (Test-Path $bash)) {
  throw "Cygwin bash not found: $bash (set -CygwinRoot if needed)"
}

New-Item -ItemType Directory -Force -Path $engineOutDir | Out-Null

$cygEngineSrc = Convert-ToCygPath $engineSrc

Write-Host "[build] repoRoot=$repoRoot"
Write-Host "[build] engineSrc=$engineSrc"
Write-Host "[build] cygEngineSrc=$cygEngineSrc"

# Build inside Cygwin (Windows/Cygwin target)
& $bash -lc "cd '$cygEngineSrc' && make clean && make cygwin64"
if ($LASTEXITCODE -ne 0) {
  throw "Cygwin make failed with exit code $LASTEXITCODE"
}

$builtExe = Join-Path $engineSrc 'DGen.exe'
if (-not (Test-Path $builtExe)) {
  throw "Build succeeded but DGen.exe not found at: $builtExe"
}

Copy-Item -Force $builtExe $engineOutExe
Write-Host "[ok] wrote $engineOutExe"

if ($CopyToRepoBin) {
  $repoBinDir = Join-Path $repoRoot 'bin'
  $repoBinExe = Join-Path $repoBinDir 'DGen.exe'
  New-Item -ItemType Directory -Force -Path $repoBinDir | Out-Null
  Copy-Item -Force $builtExe $repoBinExe
  Write-Host "[ok] copied to $repoBinExe"
}
