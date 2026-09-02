# D-Gen | https://t.me/DisappearGen
param(
    [string]$Version,
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

if (-not $BinSource) {
    $BinSource = Join-Path $root 'bin'
}

Write-Host "[self-check] root=$root"
Write-Host "version=$Version"
Write-Host "binSource=$BinSource"
Write-Host "outDir=$OutDir"

# --- PS5.1 parse checks ---
Write-Host "[ps-parse]"
$psRel = @(
    'D-Gen\launcher.ps1',
    'oneclick-local.ps1',
    'utils\build-release.ps1',
    'utils\sync-strategies.ps1'
)
foreach ($rel in $psRel) {
    $p = Join-Path $root $rel
    if (!(Test-Path -LiteralPath $p)) {
        throw "Missing required ps1: $rel"
    }

    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tokens, [ref]$errors) | Out-Null

    $ec = if ($errors) { $errors.Count } else { 0 }
    Write-Host "ps_parse file=$rel errors=$ec"
    if ($ec -gt 0) {
        $errors | Select-Object -First 10 | ForEach-Object {
            Write-Host ("  " + $_.Message + " @" + $_.Extent.StartLineNumber + ":" + $_.Extent.StartColumnNumber)
        }
        throw "Parse errors in $rel"
    }
}

# --- BOM sanity (launcher.ps1) ---
Write-Host "[bom]"
$launcher = Join-Path $root 'D-Gen\launcher.ps1'
$b = [System.IO.File]::ReadAllBytes($launcher)
if ($b.Length -lt 3 -or $b[0] -ne 0xEF -or $b[1] -ne 0xBB -or $b[2] -ne 0xBF) {
    throw "launcher.ps1 must be UTF-8 with BOM for PS5.1 compatibility"
}
if ($b.Length -ge 6 -and $b[3] -eq 0xEF -and $b[4] -eq 0xBB -and $b[5] -eq 0xBF) {
    throw "launcher.ps1 contains repeated BOM (EF BB BF EF BB BF)"
}
Write-Host "launcher_bom=OK"

# --- Engine rebuild / binary consistency (production contract) ---
Write-Host "[engine]"
function To-CygPath([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $p }
    $x = $p -replace '\\','/'
    if ($x -match '^[A-Za-z]:/') {
        $drive = $x.Substring(0,1).ToLower()
        $rest = $x.Substring(2)
        return "/cygdrive/$drive$rest"
    }
    return $x
}

$engineDir = Join-Path $root 'engine\\src\\nfq'
$engineExe = Join-Path $engineDir 'DGen.exe'
$binExe = Join-Path $BinSource 'DGen.exe'
if (-not (Test-Path -LiteralPath $binExe)) {
    throw "BinSource missing DGen.exe: $binExe"
}

$cygCandidates = @(
    'E:\\NoDpi\\_tools\\cygwin64\\bin\\bash.exe',
    'E:\\NoDpi\\_tools\\cygwin64\\bin\\bash',
    'C:\\cygwin64\\bin\\bash.exe',
    'C:\\cygwin64\\bin\\bash'
)
$cyg = $cygCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($cyg) {
    $cygRoot = To-CygPath $root
    Write-Host "engine_build=RUN"
    & $cyg -lc ("cd '{0}/engine/src/nfq' && make -f Makefile cygwin64" -f $cygRoot)
    if ($LASTEXITCODE -ne 0) { throw "Engine build failed exit=$LASTEXITCODE" }
    if (-not (Test-Path -LiteralPath $engineExe)) { throw "Engine build did not produce DGen.exe: $engineExe" }
    Copy-Item -Force -LiteralPath $engineExe -Destination $binExe
} else {
    Write-Host "engine_build=SKIP (cygwin bash not found)"
    if (Test-Path -LiteralPath $engineExe) {
        $h1 = (Get-FileHash -Algorithm SHA256 -LiteralPath $engineExe).Hash
        $h2 = (Get-FileHash -Algorithm SHA256 -LiteralPath $binExe).Hash
        if ($h1 -ne $h2) {
            throw ("Engine/BinSource DGen.exe mismatch: engine={0} bin={1}" -f $h1, $h2)
        }
        Write-Host "engine_bin_hash=OK"
    } else {
        Write-Host "engine_bin_hash=SKIP (engine exe not found)"
    }
}

# --- Build release zip ---
Write-Host "[build-release]"
$build = Join-Path $root 'utils\build-release.ps1'
& $build -Version $Version -BinSource $BinSource -OutDir $OutDir

$zipPath = Join-Path $OutDir ("NoDPI-D-Gen-{0}.zip" -f $Version)
$stage = Join-Path $OutDir ("NoDPI-D-Gen-{0}" -f $Version)

if (!(Test-Path -LiteralPath $zipPath)) {
    throw "release zip not found after build: $zipPath"
}

$zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash
$zipBytes = (Get-Item -LiteralPath $zipPath).Length
Write-Host "zip=$zipPath"
Write-Host "zip_sha256=$zipHash zip_bytes=$zipBytes"

# --- Inspect zip contents ---
Write-Host "[zip-inspect]"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$za = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $names = @($za.Entries | ForEach-Object { $_.FullName })

    $bak = @($names | Where-Object { $_ -match '(?i)DGen\\.exe\\.bak' })
    if ($bak.Count -gt 0) {
        throw "zip contains DGen.exe backups: $($bak.Count)"
    }

    $tpl = @($names | Where-Object { $_ -match '(?i)(tls_clienthello_|quic_initial_).*\\.bin$' })
    if ($tpl.Count -gt 0) {
        throw "zip contains template .bin files: $($tpl.Count)"
    }

    $logFiles = @($names | Where-Object { $_ -match '(?i)(^|[\\/])D-Gen[\\/]logs[\\/]' -and $_ -notmatch '(?i)\\.gitkeep$' })
    if ($logFiles.Count -gt 0) {
        throw "zip contains runtime logs under D-Gen/logs: $($logFiles.Count)"
    }

    function Normalize-ZipPath([string]$p) {
        if ([string]::IsNullOrWhiteSpace($p)) { return $p }
        $x = $p -replace '/', '\\'
        $x = [regex]::Replace($x, '\\\\+', '\\')
        return $x.TrimStart('\\')
    }

    $utilsEntries = @($names | Where-Object { $_ -match '(?i)(^|[\\/])utils[\\/]' })
    $allowedUtils = @(
        (Normalize-ZipPath 'utils\ai_request_rewriter.ps1'),
        (Normalize-ZipPath 'utils\Disappear_gen_windows_icon.ico'),
        (Normalize-ZipPath 'utils\sanity-elevated.ps1')
    )

    $utilsUnexpected = @(
        $utilsEntries |
            ForEach-Object { Normalize-ZipPath $_ } |
            Where-Object { $allowedUtils -notcontains $_ }
    )

    if ($utilsUnexpected.Count -gt 0) {
        throw "zip contains unexpected utils files: $($utilsUnexpected -join ', ')"
    }

    $wantDgen = (Normalize-ZipPath 'bin\DGen.exe')
    $dgenEntry = $za.Entries |
        Where-Object { (Normalize-ZipPath $_.FullName) -ieq $wantDgen } |
        Select-Object -First 1
    if (-not $dgenEntry) {
        throw "zip missing bin\DGen.exe"
    }

    $tmp = Join-Path $env:TEMP ("dgen_zip_" + [guid]::NewGuid().ToString('n') + '.exe')
    $s = $dgenEntry.Open()
    try {
        $fs = [System.IO.File]::OpenWrite($tmp)
        try { $s.CopyTo($fs) } finally { $fs.Dispose() }
    }
    finally { $s.Dispose() }

    $zipDgenHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash
    Remove-Item -LiteralPath $tmp -Force

    $srcDgen = Join-Path $BinSource 'DGen.exe'
    if (!(Test-Path -LiteralPath $srcDgen)) {
        throw "BinSource missing DGen.exe: $srcDgen"
    }
    $srcHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $srcDgen).Hash

    if ($zipDgenHash -ne $srcHash) {
        throw ("DGen.exe hash mismatch: zip={0} BinSource={1}" -f $zipDgenHash, $srcHash)
    }

    Write-Host "zip_dgen_sha256=$zipDgenHash"

    # Verify policy.lua and sanity runner are shipped and match workspace.
    $checks = @(
        @{ name = 'policy.lua'; zip = (Normalize-ZipPath 'D-Gen\policy.lua'); src = (Join-Path $root 'D-Gen\policy.lua'); suffix = '.lua' },
        @{ name = 'sanity-elevated.ps1'; zip = (Normalize-ZipPath 'utils\sanity-elevated.ps1'); src = (Join-Path $root 'utils\sanity-elevated.ps1'); suffix = '.ps1' }
    )

    foreach ($c in $checks) {
        if (!(Test-Path -LiteralPath $c.src)) {
            throw ("workspace missing {0}: {1}" -f $c.name, $c.src)
        }

        $entry = $za.Entries |
            Where-Object { (Normalize-ZipPath $_.FullName) -ieq $c.zip } |
            Select-Object -First 1
        if (-not $entry) {
            throw ("zip missing {0}: {1}" -f $c.name, $c.zip)
        }

        $tmp = Join-Path $env:TEMP ("dgen_zip_" + [guid]::NewGuid().ToString('n') + $c.suffix)
        $s = $entry.Open()
        try {
            $fs = [System.IO.File]::OpenWrite($tmp)
            try { $s.CopyTo($fs) } finally { $fs.Dispose() }
        }
        finally { $s.Dispose() }

        $zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash
        Remove-Item -LiteralPath $tmp -Force
        $srcHash2 = (Get-FileHash -Algorithm SHA256 -LiteralPath $c.src).Hash

        if ($zipHash -ne $srcHash2) {
            throw ("{0} hash mismatch: zip={1} workspace={2}" -f $c.name, $zipHash, $srcHash2)
        }

        Write-Host ("zip_{0}_sha256={1}" -f ($c.name -replace '[^A-Za-z0-9]+','_'), $zipHash)
    }
}
finally {
    $za.Dispose()
}

Write-Host "OK: self-check passed"