# D-Gen | https://t.me/DisappearGen
param(
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$strategiesDir = Join-Path $root 'strategies'

if (-not (Test-Path -LiteralPath $strategiesDir)) {
    throw "strategies dir not found: $strategiesDir"
}

function Get-RequiredListFiles([string]$text) {
    $set = @{}

    foreach ($m in [regex]::Matches($text, '(?i)%LISTS%([a-z0-9\-]+\.txt)')) {
        $name = $m.Groups[1].Value
        if ($name) { $set[$name.ToLowerInvariant()] = $true }
    }

    # When strategies are converted into thin stubs ("--profile <id>"), they may no longer reference
    # "%LISTS%..." directly in the start command. Preserve required list checks by extracting
    # list names from the existing DGEN_PREFLIGHT block as well.
    $prefMatch = [regex]::Match($text, '(?is)::\s*DGEN_PREFLIGHT_BEGIN.*?::\s*DGEN_PREFLIGHT_END')
    if ($prefMatch.Success) {
        foreach ($m in [regex]::Matches($prefMatch.Value, '"([a-z0-9\-]+\.txt)"', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $name = $m.Groups[1].Value
            if ($name) { $set[$name.ToLowerInvariant()] = $true }
        }
    }

    return @($set.Keys | Sort-Object)
}

function Ensure-UpdateCheckGuard([string]$text) {
    if ($text -match '(?i)DGEN_SKIP_UPDATE_CHECK') { return $text }

    $pattern = '(?im)^[ \t]*call[ \t]+service\.bat[ \t]+check_updates[ \t]*\r?$'
    if (-not ([regex]::IsMatch($text, $pattern))) {
        return $text
    }

    $replacement = 'if not "%DGEN_SKIP_UPDATE_CHECK%"=="1" (' + "`r`n" +
        '    call service.bat check_updates' + "`r`n" +
        ')'

    return [regex]::Replace($text, $pattern, $replacement, [System.Text.RegularExpressions.RegexOptions]::Multiline)
}

function Ensure-WfUdpRange([string]$text) {
    $pattern = '(?i)(--wf-udp=443,19294-19344,)(50000-65535)'
    $replacement = '${1}49152-65535'
    return [regex]::Replace($text, $pattern, $replacement)
}

function Ensure-DiscordStunUdpRange([string]$text) {
    $pattern = '(?i)(--filter-udp=19294-19344,)(50000-65535)([ \t]+--filter-l7=discord,stun)'
    $replacement = '${1}49152-65535${3}'
    return [regex]::Replace($text, $pattern, $replacement)
}

function Build-PreflightBlock([string[]]$requiredLists) {
    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(':: DGEN_PREFLIGHT_BEGIN')
    $lines.Add('if not defined GameFilter set "GameFilter=12"')
    $lines.Add('if not defined AGGRESSIVE_MODE set "AGGRESSIVE_MODE=0"')
    $lines.Add('')
    $lines.Add('if not exist "%BIN%DGen.exe" (')
    $lines.Add('    echo [ERROR] DGen.exe not found in %BIN%')
    $lines.Add('    exit /b 1')
    $lines.Add(')')

    if ($requiredLists -and $requiredLists.Count -gt 0) {
        $quoted = $requiredLists | ForEach-Object { '"' + $_ + '"' }
        $lines.Add('for %%F in (' + ($quoted -join ' ') + ') do (')
        $lines.Add('    if not exist "%LISTS%%%~F" (')
        $lines.Add('        echo [ERROR] Required list missing: %LISTS%%%~F')
        $lines.Add('        exit /b 1')
        $lines.Add('    )')
        $lines.Add(')')
    }

    $lines.Add('echo [D-Gen] Starting %~n0 (GameFilter=%GameFilter% Aggressive=%AGGRESSIVE_MODE%) with BIN=%BIN% LISTS=%LISTS%')
    $lines.Add('set REPEATS_')
    $lines.Add(':: DGEN_PREFLIGHT_END')

    return ($lines -join "`r`n")
}

function Replace-Or-Insert-Preflight([string]$text, [string]$block) {
    $begin = ':: DGEN_PREFLIGHT_BEGIN'
    $end = ':: DGEN_PREFLIGHT_END'

    if ($text -match [regex]::Escape($begin) -and $text -match [regex]::Escape($end)) {
        $pattern = '(?is)' + [regex]::Escape($begin) + '.*?' + [regex]::Escape($end)
        return [regex]::Replace($text, $pattern, $block)
    }

    $startMatch = [regex]::Match($text, '(?im)^[ \t]*start[ \t]+"')
    if (-not $startMatch.Success) {
        return ($text.TrimEnd("`r", "`n") + "`r`n`r`n" + $block + "`r`n")
    }

    $idx = $startMatch.Index
    $before = $text.Substring(0, $idx).TrimEnd("`r", "`n")
    $after = $text.Substring($idx)

    return ($before + "`r`n`r`n" + $block + "`r`n`r`n" + $after)
}

function Remove-LegacyPreflightBeforeMarker([string]$text) {
    $marker = ':: DGEN_PREFLIGHT_BEGIN'
    $markerIdx = $text.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase)
    if ($markerIdx -lt 0) { return $text }

    $before = $text.Substring(0, $markerIdx)
    $matches = [regex]::Matches($before, '(?im)^[ \t]*if not exist "%BIN%DGen\.exe" \(')
    if ($matches.Count -eq 0) { return $text }

    $last = $matches[$matches.Count - 1]
    $tail = $before.Substring($last.Index)
    if ($tail -notmatch '(?im)^[ \t]*echo[ \t]+\[D-Gen\][ \t]+Starting') { return $text }

    $cleanBefore = $before.Substring(0, $last.Index).TrimEnd("`r", "`n")
    return ($cleanBefore + "`r`n`r`n" + $text.Substring($markerIdx))
}

function Ensure-TrailingNewline([string]$text) {
    if ($text.EndsWith("`r`n")) { return $text }
    return ($text.TrimEnd("`r", "`n") + "`r`n")
}

# D-Gen | https://t.me/DisappearGen
$strategyFiles = Get-ChildItem -LiteralPath $strategiesDir -Filter 'general*.bat' -File | Sort-Object Name

$changed = 0
foreach ($f in $strategyFiles) {
    $path = $f.FullName

    $orig = [System.IO.File]::ReadAllText($path, $utf8NoBom)
    $text = $orig

    $text = Ensure-UpdateCheckGuard $text
    $text = Ensure-WfUdpRange $text
    $text = Ensure-DiscordStunUdpRange $text

    $requiredLists = Get-RequiredListFiles $text
    $block = Build-PreflightBlock $requiredLists
    $text = Replace-Or-Insert-Preflight $text $block
    $text = Remove-LegacyPreflightBeforeMarker $text

    $text = Ensure-TrailingNewline $text

    if ($text -ne $orig) {
        if ($WhatIf) {
            Write-Host "[whatif] would update: $($f.Name)"
        } else {
            [System.IO.File]::WriteAllText($path, $text, $utf8NoBom)
            Write-Host "[updated] $($f.Name)"
        }
        $changed++
    } else {
        Write-Host "[ok] $($f.Name)"
    }
}

$bad = @()
foreach ($f in $strategyFiles) {
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $bad += "$($f.Name): has UTF8 BOM"
        continue
    }

    $nl = [Array]::IndexOf($bytes, [byte]0x0A)
    if ($nl -lt 0) { $nl = $bytes.Length }
    $lineBytes = if ($nl -gt 0) { $bytes[0..($nl-1)] } else { @() }
    if ($lineBytes.Length -gt 0 -and $lineBytes[$lineBytes.Length-1] -eq 0x0D) { $lineBytes = $lineBytes[0..($lineBytes.Length-2)] }
    $lineAscii = [System.Text.Encoding]::ASCII.GetString($lineBytes)
    if (-not $lineAscii.StartsWith('@echo off')) {
        $bad += "$($f.Name): header is not '@echo off'"
    }
}

if ($bad.Count -gt 0) {
    Write-Host "[FAIL] strategy verification failed:"
    $bad | ForEach-Object { Write-Host " - $_" }
    exit 1
}

Write-Host "[DONE] strategies updated=$changed total=$($strategyFiles.Count)"