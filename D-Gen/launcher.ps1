# D-Gen | https://t.me/DisappearGen
param(
    [switch]$AutoStart,

    [switch]$NoElevate,

    [ValidateSet('Logs', 'Status')]
    [string]$InitialView = 'Logs'
)

try {

# D-Gen | https://t.me/DisappearGen
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type -AssemblyName System.Net.Http

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$configPath = Join-Path $PSScriptRoot "config.json"
$generatorPath = Join-Path $root "utils\ai_request_rewriter.ps1"
$strategiesDir = Join-Path $root "strategies"
$listsDir = Join-Path $root "lists"
$listGeneralPath = Join-Path $listsDir "list-general.txt"
$ipsetAllPath = Join-Path $listsDir "ipset-all.txt"
$logsDir = Join-Path $PSScriptRoot "logs"
$logPath = Join-Path $logsDir "dgen-launch.log"
$botStatePath = Join-Path $PSScriptRoot "bot-state.json"
$script:activeLogPath = $logPath
$defaultGeneratorOutPath = Join-Path $logsDir "dgen-generator.stdout.log"
$defaultGeneratorErrPath = Join-Path $logsDir "dgen-generator.stderr.log"
$defaultStrategyOutPath = Join-Path $logsDir "engine.stdout.log"
$defaultStrategyErrPath = Join-Path $logsDir "engine.log"
$defaultSummaryPath = Join-Path $logsDir "dgen-summary.json"
$powershellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

# Engine-side autopick (anti-copy): launcher no longer embeds target URL lists / scoring logic.
# DGen.exe handles `--profile auto` internally.

if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir | Out-Null }

function Get-IpsetAllHealth {
    param([string]$path)

    if (-not $path) { return $null }
    if (-not (Test-Path -LiteralPath $path)) { return $null }

    $fi = Get-Item -LiteralPath $path
    $lineCount = 0
    $cidrLike = 0

    Get-Content -LiteralPath $path -ReadCount 8192 | ForEach-Object {
        $lineCount += $_.Count
        foreach ($line in $_) {
            $l = ([string]$line).Trim()
            if (-not $l) { continue }
            if ($l -match '^[0-9a-fA-F:.]+/\d{1,3}$') { $cidrLike++ }
        }
    }

    return [pscustomobject]@{
        Path = $path
        SizeBytes = [int64]$fi.Length
        Lines = $lineCount
        CidrLike = $cidrLike
    }
}

function Export-DGenReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$zipPath
    )

    $tmp = $null
    try {
        $ts = Get-Date -Format "yyyyMMdd-HHmmss"
        $tmp = Join-Path $env:TEMP ("DGen-report-{0}-{1}" -f $ts, ([Guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null

        # Copy logs folder as-is (engine.log/prev, summary.json/prev, stdout/stderr, etc.)
        $dstLogs = Join-Path $tmp 'logs'
        if (Test-Path -LiteralPath $logsDir) {
            Copy-Item -LiteralPath $logsDir -Destination $dstLogs -Recurse -Force
        } else {
            New-Item -ItemType Directory -Path $dstLogs -Force | Out-Null
        }

        # Add a single diagnostics.txt for quick context
        $diagPath = Join-Path $tmp 'diagnostics.txt'
        $diag = ''
        try { $diag = Get-DiagnosticsText } catch { $diag = '' }
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($diagPath, $diag + [Environment]::NewLine, $utf8NoBom)

        if (Test-Path -LiteralPath $zipPath) {
            Remove-Item -LiteralPath $zipPath -Force
        }
        Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $zipPath -Force
    } finally {
        if ($tmp -and (Test-Path -LiteralPath $tmp)) {
            try { Remove-Item -LiteralPath $tmp -Recurse -Force } catch { }
        }
    }
}

function Invoke-ExportReportUI {
    try {
        $ts = Get-Date -Format "yyyyMMdd-HHmmss"
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Title = "Save D-Gen report"
        $sfd.Filter = "Zip (*.zip)|*.zip"
        $sfd.FileName = ("DGen-report-{0}.zip" -f $ts)
        try {
            $desk = Join-Path $env:USERPROFILE 'Desktop'
            if (Test-Path -LiteralPath $desk) { $sfd.InitialDirectory = $desk }
        } catch { }

        if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

        $zipPath = [string]$sfd.FileName
        if (-not $zipPath) { return }
        Export-DGenReport -zipPath $zipPath

        try { if ($statusLabel) { $statusLabel.Text = ("Report saved: {0}" -f $zipPath) } } catch { }
        try { Start-Process -FilePath explorer.exe -ArgumentList ('/select,"{0}"' -f $zipPath) } catch { }
    } catch {
        try { if ($statusLabel) { $statusLabel.Text = "Report export failed" } } catch { }
        try { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "D-Gen", 'OK', 'Error') | Out-Null } catch { }
    }
}

function Ensure-IpsetAllHealthy {
    $minCidr = 1000
    $minLines = 1000
    $minBytes = 50000

    $path = $ipsetAllPath
    $backup = Join-Path $listsDir 'ipset-all.txt.backup'

    $h = Get-IpsetAllHealth -path $path
    $needFix = $false
    $reason = ''
    if (-not $h) {
        $needFix = $true
        $reason = 'missing'
    } elseif ($h.CidrLike -lt $minCidr -or $h.Lines -lt $minLines -or $h.SizeBytes -lt $minBytes) {
        $needFix = $true
        $reason = ("too small: cidrLike={0}, lines={1}, bytes={2}" -f $h.CidrLike, $h.Lines, $h.SizeBytes)
    }

    if (-not $needFix) { return $true }

    $hb = Get-IpsetAllHealth -path $backup
    if ($hb -and $hb.CidrLike -ge $minCidr -and $hb.Lines -ge $minLines -and $hb.SizeBytes -ge $minBytes) {
        try {
            Copy-Item -Force -LiteralPath $backup -Destination $path
            $h2 = Get-IpsetAllHealth -path $path
            Write-Log ("IpsetAll: restored from backup (reason={0}, after: cidrLike={1}, lines={2}, bytes={3})" -f $reason, $h2.CidrLike, $h2.Lines, $h2.SizeBytes)
            return $true
        } catch {
            Write-Log "IpsetAll: restore from backup failed: $($_.Exception.Message)"
        }
    }

    Write-Log ("IpsetAll: WARNING suspicious ipset-all.txt ({0})." -f $reason)
    try {
        $msg = "Your lists\\ipset-all.txt seems incomplete/damaged.\r\n\r\n" +
            "This can make the bypass fail on many providers.\r\n\r\n" +
            "Fix: use the Release zip (not Code ZIP) and ensure lists\\ipset-all.txt is intact."
        [System.Windows.Forms.MessageBox]::Show($msg, "D-Gen", 'OK', 'Warning') | Out-Null
    } catch { }
    return $false
}

function Clear-CurrentLogs {
    try {
        if ($launcherLogBox) { $launcherLogBox.Clear() }
        if ($generatorLogBox) { $generatorLogBox.Clear() }
        if ($strategyLogBox) { $strategyLogBox.Clear() }
    } catch { }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    # Each Start should begin with clean logs in the launcher UI (it reads from $script:activeLogPath).
    try { [System.IO.File]::WriteAllText($script:activeLogPath, "", $utf8NoBom) } catch { }
    # Reset the per-run stdout/stderr buffers.
    try { [System.IO.File]::WriteAllText($script:generatorOutPath, "", $utf8NoBom) } catch { }
    try { [System.IO.File]::WriteAllText($script:generatorErrPath, "", $utf8NoBom) } catch { }
    try { [System.IO.File]::WriteAllText($script:strategyOutPath, "", $utf8NoBom) } catch { }
    try { [System.IO.File]::WriteAllText($script:strategyErrPath, "", $utf8NoBom) } catch { }
    try { [System.IO.File]::WriteAllText($defaultSummaryPath, "", $utf8NoBom) } catch { }

    try { $script:lastSummaryRunId = '' } catch { }
    try { $script:lastSummarySourcePath = '' } catch { }
    try { $script:lastSummarySourceWriteUtc = [datetime]::MinValue } catch { }
    try { $script:lastSummaryPostStartSig = '' } catch { }
}

$script:lastSummaryRunId = ''
$script:lastSummarySourcePath = ''
$script:lastSummarySourceWriteUtc = [datetime]::MinValue
$script:lastSummaryPostStartSig = ''

function Cleanup-LegacyRunLogs {
    $deleted = 0
    $failed = 0
    $errors = New-Object System.Collections.Generic.List[string]

    if (-not (Test-Path -LiteralPath $logsDir)) {
        return [pscustomobject]@{ Deleted = 0; Failed = 0; Errors = @() }
    }

    $patterns = @(
        'dgen-generator.*.stdout.log',
        'dgen-generator.*.stderr.log',
        'dgen-strategy.*.stdout.log',
        'dgen-strategy.*.stderr.log',
        'dgen-strategy.*.try*.stdout.log',
        'dgen-strategy.*.try*.stderr.log'
    )

    $files = @()
    try { $files = @(Get-ChildItem -LiteralPath $logsDir -File -Force -ErrorAction SilentlyContinue) } catch { $files = @() }

    foreach ($f in $files) {
        if (-not $f) { continue }
        if ($f.Name -ieq '.gitkeep') { continue }

        $isLegacy = $false
        foreach ($pat in $patterns) {
            if ($f.Name -like $pat) { $isLegacy = $true; break }
        }

        if (-not $isLegacy) {
            if ($f.Name -ieq 'dgen-strategy.stdout.log' -or $f.Name -ieq 'dgen-strategy.stderr.log') { $isLegacy = $true }
            if ($f.Name -ieq 'dgen-strategy.stdout.log.prev' -or $f.Name -ieq 'dgen-strategy.stderr.log.prev') { $isLegacy = $true }
        }

        if (-not $isLegacy) { continue }

        try {
            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
            $deleted++
        } catch {
            $failed++
            try { $errors.Add(("{0}: {1}" -f $f.Name, $_.Exception.Message)) | Out-Null } catch { }
        }
    }

    if (($deleted + $failed) -gt 0) {
        try { Write-Log ("Logs: cleaned legacy run files: deleted={0} failed={1}" -f $deleted, $failed) } catch { }
    }

    return [pscustomobject]@{ Deleted = $deleted; Failed = $failed; Errors = $errors.ToArray() }
}

function Get-Sha256Hex {
    param([string]$path)

    if (-not $path) { return '' }
    if (-not (Test-Path -LiteralPath $path)) { return '' }

    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fs = [System.IO.File]::OpenRead($path)
        try {
            $hash = $sha.ComputeHash($fs)
        } finally {
            if ($fs) { $fs.Dispose() }
            if ($sha) { $sha.Dispose() }
        }

        return ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
    } catch {
        return ''
    }
}

function Parse-AutopickFromEngineLogLines {
    param([string[]]$lines)

    $dnsLine = $null
    $coreLine = $null
    $keyLine = $null
    $scoreHintLine = $null
    $retuneLine = $null

    foreach ($l in @($lines)) {
        if (-not $l) { continue }
        if ($l -like '*autopick: dns FAIL*') { $dnsLine = $l }
        if ($l -like '*autopick: coreprobes*') { $coreLine = $l }
        if ($l -like '*autopick: key=*') { $keyLine = $l }
        if ($l -like '*autopick: score=*') { $scoreHintLine = $l }
        if ($l -like '*autopick: retune GameFilter=*') { $retuneLine = $l }
    }

    $autopick = $null
    if ($keyLine -and ($keyLine -match 'autopick:\s*key=(?<key>\S+)\s+profile=(?<profile>\S+)(?:\s+score=(?<score>-?\d+))?(?:\s+mode=(?<mode>\S+))?(?:\s+ms=(?<ms>\d+))?')) {
        $score = $null
        if ($Matches['score']) { try { $score = [int]$Matches['score'] } catch { $score = $null } }
        $ms = $null
        if ($Matches['ms']) { try { $ms = [int]$Matches['ms'] } catch { $ms = $null } }
        $autopick = [pscustomobject]@{
            key = $Matches['key']
            profile = $Matches['profile']
            score = $score
            mode = [string]$Matches['mode']
            ms = $ms
        }
    }

    $core = $null
    if ($coreLine -and ($coreLine -match 'autopick:\s*coreprobes\s+profile=(?<profile>\S+)\s+(?<rest>.*)$')) {
        $profile = $Matches['profile']
        $rest = $Matches['rest']
        $map = @{}
        foreach ($tok in ($rest -split '\s+')) {
            if (-not $tok) { continue }
            if ($tok -match '^(?<k>[a-zA-Z0-9_]+)=(?<v>\S+)$') {
                $map[$Matches['k']] = $Matches['v']
            }
        }
        $core = [pscustomobject]@{ profile = $profile; results = $map }
    }

    $blockClass = ''
    $blockReason = ''
    $allText = (($dnsLine, $coreLine, $keyLine, $scoreHintLine) | Where-Object { $_ }) -join ' '
    if ($allText -match 'NAME_NOT_RESOLVED') {
        $blockClass = 'DNS'
        $blockReason = 'NAME_NOT_RESOLVED'
    } elseif ($allText -match 'SECURE_FAILURE|CERT|TLS') {
        $blockClass = 'TLS'
        $blockReason = 'SECURE_FAILURE/CERT/TLS'
    } elseif ($allText -match 'CANNOT_CONNECT|TIMEOUT|CONNECTION|RESET|REFUSED') {
        $blockClass = 'CONNECT'
        $blockReason = 'connect/timeout'
    }

    $autotune = [pscustomobject]@{ retuned = $false; gameFilter = '' }
    if ($retuneLine) {
        $gf = ''
        if ($retuneLine -match 'GameFilter=(?<gf>\S+)') { $gf = [string]$Matches['gf'] }
        $autotune = [pscustomobject]@{ retuned = $true; gameFilter = $gf }
    }

    return [pscustomobject]@{
        Autopick = $autopick
        Coreprobes = $core
        Autotune = $autotune
        BlockClass = $blockClass
        BlockReason = $blockReason
        DnsFailLine = $dnsLine
        CoreprobesLine = $coreLine
        KeyLine = $keyLine
        ScoreHintLine = $scoreHintLine
        RetuneLine = $retuneLine
    }
}

function Write-DGenSummaryJson {
    param([string]$engineLogPath)

    if (-not $engineLogPath) { $engineLogPath = $script:strategyErrPath }
    if (-not $engineLogPath) { return }
    if (-not (Test-Path -LiteralPath $engineLogPath)) { return }

    $lines = @()
    try { $lines = @(Get-Content -LiteralPath $engineLogPath -Tail 600 -Encoding UTF8 -ErrorAction Stop) } catch { $lines = @() }
    $parsed = Parse-AutopickFromEngineLogLines -lines $lines

    $engineExe = Join-Path (Join-Path $root 'bin') 'DGen.exe'
    $sha256 = Get-Sha256Hex -path $engineExe

    $strategyRel = ''
    try { if ($cfg -and ($cfg.PSObject.Properties.Name -contains 'strategy')) { $strategyRel = [string]$cfg.strategy } } catch { $strategyRel = '' }

    $strategyName = ''
    try { if ($script:currentStrategyFile) { $strategyName = [string]$script:currentStrategyFile.Name } } catch { $strategyName = '' }

    $postStart = $null
    $postBlockClass = ''
    $postBlockReason = ''
    try {
        $p = $script:ethernetAutoRotateLastProbe
        if ($p) {
            $postStart = [ordered]@{
                discordOk = $p.DiscordOk
                robloxOk = $p.RobloxOk
                ctrlOk = $p.ControlOk
                ytOk = $p.YtOk
                ytMainOk = $p.YtMainOk
                ytAccountsOk = $p.YtAccountsOk
                ytVideoOk = $p.YtVideoOk
                ytImgOk = $p.YtImgOk
                discordTcp = $p.DiscordTcp
                robloxTcp = $p.RobloxTcp
                discordDiag = $p.DiscordDiag
                robloxDiag = $p.RobloxDiag
                ctrlDiag = $p.CtrlDiag
                ytDiag = $p.YtDiag
            }

            $postBlockReason = ("discord:{0} roblox:{1} ctrl:{2}" -f [string]$p.DiscordDiag, [string]$p.RobloxDiag, [string]$p.CtrlDiag)

            $txt = ($postBlockReason + ' ' + [string]$p.DiscordTcp + ' ' + [string]$p.RobloxTcp).ToLowerInvariant()
            $tcpFail = $false
            try { if ($p.DiscordTcp -and $p.DiscordTcp -ne 'ok') { $tcpFail = $true } } catch { }
            try { if ($p.RobloxTcp -and $p.RobloxTcp -ne 'ok') { $tcpFail = $true } } catch { }

            if ($txt -match '\bdns\b') {
                $postBlockClass = 'DNS'
            } elseif ($tcpFail) {
                $postBlockClass = 'CONNECT'
            } elseif ($txt -match '\btls\b') {
                $postBlockClass = 'TLS'
            } elseif ($txt -match '\btimeout\b') {
                $postBlockClass = 'TIMEOUT'
            } elseif (-not $p.DiscordOk -or -not $p.RobloxOk) {
                $postBlockClass = 'FAIL'
            } else {
                $postBlockClass = 'OK'
                $postBlockReason = ''
            }
        }
    } catch { }

    $blockClass = $parsed.BlockClass
    $blockReason = $parsed.BlockReason
    if ($postBlockClass) { $blockClass = $postBlockClass; $blockReason = $postBlockReason }

    $obj = [ordered]@{
        schema = 1
        generatedAt = (Get-Date).ToString('o')
        runId = $script:runId
        networkProfileKey = $script:networkProfileKey
        linkType = $script:networkLinkType
        strategy = [ordered]@{
            configured = $strategyRel
            file = $strategyName
        }
        engine = [ordered]@{
            exe = $engineExe
            sha256 = $sha256
        }
        logs = [ordered]@{
            launcher = $script:activeLogPath
            generatorStdout = $script:generatorOutPath
            generatorStderr = $script:generatorErrPath
            engineStdout = $script:strategyOutPath
            engineLog = $engineLogPath
        }
        autopick = $parsed.Autopick
        coreprobes = $parsed.Coreprobes
        autotune = $parsed.Autotune
        postStart = $postStart
        gameFilterOverride = $script:gameFilterOverride
        blockClass = $blockClass
        blockReason = $blockReason
        raw = [ordered]@{
            dnsFailLine = $parsed.DnsFailLine
            coreprobesLine = $parsed.CoreprobesLine
            keyLine = $parsed.KeyLine
            scoreHintLine = $parsed.ScoreHintLine
            retuneLine = $parsed.RetuneLine
        }
    }

    $json = $obj | ConvertTo-Json -Depth 10
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    try {
        if (Test-Path -LiteralPath $defaultSummaryPath) {
            # Preserve the last *informative* summary in .prev.
            # When Ethernet auto-rotate starts fixed-profile strategies, their summaries don't include autopick/coreprobes,
            # so we must not overwrite a previous autopick/coreprobes-rich summary with a null one.
            $copyPrev = $false
            try {
                $prevText = Get-Content -LiteralPath $defaultSummaryPath -Raw -ErrorAction SilentlyContinue
                if ($prevText) {
                    $prevObj = $prevText | ConvertFrom-Json -ErrorAction Stop
                    if ($prevObj) {
                        if (($prevObj.PSObject.Properties.Name -contains 'autopick') -and $prevObj.autopick) { $copyPrev = $true }
                        if (($prevObj.PSObject.Properties.Name -contains 'coreprobes') -and $prevObj.coreprobes) { $copyPrev = $true }
                    }
                }
            } catch { $copyPrev = $false }

            if ($copyPrev) {
                Copy-Item -Force -LiteralPath $defaultSummaryPath -Destination ($defaultSummaryPath + '.prev')
            }
        }
    } catch { }

    try { [System.IO.File]::WriteAllText($defaultSummaryPath, $json, $utf8NoBom) } catch { }
}

function Update-DGenSummaryJsonIfNeeded {
    try {
        $src = $script:strategyErrPath
        if (-not $src) { return }
        if (-not (Test-Path -LiteralPath $src)) { return }

        $fi = $null
        try { $fi = Get-Item -LiteralPath $src -ErrorAction Stop } catch { $fi = $null }
        if (-not $fi) { return }

        $run = [string]$script:runId
        if (-not $run) { $run = '' }

        $postSig = ''
        try {
            $p = $script:ethernetAutoRotateLastProbe
            if ($p) {
                $postSig = ("{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}|{11}" -f $p.DiscordOk, $p.RobloxOk, $p.ControlOk, $p.YtOk, $p.YtAccountsOk, $p.YtVideoOk, $p.DiscordTcp, $p.RobloxTcp, $p.DiscordDiag, $p.RobloxDiag, $p.CtrlDiag, $p.YtDiag)
            }
        } catch { $postSig = '' }

        if ($script:lastSummaryRunId -eq $run -and $script:lastSummarySourcePath -eq $fi.FullName -and $script:lastSummarySourceWriteUtc -eq $fi.LastWriteTimeUtc -and $script:lastSummaryPostStartSig -eq $postSig) {
            return
        }

        $script:lastSummaryRunId = $run
        $script:lastSummarySourcePath = $fi.FullName
        $script:lastSummarySourceWriteUtc = $fi.LastWriteTimeUtc
        $script:lastSummaryPostStartSig = $postSig

        Write-DGenSummaryJson -engineLogPath $fi.FullName
    } catch { }
}

function Delete-LogFiles {
    $deleted = 0
    $failed = 0
    $errors = New-Object System.Collections.Generic.List[string]

    $files = @()
    try {
        if (-not (Test-Path $logsDir)) {
            return [pscustomobject]@{ Deleted = 0; Failed = 0; Errors = @() }
        }

        $files = @(Get-ChildItem -LiteralPath $logsDir -File -Force -ErrorAction SilentlyContinue)
    } catch {
        return [pscustomobject]@{ Deleted = 0; Failed = 0; Errors = @("enumeration failed: $($_.Exception.Message)") }
    }

    foreach ($f in $files) {
        if (-not $f) { continue }
        if ($f.Name -ieq '.gitkeep') { continue }

        try {
            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
            $deleted++
        } catch {
            $failed++
            try { $errors.Add(("{0}: {1}" -f $f.Name, $_.Exception.Message)) } catch { }
        }
    }

    return [pscustomobject]@{ Deleted = $deleted; Failed = $failed; Errors = $errors.ToArray() }
}

function Invoke-DeleteLogsUI {
    try {
        $ans = [System.Windows.Forms.MessageBox]::Show(
            ("Delete all files in:`r`n{0}`r`n`r`nThis cannot be undone." -f $logsDir),
            "D-Gen",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        $r = Delete-LogFiles

        try { $script:activeLogPath = $logPath } catch { }
        try { $script:generatorOutPath = $defaultGeneratorOutPath } catch { }
        try { $script:generatorErrPath = $defaultGeneratorErrPath } catch { }
        try { $script:strategyOutPath = $defaultStrategyOutPath } catch { }
        try { $script:strategyErrPath = $defaultStrategyErrPath } catch { }

        try { Clear-CurrentLogs } catch { }
        try { Refresh-Logs } catch { }

        if ($statusLabel) {
            if ($r.Failed -gt 0) {
                $statusLabel.Text = ("Logs cleared: {0}, failed: {1}" -f $r.Deleted, $r.Failed)
            } else {
                $statusLabel.Text = ("Logs cleared: {0}" -f $r.Deleted)
            }
        }

        if ($r.Failed -gt 0) {
            $msg = "Some files couldn't be deleted:`r`n" + ($r.Errors -join "`r`n")
            [System.Windows.Forms.MessageBox]::Show($msg, "D-Gen", 'OK', 'Warning') | Out-Null
        }
    } catch {
        try { if ($statusLabel) { $statusLabel.Text = "Clear logs failed" } } catch { }
    }
}

function Show-LoadingOverlay {
    param(
        [string]$text,
        [int]$percent = -1
    )

    try {
        if ($text) { $script:loadingOverlayText = $text }
        if ($percent -ge 0) { $script:loadingOverlayPercent = $percent }
        if ($script:loadingOverlay) {
            $script:loadingOverlay.Visible = $true
            try { $script:loadingOverlay.BringToFront() } catch { }
            try { $script:loadingOverlay.Invalidate() } catch { }
        }
        if ($script:loadingTimer) { $script:loadingTimer.Start() }
    } catch { }
}

function Set-LoadingOverlayText {
    param(
        [string]$text,
        [int]$percent = -1
    )

    try {
        if (-not $text) { return }
        $script:loadingOverlayText = $text
        if ($percent -ge 0) { $script:loadingOverlayPercent = $percent }
        if ($script:loadingOverlay) { try { $script:loadingOverlay.Invalidate() } catch { } }
    } catch { }
}

function Hide-LoadingOverlay {
    try {
        if ($script:loadingTimer) { $script:loadingTimer.Stop() }
        if ($script:loadingOverlay) { $script:loadingOverlay.Visible = $false }
    } catch { }
}

function Dispose-LoadingOverlayResources {
    try {
        if ($script:loadingTimer) {
            $script:loadingTimer.Stop()
            $script:loadingTimer.Dispose()
            $script:loadingTimer = $null
        }
    } catch { }

    try {
        if ($script:loadingBuildings) {
            foreach ($b in $script:loadingBuildings) {
                try { if ($b -and $b.Brush) { $b.Brush.Dispose() } } catch { }
            }
        }
    } catch { }
    try { $script:loadingBuildings = @() } catch { }

    try { if ($script:loadingFontTitle) { $script:loadingFontTitle.Dispose(); $script:loadingFontTitle = $null } } catch { }
    try { if ($script:loadingFontStage) { $script:loadingFontStage.Dispose(); $script:loadingFontStage = $null } } catch { }
    try { if ($script:loadingBrushVeil) { $script:loadingBrushVeil.Dispose(); $script:loadingBrushVeil = $null } } catch { }
    try { if ($script:loadingBrushText) { $script:loadingBrushText.Dispose(); $script:loadingBrushText = $null } } catch { }
    try { if ($script:loadingBrushMuted) { $script:loadingBrushMuted.Dispose(); $script:loadingBrushMuted = $null } } catch { }
    try { if ($script:loadingBrushRoad) { $script:loadingBrushRoad.Dispose(); $script:loadingBrushRoad = $null } } catch { }
    try { if ($script:loadingPenRoadEdge) { $script:loadingPenRoadEdge.Dispose(); $script:loadingPenRoadEdge = $null } } catch { }
    try { if ($script:loadingPenLane) { $script:loadingPenLane.Dispose(); $script:loadingPenLane = $null } } catch { }
    try { if ($script:loadingBrushDevil) { $script:loadingBrushDevil.Dispose(); $script:loadingBrushDevil = $null } } catch { }
    try { if ($script:loadingPenDevil) { $script:loadingPenDevil.Dispose(); $script:loadingPenDevil = $null } } catch { }
    try { if ($script:loadingPenFork) { $script:loadingPenFork.Dispose(); $script:loadingPenFork = $null } } catch { }
    try { if ($script:loadingPenForkGlow) { $script:loadingPenForkGlow.Dispose(); $script:loadingPenForkGlow = $null } } catch { }
    try { if ($script:loadingBrushWindow) { $script:loadingBrushWindow.Dispose(); $script:loadingBrushWindow = $null } } catch { }
    try { if ($script:loadingBrushCardBg) { $script:loadingBrushCardBg.Dispose(); $script:loadingBrushCardBg = $null } } catch { }
    try { if ($script:loadingBrushShadow) { $script:loadingBrushShadow.Dispose(); $script:loadingBrushShadow = $null } } catch { }
    try { if ($script:loadingPenCardBorder) { $script:loadingPenCardBorder.Dispose(); $script:loadingPenCardBorder = $null } } catch { }
    try { if ($script:loadingBrushBarBg) { $script:loadingBrushBarBg.Dispose(); $script:loadingBrushBarBg = $null } } catch { }
    try { if ($script:loadingPenBarBorder) { $script:loadingPenBarBorder.Dispose(); $script:loadingPenBarBorder = $null } } catch { }
    try { if ($script:loadingBrushGlow1) { $script:loadingBrushGlow1.Dispose(); $script:loadingBrushGlow1 = $null } } catch { }
    try { if ($script:loadingBrushGlow2) { $script:loadingBrushGlow2.Dispose(); $script:loadingBrushGlow2 = $null } } catch { }
    try { if ($script:loadingBrushProgress) { $script:loadingBrushProgress.Dispose(); $script:loadingBrushProgress = $null } } catch { }
}

function Clear-DiscordCache {
    $ts = Get-Date -Format "yyyyMMdd-HHmmss"
    $base = Join-Path $env:APPDATA 'discord'
    $targets = @('Cache', 'Code Cache', 'GPUCache')

    try {
        Get-Process -Name 'Discord' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Get-Process -Name 'Update' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch { }

    $moved = @()
    foreach ($t in $targets) {
        $p = Join-Path $base $t
        if (Test-Path $p) {
            $dst = "$p.bak-$ts"
            try {
                Move-Item -Force -Path $p -Destination $dst
                $moved += $dst
            } catch { }
        }
    }

    if ($moved.Count -gt 0) {
        [System.Windows.Forms.MessageBox]::Show(("Discord cache moved:\r\n" + ($moved -join "\r\n")), "D-Gen", 'OK', 'Information') | Out-Null
    } else {
        [System.Windows.Forms.MessageBox]::Show("Discord cache folders not found (nothing to clear).", "D-Gen", 'OK', 'Information') | Out-Null
    }
}

function Get-UserProxySettings {
    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    try {
        $p = Get-ItemProperty -Path $reg -ErrorAction Stop
        return [pscustomobject]@{
            ProxyEnable = [int]($p.ProxyEnable)
            ProxyServer = [string]($p.ProxyServer)
            ProxyOverride = [string]($p.ProxyOverride)
            AutoConfigURL = [string]($p.AutoConfigURL)
            AutoDetect = [int]($p.AutoDetect)
        }
    } catch {
        return [pscustomobject]@{
            ProxyEnable = 0
            ProxyServer = ''
            ProxyOverride = ''
            AutoConfigURL = ''
            AutoDetect = 0
        }
    }
}

function Get-LoopbackProxyEndpoint {
    param([string]$proxyServer)

    if (-not $proxyServer) { return $null }
    # - 127.0.0.1:8881
    $parts = @($proxyServer -split ';')
    foreach ($p in $parts) {
        $candidate = $p.Trim()
        if (-not $candidate) { continue }
        if ($candidate -match '^(?:http=|https=)?(?<h>127\.0\.0\.1|localhost):(?<port>\d+)$') {
            return [pscustomobject]@{ Host = $Matches['h']; Port = [int]$Matches['port'] }
        }
    }

    return $null
}

function Get-RobloxLogDir {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Roblox\logs"),
        (Join-Path $env:TEMP "Roblox\logs")
    )

    # Microsoft Store Roblox can write logs under:
    # %LOCALAPPDATA%\Packages\ROBLOXCORPORATION.ROBLOX*\LocalState\logs
    try {
        $pkgRoot = Join-Path $env:LOCALAPPDATA 'Packages'
        if ($pkgRoot -and (Test-Path -LiteralPath $pkgRoot)) {
            $pkgs = @(
                Get-ChildItem -LiteralPath $pkgRoot -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like 'ROBLOXCORPORATION.ROBLOX*' } |
                    Sort-Object LastWriteTime -Descending
            )
            foreach ($pkg in $pkgs) {
                $p1 = Join-Path $pkg.FullName 'LocalState\logs'
                $p2 = Join-Path $pkg.FullName 'LocalState\Roblox\logs'
                if ($p1) { $candidates += $p1 }
                if ($p2) { $candidates += $p2 }
            }
        }
    } catch { }

    $existing = @(
        $candidates |
            Where-Object { $_ } |
            ForEach-Object { [string]$_ } |
            Sort-Object -Unique |
            Where-Object { Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue }
    )

    if (-not $existing -or $existing.Count -eq 0) { return $null }

    # Prefer the log dir that has the newest log file.
    $best = $null
    $bestTime = [datetime]::MinValue
    foreach ($p in $existing) {
        $t = $null
        try {
            $latest = @(Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
            if ($latest -and $latest.Count -gt 0) {
                $t = $latest[0].LastWriteTime
            } else {
                $t = (Get-Item -LiteralPath $p -ErrorAction SilentlyContinue).LastWriteTime
            }
        } catch { $t = $null }

        if ($t -and $t -gt $bestTime) {
            $bestTime = $t
            $best = $p
        }
    }

    if ($best) { return $best }
    return $existing[0]
}

function Test-IsPrivateOrLocalIp {
    param([System.Net.IPAddress]$ip)

    if (-not $ip) { return $true }

    try {
        if ([System.Net.IPAddress]::IsLoopback($ip)) { return $true }

        if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $b = $ip.GetAddressBytes()
            if ($b[0] -eq 0) { return $true }
            if ($b[0] -eq 10) { return $true }
            if ($b[0] -eq 127) { return $true }
            if ($b[0] -eq 169 -and $b[1] -eq 254) { return $true }
            if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true }
            if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }
            if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $true }
            if ($b[0] -ge 224) { return $true }
            return $false
        }

        if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            if ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal) { return $true }
            $b = $ip.GetAddressBytes()
            if (($b[0] -band 0xfe) -eq 0xfc) { return $true }
            if ($b[0] -eq 0xff) { return $true }
            return $false
        }
    } catch { }

    return $false
}

function Get-RobloxEndpointsFromRecentLogs {
    param([int]$tailLines = 4000)

    $logDir = Get-RobloxLogDir
    if (-not $logDir) { return $null }

    $files = @(Get-ChildItem -LiteralPath $logDir -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20)
    if (-not $files -or $files.Count -eq 0) { return $null }

    $hosts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ips = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $sample = $null
    $has277 = $false
    $has279 = $false
    $has529 = $false

    $rxBad = [regex]'\b(277|279|529|connect|connecting|connection|timeout|timed out|failed|handshake|udp|tcp|unreachable|reset|refused)\b'
    $rxUrl = [regex]'https?://([a-zA-Z0-9.-]+)'
    $rxHostPort = [regex]'(?<![a-zA-Z0-9.-])([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::\d{2,5})?'
    $rxIPv4 = [regex]'(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?::\d{2,5})?'
    $rxIPv6 = [regex]'\[([0-9a-fA-F:]+)\](?::\d{2,5})?'

    foreach ($f in $files) {
        $lines = @()
        $hasNul = $false
        try { $lines = Get-Content -LiteralPath $f.FullName -Tail $tailLines -Encoding UTF8 -ErrorAction Stop } catch { $lines = @() }
        try {
            foreach ($ln in $lines) { if ($ln -match [char]0) { $hasNul = $true; break } }
        } catch { $hasNul = $false }
        if (-not $lines -or $lines.Count -eq 0 -or $hasNul) {
            try { $lines = Get-Content -LiteralPath $f.FullName -Tail $tailLines -Encoding Unicode -ErrorAction Stop } catch { continue }
        }

        foreach ($line in $lines) {
            $bad = $false
            try { $bad = $rxBad.IsMatch($line) } catch { $bad = $false }

            # Even when a line doesn't contain a keyword like "timeout", Roblox logs can still print
            # the actual game server IP. Capture those too.
            $ipLine = $false
            try { $ipLine = $rxIPv4.IsMatch($line) -or $rxIPv6.IsMatch($line) } catch { $ipLine = $false }

            if (-not $bad -and -not $ipLine) { continue }

            if ($bad -and -not $sample) {
                $sample = if ($line.Length -gt 220) { $line.Substring(0, 220) + '...' } else { $line }
            }

            if (-not $has277 -and ($line -match '\b277\b')) { $has277 = $true }
            if (-not $has279 -and ($line -match '\b279\b')) { $has279 = $true }
            if (-not $has529 -and ($line -match '\b529\b')) { $has529 = $true }

            foreach ($m in $rxUrl.Matches($line)) {
                $h = $m.Groups[1].Value
                if ($h) { [void]$hosts.Add($h.ToLower().Trim()) }
            }
            foreach ($m in $rxHostPort.Matches($line)) {
                $h = $m.Groups[1].Value
                if ($h) { [void]$hosts.Add($h.ToLower().Trim()) }
            }
            foreach ($m in $rxIPv4.Matches($line)) {
                $raw = $m.Groups[1].Value
                $tmp = $null
                if ([System.Net.IPAddress]::TryParse($raw, [ref]$tmp) -and (-not (Test-IsPrivateOrLocalIp -ip $tmp))) {
                    [void]$ips.Add($tmp.IPAddressToString)
                }
            }
            foreach ($m in $rxIPv6.Matches($line)) {
                $raw = $m.Groups[1].Value
                $tmp = $null
                if ([System.Net.IPAddress]::TryParse($raw, [ref]$tmp) -and (-not (Test-IsPrivateOrLocalIp -ip $tmp))) {
                    [void]$ips.Add($tmp.IPAddressToString)
                }
            }
        }
    }

    $allowSuffixes = @(
        'roblox.com',
        'rbxcdn.com',
        'robloxapis.com',
        'rbx.com',
        'amazonaws.com',
        'cloudfront.net'
    )

    $hostList = @($hosts) |
        Where-Object { $_ } |
        ForEach-Object { $_.ToLower().Trim() } |
        Where-Object {
            $h = $_
            if (-not $h.Contains('.')) { return $false }
            if ($h -match '^(localhost|127\..*)$') { return $false }
            if ($h.Length -gt 253) { return $false }
            foreach ($lab in $h.Split('.')) {
                if ($lab.Length -lt 1 -or $lab.Length -gt 63) { return $false }
            }
            foreach ($suf in $allowSuffixes) {
                if ($h -eq $suf -or $h.EndsWith('.' + $suf)) { return $true }
            }
            return $false
        } |
        Sort-Object -Unique
    $ipList = @($ips) | Where-Object { $_ } | Sort-Object -Unique

    return [pscustomobject]@{
        Hosts = $hostList
        Ips = $ipList
        Sample = $sample
        Has277 = $has277
        Has279 = $has279
        Has529 = $has529
    }
}

function Get-LoopbackPacEndpoint {
    param([string]$autoConfigUrl)

    if (-not $autoConfigUrl) { return $null }
    try {
        $uri = [System.Uri]$autoConfigUrl
    } catch {
        return $null
    }

    if ($uri.Scheme -ne 'http' -and $uri.Scheme -ne 'https') { return $null }
    if ($uri.Host -match '^(127\.0\.0\.1|localhost)$') {
        return [pscustomobject]@{ Host = $uri.Host; Port = [int]$uri.Port }
    }

    return $null
}

function Refresh-WindowsProxySettings {
    try {
        if (-not ('WinInet.NativeMethods' -as [type])) {
            Add-Type -Namespace WinInet -Name NativeMethods -MemberDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NativeMethods
{
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
'@
        }

        [void][WinInet.NativeMethods]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
        [void][WinInet.NativeMethods]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
    } catch {
        Write-Log "Proxy: wininet refresh failed: $($_.Exception.Message)"
    }
}

function Test-TcpConnect {
    param(
        [string]$hostName,
        [int]$port,
        [int]$timeoutMs = 800
    )

    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($hostName, $port, $null, $null)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $ar.AsyncWaitHandle.WaitOne(20, $false)) {
            try { [System.Windows.Forms.Application]::DoEvents() } catch { }
            if ($sw.ElapsedMilliseconds -ge $timeoutMs) {
                return [pscustomobject]@{ Ok = $false; Error = "timeout" }
            }
        }
        $client.EndConnect($ar)
        return [pscustomobject]@{ Ok = $true; Error = '' }
    } catch {
        return [pscustomobject]@{ Ok = $false; Error = $_.Exception.Message }
    } finally {
        if ($client) { try { $client.Close() } catch { } }
    }
}

$script:proxySaved = $false
$script:proxySavedState = $null

function Disable-WindowsProxyTemporarily {
    if ($script:proxySaved) { return }

    $st = Get-UserProxySettings
    $script:proxySavedState = $st
    $script:proxySaved = $true

    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $proxyActive = ($st.ProxyEnable -eq 1) -or (-not [string]::IsNullOrWhiteSpace($st.AutoConfigURL)) -or ($st.AutoDetect -eq 1)
    if (-not $proxyActive) {
        Write-Log 'Proxy: not enabled; nothing to disable'
        return
    }

    try {
        Set-ItemProperty -Path $reg -Name ProxyEnable -Value 0 -ErrorAction Stop
        Set-ItemProperty -Path $reg -Name ProxyServer -Value '' -ErrorAction Stop
        Set-ItemProperty -Path $reg -Name ProxyOverride -Value '' -ErrorAction Stop
        Set-ItemProperty -Path $reg -Name AutoConfigURL -Value '' -ErrorAction Stop
        Set-ItemProperty -Path $reg -Name AutoDetect -Value 0 -ErrorAction Stop
        Refresh-WindowsProxySettings
        Write-Log ("Proxy: disabled temporarily (restore on Stop). Previous: enable={0} server={1} pac={2} autodetect={3}" -f $st.ProxyEnable, $st.ProxyServer, $st.AutoConfigURL, $st.AutoDetect)
    } catch {
        Write-Log "Proxy: disable failed: $($_.Exception.Message)"
    }
}

function Restore-WindowsProxyIfNeeded {
    if (-not $script:proxySaved -or -not $script:proxySavedState) { return }

    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    try {
        Set-ItemProperty -Path $reg -Name ProxyServer -Value $script:proxySavedState.ProxyServer
        Set-ItemProperty -Path $reg -Name ProxyOverride -Value $script:proxySavedState.ProxyOverride
        Set-ItemProperty -Path $reg -Name AutoConfigURL -Value $script:proxySavedState.AutoConfigURL
        Set-ItemProperty -Path $reg -Name AutoDetect -Value $script:proxySavedState.AutoDetect
        Set-ItemProperty -Path $reg -Name ProxyEnable -Value $script:proxySavedState.ProxyEnable
        Refresh-WindowsProxySettings
        Write-Log ("Proxy: restored. enable={0} server={1} pac={2} autodetect={3}" -f $script:proxySavedState.ProxyEnable, $script:proxySavedState.ProxyServer, $script:proxySavedState.AutoConfigURL, $script:proxySavedState.AutoDetect)
    } catch {
        Write-Log "Proxy: restore failed: $($_.Exception.Message)"
    } finally {
        $script:proxySaved = $false
        $script:proxySavedState = $null
    }
}

















function Write-Log {
    param([string]$msg)
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::AppendAllText($script:activeLogPath, ("$stamp | $msg`r`n"), $utf8NoBom)
}

function Ensure-DGenEngineReady {
    $binDir = Join-Path $root 'bin'
    $exePath = Join-Path $binDir 'DGen.exe'

    if (-not (Test-Path -LiteralPath $exePath)) {
        Write-Log ("Engine missing: {0}" -f $exePath)
        try { Hide-LoadingOverlay } catch { }
        try { $statusLabel.Text = "Start blocked: missing DGen.exe" } catch { }

        $msg = "DGen.exe not found in bin.\r\n\r\n" +
            "Most common cause: you downloaded the source 'Code ZIP' from GitHub (it does not include bin/).\r\n\r\n" +
            "Fix: use the Release zip (recommended), OR place/rename the engine binary to:\r\n\r\n$exePath"
        try { [System.Windows.Forms.MessageBox]::Show($msg, 'D-Gen', 'OK', 'Error') | Out-Null } catch { }
        return $false
    }

    $missing = New-Object System.Collections.Generic.List[string]

    try {
        if (-not (Test-Path -LiteralPath (Join-Path $binDir 'WinDivert.dll'))) { [void]$missing.Add('WinDivert.dll') }
    } catch { [void]$missing.Add('WinDivert.dll') }

    try {
        $drv64 = Join-Path $binDir 'WinDivert64.sys'
        $drv = Join-Path $binDir 'WinDivert.sys'
        if (-not (Test-Path -LiteralPath $drv64) -and -not (Test-Path -LiteralPath $drv)) {
            [void]$missing.Add('WinDivert64.sys')
        }
    } catch { [void]$missing.Add('WinDivert64.sys') }

    try {
        if (-not (Test-Path -LiteralPath (Join-Path $binDir 'cygwin1.dll'))) { [void]$missing.Add('cygwin1.dll') }
    } catch { [void]$missing.Add('cygwin1.dll') }

    $templates = @(
        'quic_initial_www_google_com.bin',
        'tls_clienthello_4pda_to.bin',
        'tls_clienthello_www_google_com.bin'
    )
    foreach ($f in $templates) {
        try {
            if (-not (Test-Path -LiteralPath (Join-Path $binDir $f))) { [void]$missing.Add($f) }
        } catch {
            [void]$missing.Add($f)
        }
    }

    if ($missing.Count -gt 0) {
        $uniq = @($missing | Sort-Object -Unique)
        $lines = ($uniq | ForEach-Object { " - $_" }) -join "`r`n"

        Write-Log ("Engine deps missing in bin: {0}" -f (($uniq) -join ', '))
        try { Hide-LoadingOverlay } catch { }
        try { $statusLabel.Text = "Start blocked: missing runtime files" } catch { }

        $msg = "Required runtime files are missing in bin:\r\n\r\n$lines\r\n\r\n" +
            "Most common cause: GitHub 'Code ZIP' (does not include bin/).\r\n\r\n" +
            "Fix: use the Release zip (recommended) OR copy the full bin/ folder next to launcher.\r\n\r\nBin folder:\r\n$binDir"
        try { [System.Windows.Forms.MessageBox]::Show($msg, 'D-Gen', 'OK', 'Error') | Out-Null } catch { }
        return $false
    }

    return $true
}

function Reset-TextLog {
    param([string]$path)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, "", $utf8NoBom)
}

$script:logPreviewCache = @{}

function Read-LogTail {
    param(
        [string]$path,
        [int]$maxChars = 250000,
        [int]$headLines = 140,
        [int]$tailLines = 2600
    )

    if (-not $path) { return "" }
    if (-not (Test-Path -LiteralPath $path)) { return "" }

    $fi = $null
    try { $fi = Get-Item -LiteralPath $path -ErrorAction Stop } catch { return "" }

    $key = $fi.FullName.ToLowerInvariant()
    $cached = $script:logPreviewCache[$key]
    if ($cached -and $cached.Length -eq $fi.Length -and $cached.LastWriteTimeUtc -eq $fi.LastWriteTimeUtc) {
        return $cached.Text
    }

    $text = ""

    try {
        if ($fi.Length -le ($maxChars * 2)) {
            $text = Get-Content -LiteralPath $fi.FullName -Raw -Encoding UTF8 -ErrorAction Stop
        } else {
            $head = @()
            $tail = @()
            try { $head = Get-Content -LiteralPath $fi.FullName -TotalCount $headLines -Encoding UTF8 -ErrorAction Stop } catch { $head = @() }
            try { $tail = Get-Content -LiteralPath $fi.FullName -Tail $tailLines -Encoding UTF8 -ErrorAction Stop } catch { $tail = @() }

            $marker = "`r`n... [log truncated: showing beginning and end; open log file for full content] ...`r`n"
            $text = ($head -join "`r`n") + $marker + ($tail -join "`r`n")
        }
    } catch {
        $text = ""
    }

    if ($null -eq $text) { $text = "" }
    try { $text = $text.TrimStart([char]0xFEFF) } catch { }
    if ($text.Length -gt $maxChars) {
        $text = $text.Substring($text.Length - $maxChars)
    }

    try {
        $script:logPreviewCache[$key] = [pscustomobject]@{
            Length           = $fi.Length
            LastWriteTimeUtc = $fi.LastWriteTimeUtc
            Text             = $text
        }
    } catch { }

    return $text
}

$script:uiLogImportantOnly = $true

function Filter-LauncherLogForUi {
    param([string]$text)

    if (-not $script:uiLogImportantOnly) { return $text }
    if (-not $text) { return $text }

    $lines = $text -split "`r?`n"

    # UX: make logs "start" only when the session is actually ready.
    # Prefer the concise readiness marker we print at the end of Start.
    $readyIdx = -1
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $l = $lines[$i]
        if ($l -and ($l -match '\bDGen\s+RUN:')) { $readyIdx = $i; break }
    }
    if ($readyIdx -lt 0) {
        for ($i = 0; $i -lt $lines.Length; $i++) {
            $l = $lines[$i]
            if ($l -and ($l -match '\bREADY:')) { $readyIdx = $i; break }
        }
    }
    if ($readyIdx -ge 0) {
        $lines = $lines[$readyIdx..($lines.Length - 1)]
    }

    # User UX: normally show exactly ONE readiness line in the UI,
    # but always surface Stop / auto-rotate / auto-retry lines so the user can see progress.
    $runLine = $null
    $important = New-Object System.Collections.Generic.List[string]

    foreach ($line in $lines) {
        if (-not $line) { continue }

        if ($line -match '\bDGen\s+RUN:') {
            $runLine = $line
            continue
        }

        $msg = $line
        $parts = $line -split '\s\|\s', 2
        if ($parts.Count -eq 2) { $msg = $parts[1] }

        # Hide high-frequency progress spam; keep summaries/errors.
        if ($msg -like 'Preflight: checking *') { continue }

        if (
            $msg -eq 'Stop requested' -or
            $msg -like 'Stop-All:*' -or
            $msg -like 'Ethernet auto-rotate:*' -or
            $msg -like 'WiFi auto-rotate:*' -or
            $msg -like 'Roblox auto-retry:*' -or
            $msg -like 'FATAL:*' -or
            $msg -like 'ERROR:*' -or
            $msg -like 'Start failed*' -or
            $msg -like 'Fail-*'
        ) {
            $important.Add($line) | Out-Null
            continue
        }
    }

    if ($runLine -and $important.Count -gt 0) {
        $recent = @($important | Select-Object -Last 8)
        return (($recent + $runLine) -join "`r`n")
    }

    if ($runLine) { return $runLine }

    $out = New-Object System.Collections.Generic.List[string]

    foreach ($line in $lines) {
        if (-not $line) { continue }

        $msg = $line
        $parts = $line -split '\s\|\s', 2
        if ($parts.Count -eq 2) { $msg = $parts[1] }

        # Hide high-frequency progress spam; keep summaries/errors.
        if ($msg -like 'Preflight: checking *') { continue }

        $out.Add($line) | Out-Null
    }

    return ($out -join "`r`n")
}

function Can-OverwriteTextBox {
    param($tb)
    try {
        if (-not $tb) { return $false }
        if (-not $tb.Focused) { return $true }
        return ($tb.SelectionStart -ge ($tb.TextLength - 5))
    } catch {
        return $true
    }
}

function New-RunId {
    $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $nonce = [Guid]::NewGuid().ToString('N').Substring(0, 6)
    return "$ts-$nonce"
}

function Fail {
    param([string]$msg)
    Write-Log "FATAL: $msg"
    [System.Windows.Forms.MessageBox]::Show($msg, "D-Gen", 'OK', 'Error') | Out-Null
    exit 1
}

function Test-IsAdmin {
    $currUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-Elevated {
    param(
        [switch]$AutoStart
    )

    Write-Log "Requesting elevation..."

    $selfArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-STA",
        "-WindowStyle", "Hidden",
        "-File", "`"$PSCommandPath`""
    )
    if ($AutoStart) { $selfArgs += "-AutoStart" }

    try {
        Start-Process -FilePath $powershellExe -ArgumentList $selfArgs -Verb RunAs -WindowStyle Hidden | Out-Null
    } catch {
        Fail ("Failed to elevate. Please approve the UAC prompt (Run as Administrator) and try again.`r`n`r`n" + $_.Exception.Message)
    }
}

$script:isAdmin = Test-IsAdmin

if (-not $script:isAdmin -and -not $NoElevate) {
    Restart-Elevated
    exit
}

Write-Log "Launcher build: 2025-12-30 (updater-manifest http-check + detailed diagnostics)"

if (-not (Test-Path $generatorPath)) { Fail "Generator not found: $generatorPath" }
if (-not (Test-Path $strategiesDir)) { Fail "Strategies folder not found: $strategiesDir" }

if (-not (Test-Path $configPath)) {
    $default = @{
        domains = @("discord.com", "youtube.com")
        targetDescription = "D-Gen launcher default"
        strategy = "strategies\\general.bat"
        aggressiveMode = $false
        enableRemote = $false
        apiKey = ""
        baseUri = "http://127.0.0.1:11434/v1"
    } | ConvertTo-Json -Compress

    $default | Set-Content -Path $configPath -Encoding UTF8
}

try {
    $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
} catch {
    Fail "config.json is invalid. See D-Gen\\logs\\dgen-launch.log"
}

function Save-Config {
    param($cfgObj)
    try {
        if (-not $cfgObj) { return }
        $json = $cfgObj | ConvertTo-Json -Depth 10
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($configPath, $json, $utf8NoBom)
    } catch {
        Write-Log "Config: save failed: $($_.Exception.Message)"
    }
}

function New-DefaultBotState {
    return [pscustomobject]@{
        LastBestStrategy   = ""
        LastBestPassed     = 0
        LastBestTotal      = 0
        LastBestBlockType  = ""
        LastBestAt         = ""
        LastBestGameFilter = ""
        LastBestAggressive = $false
        LastBestQuicBlock  = $false
    }
}

function New-DefaultBotStateFile {
    return [pscustomobject]@{
        Version  = 2
        Profiles = [pscustomobject]@{}
    }
}

function Get-NetworkProfileKey {
    try {
        $script:networkLinkType = 'unknown'
        $script:networkIfIndex = $null
        $script:networkIfGuid = ''
        $script:networkIfAlias = ''
        $script:networkMtu = $null

        $activeIfIndex = $null
        try {
            $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' })
            if ($routes.Count -gt 0) {
                foreach ($r in $routes) {
                    $ifMetric = 9999
                    try {
                        $ipif = Get-NetIPInterface -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
                        if ($ipif) { $ifMetric = [int]$ipif.InterfaceMetric }
                    } catch { $ifMetric = 9999 }
                    try { $r | Add-Member -NotePropertyName _ifMetric -NotePropertyValue $ifMetric -Force } catch { }
                }

                $best = $routes | Sort-Object RouteMetric, _ifMetric, InterfaceIndex | Select-Object -First 1
                $activeIfIndex = [int]$best.InterfaceIndex
            }
        } catch {
            $activeIfIndex = $null
        }

        if ($activeIfIndex -ne $null) {
            try { $script:networkIfIndex = [int]$activeIfIndex } catch { $script:networkIfIndex = $null }
            try {
                $na = Get-NetAdapter -InterfaceIndex $activeIfIndex -ErrorAction Stop | Select-Object -First 1
                if ($na) {
                    $script:networkIfGuid = [string]$na.InterfaceGuid
                    $script:networkIfAlias = [string]$na.Name
                }
            } catch { }
            try {
                $ipif = Get-NetIPInterface -InterfaceIndex $activeIfIndex -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1
                if ($ipif) { $script:networkMtu = [int]$ipif.NlMtu }
            } catch { }
        }

        $dns = New-Object System.Collections.Generic.List[string]
        $gw = New-Object System.Collections.Generic.List[string]
        $ipPrefixes = New-Object System.Collections.Generic.List[string]
        $dhcp = New-Object System.Collections.Generic.List[string]

        foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($ni.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            if ($ni.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback) { continue }

            $ipProps = $null
            try { $ipProps = $ni.GetIPProperties() } catch { continue }
            if (-not $ipProps) { continue }

            $ifIndex = $null
            try { $ifIndex = [int]($ipProps.GetIPv4Properties().Index) } catch { $ifIndex = $null }
            if ($activeIfIndex -ne $null -and $ifIndex -ne $activeIfIndex) { continue }

            if ($script:networkIfIndex -eq $null -and $ifIndex -ne $null) {
                try { $script:networkIfIndex = [int]$ifIndex } catch { $script:networkIfIndex = $null }
            }
            if (-not $script:networkIfGuid) {
                try { if ($ni.Id) { $script:networkIfGuid = [string]$ni.Id } } catch { }
            }
            if (-not $script:networkIfAlias) {
                try { if ($ni.Name) { $script:networkIfAlias = [string]$ni.Name } } catch { }
            }
            if ($script:networkMtu -eq $null) {
                try {
                    $ipv4 = $ipProps.GetIPv4Properties()
                    if ($ipv4) { $script:networkMtu = [int]$ipv4.Mtu }
                } catch { }
            }

            if ($script:networkLinkType -eq 'unknown') {
                try {
                    if ($ni.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Wireless80211) {
                        $script:networkLinkType = 'wifi'
                    } elseif ($ni.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Ethernet) {
                        $script:networkLinkType = 'ethernet'
                    }
                } catch { }
            }

            foreach ($a in @($ipProps.DnsAddresses)) {
                try {
                    if ($a -and $a.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $dns.Add($a.IPAddressToString) | Out-Null }
                } catch { }
            }

            foreach ($g in @($ipProps.GatewayAddresses)) {
                try {
                    $addr = $g.Address
                    if ($addr -and $addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $gw.Add($addr.IPAddressToString) | Out-Null }
                } catch { }
            }

            foreach ($u in @($ipProps.UnicastAddresses)) {
                try {
                    $addr = $u.Address
                    if (-not $addr) { continue }
                    if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
                    $s = $addr.IPAddressToString
                    if (-not $s) { continue }
                    if ($s -like '127.*' -or $s -like '169.254.*') { continue }
                    $parts = $s.Split('.')
                    if ($parts.Count -eq 4) {
                        $ipPrefixes.Add((@($parts[0], $parts[1], $parts[2]) -join '.')) | Out-Null
                    }
                } catch { }
            }

            foreach ($d in @($ipProps.DhcpServerAddresses)) {
                try {
                    if ($d -and $d.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $dhcp.Add($d.IPAddressToString) | Out-Null }
                } catch { }
            }
        }

        if ($script:networkLinkType -eq 'unknown' -and $activeIfIndex -ne $null) {
            $alias = ''
            try { if ($script:networkIfAlias) { $alias = [string]$script:networkIfAlias } } catch { $alias = '' }
            if (-not $alias) { $alias = '' }

            $aliasNorm = $alias.ToLowerInvariant()
            if ($aliasNorm.Contains('wi-fi') -or $aliasNorm.Contains('wifi') -or $aliasNorm.Contains('wireless')) {
                $script:networkLinkType = 'wifi'
            } else {
                $script:networkLinkType = 'ethernet'
            }
        }

        $dnsKey = (@($dns | Where-Object { $_ } | Sort-Object -Unique) -join ',')
        $gwKey = (@($gw | Where-Object { $_ } | Sort-Object -Unique) -join ',')
        $ipKey = (@($ipPrefixes | Where-Object { $_ } | Sort-Object -Unique) -join ',')
        $dhcpKey = (@($dhcp | Where-Object { $_ } | Sort-Object -Unique) -join ',')

        $ifGuid = ''
        $ifAlias = ''
        $ifIndex = ''
        $mtu = ''
        try { if ($script:networkIfGuid) { $ifGuid = [string]$script:networkIfGuid } } catch { $ifGuid = '' }
        try { if ($script:networkIfAlias) { $ifAlias = [string]$script:networkIfAlias } } catch { $ifAlias = '' }
        try { if ($script:networkIfIndex -ne $null) { $ifIndex = [string]$script:networkIfIndex } } catch { $ifIndex = '' }
        try { if ($script:networkMtu -ne $null) { $mtu = [string]$script:networkMtu } } catch { $mtu = '' }

        $ifGuid = $ifGuid.Replace('|', '/').Replace('"', '').Trim()
        $ifAlias = $ifAlias.Replace('|', '/').Replace('"', '').Trim()
        $ifIndex = $ifIndex.Replace('|', '/').Replace('"', '').Trim()
        $mtu = $mtu.Replace('|', '/').Replace('"', '').Trim()

        $raw = ("ifIndex={0}|ifGuid={1}|ifAlias={2}|mtu={3}|link={4}|dns={5}|gw={6}|ip={7}|dhcp={8}" -f $ifIndex, $ifGuid, $ifAlias, $mtu, $script:networkLinkType, $dnsKey, $gwKey, $ipKey, $dhcpKey)
        if (-not $dnsKey -and -not $gwKey -and -not $ipKey -and -not $dhcpKey) { $raw = ("none|ifIndex={0}|ifGuid={1}|ifAlias={2}|mtu={3}|link={4}" -f $ifIndex, $ifGuid, $ifAlias, $mtu, $script:networkLinkType) }

        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
        $hash = $sha.ComputeHash($bytes)
        $hex = ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
        return $hex.Substring(0, 16)
    } catch {
        return 'unknown'
    }
}

function Get-BotProfileKey {
    $k = $script:networkProfileKey
    if (-not $k) {
        try { $k = Get-NetworkProfileKey } catch { $k = '' }
    }
    if (-not $k) { $k = 'unknown' }
    return [string]$k
}





function Kill-ProcessTree {
    param([int]$processId)
    & taskkill.exe /PID $processId /T /F | Out-Null
}

function Stop-Winws {
    $pids = @(Get-Process -Name "DGen" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    foreach ($procId in $pids) {
        try { Kill-ProcessTree -processId $procId } catch { }
    }
}

function Test-WinwsRunning {
    try {
        $pids = @(Get-Process -Name "DGen" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
        return ($pids.Count -gt 0)
    } catch {
        return $false
    }
}

function Write-StrategyLogTailToLauncherLog {
    param([int]$maxLines = 30)

    try {
        if ($script:strategyOutPath -and (Test-Path -LiteralPath $script:strategyOutPath)) {
            $tail = @()
            try { $tail = @(Get-Content -LiteralPath $script:strategyOutPath -Tail $maxLines -ErrorAction Stop) } catch { $tail = @() }
            if ($tail.Count -gt 0) {
                Write-Log "Strategy stdout tail:"
                foreach ($l in $tail) { Write-Log ("  " + $l) }
            }
        }
    } catch { }

    try {
        if ($script:strategyErrPath -and (Test-Path -LiteralPath $script:strategyErrPath)) {
            $tail = @()
            try { $tail = @(Get-Content -LiteralPath $script:strategyErrPath -Tail $maxLines -ErrorAction Stop) } catch { $tail = @() }
            if ($tail.Count -gt 0) {
                Write-Log "Strategy stderr tail:"
                foreach ($l in $tail) { Write-Log ("  " + $l) }
            }
        }
    } catch { }
}

function Fail-StrategyStart {
    param(
        [System.IO.FileInfo]$strategyFile,
        [string]$reason
    )

    $name = "unknown"
    try { if ($strategyFile) { $name = $strategyFile.Name } } catch { }

    Write-Log ("Strategy start failed: {0}: {1}" -f $name, $reason)

    # Helpful diagnostics: cmd.exe exit code (usually propagates the last program's exit code).
    try {
        if ($script:strategyRunnerProc) {
            try { $script:strategyRunnerProc.Refresh() } catch { }
            if ($script:strategyRunnerProc.HasExited) {
                $code = 0
                try { $code = [int]$script:strategyRunnerProc.ExitCode } catch { $code = 0 }
                $hex = ('0x{0:X8}' -f ($code -band 0xffffffff))
                Write-Log ("Strategy runner ExitCode: {0} ({1})" -f $code, $hex)
            } else {
                try { Write-Log ("Strategy runner still running: pid={0}" -f [int]$script:strategyRunnerProc.Id) } catch { }
            }
        }
    } catch { }

    try {
        $svc = Get-Service -Name "DGen" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Log "Hint: DGen service is RUNNING. Use service.bat -> Remove Services, then retry Start."
        }
    } catch { }

    try { Write-StrategyLogTailToLauncherLog -maxLines 35 } catch { }

    try { Hide-LoadingOverlay } catch { }

    try {
        if ($script:strategyRunnerProc -and (-not $script:strategyRunnerProc.HasExited)) {
            Kill-ProcessTree -processId $script:strategyRunnerProc.Id
        }
    } catch { }
    try { Stop-Winws } catch { }
    try { Disable-QuicBlock } catch { }
    try { Restore-WindowsProxyIfNeeded } catch { }

    try { $script:strategyRunnerProc = $null } catch { }
    try { $script:waitUntil = $null } catch { }
    try { $script:winwsStartDeadline = $null } catch { }
    try { $script:startState = "Idle" } catch { }

    try { $statusLabel.Text = "Start failed: see logs" } catch { }
    try { Update-ToggleButton } catch { }

    $msg = "Strategy failed to start DGen.exe.`r`n`r`n" +
        "See Logs for stdout/stderr tail. Common reasons:`r`n" +
        "- DGen service is running (conflicts)`r`n" +
        "- missing admin rights / WinDivert driver problem`r`n" +
        "- antivirus / other bypass conflicts`r`n`r`n" +
        "Fix the cause and retry Start."
    try { [System.Windows.Forms.MessageBox]::Show($msg, "D-Gen", 'OK', 'Error') | Out-Null } catch { }
}

$script:quicRuleName = 'D-Gen QUIC Block UDP 443'

function Enable-QuicBlock {
    try {
        & netsh.exe advfirewall firewall delete rule name="$script:quicRuleName" | Out-Null

        & netsh.exe advfirewall firewall add rule name="$script:quicRuleName" dir=out action=block protocol=UDP remoteport=443 | Out-Null
        Write-Log 'QUIC: firewall rule enabled (blocking UDP remoteport 443)'
    } catch {
        Write-Log "QUIC: failed to enable firewall rule: $($_.Exception.Message)"
    }
}

function Disable-QuicBlock {
    try {
        & netsh.exe advfirewall firewall delete rule name="$script:quicRuleName" | Out-Null
        Write-Log 'QUIC: firewall rule disabled'
    } catch {
        Write-Log "QUIC: failed to disable firewall rule: $($_.Exception.Message)"
    }
}

function Get-ExceptionSummary {
    param(
        [Exception]$ex,
        [int]$maxLen = 260
    )

    if (-not $ex) { return "" }

    try {
        if ($ex -is [System.AggregateException]) {
            $flat = $ex.Flatten()
            $innerTexts = @()
            foreach ($inner in @($flat.InnerExceptions)) {
                if (-not $inner) { continue }
                $innerTexts += (Get-ExceptionSummary -ex $inner -maxLen $maxLen)
            }

            $txt = "AggregateException: " + (($innerTexts | Where-Object { $_ }) -join " || ")
            if ($txt.Length -gt $maxLen) { $txt = $txt.Substring(0, $maxLen) }
            return $txt
        }
    } catch { }

    $parts = @()
    $cur = $ex
    for ($i = 0; $i -lt 4 -and $cur; $i++) {
        $t = $cur.GetType().Name
        $m = [string]$cur.Message
        if ($m) { $parts += ("{0}: {1}" -f $t, $m) } else { $parts += $t }
        $cur = $cur.InnerException
    }

    $txt = ($parts -join " | ")
    if ($txt.Length -gt $maxLen) { $txt = $txt.Substring(0, $maxLen) }
    return $txt
}

function Test-HttpUrl {
    param(
        [string]$url,
        [int]$timeoutMs = 3000
    )

    $client = $null
    $resp = $null
    $sw = $null
    try {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromMilliseconds($timeoutMs)

        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        $t = $client.GetAsync($url)
        while (-not $t.IsCompleted) {
            try { [System.Windows.Forms.Application]::DoEvents() } catch { }
            Start-Sleep -Milliseconds 15

            if ($sw.ElapsedMilliseconds -ge $timeoutMs) {
                try { $client.CancelPendingRequests() } catch { }
                return [pscustomobject]@{ Ok = $false; StatusCode = 0; Error = ("timeout after {0}ms" -f $timeoutMs) }
            }
        }

        $resp = $t.GetAwaiter().GetResult()
        $code = [int]$resp.StatusCode

        return [pscustomobject]@{ Ok = $true; StatusCode = $code; Error = "" }
    } catch {
        $msg = Get-ExceptionSummary -ex $_.Exception
        return [pscustomobject]@{ Ok = $false; StatusCode = 0; Error = $msg }
    } finally {
        if ($resp) { try { $resp.Dispose() } catch { } }
        if ($client) { try { $client.Dispose() } catch { } }
    }
}

function Test-HttpUrlsParallel {
    param(
        [string[]]$Urls,
        [int]$timeoutMs = 3000
    )

    if (-not $Urls -or $Urls.Count -eq 0) { return @() }

    $handler = $null
    $client = $null
    $cts = $null
    $sw = $null

    try {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromMilliseconds($timeoutMs)

        $cts = New-Object System.Threading.CancellationTokenSource
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        $tasks = @{}
        foreach ($u in $Urls) {
            $tasks[$u] = $client.GetAsync($u, $cts.Token)
        }

        while ($true) {
            $allDone = $true
            foreach ($t in $tasks.Values) {
                if (-not $t.IsCompleted) { $allDone = $false; break }
            }
            if ($allDone) { break }

            try { [System.Windows.Forms.Application]::DoEvents() } catch { }
            Start-Sleep -Milliseconds 15

            if ($sw.ElapsedMilliseconds -ge $timeoutMs) {
                try { $cts.Cancel() } catch { }
                try { $client.CancelPendingRequests() } catch { }
                break
            }
        }

        $out = @()
        foreach ($u in $Urls) {
            $task = $tasks[$u]
            $resp = $null
            try {
                if ($task.IsCompleted -and (-not $task.IsFaulted) -and (-not $task.IsCanceled)) {
                    $resp = $task.GetAwaiter().GetResult()
                    $code = 0
                    try { $code = [int]$resp.StatusCode } catch { }
                    $out += [pscustomobject]@{ Ok = $true; StatusCode = $code; Error = ""; Url = $u }
                } else {
                    $err = ""
                    if ($task.IsCanceled -or ($sw.ElapsedMilliseconds -ge $timeoutMs)) {
                        $err = ("timeout after {0}ms" -f $timeoutMs)
                    } elseif ($task.IsFaulted -and $task.Exception) {
                        $err = Get-ExceptionSummary -ex $task.Exception
                    } else {
                        $err = "request failed"
                    }
                    $out += [pscustomobject]@{ Ok = $false; StatusCode = 0; Error = $err; Url = $u }
                }
            } catch {
                $msg = Get-ExceptionSummary -ex $_.Exception
                $out += [pscustomobject]@{ Ok = $false; StatusCode = 0; Error = $msg; Url = $u }
            } finally {
                if ($resp) { try { $resp.Dispose() } catch { } }
            }
        }

        return $out
    } finally {
        if ($cts) { try { $cts.Dispose() } catch { } }
        if ($client) { try { $client.Dispose() } catch { } }
        if ($handler) { try { $handler.Dispose() } catch { } }
    }
}

# D-Gen | https://t.me/DisappearGen






# D-Gen | https://t.me/DisappearGen




function Run-Generator {
    param(
        $cfg,
        [string]$runId
    )

    $script:generatorOutPath = $defaultGeneratorOutPath
    $script:generatorErrPath = $defaultGeneratorErrPath

    try {
        if (Test-Path -LiteralPath $script:generatorOutPath) {
            Copy-Item -Force -LiteralPath $script:generatorOutPath -Destination ($script:generatorOutPath + '.prev')
        }
    } catch { }
    try {
        if (Test-Path -LiteralPath $script:generatorErrPath) {
            Copy-Item -Force -LiteralPath $script:generatorErrPath -Destination ($script:generatorErrPath + '.prev')
        }
    } catch { }

    New-Item -ItemType File -Path $script:generatorOutPath -Force | Out-Null
    New-Item -ItemType File -Path $script:generatorErrPath -Force | Out-Null

    $gp = ([string]$generatorPath).Replace([string][char]34, '')
    $args = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", "`"$gp`"",
        "-Domains"
    )

    if ($cfg.domains) { $args += $cfg.domains }
    if ($cfg.targetDescription) {
        $td = ([string]$cfg.targetDescription).Replace([string][char]34, '')
        $args += @("-TargetDescription", "`"$td`"")
    }

    if ($cfg.enableRemote -and $cfg.apiKey) {
        $args += @("-EnableRemote", "-ApiKey", $cfg.apiKey)
        if ($cfg.baseUri) { $args += @("-BaseUri", $cfg.baseUri) }
    }

    Write-Log "Running generator: $powershellExe $($args -join ' ')"
    $proc = Start-Process -FilePath $powershellExe -ArgumentList $args -PassThru -WindowStyle Hidden -RedirectStandardOutput $script:generatorOutPath -RedirectStandardError $script:generatorErrPath
    return $proc
}

function Get-DiscordLogDir {
    $candidates = @(
        (Join-Path $env:APPDATA "discord\logs"),
        (Join-Path $env:APPDATA "Discord\logs"),
        (Join-Path $env:APPDATA "discordcanary\logs"),
        (Join-Path $env:APPDATA "discordptb\logs")
    )

    foreach ($p in $candidates) {
        if ($p -and (Test-Path $p)) { return $p }
    }

    return $null
}

function Get-DiscordHostsFromLogs {
    param([int]$tailLines = 2500)

    $logDir = Get-DiscordLogDir
    if (-not $logDir) { return @() }

    $files = @(Get-ChildItem -LiteralPath $logDir -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 6)
    if (-not $files -or $files.Count -eq 0) { return @() }

    $hosts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $rxUrl = [regex]"https?://([a-zA-Z0-9.-]+)"
    $rxDomain = [regex]'Domain\("([a-zA-Z0-9.-]+)"\)'

    foreach ($f in $files) {
        $lines = @()
        try { $lines = Get-Content -LiteralPath $f.FullName -Tail $tailLines -ErrorAction Stop } catch { continue }

        foreach ($line in $lines) {
            foreach ($m in $rxUrl.Matches($line)) {
                $h = $m.Groups[1].Value
                if ($h) { [void]$hosts.Add($h.ToLower().Trim()) }
            }
            foreach ($m in $rxDomain.Matches($line)) {
                $h = $m.Groups[1].Value
                if ($h) { [void]$hosts.Add($h.ToLower().Trim()) }
            }
        }
    }

    return @($hosts) |
        Where-Object { $_ -and $_.Contains('.') -and $_ -notmatch '^(localhost|127\.)' } |
        Sort-Object -Unique
}

function Add-UniqueLines {
    param(
        [string]$path,
        [string[]]$lines,
        [string]$encoding = "UTF8"
    )

    if (-not $lines -or $lines.Count -eq 0) { return 0 }
    if (-not (Test-Path $path)) { "" | Out-File -FilePath $path -Encoding $encoding }

    $existing = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($l in (Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {
        $t = $l.ToLower().Trim()
        if ($t) { [void]$existing.Add($t) }
    }

    $toAdd = @()
    foreach ($l in $lines) {
        $t = $l.ToLower().Trim()
        if (-not $t) { continue }
        if (-not $existing.Contains($t)) { $toAdd += $t }
    }

    if ($toAdd.Count -gt 0) {
        Add-Content -LiteralPath $path -Encoding $encoding -Value $toAdd
    }

    return $toAdd.Count
}

function Update-IpsetAllFromIps {
    param([string[]]$ips)

    if (-not $ips -or $ips.Count -eq 0) { return 0 }
    if (-not (Test-Path $ipsetAllPath)) { "" | Out-File -FilePath $ipsetAllPath -Encoding ASCII }

    $existing = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($l in (Get-Content -LiteralPath $ipsetAllPath -ErrorAction SilentlyContinue)) {
        $t = $l.Trim()
        if ($t) { [void]$existing.Add($t) }
    }

    $toAdd = [System.Collections.Generic.List[string]]::new()

    foreach ($raw in $ips) {
        $s = ([string]$raw).Trim()
        if (-not $s) { continue }

        $tmp = $null
        if (-not [System.Net.IPAddress]::TryParse($s, [ref]$tmp)) { continue }
        if (Test-IsPrivateOrLocalIp -ip $tmp) { continue }

        $cidr = if ($tmp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { "$($tmp.IPAddressToString)/32" } else { "$($tmp.IPAddressToString)/128" }
        if (-not $existing.Contains($cidr)) {
            [void]$existing.Add($cidr)
            $toAdd.Add($cidr) | Out-Null
        }
    }

    if ($toAdd.Count -gt 0) {
        Add-Content -LiteralPath $ipsetAllPath -Encoding ASCII -Value ($toAdd | Sort-Object -Unique)
    }

    return $toAdd.Count
}

function Update-IpsetAllFromHosts {
    param([string[]]$hosts)

    if (-not $hosts -or $hosts.Count -eq 0) { return 0 }
    if (-not (Test-Path $ipsetAllPath)) { "" | Out-File -FilePath $ipsetAllPath -Encoding ASCII }

    # Fix legacy bad CIDR lines produced by older launcher versions (IPv4 /128).
    try {
        $fileLines = @(Get-Content -LiteralPath $ipsetAllPath -ErrorAction SilentlyContinue)
        $needsFix = $false
        $fixedLines = foreach ($l in $fileLines) {
            $t = $l.Trim()
            if ($t -match '^\d{1,3}(?:\.\d{1,3}){3}/128$') {
                $needsFix = $true
                ($t -replace '/128$', '/32')
            } else {
                $l
            }
        }
        if ($needsFix) {
            Set-Content -LiteralPath $ipsetAllPath -Encoding ASCII -Value $fixedLines
        }
    } catch { }

    $existing = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($l in (Get-Content -LiteralPath $ipsetAllPath -ErrorAction SilentlyContinue)) {
        $t = $l.Trim()
        if ($t) { [void]$existing.Add($t) }
    }

    $toAdd = [System.Collections.Generic.List[string]]::new()

    foreach ($h in $hosts) {
        foreach ($type in @('A','AAAA')) {
            try {
                $res = Resolve-DnsName -Name $h -Type $type -ErrorAction Stop
            } catch { continue }

            foreach ($r in $res) {
                $ip = $r.IPAddress
                if (-not $ip) { continue }

                $tmp = $null
                if (-not [System.Net.IPAddress]::TryParse([string]$ip, [ref]$tmp)) { continue }
                if (Test-IsPrivateOrLocalIp -ip $tmp) { continue }

                $cidr = if ($tmp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { "$($tmp.IPAddressToString)/32" } else { "$($tmp.IPAddressToString)/128" }
                if (-not $existing.Contains($cidr)) {
                    [void]$existing.Add($cidr)
                    $toAdd.Add($cidr) | Out-Null
                }
            }
        }
    }

    if ($toAdd.Count -gt 0) {
        Add-Content -LiteralPath $ipsetAllPath -Encoding ASCII -Value ($toAdd | Sort-Object -Unique)
    }

    return $toAdd.Count
}

function SmartMode-UpdateDiscordLists {
    try {
        $hosts = @(Get-DiscordHostsFromLogs)
        if (-not $hosts -or $hosts.Count -eq 0) {
            Write-Log "Smart Mode: no discord hosts found in logs"
            return
        }

        $addedDomains = Add-UniqueLines -path $listGeneralPath -lines $hosts -encoding "UTF8"
        $addedIps = Update-IpsetAllFromHosts -hosts $hosts

        $sampleHosts = @($hosts | Select-Object -First 8) -join ','
        Write-Log ("Smart Mode: hostsFromLogs={0} addedDomains={1} addedIps={2} sample={3}" -f $hosts.Count, $addedDomains, $addedIps, $sampleHosts)
    } catch {
        Write-Log "Smart Mode error: $($_.Exception.Message)"
    }
}

function Get-StrategyFiles {
    $files = @(Get-ChildItem -Path $strategiesDir -Filter "general*.bat" -File)
    if (-not $files -or $files.Count -eq 0) { return @() }

    $manifestPath = Join-Path $strategiesDir 'manifest.json'
    $manifest = $null
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            Write-Log "Strategies: manifest loaded: $manifestPath"
        } catch {
            Write-Log "Strategies: manifest parse failed, falling back to filename order: $($_.Exception.Message)"
            $manifest = $null
        }
    }

    $defaultEnabled = $true
    $defaultPriority = 0
    if ($manifest -and $manifest.defaults) {
        try {
            if ($manifest.defaults.PSObject.Properties.Name -contains 'enabled') { $defaultEnabled = [bool]$manifest.defaults.enabled }
            if ($manifest.defaults.PSObject.Properties.Name -contains 'priority') { $defaultPriority = [int]$manifest.defaults.priority }
        } catch { }
    }

    $overrides = @{}
    if ($manifest -and $manifest.overrides) {
        foreach ($p in $manifest.overrides.PSObject.Properties) {
            $overrides[$p.Name] = $p.Value
        }
    }

    $manifestMeta = @{}

    $items = @()
    foreach ($f in $files) {
        $name = $f.Name
        $enabled = $defaultEnabled
        $priority = $defaultPriority
        $note = ''
        $tags = @()

        if ($overrides.ContainsKey($name)) {
            $o = $overrides[$name]
            try {
                if ($o.PSObject.Properties.Name -contains 'enabled') { $enabled = [bool]$o.enabled }
                if ($o.PSObject.Properties.Name -contains 'priority') { $priority = [int]$o.priority }
                if ($o.PSObject.Properties.Name -contains 'note') { $note = [string]$o.note }
                if ($o.PSObject.Properties.Name -contains 'tags' -and $o.tags) { $tags = @($o.tags | ForEach-Object { [string]$_ }) }
            } catch { }
        } else {
            try {
                if ($enabled -and (Select-String -LiteralPath $f.FullName -Pattern 'NOT RECOMMENDED' -SimpleMatch -Quiet)) {
                    $enabled = $false
                    $note = 'auto-disabled: NOT RECOMMENDED'
                }
            } catch { }
        }

        try {
            $manifestMeta[$name.ToLowerInvariant()] = [pscustomobject]@{ Priority = $priority; Tags = $tags }
        } catch { }

        $items += [pscustomobject]@{
            File = $f
            Name = $name
            Enabled = $enabled
            Priority = $priority
            Note = $note
        }
    }

    try { $script:strategyManifestMetaByName = $manifestMeta } catch { }

    $enabledItems = @($items | Where-Object { $_.Enabled })
    $disabledItems = @($items | Where-Object { -not $_.Enabled })
    if ($disabledItems.Count -gt 0) {
        if (-not $defaultEnabled) {
            Write-Log ("Strategies: enabled via manifest ({0}/{1}); others disabled by default" -f $enabledItems.Count, $items.Count)
        } else {
            $names = @($disabledItems | Select-Object -ExpandProperty Name)
            Write-Log ("Strategies: disabled ({0}/{1}): {2}" -f $disabledItems.Count, $items.Count, ($names -join ', '))
        }
    }

    return @(
        $enabledItems |
            Sort-Object @(
                @{ Expression = 'Priority'; Descending = $true },
                @{ Expression = 'Name'; Descending = $false }
            ) |
            Select-Object -ExpandProperty File
    )
}

$script:strategyFeatureMapByName = $null
$script:strategyFeatureMapWarned = $false

function Ensure-StrategyFeatureMapLoaded {
    if ($null -ne $script:strategyFeatureMapByName) { return }

    $script:strategyFeatureMapByName = @{}
    $path = Join-Path $logsDir 'strategy-feature-map.json'
    if (-not (Test-Path -LiteralPath $path)) { return }

    try {
        $text = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }

        $arr = $text | ConvertFrom-Json -ErrorAction Stop
        if (-not ($arr -is [System.Array])) { throw "expected JSON array" }

        $map = @{}
        foreach ($rec in $arr) {
            if (-not $rec) { continue }
            $n = $null
            try { $n = [string]$rec.Name } catch { $n = $null }
            if (-not $n) { continue }
            $map[$n.ToLowerInvariant()] = $rec
        }

        $script:strategyFeatureMapByName = $map
        Write-Log ("Strategies: feature-map loaded: {0} entries={1}" -f $path, $map.Count)
    } catch {
        $script:strategyFeatureMapByName = @{}
        if (-not $script:strategyFeatureMapWarned) {
            $script:strategyFeatureMapWarned = $true
            Write-Log ("Strategies: feature-map parse failed; falling back to name heuristics: {0}" -f $_.Exception.Message)
        }
    }
}





# D-Gen | https://t.me/DisappearGen
function Start-StrategyFile {
    param(
        [System.IO.FileInfo]$strategyFile,
        [int]$attemptIndex,
        [string]$runId
    )

    $attemptTag = ("{0:D4}" -f [int]$script:strategyAttemptSeq)
    $script:strategyAttemptSeq++

    # Consolidate logs: keep only a few stable files.
    $script:strategyOutPath = $defaultStrategyOutPath
    $script:strategyErrPath = $defaultStrategyErrPath

    try {
        if (Test-Path -LiteralPath $script:strategyOutPath) {
            $fi = Get-Item -LiteralPath $script:strategyOutPath -ErrorAction SilentlyContinue
            if ($fi -and $fi.Length -gt 0) {
                Copy-Item -Force -LiteralPath $script:strategyOutPath -Destination ($script:strategyOutPath + '.prev')
            }
        }
    } catch { }
    try {
        if (Test-Path -LiteralPath $script:strategyErrPath) {
            $fi = Get-Item -LiteralPath $script:strategyErrPath -ErrorAction SilentlyContinue
            if ($fi -and $fi.Length -gt 0) {
                Copy-Item -Force -LiteralPath $script:strategyErrPath -Destination ($script:strategyErrPath + '.prev')
            }
        }
    } catch { }

    New-Item -ItemType File -Path $script:strategyOutPath -Force | Out-Null
    New-Item -ItemType File -Path $script:strategyErrPath -Force | Out-Null

    Write-Log "Starting strategy: $($strategyFile.FullName) (try=$attemptTag)"
    $cmdExe = Join-Path $env:SystemRoot "System32\cmd.exe"
    $bat = "`"$($strategyFile.FullName)`""
    $cmdParts = @()
    if ($cfg -and ($cfg.PSObject.Properties.Name -contains 'aggressiveMode') -and ($cfg.aggressiveMode -eq $true)) {
        $cmdParts += 'set "AGGRESSIVE_MODE=1"'
    }
    if ($script:gameFilterOverride) {
        $cmdParts += ('set "GameFilter={0}"' -f [string]$script:gameFilterOverride)
        $cmdParts += 'set "DGEN_WF_UDP_WIDE=1"'
    }

    # Engine autopick support: pass network profile key so DGen.exe can persist last-good profile per network.
    $botKey = ''
    try { $botKey = Get-BotProfileKey } catch { $botKey = '' }
    if (-not $botKey) { $botKey = 'unknown' }
    $botKey = ([string]$botKey).Replace('"', '')
    $cmdParts += ('set "DGEN_NET_PROFILE={0}"' -f $botKey)

    $link = ''
    try { $link = [string]$script:networkLinkType } catch { $link = '' }
    if (-not $link) { $link = 'unknown' }
    $link = $link.Replace('"', '')
    $cmdParts += ('set "DGEN_LINK_TYPE={0}"' -f $link)

    $ifIndex = $null
    try { $ifIndex = $script:networkIfIndex } catch { $ifIndex = $null }
    if ($ifIndex -ne $null) {
        $cmdParts += ('set "DGEN_IF_INDEX={0}"' -f [string]$ifIndex)
    }

    $mtu = ''
    try { if ($script:networkMtu -ne $null) { $mtu = [string]$script:networkMtu } } catch { $mtu = '' }
    if ($mtu) {
        $mtu = $mtu.Replace('"', '')
        $cmdParts += ('set "DGEN_MTU={0}"' -f $mtu)
    }

    $cmdParts += 'set "DGEN_AUTOPICK_SAVE=1"'

    $cmdParts += 'set "DGEN_SKIP_UPDATE_CHECK=1"'
    if ($cmdParts.Count -gt 0) {
        $prefix = ($cmdParts -join ' && ')
        $cmdArgs = @('/c', "$prefix && $bat")
    } else {
        $cmdArgs = @('/c', $bat)
    }
    $proc = Start-Process -FilePath $cmdExe -ArgumentList $cmdArgs -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput $script:strategyOutPath -RedirectStandardError $script:strategyErrPath
    return $proc
}

function Remove-ServiceIfExists {
    param([string]$serviceName)

    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $svc) { return }

    Write-Log "Removing service: $serviceName (status=$($svc.Status))"

    try {
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -Force -ErrorAction Stop
        }
    } catch {
        Write-Log "Stop-Service failed for ${serviceName}: $($_.Exception.Message)"
    }

    try {
        & sc.exe delete $serviceName | Out-Null
    } catch {
        Write-Log "sc delete failed for ${serviceName}: $($_.Exception.Message)"
    }
}

function Stop-ServiceIfRunning {
    param(
        [string]$serviceName,
        [int]$waitMs = 4000
    )

    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $svc) { return $true }
    if ($svc.Status -ne 'Running') { return $true }

    try { Write-Log ("Service: stopping {0}..." -f $serviceName) } catch { }
    try { & sc.exe stop $serviceName | Out-Null } catch { }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $waitMs) {
        Start-Sleep -Milliseconds 150
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $svc) { return $true }
        if ($svc.Status -ne 'Running') { return $true }
    }

    try { Write-Log ("Service: {0} still running after {1}ms" -f $serviceName, $waitMs) } catch { }
    return $false
}

function Stop-WinDivertServices {
    param(
        [int]$waitMs = 4000
    )

    $ok = $true
    foreach ($name in @('WinDivert', 'WinDivert14')) {
        try {
            if (-not (Stop-ServiceIfRunning -serviceName $name -waitMs $waitMs)) { $ok = $false }
        } catch {
            $ok = $false
            try { Write-Log ("Service: stop failed for {0}: {1}" -f $name, $_.Exception.Message) } catch { }
        }
    }
    return $ok
}

function Stop-All {
    Write-Log "Stop requested"

    if ($script:generatorProc -and (-not $script:generatorProc.HasExited)) {
        try {
            Write-Log ("Stop-All: killing generatorProc pid={0}" -f $script:generatorProc.Id)
            Kill-ProcessTree -processId $script:generatorProc.Id
        } catch {
            Write-Log ("Stop-All: failed to kill generatorProc: {0}" -f $_.Exception.Message)
        }
    }
    if ($script:strategyRunnerProc -and (-not $script:strategyRunnerProc.HasExited)) {
        try {
            Write-Log ("Stop-All: killing strategyRunnerProc pid={0}" -f $script:strategyRunnerProc.Id)
            Kill-ProcessTree -processId $script:strategyRunnerProc.Id
        } catch {
            Write-Log ("Stop-All: failed to kill strategyRunnerProc: {0}" -f $_.Exception.Message)
        }
    }

    $script:generatorProc = $null
    $script:strategyRunnerProc = $null

    try {
        $pids = @(Get-Process -Name "DGen" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
        if ($pids -and $pids.Count -gt 0) { Write-Log ("Stop-All: DGen process count={0}" -f $pids.Count) }
    } catch { }

    Stop-Winws

    # Verify we didn't leave any DGen.exe behind (taskkill can race with process teardown on some systems).
    try {
        Start-Sleep -Milliseconds 200
        $pidsAfter = @(Get-Process -Name "DGen" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
        if ($pidsAfter -and $pidsAfter.Count -gt 0) {
            Write-Log ("Stop-All: DGen still running after stop; pidCount={0}" -f $pidsAfter.Count)
            foreach ($procId in $pidsAfter) {
                try { Kill-ProcessTree -processId $procId } catch { }
            }
        }
    } catch { }

    # Kill leftover console runners that might outlive the tracked Process objects (cmd/powershell).
    try {
        $rootPath = $root
        if ($rootPath) {
            $cmds = @()
            try {
                $cmds = @(Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine -like "*$rootPath\strategies\*" })
            } catch {
                $cmds = @()
            }
            foreach ($p in $cmds) {
                try { Kill-ProcessTree -processId ([int]$p.ProcessId) } catch { }
            }
            if ($cmds.Count -gt 0) { Write-Log ("Stop-All: killed leftover cmd.exe count={0}" -f $cmds.Count) }

            $ps = @()
            try {
                $ps = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine -like "*$rootPath\utils\*" })
            } catch {
                $ps = @()
            }
            foreach ($p in $ps) {
                try { Kill-ProcessTree -processId ([int]$p.ProcessId) } catch { }
            }
            if ($ps.Count -gt 0) { Write-Log ("Stop-All: killed leftover powershell.exe count={0}" -f $ps.Count) }
        }
    } catch { }

    Remove-ServiceIfExists -serviceName "DGen"
    # WinDivert* services may belong to other bypass tools; don't delete automatically on Stop.

    Stop-Winws

    # WinDivert driver services can linger after DGen exit; stop/wait so next Start doesn't see WinDivert=Running.
    try {
        $ok = Stop-WinDivertServices -waitMs 5000
        if (-not $ok) { Write-Log "Stop-All: WinDivert still running after stop; next Start may complain until it unloads." }
    } catch {
        Write-Log "Stop-All: WinDivert stop failed: $($_.Exception.Message)"
    }

    Restore-WindowsProxyIfNeeded
}

function Refresh-Views {
    if (-not $procList -or -not $serviceList) { return }

    $procList.Items.Clear()

    $procs = @()
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='DGen.exe'" | Select-Object ProcessId, ExecutablePath, CommandLine
    } catch {
        Write-Log "Failed to read Win32_Process: $($_.Exception.Message)"
    }

    foreach ($p in $procs) {
        $procId = [string]$p.ProcessId
        $exe = [string]$p.ExecutablePath
        $cmd = if ($null -ne $p.CommandLine) { [string]$p.CommandLine } else { "" }
        if ($cmd.Length -gt 140) { $cmd = $cmd.Substring(0, 140) + "..." }

        $item = New-Object System.Windows.Forms.ListViewItem($procId)
        $item.SubItems.Add($exe) | Out-Null
        $item.SubItems.Add($cmd) | Out-Null
        $procList.Items.Add($item) | Out-Null
    }

    try { $procList.GridLines = $false } catch { }
    if ($script:procEmptyLbl) {
        $empty = ($procList.Items.Count -eq 0)
        $script:procEmptyLbl.Visible = $empty
        $procList.Visible = -not $empty
        if ($empty) { try { $script:procEmptyLbl.BringToFront() } catch { } }
    }

    $serviceList.Items.Clear()
    foreach ($name in @("DGen", "WinDivert", "WinDivert14")) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        $status = if ($svc) { [string]$svc.Status } else { "Not installed" }

        $item = New-Object System.Windows.Forms.ListViewItem($name)
        $item.SubItems.Add($status) | Out-Null
        $serviceList.Items.Add($item) | Out-Null
    }

    try { $serviceList.GridLines = $false } catch { }
    if ($script:svcEmptyLbl) {
        $empty = ($serviceList.Items.Count -eq 0)
        $script:svcEmptyLbl.Visible = $empty
        $serviceList.Visible = -not $empty
        if ($empty) { try { $script:svcEmptyLbl.BringToFront() } catch { } }
    }

    if (-not $script:startState -or $script:startState -eq "Idle") {
        if (-not $script:isAdmin) {
            $statusLabel.Text = "Ready (debug: not elevated). DGen: $($procs.Count)"
        } else {
            $statusLabel.Text = "Ready. DGen processes: $($procs.Count)"
        }
    }

    try { Resize-StatusColumns } catch { }
}

function Refresh-Logs {
    # UX: while we're still starting (generator/autopick), keep the UI log view empty.
    # We'll show a clear READY marker and start updating logs only after capture is started.
    if ($script:startState -and $script:startState -ne "Idle" -and $script:startState -ne "Running") {
        return
    }

    if ($launcherLogBox -and (Can-OverwriteTextBox $launcherLogBox)) {
        $launcherText = Read-LogTail -path $script:activeLogPath
        $launcherText = Filter-LauncherLogForUi -text $launcherText
        if ($launcherLogBox.Text -ne $launcherText) { $launcherLogBox.Text = $launcherText }
    }

    if ($generatorLogBox -and (Can-OverwriteTextBox $generatorLogBox)) {
        $genOut = Read-LogTail -path $script:generatorOutPath
        $genErr = Read-LogTail -path $script:generatorErrPath
        $genText = $genOut
        if ($genErr) { $genText = $genText + "`r`n`r`n--- STDERR ---`r`n" + $genErr }
        if ($generatorLogBox.Text -ne $genText) { $generatorLogBox.Text = $genText }
    }

    if ($strategyLogBox -and (Can-OverwriteTextBox $strategyLogBox)) {
        $strOut = Read-LogTail -path $script:strategyOutPath
        $strErr = Read-LogTail -path $script:strategyErrPath
        $strText = $strOut
        if ($strErr) { $strText = $strText + "`r`n`r`n--- STDERR ---`r`n" + $strErr }
        if ($strategyLogBox.Text -ne $strText) { $strategyLogBox.Text = $strText }
    }
}

$uiBg = [System.Drawing.Color]::FromArgb(22, 22, 22)
$uiPanel = [System.Drawing.Color]::FromArgb(30, 30, 30)
$uiFg = [System.Drawing.Color]::Gainsboro
$uiMuted = [System.Drawing.Color]::FromArgb(160, 160, 160)
$uiAccent = [System.Drawing.Color]::FromArgb(0, 120, 215)
$uiStart = [System.Drawing.Color]::FromArgb(46, 204, 113)
$uiStop = [System.Drawing.Color]::FromArgb(231, 76, 60)

$form = New-Object System.Windows.Forms.Form
$form.Text = "D-Gen Launcher"
$form.Size = New-Object System.Drawing.Size(1040, 720)
$form.MinimumSize = New-Object System.Drawing.Size(900, 640)
$form.StartPosition = "CenterScreen"
$form.ShowInTaskbar = $true
$form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
$form.Topmost = $false
$form.BackColor = $uiBg
$form.ForeColor = $uiFg
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

$iconPath = Join-Path $root "utils\\Disappear_gen_windows_icon.ico"
try {
    if (Test-Path -LiteralPath $iconPath) {
        $script:launcherIcon = New-Object System.Drawing.Icon($iconPath)
        $form.Icon = $script:launcherIcon
    }
} catch { }

$rootLayout = New-Object System.Windows.Forms.TableLayoutPanel
$rootLayout.Dock = [System.Windows.Forms.DockStyle]::Fill
$rootLayout.BackColor = $uiBg
$rootLayout.ColumnCount = 1
$rootLayout.RowCount = 3
[void]$rootLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$rootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize, 0)))
[void]$rootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize, 0)))
[void]$rootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$form.Controls.Add($rootLayout)

$header = New-Object System.Windows.Forms.Panel
$header.Dock = [System.Windows.Forms.DockStyle]::Fill
$header.AutoSize = $true
$header.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$header.Height = 0
$header.BackColor = $uiPanel
$header.Padding = New-Object System.Windows.Forms.Padding(16, 10, 16, 10)
$rootLayout.Controls.Add($header, 0, 0)

$headerLayout = New-Object System.Windows.Forms.TableLayoutPanel
$headerLayout.Dock = [System.Windows.Forms.DockStyle]::Fill
$headerLayout.AutoSize = $true
$headerLayout.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$headerLayout.BackColor = $uiPanel
$headerLayout.ColumnCount = 2
$headerLayout.RowCount = 1
[void]$headerLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$headerLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize, 0)))
$header.Controls.Add($headerLayout)

$headerLeft = New-Object System.Windows.Forms.FlowLayoutPanel
$headerLeft.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
$headerLeft.WrapContents = $false
$headerLeft.AutoSize = $true
$headerLeft.Dock = [System.Windows.Forms.DockStyle]::Fill
$headerLeft.BackColor = $uiPanel
[void]$headerLayout.Controls.Add($headerLeft, 0, 0)

$titleLbl = New-Object System.Windows.Forms.Label
$titleLbl.Text = "D-Gen"
$titleLbl.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 22)
$titleLbl.ForeColor = $uiFg
$titleLbl.AutoSize = $true
[void]$headerLeft.Controls.Add($titleLbl)

$subtitleLbl = New-Object System.Windows.Forms.Label
$subtitleLbl.Text = "Disappear Gen"
$subtitleLbl.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$subtitleLbl.ForeColor = $uiMuted
$subtitleLbl.AutoSize = $true
[void]$headerLeft.Controls.Add($subtitleLbl)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$statusLabel.ForeColor = $uiMuted
$statusLabel.AutoSize = $false
$statusLabel.AutoEllipsis = $true
$statusLabel.Size = New-Object System.Drawing.Size(620, 22)
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
[void]$headerLeft.Controls.Add($statusLabel)

$headerRight = New-Object System.Windows.Forms.TableLayoutPanel
$headerRight.AutoSize = $true
$headerRight.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$headerRight.Dock = [System.Windows.Forms.DockStyle]::Right
$headerRight.BackColor = $uiPanel
$headerRight.ColumnCount = 1
$headerRight.RowCount = 2
[void]$headerRight.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize, 0)))
[void]$headerRight.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 48)))
[void]$headerRight.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize, 0)))
[void]$headerLayout.Controls.Add($headerRight, 1, 0)

$toggleBtn = New-Object System.Windows.Forms.Button
$toggleBtn.Text = "Start"
$toggleBtn.Size = New-Object System.Drawing.Size(170, 42)
$toggleBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$toggleBtn.FlatAppearance.BorderSize = 0
$toggleBtn.BackColor = $uiStart
$toggleBtn.ForeColor = [System.Drawing.Color]::White
$toggleBtn.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 12)
$toggleBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$toggleBtn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
[void]$headerRight.Controls.Add($toggleBtn, 0, 0)

$script:headerNav = New-Object System.Windows.Forms.FlowLayoutPanel
$script:headerNav.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$script:headerNav.WrapContents = $false
$script:headerNav.AutoSize = $true
$script:headerNav.Dock = [System.Windows.Forms.DockStyle]::None
$script:headerNav.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$script:headerNav.BackColor = $uiPanel
[void]$headerRight.Controls.Add($script:headerNav, 0, 1)

$advancedBtn = New-Object System.Windows.Forms.Button
$advancedBtn.Text = "Advanced"
$advancedBtn.Size = New-Object System.Drawing.Size(110, 30)
$advancedBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$advancedBtn.FlatAppearance.BorderSize = 0
$advancedBtn.BackColor = $uiPanel
$advancedBtn.ForeColor = $uiMuted
$advancedBtn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)

$clearLogsHeaderBtn = New-Object System.Windows.Forms.Button
$clearLogsHeaderBtn.Text = "Clear logs"
$clearLogsHeaderBtn.Size = New-Object System.Drawing.Size(110, 30)
$clearLogsHeaderBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$clearLogsHeaderBtn.FlatAppearance.BorderSize = 0
$clearLogsHeaderBtn.BackColor = $uiPanel
$clearLogsHeaderBtn.ForeColor = $uiMuted
$clearLogsHeaderBtn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
$clearLogsHeaderBtn.Add_Click({ Invoke-DeleteLogsUI })

$reportHeaderBtn = New-Object System.Windows.Forms.Button
$reportHeaderBtn.Text = "Report"
$reportHeaderBtn.Size = New-Object System.Drawing.Size(90, 30)
$reportHeaderBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$reportHeaderBtn.FlatAppearance.BorderSize = 0
$reportHeaderBtn.BackColor = $uiPanel
$reportHeaderBtn.ForeColor = $uiMuted
$reportHeaderBtn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
$reportHeaderBtn.Add_Click({ Invoke-ExportReportUI })

$closeBtn = New-Object System.Windows.Forms.Button
$closeBtn.Text = "Close"
$closeBtn.Size = New-Object System.Drawing.Size(90, 30)
$closeBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$closeBtn.FlatAppearance.BorderSize = 0
$closeBtn.BackColor = $uiPanel
$closeBtn.ForeColor = $uiMuted
$closeBtn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)

[void]$script:headerNav.Controls.Add($advancedBtn)
[void]$script:headerNav.Controls.Add($clearLogsHeaderBtn)
[void]$script:headerNav.Controls.Add($reportHeaderBtn)
[void]$script:headerNav.Controls.Add($closeBtn)

$optionsPanel = New-Object System.Windows.Forms.Panel
$optionsPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$optionsPanel.AutoSize = $true
$optionsPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$optionsPanel.BackColor = $uiPanel
$optionsPanel.Visible = $false
$rootLayout.Controls.Add($optionsPanel, 0, 1)

$optsTable = New-Object System.Windows.Forms.TableLayoutPanel
$optsTable.Dock = [System.Windows.Forms.DockStyle]::Fill
$optsTable.AutoSize = $true
$optsTable.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$optsTable.BackColor = $uiPanel
$optsTable.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 8)
$optsTable.ColumnCount = 1
$optsTable.RowCount = 0
[void]$optsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$optionsPanel.Controls.Add($optsTable)

function Add-OptRow($ctl) {
    $r = $optsTable.RowCount
    $optsTable.RowCount = $r + 1
    [void]$optsTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize, 0)))
    $optsTable.Controls.Add($ctl, 0, $r) | Out-Null
}

function Style-CheckBox($cb) {
    $cb.AutoSize = $true
    $cb.ForeColor = $uiFg
    $cb.BackColor = $uiPanel
    $cb.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
}

$smartModeChk = New-Object System.Windows.Forms.CheckBox
$smartModeChk.Text = "Smart Mode (Discord)"
$smartModeChk.Checked = $true
Style-CheckBox $smartModeChk
Add-OptRow $smartModeChk

$aggressiveModeChk = New-Object System.Windows.Forms.CheckBox
$aggressiveModeChk.Text = "Aggressive Mode"
$aggressiveModeChk.Checked = $false
try {
    if ($cfg -and ($cfg.PSObject.Properties.Name -contains 'aggressiveMode')) {
        $aggressiveModeChk.Checked = [bool]$cfg.aggressiveMode
    } elseif ($cfg) {
        $cfg | Add-Member -NotePropertyName aggressiveMode -NotePropertyValue $false -Force
        Save-Config $cfg
    }
} catch { }
Style-CheckBox $aggressiveModeChk
Add-OptRow $aggressiveModeChk

$aggressiveModeChk.Add_CheckedChanged({
    try {
        if (-not $cfg) { return }
        if ($cfg.PSObject.Properties.Name -contains 'aggressiveMode') {
            $cfg.aggressiveMode = [bool]$aggressiveModeChk.Checked
        } else {
            $cfg | Add-Member -NotePropertyName aggressiveMode -NotePropertyValue ([bool]$aggressiveModeChk.Checked) -Force
        }

        if ([bool]$cfg.aggressiveMode) {
            Write-Log "Aggressive Mode: enabled via UI checkbox."
        } else {
            Write-Log "Aggressive Mode: disabled via UI checkbox."
        }

        Save-Config $cfg
    } catch {
        Write-Log "Aggressive Mode: failed to toggle: $($_.Exception.Message)"
    }
})

$quicBlockChk = New-Object System.Windows.Forms.CheckBox
$quicBlockChk.Text = "Block QUIC (UDP 443)"
$quicBlockChk.Checked = $false
Style-CheckBox $quicBlockChk
Add-OptRow $quicBlockChk

$quicBlockChk.Add_CheckedChanged({
    try {
        if ($quicBlockChk.Checked) {
            Write-Log 'QUIC: enabled via UI checkbox'
            if ($script:startState -and $script:startState -ne 'Idle') { Enable-QuicBlock }
        } else {
            Write-Log 'QUIC: disabled via UI checkbox'
            if ($script:startState -and $script:startState -ne 'Idle') { Disable-QuicBlock }
        }
    } catch {
        Write-Log "QUIC: toggle failed: $($_.Exception.Message)"
    }
})

$proxyFixChk = New-Object System.Windows.Forms.CheckBox
$proxyFixChk.Text = "Disable Windows Proxy/PAC`r`n(restore on Stop)"
$proxyFixChk.Checked = $false
Style-CheckBox $proxyFixChk
Add-OptRow $proxyFixChk

$clearCacheBtn = New-Object System.Windows.Forms.Button
$clearCacheBtn.Text = "Clear Discord cache"
$clearCacheBtn.Size = New-Object System.Drawing.Size(170, 30)
$clearCacheBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$clearCacheBtn.FlatAppearance.BorderSize = 0
$clearCacheBtn.BackColor = $uiPanel
$clearCacheBtn.ForeColor = $uiFg
try { $clearCacheBtn.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 0) } catch { }
Add-OptRow $clearCacheBtn

$clearCacheBtn.Add_Click({
    try { Clear-DiscordCache } catch { }
})

try {
    $px = Get-UserProxySettings
    $ep = $null
    $kind = ''

    if ($px.ProxyEnable -eq 1) {
        $ep = Get-LoopbackProxyEndpoint -proxyServer $px.ProxyServer
        if ($ep) { $kind = 'proxy' }
    }

    if (-not $ep -and -not [string]::IsNullOrWhiteSpace($px.AutoConfigURL)) {
        $pac = Get-LoopbackPacEndpoint -autoConfigUrl $px.AutoConfigURL
        if ($pac) { $ep = $pac; $kind = 'pac' }
    }

    if ($ep) {
        $probe = Test-TcpConnect -hostName $ep.Host -port $ep.Port -timeoutMs 500
        if (-not $probe.Ok) {
            $proxyFixChk.Checked = $true
            $extra = if ($kind -eq 'pac') { " url=$($px.AutoConfigURL)" } else { '' }
            Write-Log ("Proxy: loopback {0} enabled but not reachable ({1}:{2}); pre-checking Disable Windows Proxy option{3}" -f $kind, $ep.Host, $ep.Port, $extra)
        }
    }
} catch { }

$advancedBtn.Add_Click({
    $optionsPanel.Visible = -not $optionsPanel.Visible
    $advancedBtn.ForeColor = if ($optionsPanel.Visible) { $uiAccent } else { $uiMuted }
    try { $form.PerformLayout() } catch { }
})

$logsTab = New-Object System.Windows.Forms.Panel
$logsTab.Dock = [System.Windows.Forms.DockStyle]::Fill
$logsTab.BackColor = $uiBg
$logsTab.ForeColor = $uiFg
$rootLayout.Controls.Add($logsTab, 0, 2)

$quickGroup = New-Object System.Windows.Forms.GroupBox
$quickGroup.Text = "Quick Start"
$quickGroup.Dock = [System.Windows.Forms.DockStyle]::Top
$quickGroup.Height = 110
$quickGroup.BackColor = $uiBg
$quickGroup.ForeColor = $uiFg
$quickGroup.Visible = $false

$quickText = New-Object System.Windows.Forms.Label
$quickText.Text = "1) Click Start`r`n2) Open Discord Desktop`r`n3) If something breaks, open Logs or Copy diagnostics"
$quickText.AutoSize = $false
$quickText.Size = New-Object System.Drawing.Size(560, 70)
$quickText.Location = New-Object System.Drawing.Point(12, 26)
$quickText.ForeColor = $uiFg
$quickGroup.Controls.Add($quickText)

$openLogsBtn = New-Object System.Windows.Forms.Button
$openLogsBtn.Text = "Logs folder"
$openLogsBtn.Size = New-Object System.Drawing.Size(110, 28)
$openLogsBtn.Location = New-Object System.Drawing.Point(12, 6)
$openLogsBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$openLogsBtn.FlatAppearance.BorderSize = 0
$openLogsBtn.BackColor = $uiPanel
$openLogsBtn.ForeColor = $uiFg

$copyDiagBtn = New-Object System.Windows.Forms.Button
$copyDiagBtn.Text = "Copy diagnostics"
$copyDiagBtn.Size = New-Object System.Drawing.Size(140, 28)
$copyDiagBtn.Location = New-Object System.Drawing.Point(138, 6)
$copyDiagBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$copyDiagBtn.FlatAppearance.BorderSize = 0
$copyDiagBtn.BackColor = $uiPanel
$copyDiagBtn.ForeColor = $uiFg

$script:procEmptyLbl = New-Object System.Windows.Forms.Label
$script:procEmptyLbl.Text = "No processes yet. Click Start."
$script:procEmptyLbl.Dock = [System.Windows.Forms.DockStyle]::Fill
$script:procEmptyLbl.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$script:procEmptyLbl.ForeColor = $uiMuted
$script:procEmptyLbl.BackColor = [System.Drawing.Color]::FromArgb(28, 28, 28)

$script:svcEmptyLbl = New-Object System.Windows.Forms.Label
$script:svcEmptyLbl.Text = "No services found."
$script:svcEmptyLbl.Dock = [System.Windows.Forms.DockStyle]::Fill
$script:svcEmptyLbl.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$script:svcEmptyLbl.ForeColor = $uiMuted
$script:svcEmptyLbl.BackColor = [System.Drawing.Color]::FromArgb(28, 28, 28)

$openLogsBtn.Add_Click({
    try { Start-Process -FilePath explorer.exe -ArgumentList $logsDir } catch { }
})

function Get-DiagnosticsText {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("D-Gen diagnostics") | Out-Null
    $lines.Add("Time: " + (Get-Date -Format o)) | Out-Null
    $lines.Add("State: " + [string]$script:startState) | Out-Null
    if ($script:currentStrategyFile) { $lines.Add("Strategy: " + $script:currentStrategyFile.FullName) | Out-Null }
    $lines.Add("SmartMode: " + [string]$smartModeChk.Checked) | Out-Null
    $lines.Add("AggressiveMode: " + [string]$aggressiveModeChk.Checked) | Out-Null
    if ($script:gameFilterOverride) { $lines.Add("GameFilterOverride: " + [string]$script:gameFilterOverride) | Out-Null }
    if ($script:lastRobloxIngestion) {
        $ri = $script:lastRobloxIngestion
        try {
            $lines.Add(("RobloxIngestion: hostsFound={0} ipsFound={1} addedDomains={2} addedIps={3}" -f $ri.HostsFound, $ri.IpsFound, $ri.AddedDomains, $ri.AddedIps)) | Out-Null
            if ($ri.Sample) { $lines.Add(("RobloxSample: " + [string]$ri.Sample)) | Out-Null }
        } catch { }
    }
    $lines.Add("DisableProxy: " + [string]$proxyFixChk.Checked) | Out-Null
    if ($script:lastBlockType) { $lines.Add("LastBlockType: " + [string]$script:lastBlockType) | Out-Null }
    try {
        $proxy = Get-UserProxySettings
        $lines.Add(("WindowsProxy: enable={0} server={1} pac={2} autodetect={3}" -f $proxy.ProxyEnable, $proxy.ProxyServer, $proxy.AutoConfigURL, $proxy.AutoDetect)) | Out-Null
    } catch { }
    $lines.Add("LogsDir: " + $logsDir) | Out-Null
    return ($lines -join "`r`n")
}

$copyDiagBtn.Add_Click({
    try {
        [System.Windows.Forms.Clipboard]::SetText((Get-DiagnosticsText))
        $statusLabel.Text = "Diagnostics copied to clipboard"
    } catch {
        $statusLabel.Text = "Copy failed"
    }
})

$script:logsHost = $logsTab

$script:loadingOverlayText = "Starting..."
$script:loadingPhase = 0
$script:loadingOverlayPercent = 0

$script:loadingOverlay = New-Object System.Windows.Forms.Panel
$script:loadingOverlay.Dock = [System.Windows.Forms.DockStyle]::Fill
$script:loadingOverlay.Visible = $false
$script:loadingOverlay.BackColor = $uiBg
try { $script:loadingOverlay.Margin = New-Object System.Windows.Forms.Padding(0) } catch { }
try { $logsTab.Controls.Add($script:loadingOverlay) } catch { }
try { $script:loadingOverlay.BringToFront() } catch { }

try {
    $p = $script:loadingOverlay.GetType().GetProperty('DoubleBuffered', ([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic))
    if ($p) { $p.SetValue($script:loadingOverlay, $true, $null) }
} catch { }

$script:loadingFontTitle = New-Object System.Drawing.Font("Segoe UI Semibold", 16)
$script:loadingFontStage = New-Object System.Drawing.Font("Segoe UI", 10)
$script:loadingBrushVeil = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(235, 10, 10, 10))
$script:loadingBrushText = New-Object System.Drawing.SolidBrush($uiFg)
$script:loadingBrushMuted = New-Object System.Drawing.SolidBrush($uiMuted)

$script:loadingAccent = [System.Drawing.Color]::FromArgb(255, 88, 166, 255)
$script:loadingBrushGlow1 = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(18, $script:loadingAccent.R, $script:loadingAccent.G, $script:loadingAccent.B))
$script:loadingBrushGlow2 = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(12, 255, 255, 255))

try {
    $c = $uiPanel
    $script:loadingBrushCardBg = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(238, $c.R, $c.G, $c.B))
} catch {
    $script:loadingBrushCardBg = New-Object System.Drawing.SolidBrush($uiPanel)
}
$script:loadingBrushShadow = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(90, 0, 0, 0))
$script:loadingPenCardBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(60, 255, 255, 255), 1)

$script:loadingBrushBarBg = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 34, 34, 34))
$script:loadingPenBarBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(70, 255, 255, 255), 1)

$script:loadingBrushProgress = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(80, $script:loadingAccent.R, $script:loadingAccent.G, $script:loadingAccent.B))

$script:loadingBrushDevil = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(120, 230, 77, 77))
$script:loadingPenDevil = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(170, 255, 190, 190), 2)

$script:loadingPenFork = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 20, 20, 20), 2)
$script:loadingPenForkGlow = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(120, 230, 80, 80), 4)
try { $script:loadingPenFork.StartCap = [System.Drawing.Drawing2D.LineCap]::Round; $script:loadingPenFork.EndCap = [System.Drawing.Drawing2D.LineCap]::Round } catch { }
try { $script:loadingPenForkGlow.StartCap = [System.Drawing.Drawing2D.LineCap]::Round; $script:loadingPenForkGlow.EndCap = [System.Drawing.Drawing2D.LineCap]::Round } catch { }

$script:loadingTimer = New-Object System.Windows.Forms.Timer
$script:loadingTimer.Interval = 40
$script:loadingTimer.Add_Tick({
    try {
        $script:loadingPhase = $script:loadingPhase + 1
        if ($script:loadingPhase -gt 1000000) { $script:loadingPhase = 0 }
        if ($script:loadingOverlay -and $script:loadingOverlay.Visible) { $script:loadingOverlay.Invalidate() }
    } catch { }
})

$script:loadingOverlay.Add_Paint({
    param($sender, $e)
    try {
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

        $w = $script:loadingOverlay.ClientSize.Width
        $h = $script:loadingOverlay.ClientSize.Height
        if ($w -lt 10 -or $h -lt 10) { return }

        $g.FillRectangle($script:loadingBrushVeil, 0, 0, $w, $h)

        $spin = $script:loadingPhase * 6
        $gx1 = (($spin) % ($w + 480)) - 240
        $gy1 = [int]($h * 0.20) - 200
        $g.FillEllipse($script:loadingBrushGlow1, $gx1, $gy1, 480, 480)
        $gx2 = (($spin + 600) % ($w + 560)) - 280
        $gy2 = [int]($h * 0.70) - 260
        $g.FillEllipse($script:loadingBrushGlow2, $gx2, $gy2, 560, 560)

        $cardW = [Math]::Min(560, [Math]::Max(360, [int]($w * 0.62)))
        $cardH = 170
        $cardX = [int](($w - $cardW) / 2)
        $cardY = [int](($h - $cardH) / 2)
        $r = 18
        $d = $r * 2

        try {
            $devW = [Math]::Max(56, [int]($cardH * 0.38))
            $devH = $devW
            $trackW = $cardW + $devW + 120
            $devX = ($cardX - $devW - 40) + (($script:loadingPhase * 6) % $trackW)
            $devY = $cardY + [int]($cardH * 0.58)

            $s = [Math]::Sin($script:loadingPhase * 0.25)
            $legDx = [int](6 * $s)

            $headR = [int]($devW * 0.18)
            $headCx = [int]($devX + ($devW * 0.55))
            $headCy = [int]($devY + ($devH * 0.22))

            $g.FillEllipse($script:loadingBrushDevil, $headCx - $headR, $headCy - $headR, $headR * 2, $headR * 2)

            $g.DrawLine($script:loadingPenDevil, $headCx - 6, $headCy - $headR, $headCx - 14, $headCy - $headR - 10)
            $g.DrawLine($script:loadingPenDevil, $headCx + 6, $headCy - $headR, $headCx + 14, $headCy - $headR - 10)

            $neckY = $headCy + $headR
            $hipY = [int]($devY + ($devH * 0.62))
            $g.DrawLine($script:loadingPenDevil, $headCx, $neckY, $headCx, $hipY)

            $armY = [int]($devY + ($devH * 0.40))
            $armDx = [int](-4 * $s)
            $armDy = [int](2 * $s)

            # Right arm (pitchfork)
            $handX = $headCx + 18 + $armDx
            $handY = $armY + 6 + $armDy
            $g.DrawLine($script:loadingPenDevil, $headCx, $armY, $handX, $handY)

            # Left arm (free hand)
            $freeHandX = $headCx - 18 - $armDx
            $freeHandY = $armY + 6 - $armDy
            $g.DrawLine($script:loadingPenDevil, $headCx, $armY, $freeHandX, $freeHandY)
            try {
                $g.FillEllipse($script:loadingBrushDevil, ($freeHandX - 2), ($freeHandY - 2), 4, 4)
                $g.DrawEllipse($script:loadingPenDevil, ($freeHandX - 2), ($freeHandY - 2), 4, 4)
            } catch { }

            try {
                $forkX = $handX + 2
                $forkBottomY = [int]($devY + $devH)
                $forkTopY = $headCy - $headR - 10

                $sp = 6
                $pr = 14
                $crossY = $forkTopY

                if ($script:loadingPenForkGlow) {
                    $g.DrawLine($script:loadingPenForkGlow, $forkX, $forkBottomY, $forkX, $crossY)
                    $g.DrawLine($script:loadingPenForkGlow, ($forkX - $sp - 1), $crossY, ($forkX + $sp + 1), $crossY)
                    $g.DrawLine($script:loadingPenForkGlow, ($forkX - $sp), $crossY, ($forkX - $sp), ($crossY - $pr))
                    $g.DrawLine($script:loadingPenForkGlow, $forkX, $crossY, $forkX, ($crossY - ($pr + 4)))
                    $g.DrawLine($script:loadingPenForkGlow, ($forkX + $sp), $crossY, ($forkX + $sp), ($crossY - $pr))
                }

                if ($script:loadingPenFork) {
                    $g.DrawLine($script:loadingPenFork, $forkX, $forkBottomY, $forkX, $crossY)
                    $g.DrawLine($script:loadingPenFork, ($forkX - $sp - 1), $crossY, ($forkX + $sp + 1), $crossY)
                    $g.DrawLine($script:loadingPenFork, ($forkX - $sp), $crossY, ($forkX - $sp), ($crossY - $pr))
                    $g.DrawLine($script:loadingPenFork, $forkX, $crossY, $forkX, ($crossY - ($pr + 4)))
                    $g.DrawLine($script:loadingPenFork, ($forkX + $sp), $crossY, ($forkX + $sp), ($crossY - $pr))
                }
            } catch { }

            # Tail (behind the body): curve anchored at hip, sways slightly with the gait.
            try {
                $tailBaseX = [single]($headCx - 2)
                $tailBaseY = [single]($hipY - 2)
                $tailMidX = [single]($headCx - 16 - [int]($armDx / 2))
                $tailMidY = [single]($hipY + 6)
                $tailTipX = [single]($headCx - 34 - $armDx)
                $tailTipY = [single]($hipY - 10)

                $pts = @(
                    (New-Object System.Drawing.PointF($tailBaseX, $tailBaseY)),
                    (New-Object System.Drawing.PointF($tailMidX, $tailMidY)),
                    (New-Object System.Drawing.PointF($tailTipX, $tailTipY))
                )

                $g.DrawCurve($script:loadingPenDevil, $pts)
            } catch { }

            $groundY = [int]($devY + $devH)
            $g.DrawLine($script:loadingPenDevil, $headCx, $hipY, $headCx - 10 - $legDx, $groundY)
            $g.DrawLine($script:loadingPenDevil, $headCx, $hipY, $headCx + 4 + $legDx, $groundY)
        } catch { }

        $shadowPath = $null
        $cardPath = $null
        try {
            $shadowPath = New-Object System.Drawing.Drawing2D.GraphicsPath
            $shadowPath.AddArc($cardX, ($cardY + 6), $d, $d, 180, 90)
            $shadowPath.AddArc(($cardX + $cardW - $d), ($cardY + 6), $d, $d, 270, 90)
            $shadowPath.AddArc(($cardX + $cardW - $d), ($cardY + 6 + $cardH - $d), $d, $d, 0, 90)
            $shadowPath.AddArc($cardX, ($cardY + 6 + $cardH - $d), $d, $d, 90, 90)
            $shadowPath.CloseFigure()
            $g.FillPath($script:loadingBrushShadow, $shadowPath)
        } catch { }

        try {
            $cardPath = New-Object System.Drawing.Drawing2D.GraphicsPath
            $cardPath.AddArc($cardX, $cardY, $d, $d, 180, 90)
            $cardPath.AddArc(($cardX + $cardW - $d), $cardY, $d, $d, 270, 90)
            $cardPath.AddArc(($cardX + $cardW - $d), ($cardY + $cardH - $d), $d, $d, 0, 90)
            $cardPath.AddArc($cardX, ($cardY + $cardH - $d), $d, $d, 90, 90)
            $cardPath.CloseFigure()

            $g.FillPath($script:loadingBrushCardBg, $cardPath)
            $g.DrawPath($script:loadingPenCardBorder, $cardPath)
        } catch { }

        try { if ($shadowPath) { $shadowPath.Dispose() } } catch { }
        try { if ($cardPath) { $cardPath.Dispose() } } catch { }

        $g.DrawString("Loading", $script:loadingFontTitle, $script:loadingBrushText, ($cardX + 24), ($cardY + 18))
        $stage = $script:loadingOverlayText
        if ($stage) { $g.DrawString($stage, $script:loadingFontStage, $script:loadingBrushMuted, ($cardX + 26), ($cardY + 52)) }

        $pct = 0
        try { $pct = [int]$script:loadingOverlayPercent } catch { $pct = 0 }
        if ($pct -lt 0) { $pct = 0 }
        if ($pct -gt 100) { $pct = 100 }
        try { $g.DrawString(("{0}%" -f $pct), $script:loadingFontStage, $script:loadingBrushMuted, ($cardX + $cardW - 64), ($cardY + 26)) } catch { }

        $barX = $cardX + 24
        $barW = $cardW - 48
        $barH = 10
        $barY = $cardY + $cardH - 38

        $g.FillRectangle($script:loadingBrushBarBg, $barX, $barY, $barW, $barH)
        $g.DrawRectangle($script:loadingPenBarBorder, $barX, $barY, $barW, $barH)

        $fillW = [int]([Math]::Floor(($barW * $pct) / 100.0))
        if ($fillW -gt 0) { $g.FillRectangle($script:loadingBrushProgress, $barX, $barY, $fillW, $barH) }

        $hlW = [int]([Math]::Max(70, [int]($barW * 0.35)))
        $hlX = (($script:loadingPhase * 14) % ($barW + $hlW)) - $hlW
        $highlight = New-Object System.Drawing.Rectangle(($barX + $hlX), $barY, $hlW, $barH)
        $brush = $null
        try {
            $c0 = [System.Drawing.Color]::FromArgb(0, $script:loadingAccent.R, $script:loadingAccent.G, $script:loadingAccent.B)
            $c1 = [System.Drawing.Color]::FromArgb(170, $script:loadingAccent.R, $script:loadingAccent.G, $script:loadingAccent.B)

            $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($highlight, $c0, $c0, 0.0)
            $cb = New-Object System.Drawing.Drawing2D.ColorBlend
            $cb.Colors = @($c0, $c1, $c0)
            $cb.Positions = @(0.0, 0.5, 1.0)
            $brush.InterpolationColors = $cb

            $g.FillRectangle($brush, $highlight)
        } catch { }
        try { if ($brush) { $brush.Dispose() } } catch { }
    } catch { }
})

$launcherLogBox = New-Object System.Windows.Forms.TextBox
$launcherLogBox.Multiline = $true
$launcherLogBox.ReadOnly = $true
$launcherLogBox.ScrollBars = "Both"
$launcherLogBox.WordWrap = $false
$launcherLogBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$launcherLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$launcherLogBox.BackColor = $uiBg
$launcherLogBox.ForeColor = $uiFg
$launcherLogBox.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$launcherLogBox.Visible = $true
$script:logsHost.Controls.Add($launcherLogBox)

$generatorLogBox = New-Object System.Windows.Forms.TextBox
$generatorLogBox.Multiline = $true
$generatorLogBox.ReadOnly = $true
$generatorLogBox.ScrollBars = "Both"
$generatorLogBox.WordWrap = $false
$generatorLogBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$generatorLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$generatorLogBox.BackColor = $uiBg
$generatorLogBox.ForeColor = $uiFg
$generatorLogBox.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$generatorLogBox.Visible = $false

$strategyLogBox = New-Object System.Windows.Forms.TextBox
$strategyLogBox.Multiline = $true
$strategyLogBox.ReadOnly = $true
$strategyLogBox.ScrollBars = "Both"
$strategyLogBox.WordWrap = $false
$strategyLogBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$strategyLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$strategyLogBox.BackColor = $uiBg
$strategyLogBox.ForeColor = $uiFg
$strategyLogBox.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$strategyLogBox.Visible = $false

$script:startState = "Idle"
$script:uiBusy = $false
$script:runId = $null
$script:networkProfileKey = ''
$script:networkLinkType = ''

# Manual start sequence (increments only on user Start click).
# Used to prevent auto-retry loops across internal restarts.
$script:manualStartSeq = 0

# Roblox auto-retry: allow at most one internal restart per manual Start.
$script:robloxAutoRetryRestartCount = 0

# WiFi auto-rotate: allow at most one internal restart per manual Start.
$script:wifiAutoRotateRestartCount = 0
$script:generatorOutPath = $defaultGeneratorOutPath
$script:generatorErrPath = $defaultGeneratorErrPath
$script:strategyOutPath = $defaultStrategyOutPath
$script:strategyErrPath = $defaultStrategyErrPath

# Roblox auto-retry (fast, non-blocking): after Start, watch Roblox logs briefly; if we see 279/529,
# restart DGen once with wide GameFilter to avoid requiring a manual second Start.
$script:robloxAutoRetryEnabled = $false
$script:robloxAutoRetryUntil = $null
$script:robloxAutoRetryNextCheckAt = $null
$script:robloxAutoRetryTriggered = $false
$script:robloxAutoRetryStartedAt = $null
$script:robloxAutoRetryHadWideGameFilter = $false

function Test-WantsRoblox {
    try {
        if (-not $cfg) { return $false }
        if (-not ($cfg.PSObject.Properties.Name -contains 'domains')) { return $false }
        if (-not $cfg.domains) { return $false }
        foreach ($d in @($cfg.domains)) {
            $t = ([string]$d).ToLower().Trim()
            if (-not $t) { continue }
            if ($t -eq 'roblox.com' -or $t.EndsWith('.roblox.com') -or $t -eq 'rbxcdn.com' -or $t.EndsWith('.rbxcdn.com') -or $t -eq 'robloxapis.com' -or $t.EndsWith('.robloxapis.com')) {
                return $true
            }
        }
    } catch { }
    return $false
}

function Start-RobloxAutoRetryWatcher {
    # Safety: never allow more than one internal restart per manual Start.
    # Internal restarts re-enter Running and would otherwise re-arm the watcher.
    try { if ($script:robloxAutoRetryRestartCount -ge 1) { return } } catch { }

    # Only watch when Roblox is a requested domain and we are NOT already in wide GameFilter mode.
    $script:robloxAutoRetryEnabled = $false
    $script:robloxAutoRetryTriggered = $false
    $script:robloxAutoRetryUntil = $null
    $script:robloxAutoRetryNextCheckAt = $null
    $script:robloxAutoRetryStartedAt = $null
    $script:robloxAutoRetryHadWideGameFilter = $false

    try {
        if (-not (Test-WantsRoblox)) { return }

        # Even if GameFilterOverride is already enabled (e.g., from previous 279 logs),
        # still watch for *new* 279/529 so we can ingest fresh server IPs and restart once.
        try { if ($script:gameFilterOverride) { $script:robloxAutoRetryHadWideGameFilter = $true } } catch { $script:robloxAutoRetryHadWideGameFilter = $false }

        $script:robloxAutoRetryEnabled = $true
        $script:robloxAutoRetryStartedAt = Get-Date
        $script:robloxAutoRetryUntil = (Get-Date).AddMinutes(10)
        # Debounce initial scan to avoid flapping and allow IP collection.
        $script:robloxAutoRetryNextCheckAt = (Get-Date).AddSeconds(3)
        Write-Log "Roblox auto-retry: watcher armed (10min window)"
    } catch { }
}

function Tick-RobloxAutoRetry {
    if (-not $script:robloxAutoRetryEnabled) { return }
    if ($script:robloxAutoRetryTriggered) { return }
    if (-not $script:robloxAutoRetryUntil) { return }
    if ((Get-Date) -ge $script:robloxAutoRetryUntil) {
        $script:robloxAutoRetryEnabled = $false
        return
    }

    if ($script:robloxAutoRetryNextCheckAt -and (Get-Date) -lt $script:robloxAutoRetryNextCheckAt) { return }
    $script:robloxAutoRetryNextCheckAt = (Get-Date).AddSeconds(5)

    # Avoid reacting to ancient 279/529 entries: only consider logs that were written after we armed the watcher.
    try {
        if ($script:robloxAutoRetryStartedAt) {
            $logDir = Get-RobloxLogDir
            if (-not $logDir) { return }
            $latest = @(Get-ChildItem -LiteralPath $logDir -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
            if (-not $latest -or $latest.Count -eq 0) { return }
            if ($latest[0].LastWriteTime -lt $script:robloxAutoRetryStartedAt) { return }
        }
    } catch { }

    try {
        $rob = Get-RobloxEndpointsFromRecentLogs -tailLines 8000
        if (-not $rob) { return }

        $hosts = @()
        $ips = @()
        try { if ($rob.PSObject.Properties.Name -contains 'Hosts') { $hosts = @($rob.Hosts) } } catch { $hosts = @() }
        try { if ($rob.PSObject.Properties.Name -contains 'Ips') { $ips = @($rob.Ips) } } catch { $ips = @() }

        $addedIps = 0
        try {
            if ($ips.Count -gt 0) {
                $addedIps += Update-IpsetAllFromIps -ips $ips
            }
            if ($addedIps -eq 0 -and $hosts.Count -gt 0) {
                # DNS fallback if logs don't contain server IPs.
                $addedIps += Update-IpsetAllFromHosts -hosts $hosts
            }
        } catch { }

        $hadWide = $false
        try { if ($script:gameFilterOverride) { $hadWide = $true } } catch { $hadWide = $false }

        $needWidePorts = $false
        try { if ($rob.PSObject.Properties.Name -contains 'Has277' -and $rob.Has277) { $needWidePorts = $true } } catch { }
        try { if ($rob.PSObject.Properties.Name -contains 'Has279' -and $rob.Has279) { $needWidePorts = $true } } catch { }
        try { if ($rob.PSObject.Properties.Name -contains 'Has529' -and $rob.Has529) { $needWidePorts = $true } } catch { }

        # Optimization: if we are already running with wide GameFilter and we learned new Roblox server IPs,
        # restart once early to apply the ipset updates (helps avoid "Roblox only works on 2nd try").
        if (-not $needWidePorts) {
            if (-not ($hadWide -and $addedIps -gt 0)) { return }
        }

        # If we are already in wide mode and did not learn new IPs, restarting won't help.
        if ($hadWide -and $addedIps -le 0) {
            $script:robloxAutoRetryTriggered = $true
            $script:robloxAutoRetryEnabled = $false
            Write-Log ("Roblox auto-retry: detected 277/279/529; ipsFound={0} addedIps={1}; no new IPs; skip restart" -f $ips.Count, $addedIps)
            return
        }

        $script:robloxAutoRetryTriggered = $true
        $script:robloxAutoRetryEnabled = $false
        try { $script:robloxAutoRetryRestartCount++ } catch { }

        if (-not $hadWide) {
            $script:gameFilterOverride = '1024-65535'
            Write-Log ("Roblox auto-retry: detected 277/279/529; ipsFound={0} addedIps={1}; enabling GameFilter=1024-65535 and restarting" -f $ips.Count, $addedIps)
        } else {
            if ($needWidePorts) {
                Write-Log ("Roblox auto-retry: detected 277/279/529; ipsFound={0} addedIps={1}; restarting to apply ipset updates" -f $ips.Count, $addedIps)
            } else {
                Write-Log ("Roblox auto-retry: learned new IPs; ipsFound={0} addedIps={1}; restarting early to apply ipset updates" -f $ips.Count, $addedIps)
            }
        }

        # Fast restart: stop current DGen and immediately start the same strategy with new env.
        Stop-All
        Stop-Winws
        Stop-WinDivertServices -waitMs 5000 | Out-Null

        if (-not $script:currentStrategyFile) { return }
        $script:runId = New-RunId
        Write-Log "New run: $($script:runId)"
        $script:strategyRunnerProc = Start-StrategyFile -strategyFile $script:currentStrategyFile -attemptIndex 0 -runId $script:runId
        $script:waitUntil = (Get-Date).AddSeconds(2)
        $script:winwsStartDeadline = (Get-Date).AddMilliseconds(15000)
        $script:captureStartDeadline = (Get-Date).AddSeconds(60)
        $script:startState = "Starting"
        Update-ToggleButton
        Refresh-Logs
    } catch {
        # Never break the session on watcher issues.
        try { Write-Log "Roblox auto-retry: watcher error: $($_.Exception.Message)" } catch { }
    }
}

# Ethernet auto-rotate (fast, minimal logs): after Start on Ethernet, run short HTTPS probes.
# If Discord+Roblox are both dead but control (YouTube) is alive, automatically restart with the next strategy.
$script:ethernetAutoRotateEnabled = $false
$script:ethernetAutoRotateTriggered = $false
$script:ethernetAutoRotateUntil = $null
$script:ethernetAutoRotateNextCheckAt = $null
$script:ethernetAutoRotateStartedAt = $null
$script:ethernetAutoRotateAttempt = 0
$script:ethernetAutoRotateMaxAttempts = 6
$script:ethernetAutoRotateQueue = @()
$script:ethernetAutoRotateQueueIndex = 0
$script:ethernetAutoRotateLastProbe = $null
$script:ethernetAutoRotateLastGoodStrategyFile = $null

function Reset-EthernetAutoRotateState {
    $script:ethernetAutoRotateEnabled = $false
    $script:ethernetAutoRotateTriggered = $false
    $script:ethernetAutoRotateUntil = $null
    $script:ethernetAutoRotateNextCheckAt = $null
    $script:ethernetAutoRotateStartedAt = $null
    $script:ethernetAutoRotateAttempt = 0
    $script:ethernetAutoRotateQueue = @()
    $script:ethernetAutoRotateQueueIndex = 0
    $script:ethernetAutoRotateLastProbe = $null
    $script:ethernetAutoRotateLastGoodStrategyFile = $null
}

function Test-IsEthernetLink {
    try {
        $t = [string]$script:networkLinkType
        if (-not $t) { return $false }
        return ($t.Trim().ToLowerInvariant() -eq 'ethernet')
    } catch { return $false }
}

function Invoke-PostStartProbes {
    param([int]$timeoutMs = 2000)

    $getProbeCode = {
        param($entry)

        try {
            if ($entry -and $entry.Ok) { return 'ok' }
        } catch { }

        $err = ''
        try { if ($entry -and $entry.Error) { $err = [string]$entry.Error } } catch { $err = '' }
        if ([string]::IsNullOrWhiteSpace($err)) { return 'fail' }

        $l = $err.Trim().ToLowerInvariant()
        if ($l -like 'timeout after*' -or $l -like '*timed out*' -or $l -like '*timeout*') { return 'timeout' }
        if ($l -like '*secure_failure*' -or $l -like '*ssl*' -or $l -like '*tls*' -or $l -like '*authentication*') { return 'tls' }
        if ($l -like '*no such host*' -or $l -like '*could not resolve*' -or $l -like '*name resolution*') { return 'dns' }
        if ($l -like '*refused*') { return 'refused' }
        return 'err'
    }

    $getTcpCode = {
        param($tcp)

        try {
            if ($tcp -and $tcp.Ok) { return 'ok' }
        } catch { }

        $err = ''
        try { if ($tcp) { $err = [string]$tcp.Error } } catch { $err = '' }
        if ([string]::IsNullOrWhiteSpace($err)) { return 'fail' }

        $l = $err.Trim().ToLowerInvariant()
        if ($l -eq 'timeout') { return 'timeout' }
        if ($l -like '*no such host*' -or $l -like '*could not resolve*' -or $l -like '*name resolution*') { return 'dns' }
        if ($l -like '*refused*') { return 'refused' }
        return 'err'
    }

    $discordUrls = @(
        'https://discord.com/app',
        'https://gateway.discord.gg',
        'https://dl.discordapp.net/'
    )
    $robloxUrls = @(
        'https://clientsettingscdn.roblox.com/v2/client-version/WindowsPlayer',
        'https://assetdelivery.roblox.com/',
        'https://tr.rbxcdn.com/'
    )
    # Control probes: keep them independent of YouTube so we can detect "YouTube-only" breakage.
    # Prefer HTTP for msftconnecttest to avoid TLS-related false negatives on some ISPs.
    $controlUrls = @(
        'http://www.msftconnecttest.com/connecttest.txt',
        'https://www.msftconnecttest.com/connecttest.txt'
    )

    # YouTube probes: split accounts vs video to avoid false "internet ok" when only robots.txt loads.
    $ytMainUrls = @(
        'https://www.youtube.com/robots.txt'
    )
    $ytAccountsUrls = @(
        'https://accounts.google.com/'
    )
    $ytVideoUrls = @(
        'https://redirector.googlevideo.com/'
    )
    $ytImgUrls = @(
        'https://i.ytimg.com/'
    )

    $all = @($discordUrls + $robloxUrls + $controlUrls + $ytMainUrls + $ytAccountsUrls + $ytVideoUrls + $ytImgUrls)

    $results = @()
    try { $results = @(Test-HttpUrlsParallel -Urls $all -timeoutMs $timeoutMs) } catch { $results = @() }

    $map = @{}
    foreach ($r in $results) {
        try {
            if ($r -and $r.Url) { $map[[string]$r.Url] = $r }
        } catch { }
    }

    # Discord success must include the gateway; discord.com/app alone can be a false positive.
    $discordOk = $false
    try {
        $gw = 'https://gateway.discord.gg'
        if ($map[$gw] -and $map[$gw].Ok) { $discordOk = $true }
    } catch { }

    $robloxOkCount = 0
    foreach ($u in $robloxUrls) {
        try { if ($map[$u] -and $map[$u].Ok) { $robloxOkCount++ } } catch { }
    }
    # Roblox app-like success: require 2/3 endpoints (avoid false positives from single CDN hop).
    $robloxOk = ($robloxOkCount -ge 2)

    $controlOk = $false
    foreach ($u in $controlUrls) {
        try { if ($map[$u] -and $map[$u].Ok) { $controlOk = $true; break } } catch { }
    }

    $ytMainOk = $false
    foreach ($u in $ytMainUrls) {
        try { if ($map[$u] -and $map[$u].Ok) { $ytMainOk = $true; break } } catch { }
    }

    $ytAccountsOk = $false
    foreach ($u in $ytAccountsUrls) {
        try { if ($map[$u] -and $map[$u].Ok) { $ytAccountsOk = $true; break } } catch { }
    }

    $ytVideoOk = $false
    foreach ($u in $ytVideoUrls) {
        try { if ($map[$u] -and $map[$u].Ok) { $ytVideoOk = $true; break } } catch { }
    }

    $ytImgOk = $false
    foreach ($u in $ytImgUrls) {
        try { if ($map[$u] -and $map[$u].Ok) { $ytImgOk = $true; break } } catch { }
    }

    # Overall YouTube health for UX decisions. Keep it strict: if video redirector is blocked, video won't play.
    $ytOk = ($ytMainOk -and $ytAccountsOk -and $ytVideoOk)

    $gwUrl = 'https://gateway.discord.gg'
    $csUrl = 'https://clientsettingscdn.roblox.com/v2/client-version/WindowsPlayer'
    $adUrl = 'https://assetdelivery.roblox.com/'
    $trUrl = 'https://tr.rbxcdn.com/'
    $msftHttpUrl = 'http://www.msftconnecttest.com/connecttest.txt'
    $msftHttpsUrl = 'https://www.msftconnecttest.com/connecttest.txt'
    $ytMainUrl = 'https://www.youtube.com/robots.txt'
    $ytAccountsUrl = 'https://accounts.google.com/'
    $ytVideoUrl = 'https://redirector.googlevideo.com/'
    $ytImgUrl = 'https://i.ytimg.com/'

    $discordGwCode = & $getProbeCode $map[$gwUrl]
    $robloxCsCode = & $getProbeCode $map[$csUrl]
    $robloxAdCode = & $getProbeCode $map[$adUrl]
    $robloxTrCode = & $getProbeCode $map[$trUrl]
    $ctrlMsftHttpCode = & $getProbeCode $map[$msftHttpUrl]
    $ctrlMsftHttpsCode = & $getProbeCode $map[$msftHttpsUrl]
    $ytMainCode = & $getProbeCode $map[$ytMainUrl]
    $ytAccountsCode = & $getProbeCode $map[$ytAccountsUrl]
    $ytVideoCode = & $getProbeCode $map[$ytVideoUrl]
    $ytImgCode = & $getProbeCode $map[$ytImgUrl]

    $discordTcpCode = 'ok'
    if (-not $discordOk) {
        $tcp = $null
        try { $tcp = Test-TcpConnect -hostName 'gateway.discord.gg' -port 443 -timeoutMs 800 } catch { $tcp = $null }
        $discordTcpCode = & $getTcpCode $tcp
    }

    $robloxTcpCode = 'ok'
    if (-not $robloxOk) {
        $tcp = $null
        try { $tcp = Test-TcpConnect -hostName 'clientsettingscdn.roblox.com' -port 443 -timeoutMs 800 } catch { $tcp = $null }
        $robloxTcpCode = & $getTcpCode $tcp
    }

    $discordDiag = ''
    if ($discordOk) { $discordDiag = 'ok' } else { $discordDiag = ("t={0} gw={1}" -f $discordTcpCode, $discordGwCode) }

    $robloxDiag = ''
    if ($robloxOk) {
        $robloxDiag = ("ok {0}/{1}" -f $robloxOkCount, $robloxUrls.Count)
    } else {
        $robloxDiag = ("t={0} cs={1} ad={2} tr={3} ok={4}/{5}" -f $robloxTcpCode, $robloxCsCode, $robloxAdCode, $robloxTrCode, $robloxOkCount, $robloxUrls.Count)
    }

    $ctrlDiag = ("msft_http={0} msft_https={1}" -f $ctrlMsftHttpCode, $ctrlMsftHttpsCode)
    $ytDiag = ("main={0} acc={1} video={2} img={3}" -f $ytMainCode, $ytAccountsCode, $ytVideoCode, $ytImgCode)

    return [pscustomobject]@{
        DiscordOk = $discordOk
        RobloxOk = $robloxOk
        ControlOk = $controlOk
        YtMainOk = $ytMainOk
        YtAccountsOk = $ytAccountsOk
        YtVideoOk = $ytVideoOk
        YtImgOk = $ytImgOk
        YtOk = $ytOk
        DiscordTcp = $discordTcpCode
        RobloxTcp = $robloxTcpCode
        DiscordDiag = $discordDiag
        RobloxDiag = $robloxDiag
        CtrlDiag = $ctrlDiag
        YtDiag = $ytDiag
        Results = $results
    }
}

# Post-start probe snapshot (all link types): run once shortly after Running so dgen-summary.json
# contains Control + YouTube accounts/video diagnostics even when Ethernet auto-rotate is disabled.
$script:postStartSnapshotEnabled = $false
$script:postStartSnapshotDone = $false
$script:postStartSnapshotNextCheckAt = $null

function Start-PostStartProbeSnapshot {
    $script:postStartSnapshotEnabled = $true
    $script:postStartSnapshotDone = $false
    $script:postStartSnapshotNextCheckAt = (Get-Date).AddSeconds(8)
}

function Tick-PostStartProbeSnapshot {
    if (-not $script:postStartSnapshotEnabled) { return }
    if ($script:postStartSnapshotDone) { return }

    if ($script:postStartSnapshotNextCheckAt -and (Get-Date) -lt $script:postStartSnapshotNextCheckAt) { return }

    $script:postStartSnapshotDone = $true

    $p = $null
    try { $p = Invoke-PostStartProbes -timeoutMs 2500 } catch { $p = $null }
    if ($p) {
        # Reuse the existing summary wiring (Write-DGenSummaryJson reads ethernetAutoRotateLastProbe).
        $script:ethernetAutoRotateLastProbe = $p
        Try-WifiAutoRotateFromProbe -probe $p
    }
}

# WiFi auto-rotate (conservative): if control probes are OK but YouTube/Discord fail on Wi-Fi,
# restart ONCE per manual Start with a safer fallback strategy.
function Restart-RunningWithStrategyWifi {
    param(
        [System.IO.FileInfo]$strategyFile,
        [string]$reason
    )

    if (-not $strategyFile) { return }

    try {
        if ($statusLabel) { $statusLabel.Text = ("Restarting (WiFi): {0}" -f $strategyFile.Name) }
    } catch { }

    try { Write-Log ("WiFi auto-rotate: switching -> {0} ({1})" -f $strategyFile.Name, $reason) } catch { }

    # Avoid double restarts from other watchers.
    try { $script:robloxAutoRetryEnabled = $false } catch { }
    try { $script:ethernetAutoRotateEnabled = $false } catch { }

    Stop-All
    Stop-Winws
    Stop-WinDivertServices -waitMs 5000 | Out-Null

    $script:currentStrategyFile = $strategyFile
    $script:runId = New-RunId
    Write-Log "New run: $($script:runId)"
    $script:strategyRunnerProc = Start-StrategyFile -strategyFile $strategyFile -attemptIndex 0 -runId $script:runId
    $script:waitUntil = (Get-Date).AddSeconds(2)
    $script:winwsStartDeadline = (Get-Date).AddMilliseconds(15000)
    $script:captureStartDeadline = (Get-Date).AddSeconds(60)
    $script:startState = "Starting"
    Update-ToggleButton
    Refresh-Logs
}

function Get-WifiAutoRotateFallbackStrategyFile {
    param($probe)

    $rel = ''
    try {
        if ($probe -and (-not $probe.YtOk) -and $probe.DiscordOk) { $rel = 'strategies\\general (CLASSIC).bat' }
    } catch { $rel = '' }

    if (-not $rel) {
        try {
            if ($probe -and (-not $probe.DiscordOk) -and $probe.YtOk) { $rel = 'strategies\\general (ALT11).bat' }
        } catch { $rel = '' }
    }

    if (-not $rel) { $rel = 'strategies\\general (FAKE TLS AUTO).bat' }

    try {
        $full = Join-Path $root $rel
        if (-not (Test-Path -LiteralPath $full)) { return $null }
        return (Get-Item -LiteralPath $full)
    } catch { return $null }
}

function Try-WifiAutoRotateFromProbe {
    param($probe)

    try { if (-not $probe) { return } } catch { return }

    # Only on Wi-Fi, only once per manual Start.
    try { if ($script:wifiAutoRotateRestartCount -ge 1) { return } } catch { }

    try { if (Test-IsEthernetLink) { return } } catch { }

    try {
        $t = [string]$script:networkLinkType
        if (-not $t -or $t.Trim().ToLowerInvariant() -ne 'wifi') { return }
    } catch { return }

    # Respect manual strategy selection: auto-rotate only when we started from default autopick (general.bat).
    try {
        if (-not $script:currentStrategyFile -or $script:currentStrategyFile.Name -ne 'general.bat') { return }
    } catch { return }

    # Don't risk breaking the internet when control is down.
    try { if (-not $probe.ControlOk) { return } } catch { return }

    $need = $false
    try {
        if ((-not $probe.YtOk) -or (-not $probe.DiscordOk)) { $need = $true }
    } catch { $need = $false }

    if (-not $need) { return }

    $next = $null
    try { $next = Get-WifiAutoRotateFallbackStrategyFile -probe $probe } catch { $next = $null }
    if (-not $next) {
        try { Write-Log "WiFi auto-rotate: no fallback strategy found; skipping" } catch { }
        return
    }

    try { $script:wifiAutoRotateRestartCount++ } catch { }

    $reason = ''
    try { $reason = ("ytOk={0} discordOk={1} ctrlOk={2}" -f $probe.YtOk, $probe.DiscordOk, $probe.ControlOk) } catch { $reason = 'probe failure' }
    Restart-RunningWithStrategyWifi -strategyFile $next -reason $reason
}

function Get-EthernetRotationQueue {
    $out = @()

    try {
        if ($script:currentStrategyFile) { $out += $script:currentStrategyFile }
    } catch { }

    # Ethernet escalation order. Engine autopick already visits the "strong" families,
    # so keep launcher rotation focused on the additional fallbacks.
    $rels = @(
        # Start from default autopick.
        'strategies\general.bat',
        # Strong-but-safe-first fallbacks for cable.
        'strategies\general (ALT11).bat',
        'strategies\general (FAKE TLS AUTO).bat',
        'strategies\general (FAKE TLS AUTO ALT3).bat',
        # Additional fallbacks.
        'strategies\general (ALT7).bat',
        'strategies\general (FAKE TLS AUTO SYNDATA).bat',
        'strategies\general (FAKE TLS AUTO SYNDATA STRICT).bat',
        'strategies\general (CLASSIC).bat'
    )

    foreach ($rel in $rels) {
        try {
            $full = Join-Path $root $rel
            if (-not (Test-Path -LiteralPath $full)) { continue }
            $fi = Get-Item -LiteralPath $full
            if (-not $fi) { continue }

            $exists = $false
            foreach ($x in $out) {
                try {
                    if ($x -and $x.FullName -and $x.FullName -ieq $fi.FullName) { $exists = $true; break }
                } catch { }
            }

            if (-not $exists) { $out += $fi }
        } catch { }
    }

    return @($out)
}

function Start-EthernetAutoRotateWatcher {
    try {
        if (-not (Test-IsEthernetLink)) { return }

        # Continuation across internal restarts: keep queue + attempt progress.
        $hasSession = $false
        try {
            if ($script:ethernetAutoRotateQueue -and $script:ethernetAutoRotateQueue.Count -gt 0 -and ($script:ethernetAutoRotateQueueIndex -gt 0 -or $script:ethernetAutoRotateAttempt -gt 0)) {
                $hasSession = $true
            }
        } catch { $hasSession = $false }

        if (-not $hasSession) {
            # Respect manual strategy selection: auto-rotate only when we started from default autopick (general.bat).
            try {
                if (-not $script:currentStrategyFile -or $script:currentStrategyFile.Name -ne 'general.bat') { return }
            } catch { return }

            Reset-EthernetAutoRotateState

            $q = @(Get-EthernetRotationQueue)
            if (-not $q -or $q.Count -lt 2) { return }

            $script:ethernetAutoRotateQueue = $q
            # Make attempt limit match the actual queue length so a manual Start always runs a full pass.
            try { $script:ethernetAutoRotateMaxAttempts = [Math]::Max(1, $q.Count - 1) } catch { }
            $script:ethernetAutoRotateStartedAt = Get-Date

            # Minimal log: single line only on initial arm.
            try { Write-Log ("Ethernet auto-rotate: armed (maxAttempts={0})" -f $script:ethernetAutoRotateMaxAttempts) } catch { }
        }

        # (Re)arm for this run.
        $script:ethernetAutoRotateEnabled = $true
        $script:ethernetAutoRotateTriggered = $false
        $script:ethernetAutoRotateUntil = (Get-Date).AddSeconds(180)
        $script:ethernetAutoRotateNextCheckAt = (Get-Date).AddSeconds(6)
        $script:ethernetAutoRotateLastProbe = $null
    } catch { }
}

function Restart-RunningWithStrategy {
    param(
        [System.IO.FileInfo]$strategyFile,
        [string]$reason
    )

    if (-not $strategyFile) { return }

    try {
        if ($statusLabel) { $statusLabel.Text = ("Restarting (Ethernet): {0}" -f $strategyFile.Name) }
    } catch { }

    try { Write-Log ("Ethernet auto-rotate: switching -> {0} ({1})" -f $strategyFile.Name, $reason) } catch { }

    # Avoid double restarts from other watchers.
    try { $script:robloxAutoRetryEnabled = $false } catch { }

    Stop-All
    Stop-Winws
    Stop-WinDivertServices -waitMs 5000 | Out-Null

    $script:currentStrategyFile = $strategyFile
    $script:runId = New-RunId
    Write-Log "New run: $($script:runId)"
    $script:strategyRunnerProc = Start-StrategyFile -strategyFile $strategyFile -attemptIndex 0 -runId $script:runId
    $script:waitUntil = (Get-Date).AddSeconds(2)
    $script:winwsStartDeadline = (Get-Date).AddMilliseconds(15000)
    $script:captureStartDeadline = (Get-Date).AddSeconds(60)
    $script:startState = "Starting"
    Update-ToggleButton
    Refresh-Logs
}

function Tick-EthernetAutoRotate {
    if (-not $script:ethernetAutoRotateEnabled) { return }
    if ($script:ethernetAutoRotateTriggered) { return }
    if (-not $script:ethernetAutoRotateUntil) { return }

    if ((Get-Date) -ge $script:ethernetAutoRotateUntil) {
        try { Write-Log ("Ethernet auto-rotate: giving up after attempts={0}" -f $script:ethernetAutoRotateAttempt) } catch { }
        try {
            if ($statusLabel -and $script:currentStrategyFile) {
                $statusLabel.Text = ("Ethernet: giving up after {0} attempts; running: {1}" -f $script:ethernetAutoRotateAttempt, $script:currentStrategyFile.Name)
            }
        } catch { }
        try { Reset-EthernetAutoRotateState } catch { }
        return
    }

    if ($script:ethernetAutoRotateNextCheckAt -and (Get-Date) -lt $script:ethernetAutoRotateNextCheckAt) { return }
    $script:ethernetAutoRotateNextCheckAt = (Get-Date).AddSeconds(8)

    $p = $null
    try { $p = Invoke-PostStartProbes -timeoutMs 2500 } catch { $p = $null }
    $script:ethernetAutoRotateLastProbe = $p
    if (-not $p) { return }

    # Track the last strategy that keeps control probes alive so we can safely revert
    # if an escalation strategy breaks basic connectivity.
    try {
        if ($p.ControlOk -and $script:currentStrategyFile) {
            $script:ethernetAutoRotateLastGoodStrategyFile = $script:currentStrategyFile
        }
    } catch { }

    # Success condition: Discord and Roblox both respond.
    if ($p.DiscordOk -and $p.RobloxOk) {
        try { Write-Log ("Ethernet auto-rotate: success ({0})" -f $script:currentStrategyFile.Name) } catch { }
        try { Reset-EthernetAutoRotateState } catch { }
        return
    }

    # If control is down too -> don't thrash.
    if (-not $p.ControlOk) {
        $fallback = $null
        try { $fallback = $script:ethernetAutoRotateLastGoodStrategyFile } catch { $fallback = $null }
        $didRevert = $false
        try {
            if ($fallback -and $script:currentStrategyFile -and $fallback.FullName -and $script:currentStrategyFile.FullName -and ($fallback.FullName -ine $script:currentStrategyFile.FullName)) {
                Write-Log ("Ethernet auto-rotate: control probe failed; reverting -> {0}" -f $fallback.Name)
                $script:ethernetAutoRotateTriggered = $true
                $didRevert = $true
                Restart-RunningWithStrategy -strategyFile $fallback -reason "control probe failed; revert to last-good"
            } else {
                Write-Log "Ethernet auto-rotate: control probe failed; skipping rotation"
            }
        } catch { }
        # IMPORTANT: if we reverted, keep the queue/attempt state so we can continue with the next
        # strategy after the revert run reaches Running again.
        if (-not $didRevert) {
            # We have no safe fallback and control is broken.
            # Fail-open: stop the session so we don't leave the user without internet.
            try { Write-Log "Ethernet auto-rotate: control probe failed; stopping to avoid breaking internet" } catch { }
            try {
                if ($statusLabel -and $script:currentStrategyFile) {
                    $statusLabel.Text = ("Ethernet: control probe failed; stopped: {0}" -f $script:currentStrategyFile.Name)
                } elseif ($statusLabel) {
                    $statusLabel.Text = "Ethernet: control probe failed; stopped"
                }
            } catch { }

            try { Stop-All } catch { }
            try { Reset-EthernetAutoRotateState } catch { }

            try { $script:strategyRunnerProc = $null } catch { }
            try { $script:currentStrategyFile = $null } catch { }
            try { $script:startState = "Idle" } catch { }
            try { Update-ToggleButton } catch { }
        }
        return
    }

    # Rotate when control is alive but at least one of Discord/Roblox is still failing.
    if ($p.ControlOk -and ((-not $p.DiscordOk) -or (-not $p.RobloxOk))) {
        # If both services fail on TCP connect while control is alive, this doesn't look like a DPI-only problem.
        # Rotating strategies won't help and just creates churn.
        try {
            if ((-not $p.DiscordOk) -and (-not $p.RobloxOk) -and $p.DiscordTcp -and $p.RobloxTcp -and ($p.DiscordTcp -ne 'ok') -and ($p.RobloxTcp -ne 'ok')) {
                Write-Log ("Ethernet auto-rotate: Discord+Roblox TCP probes failing (d.tcp={0} r.tcp={1}); stopping rotation" -f $p.DiscordTcp, $p.RobloxTcp)
                Reset-EthernetAutoRotateState
                return
            }
        } catch { }

        $nextIdx = [int]$script:ethernetAutoRotateQueueIndex + 1
        if (-not $script:ethernetAutoRotateQueue -or $nextIdx -ge $script:ethernetAutoRotateQueue.Count) {
            try { Write-Log ("Ethernet auto-rotate: no more strategies; attempts={0}" -f $script:ethernetAutoRotateAttempt) } catch { }
            try {
                if ($statusLabel -and $script:currentStrategyFile) {
                    $statusLabel.Text = ("Ethernet: no more strategies; attempts={0}; running: {1}" -f $script:ethernetAutoRotateAttempt, $script:currentStrategyFile.Name)
                }
            } catch { }
            try { Reset-EthernetAutoRotateState } catch { }
            return
        }

        $script:ethernetAutoRotateAttempt++
        if ($script:ethernetAutoRotateAttempt -gt $script:ethernetAutoRotateMaxAttempts) {
            try { Write-Log ("Ethernet auto-rotate: reached maxAttempts={0}" -f $script:ethernetAutoRotateMaxAttempts) } catch { }
            try {
                if ($statusLabel -and $script:currentStrategyFile) {
                    $statusLabel.Text = ("Ethernet: no success after {0} strategies; running: {1}" -f $script:ethernetAutoRotateMaxAttempts, $script:currentStrategyFile.Name)
                }
            } catch { }
            try { Reset-EthernetAutoRotateState } catch { }
            return
        }

        $script:ethernetAutoRotateQueueIndex = $nextIdx
        $next = $script:ethernetAutoRotateQueue[$nextIdx]
        $script:ethernetAutoRotateTriggered = $true

        $reason = ("discord={0}({1}) roblox={2}({3}) (ctrl ok) attempt={4}/{5}" -f $p.DiscordOk, $p.DiscordDiag, $p.RobloxOk, $p.RobloxDiag, $script:ethernetAutoRotateAttempt, $script:ethernetAutoRotateMaxAttempts)
        Restart-RunningWithStrategy -strategyFile $next -reason $reason
        return
    }
}

$script:generatorProc = $null
$script:strategies = @()
$script:strategyIndex = 0
$script:waitUntil = $null
$script:strategyRunnerProc = $null
$script:currentStrategyFile = $null
$script:bestStrategyFile = $null
$script:bestStrategyPassed = -1
$script:bestStrategyTotal = 0

$script:strategyAttemptSeq = 0

$script:autoRecoverFailCount = 0
$script:autoRecoverLastActionAt = $null
$script:autoRecoverLastCheckAt = $null

function Resize-StatusColumns {
    try {
        if (-not $procList -or -not $serviceList) { return }
        if ($procList -and $procList.Columns.Count -ge 3) {
            $w = $procList.ClientSize.Width
            if ($w -gt 100) {
                $pidW = 70
                $pathW = [Math]::Max(180, [int]($w * 0.35))
                $cmdW = $w - $pidW - $pathW - 4
                if ($cmdW -lt 140) {
                    $cmdW = 140
                    $pathW = [Math]::Max(140, $w - $pidW - $cmdW - 4)
                }
                $procList.Columns[0].Width = $pidW
                $procList.Columns[1].Width = $pathW
                $procList.Columns[2].Width = $cmdW
            }
        }

        if ($serviceList -and $serviceList.Columns.Count -ge 2) {
            $w = $serviceList.ClientSize.Width
            if ($w -gt 100) {
                $nameW = [Math]::Max(120, [int]($w * 0.55))
                $statusW = $w - $nameW - 4
                if ($statusW -lt 80) {
                    $statusW = 80
                    $nameW = [Math]::Max(80, $w - $statusW - 4)
                }
                $serviceList.Columns[0].Width = $nameW
                $serviceList.Columns[1].Width = $statusW
            }
        }
    } catch { }
}

function Update-ToggleButton {
    if (-not $script:startState -or $script:startState -eq "Idle") {
        $toggleBtn.Text = "Start"
        try {
            $toggleBtn.BackColor = $uiStart
            $toggleBtn.ForeColor = [System.Drawing.Color]::White
        } catch { }
        return
    }

    $toggleBtn.Text = "Stop"
    try {
        $toggleBtn.BackColor = $uiStop
        $toggleBtn.ForeColor = [System.Drawing.Color]::White
    } catch { }
}

function Tick-StartState {
    try {
        if (-not $script:startState -or $script:startState -eq "Idle") { return }

        if ($script:startState -eq "Generating") {
            if (-not $script:generatorProc) { throw "Generator process missing." }
            try { $script:generatorProc.Refresh() } catch { }
            if (-not $script:generatorProc.HasExited) {
                try {
                    $p = 45
                    if ($script:generatorStartedAt) {
                        $sec = ((Get-Date) - $script:generatorStartedAt).TotalSeconds
                        if ($sec -lt 0) { $sec = 0 }
                        $p = 45 + [Math]::Min(25, [int]($sec * 2))
                    }
                    Set-LoadingOverlayText "Generating..." $p
                } catch { }
                return
            }

            $genExit = 0
            try { $genExit = [int]$script:generatorProc.ExitCode } catch { $genExit = 0 }
            $genMs = 0
            try {
                if ($script:generatorStartedAt) {
                    $genMs = [int]((Get-Date) - $script:generatorStartedAt).TotalMilliseconds
                }
            } catch { $genMs = 0 }
            Write-Log ("Generator finished: exitCode={0} ms={1}" -f $genExit, $genMs)
            $script:generatorStartedAt = $null

            $script:generatorProc = $null

            $statusLabel.Text = "Starting (autopick...)"
            try { Set-LoadingOverlayText "Starting (autopick...)" 75 } catch { }

            # Engine-side autopick: start a single configured strategy. No external Selecting/scoring.
            $strategyRel = $null
            try { if ($cfg -and ($cfg.PSObject.Properties.Name -contains 'strategy')) { $strategyRel = [string]$cfg.strategy } } catch { $strategyRel = $null }
            if (-not $strategyRel) { $strategyRel = 'strategies\\general.bat' }
            $strategyFull = Join-Path $root $strategyRel
			if (-not (Test-Path -LiteralPath $strategyFull)) {
				Write-Log ("Strategy not found (from config): {0}" -f $strategyFull)
				$strategyRel = 'strategies\\general.bat'
				$strategyFull = Join-Path $root $strategyRel
				if (-not (Test-Path -LiteralPath $strategyFull)) { throw "Strategy not found: $strategyFull" }
			}
            $s = Get-Item -LiteralPath $strategyFull

            Stop-Winws
            if (-not $script:runId) {
                $script:runId = New-RunId
                Write-Log "New run: $($script:runId)"
            }

            $script:strategyRunnerProc = Start-StrategyFile -strategyFile $s -attemptIndex 0 -runId $script:runId
            $script:currentStrategyFile = $s
            $script:startingStartedAt = Get-Date
            $script:waitUntil = (Get-Date).AddSeconds(2)
            $script:winwsStartDeadline = (Get-Date).AddMilliseconds(15000)
            $script:captureStartDeadline = (Get-Date).AddSeconds(60)
            $script:startState = "Starting"
            Update-ToggleButton
            return
        }

        if ($script:startState -eq "Starting") {
            if ($script:winwsStartDeadline) {
                try {
                    if (Test-WinwsRunning) {
                        $script:winwsStartDeadline = $null
                    } elseif ((Get-Date) -ge $script:winwsStartDeadline) {
                        Fail-StrategyStart -strategyFile $script:currentStrategyFile -reason "DGen.exe did not start"
                        return
                    }
                } catch { }
            }

            if ((Get-Date) -lt $script:waitUntil) { return }

            if (-not (Test-WinwsRunning)) {
                Fail-StrategyStart -strategyFile $script:currentStrategyFile -reason "DGen.exe exited early"
                return
            }

            # DGen.exe may still be running autopick and hasn't started capture yet.
            # Only switch to Running after we see the WinDivert capture start marker.
            $captureStarted = $false
            try {
                if ($script:strategyOutPath -and (Test-Path -LiteralPath $script:strategyOutPath)) {
                    $tail = Get-Content -LiteralPath $script:strategyOutPath -Tail 120 -ErrorAction SilentlyContinue
                    foreach ($ln in $tail) {
                        if ($ln -like '*capture is started*') { $captureStarted = $true; break }
                    }
                }
            } catch { $captureStarted = $false }

            if (-not $captureStarted) {
                if ($script:captureStartDeadline -and (Get-Date) -ge $script:captureStartDeadline) {
                    Fail-StrategyStart -strategyFile $script:currentStrategyFile -reason "DGen.exe started but capture did not start (autopick hang?)"
                    return
                }
                $statusLabel.Text = "Starting (autopick...)"
                try {
                    $p = 80
                    if ($script:startingStartedAt -and $script:captureStartDeadline) {
                        $total = ($script:captureStartDeadline - $script:startingStartedAt).TotalSeconds
                        if ($total -lt 1) { $total = 60 }
                        $elapsed = ((Get-Date) - $script:startingStartedAt).TotalSeconds
                        if ($elapsed -lt 0) { $elapsed = 0 }
                        $p = 80 + [Math]::Min(19, [int](($elapsed / $total) * 19))
                    }
                    Set-LoadingOverlayText "Starting (autopick...)" $p
                } catch { }
                return
            }

            $nm = 'DGen'
            try { if ($script:currentStrategyFile) { $nm = [string]$script:currentStrategyFile.Name } } catch { }
            $statusLabel.Text = ("Running: {0}" -f $nm)
            try { Set-LoadingOverlayText "READY: можно открывать сервисы" 100 } catch { }
            Write-Log ("DGen RUN: {0}" -f $nm)

            $script:startState = "Running"
            Update-ToggleButton
            $script:waitUntil = $null
            $script:winwsStartDeadline = $null
            $script:captureStartDeadline = $null
            try { Hide-LoadingOverlay } catch { }
            try { Refresh-Logs } catch { }

            # Fast Roblox auto-retry (does NOT block start): if Roblox later reports 279/529,
            # we will restart once with wide GameFilter.
            Start-RobloxAutoRetryWatcher

            # Ethernet auto-rotation (does NOT block start): if Discord+Roblox stay dead on cable,
            # automatically try the next strategy a few times.
            Start-EthernetAutoRotateWatcher

            # Post-start snapshot (does NOT block start): record Control + YouTube accounts/video status in summary.
            Start-PostStartProbeSnapshot
            return
        }

        if ($script:startState -eq "Running") {
            Tick-PostStartProbeSnapshot
            Tick-RobloxAutoRetry
            Tick-EthernetAutoRotate
            return
        }
    } catch {
        $msg = $_.Exception.Message
        $statusLabel.Text = "Error: $msg"
        Write-Log "Start error: $msg"
        [System.Windows.Forms.MessageBox]::Show($msg, "D-Gen", 'OK', 'Error') | Out-Null

        try { Hide-LoadingOverlay } catch { }

        $script:startState = "Idle"
        $script:generatorProc = $null
        $script:generatorStartedAt = $null
        $script:strategies = @()
        $script:strategyIndex = 0
        $script:waitUntil = $null
        $script:strategyRunnerProc = $null

        try { Hide-LoadingOverlay } catch { }

        $script:currentStrategyFile = $null
        $script:autoRecoverFailCount = 0
        $script:autoTunedAggressive = $false
        $script:autoTunedQuic = $false
        $script:autoTunedGameFilter = $false
        $script:gameFilterOverride = $null
        $script:lastRobloxIngestion = $null
        $script:autoRecoverLastActionAt = $null
        $script:autoRecoverLastCheckAt = $null
        $toggleBtn.Enabled = $true
        Update-ToggleButton
    }
}

$toggleBtn.Add_Click({
    $toggleBtn.Enabled = $false

    try { $script:uiBusy = $true } catch { }

    try {
        if (-not $script:startState -or $script:startState -eq "Idle") {
            try { Show-LoadingOverlay "Preparing..." 5 } catch { }
            try { [System.Windows.Forms.Application]::DoEvents() } catch { }

            try {
                $svc = Get-Service -Name "DGen" -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq 'Running') {
                    try { Hide-LoadingOverlay } catch { }
                    try { $statusLabel.Text = "Start blocked: DGen service is running" } catch { }
                    try { Write-Log "Start blocked: DGen service is RUNNING. Use service.bat -> Remove Services, then retry Start." } catch { }
                    try {
                        $msg = "DGen is already running as a Windows service.`r`n`r`n" +
                            "This conflicts with D-Gen (DGen.exe).`r`n`r`n" +
                            "Fix: open service.bat and choose 'Remove Services' (or stop the DGen service), then press Start again."
                        [System.Windows.Forms.MessageBox]::Show($msg, "D-Gen", 'OK', 'Warning') | Out-Null
                    } catch { }
                    return
                }
            } catch { }

            $script:runId = New-RunId

            # New manual Start session.
            try { $script:manualStartSeq++ } catch { }
            try { $script:robloxAutoRetryRestartCount = 0 } catch { }
            try { $script:wifiAutoRotateRestartCount = 0 } catch { }
            try { $script:robloxAutoRetryTriggered = $false } catch { }
            try { $script:robloxAutoRetryEnabled = $false } catch { }

            # Reset post-start snapshot state for this run.
            try { $script:ethernetAutoRotateLastProbe = $null } catch { }
            try { $script:postStartSnapshotEnabled = $false } catch { }
            try { $script:postStartSnapshotDone = $false } catch { }
            try { $script:postStartSnapshotNextCheckAt = $null } catch { }

            try {
                $script:networkProfileKey = Get-NetworkProfileKey
                Write-Log ("BotProfile: key={0}" -f $script:networkProfileKey)
            } catch {
                $script:networkProfileKey = ''
            }
            $script:autoTunedAggressive = $false
            $script:autoTunedQuic = $false
            $script:autoTunedGameFilter = $false
            $script:gameFilterOverride = $null
            $script:lastRobloxIngestion = $null
            $script:postStartDeadline = $null
            $script:postStartNotBefore = $null
            $script:postStartLastCheckAt = $null
            $script:postStartLastSummary = $null
            $script:postStartTwitterTuned = $false
            $script:postStartRobloxRetried = $false
            $script:activeLogPath = $logPath
            try { Clear-CurrentLogs } catch { }
            try { if ($launcherLogBox) { $launcherLogBox.Text = "" } } catch { }
            try { Cleanup-LegacyRunLogs } catch { }

            try { if ($mainTabs -and $logsTab) { $mainTabs.SelectedTab = $logsTab } } catch { }

            if (-not (Ensure-DGenEngineReady)) {
                return
            }

            try {
                if (-not (Ensure-IpsetAllHealthy)) {
                    Write-Log "IpsetAll: continuing anyway (reduced universality)"
                }
            } catch {
                Write-Log "IpsetAll check failed: $($_.Exception.Message)"
            }

            try {
                # WinDivert services may be left RUNNING briefly after Stop; best-effort stop them without treating as a hard conflict.
                try {
                    $ok = Stop-WinDivertServices -waitMs 4000
                    if (-not $ok) { Write-Log "Start: WinDivert still running after stop attempt; continuing." }
                } catch { }

                $conflicting = @()
                try {
                    # Generic conflict detection (anti-brand): look for RUNNING services whose executable folder
                    # contains WinDivert binaries. These services often conflict with D-Gen.
                    $runningSvcs = @(Get-Service -ErrorAction Stop | Where-Object { $_.Status -eq 'Running' })
                    foreach ($svc in $runningSvcs) {
                        try {
                            if ($svc.Name -like 'WinDivert*') { continue }
                            if ($svc.Name -eq 'DGen') { continue }

                            $img = $null
                            try {
                                $img = (Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}" -f $svc.Name) -ErrorAction Stop).ImagePath
                            } catch { }

                            if (-not $img) { continue }

                            $raw = [Environment]::ExpandEnvironmentVariables([string]$img).Trim()
                            $exe = $null
                            if ($raw.StartsWith('"')) {
                                $end = $raw.IndexOf('"', 1)
                                if ($end -gt 1) { $exe = $raw.Substring(1, $end - 1) }
                            } else {
                                $exe = ($raw -split '\s+')[0]
                            }

                            if (-not $exe) { continue }
                            if ($exe -match '^[A-Za-z]:\\Windows\\') { continue }
                            if (-not (Test-Path -LiteralPath $exe)) { continue }

                            $dir = Split-Path -Parent $exe
                            $hasWinDivert = $false
                            try {
                                $hasWinDivert = (
                                    (Test-Path -LiteralPath (Join-Path $dir 'WinDivert.dll')) -or
                                    (Test-Path -LiteralPath (Join-Path $dir 'WinDivert64.sys')) -or
                                    (Test-Path -LiteralPath (Join-Path $dir 'WinDivert.sys'))
                                )
                            } catch { }

                            if ($hasWinDivert) { $conflicting += $svc }
                        } catch { }
                    }
                } catch { }

                if ($conflicting.Count -gt 0) {
                    $lines = ($conflicting | ForEach-Object { " - $($_.Name) ($($_.Status))" }) -join "`r`n"
                    Write-Log ("Conflict: detected running services: {0}" -f (($conflicting | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join ', '))

                    $msg = "Detected potentially conflicting services:`r`n$lines`r`n`r`nThey can break D-Gen and cause false `"score ok`" while apps still fail.`r`nStop them, then press Start again.`r`n`r`nContinue anyway?"
                    $resp = [System.Windows.Forms.MessageBox]::Show($msg, 'D-Gen', 'YesNo', 'Warning')
                    if ($resp -ne 'Yes') {
                        $statusLabel.Text = 'Blocked: conflicts'
                        try { Hide-LoadingOverlay } catch { }
                        try { Restore-WindowsProxyIfNeeded } catch { }
                        return
                    }
                }
            } catch {
                Write-Log "Conflict detection failed: $($_.Exception.Message)"
            }

            if ($proxyFixChk.Checked) {
                try {
                    Disable-WindowsProxyTemporarily
                } catch {
                    Write-Log "Proxy: disable failed: $($_.Exception.Message)"
                }
            }

            if ($quicBlockChk.Checked) {
                try { Enable-QuicBlock } catch { }
            }

            if ($smartModeChk.Checked) {
                $statusLabel.Text = "Smart Mode: updating lists..."
                try { Set-LoadingOverlayText "Smart Mode: updating lists..." 20 } catch { }
                [System.Windows.Forms.Application]::DoEvents()
                SmartMode-UpdateDiscordLists
            }

            try {
                $wantsRoblox = $false
                if ($cfg -and ($cfg.PSObject.Properties.Name -contains 'domains') -and $cfg.domains) {
                    foreach ($d in @($cfg.domains)) {
                        $t = ([string]$d).ToLower().Trim()
                        if (-not $t) { continue }
                        if ($t -eq 'roblox.com' -or $t.EndsWith('.roblox.com') -or $t -eq 'rbxcdn.com' -or $t.EndsWith('.rbxcdn.com') -or $t -eq 'robloxapis.com' -or $t.EndsWith('.robloxapis.com')) {
                            $wantsRoblox = $true
                            break
                        }
                    }
                }

                if ($wantsRoblox) {
                    $statusLabel.Text = "Roblox: scanning logs..."
                    try { Set-LoadingOverlayText "Roblox: scanning logs..." 30 } catch { }
                    [System.Windows.Forms.Application]::DoEvents()

                    $rob = Get-RobloxEndpointsFromRecentLogs
                    if (-not $rob) {
                        Write-Log "Roblox ingestion: logs not found yet (run Roblox once to generate logs)"
                    } else {
                        $hosts = @($rob.Hosts)
                        $ips = @($rob.Ips)

                        if (($hosts.Count -eq 0) -and ($ips.Count -eq 0)) {
                            Write-Log "Roblox ingestion: no endpoints found in recent logs"
                        } else {
                            $addedDomains = 0
                            $addedIps = 0

                            if ($hosts.Count -gt 0) {
                                $addedDomains = Add-UniqueLines -path $listGeneralPath -lines $hosts -encoding "UTF8"
                                $addedIps += Update-IpsetAllFromHosts -hosts $hosts
                            }
                            if ($ips.Count -gt 0) {
                                $addedIps += Update-IpsetAllFromIps -ips $ips
                            }

                            $script:lastRobloxIngestion = [pscustomobject]@{
                                HostsFound = $hosts.Count
                                IpsFound = $ips.Count
                                AddedDomains = $addedDomains
                                AddedIps = $addedIps
                                SampleHosts = (@($hosts | Select-Object -First 6) -join ',')
                                SampleIps = (@($ips | Select-Object -First 6) -join ',')
                                Sample = $rob.Sample
                            }

                            Write-Log ("Roblox ingestion: hostsFound={0} ipsFound={1} addedDomains={2} addedIps={3} sampleHosts=[{4}] sampleIps=[{5}]" -f $hosts.Count, $ips.Count, $addedDomains, $addedIps, $script:lastRobloxIngestion.SampleHosts, $script:lastRobloxIngestion.SampleIps)

                            $needWidePorts = $false
                            try { if ($rob -and ($rob.PSObject.Properties.Name -contains 'Has277') -and $rob.Has277) { $needWidePorts = $true } } catch { }
                            try { if ($rob -and ($rob.PSObject.Properties.Name -contains 'Has279') -and $rob.Has279) { $needWidePorts = $true } } catch { }
                            try { if ($rob -and ($rob.PSObject.Properties.Name -contains 'Has529') -and $rob.Has529) { $needWidePorts = $true } } catch { }

                            if ($needWidePorts -and (-not $script:gameFilterOverride)) {
                                $script:gameFilterOverride = '1024-65535'
                                Write-Log "Roblox ingestion: detected 277/279/529 in logs; enabling GameFilter=1024-65535 for this run"
                            }
                        }
                    }
                }
            } catch {
                Write-Log "Roblox ingestion failed: $($_.Exception.Message)"
            }

            # Engine-side autopick: launcher doesn't do target scoring / strategy selection here.
            Write-Log "Preflight: skipped (engine autopick)"

            Write-Log "New run: $($script:runId)"

            $statusLabel.Text = "Generating..."
            try { Set-LoadingOverlayText "Generating..." 45 } catch { }
            $script:generatorStartedAt = Get-Date
            $script:generatorProc = Run-Generator -cfg $cfg -runId $script:runId

            $script:strategies = @()
            $script:strategyIndex = 0
            $script:waitUntil = $null
            $script:strategyRunnerProc = $null
            $script:startState = "Generating"

            Update-ToggleButton
            Refresh-Logs
            return
        }

        $statusLabel.Text = "Stopping..."

        if ($script:generatorProc -and (-not $script:generatorProc.HasExited)) {
            try { Kill-ProcessTree -processId $script:generatorProc.Id } catch { }
        }
        if ($script:strategyRunnerProc -and (-not $script:strategyRunnerProc.HasExited)) {
            try { Kill-ProcessTree -processId $script:strategyRunnerProc.Id } catch { }
        }

        $script:startState = "Idle"
        $script:generatorProc = $null
        $script:strategies = @()
        $script:strategyIndex = 0
        $script:waitUntil = $null
        $script:strategyRunnerProc = $null

        Stop-All

        try { Disable-QuicBlock } catch { }

        try { Restore-WindowsProxyIfNeeded } catch { }

        $statusLabel.Text = "Stopped"
        Update-ToggleButton
    } catch {
        $msg = $_.Exception.Message
        $statusLabel.Text = "Error: $msg"
        Write-Log "Toggle error: $msg"
        [System.Windows.Forms.MessageBox]::Show($msg, "D-Gen", 'OK', 'Error') | Out-Null
        $script:startState = "Idle"
        try { Hide-LoadingOverlay } catch { }
        Update-ToggleButton
    } finally {
        try { $script:uiBusy = $false } catch { }
        $toggleBtn.Enabled = $true
        Refresh-Views
        Refresh-Logs
    }
})

if ($logBtn) {
    $logBtn.Add_Click({
        $mainTabs.SelectedTab = $logsTab
    })
}

$closeBtn.Add_Click({ $form.Close() })

$form.Add_FormClosing({
    try {
        try { Hide-LoadingOverlay } catch { }
        try { if ($timer) { $timer.Stop(); $timer.Dispose() } } catch { }
        try { Dispose-LoadingOverlayResources } catch { }

        Stop-All
        try { Disable-QuicBlock } catch { }
    } catch {
    }
})

$form.Add_Shown({
    try {
        $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        $form.ShowInTaskbar = $true
        $form.Text = "D-Gen Launcher"

        $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
        $pad = 40
        if (($form.Right -lt ($wa.Left + $pad)) -or ($form.Left -gt ($wa.Right - $pad)) -or ($form.Bottom -lt ($wa.Top + $pad)) -or ($form.Top -gt ($wa.Bottom - $pad))) {
            $form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
            $form.Location = New-Object System.Drawing.Point(($wa.Left + 80), ($wa.Top + 80))
        }

        $form.BringToFront() | Out-Null
        $form.Activate() | Out-Null
        $form.TopMost = $true
        $form.TopMost = $false
    } catch { }

})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    if ($script:uiBusy) { return }
    try { $script:uiBusy = $true } catch { }
    try {
        Refresh-Views
        Refresh-Logs
        Update-DGenSummaryJsonIfNeeded
        Tick-StartState
    } finally {
        try { $script:uiBusy = $false } catch { }
    }
})
$timer.Start()

[System.Windows.Forms.Application]::EnableVisualStyles()
Refresh-Views
Refresh-Logs
[System.Windows.Forms.Application]::Run($form)

} catch {
    $full = ($_ | Out-String)
    $msg = $full
    if ($msg.Length -gt 900) { $msg = $msg.Substring(0, 900) + "..." }

    try {
        $logsDir = Join-Path $PSScriptRoot 'logs'
        if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir | Out-Null }
        $errPath = Join-Path $logsDir 'launcher-startup.error.log'
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::AppendAllText($errPath, ("`r`n==== " + (Get-Date -Format o) + " ====`r`n" + $full), $utf8NoBom)
    } catch { }

    try {
# D-Gen | https://t.me/DisappearGen
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show($msg, 'D-Gen', 'OK', 'Error') | Out-Null
    } catch { }

    exit 1
}
