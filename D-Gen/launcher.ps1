param(
    # Kept for backwards-compat with older entrypoints, but intentionally unused now.
    [switch]$AutoStart,

    # Debug-only: allow launching UI without triggering UAC elevation.
    # Not used by oneclick-local; only helpful for automated screenshot capture / local debugging.
    [switch]$NoElevate,

    # Debug-only: lets us open the launcher on a specific view for screenshots.
    [ValidateSet('Logs', 'Status')]
    [string]$InitialView = 'Logs'
)

try {

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

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
$script:activeLogPath = $logPath
$defaultGeneratorOutPath = Join-Path $logsDir "dgen-generator.stdout.log"
$defaultGeneratorErrPath = Join-Path $logsDir "dgen-generator.stderr.log"
$defaultStrategyOutPath = Join-Path $logsDir "dgen-strategy.stdout.log"
$defaultStrategyErrPath = Join-Path $logsDir "dgen-strategy.stderr.log"
$powershellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$targetUrls = @(
    "https://www.youtube.com/generate_204",
    "https://discord.com/app",
    # Discord Desktop main websocket gateway (Desktop can show black screen if this is blocked)
    "https://gateway.discord.gg/?v=10&encoding=json",
    # Discord Desktop updater manifest endpoint (from %APPDATA%\discord\logs)
    "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=win&arch=x64"
)

if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir | Out-Null }

function Clear-CurrentLogs {
    try {
        if ($launcherLogBox) { $launcherLogBox.Clear() }
        if ($generatorLogBox) { $generatorLogBox.Clear() }
        if ($strategyLogBox) { $strategyLogBox.Clear() }
    } catch { }

    # Also truncate the current log files (best-effort)
    # Main launcher log is written by Write-Log into $script:activeLogPath.
    try { "" | Set-Content -Encoding UTF8 -Path $script:activeLogPath } catch { }
    try { "" | Set-Content -Encoding UTF8 -Path $script:generatorOutPath } catch { }
    try { "" | Set-Content -Encoding UTF8 -Path $script:generatorErrPath } catch { }
    try { "" | Set-Content -Encoding UTF8 -Path $script:strategyOutPath } catch { }
    try { "" | Set-Content -Encoding UTF8 -Path $script:strategyErrPath } catch { }
}

function Clear-DiscordCache {
    # Safe cache reset (backs up folders with timestamp)
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
            AutoConfigURL = [string]($p.AutoConfigURL)
        }
    } catch {
        return [pscustomobject]@{ ProxyEnable = 0; ProxyServer = ''; AutoConfigURL = '' }
    }
}

function Get-LoopbackProxyEndpoint {
    param([string]$proxyServer)

    if (-not $proxyServer) { return $null }
    # Typical formats:
    # - 127.0.0.1:8881
    # - http=127.0.0.1:8881;https=127.0.0.1:8881
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
        if (-not $ar.AsyncWaitHandle.WaitOne($timeoutMs, $false)) {
            return [pscustomobject]@{ Ok = $false; Error = "timeout" }
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

    if ($st.ProxyEnable -ne 1) {
        Write-Log 'Proxy: not enabled; nothing to disable'
        return
    }

    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    Set-ItemProperty -Path $reg -Name ProxyEnable -Value 0
    Write-Log ("Proxy: disabled temporarily (restore on Stop). Previous: enable={0} server={1}" -f $st.ProxyEnable, $st.ProxyServer)
}

function Restore-WindowsProxyIfNeeded {
    if (-not $script:proxySaved -or -not $script:proxySavedState) { return }

    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    try {
        Set-ItemProperty -Path $reg -Name ProxyEnable -Value $script:proxySavedState.ProxyEnable
        Set-ItemProperty -Path $reg -Name ProxyServer -Value $script:proxySavedState.ProxyServer
        Set-ItemProperty -Path $reg -Name AutoConfigURL -Value $script:proxySavedState.AutoConfigURL
        Write-Log ("Proxy: restored. enable={0} server={1}" -f $script:proxySavedState.ProxyEnable, $script:proxySavedState.ProxyServer)
    } catch {
        Write-Log "Proxy: restore failed: $($_.Exception.Message)"
    } finally {
        $script:proxySaved = $false
        $script:proxySavedState = $null
    }
}

function Get-DiscordFailureHostsFromRecentLogs {
    # Parse recent Discord logs and extract hostnames from *error* lines.
    # This targets the real symptom we saw before (reqwest/hyper tcp connect refused 10061).
    $logDir = Get-DiscordLogDir
    if (-not $logDir) { return @() }

    $files = @(Get-ChildItem -LiteralPath $logDir -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3)
    if (-not $files -or $files.Count -eq 0) { return @() }

    $hosts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $sample = $null

    $now = [DateTimeOffset]::Now

    $rxUrl = [regex]'https?://([a-zA-Z0-9.-]+)'
    $rxDomain = [regex]'Domain\("([a-zA-Z0-9.-]+)"\)'
    $rxBad = [regex]'10061|ConnectionRefused|tcp connect|connect error|ETIMEDOUT|timed out|timeout|reset|handshake|TLS|CERT'

    foreach ($f in $files) {
        $lines = @()
        try { $lines = Get-Content -LiteralPath $f.FullName -Tail 4000 -ErrorAction Stop } catch { continue }

        foreach ($line in $lines) {
            if (-not $rxBad.IsMatch($line)) { continue }

            # Try to parse Discord log timestamp, only react to recent errors.
            # Example: [2025-12-30 00:18:19.150825 +03:00] ERROR ...
            if ($line -match '^\[([^\]]+)\]') {
                try {
                    $ts = [DateTimeOffset]::Parse($Matches[1])
                    if (($now - $ts).TotalSeconds -gt 180) { continue }
                } catch { }
            }

            if (-not $sample) {
                $sample = if ($line.Length -gt 220) { $line.Substring(0, 220) + '...' } else { $line }
            }

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

    return [pscustomobject]@{
        Hosts = (@($hosts) | Where-Object { $_ -and $_.Contains('.') -and $_ -notmatch '^(localhost|127\.)' } | Sort-Object -Unique)
        Sample = $sample
    }
}

function Get-DiscordProcessSnapshot {
    $names = @('Discord', 'Update')
    $procs = @()
    foreach ($n in $names) {
        try {
            $procs += @(Get-Process -Name $n -ErrorAction SilentlyContinue)
        } catch { }
    }

    return $procs
}

function Test-DiscordUpdaterManifest {
    $url = $targetUrls[3]
    return Test-HttpUrl -url $url -timeoutMs 4000
}

function Get-DiscordBinaryPaths {
    $paths = [System.Collections.Generic.List[string]]::new()

    # Update.exe (common)
    $updateExe = Join-Path $env:LOCALAPPDATA 'Discord\Update.exe'
    if (Test-Path $updateExe) { $paths.Add($updateExe) | Out-Null }

    # Discord.exe under app-* folders
    $discordDir = Join-Path $env:LOCALAPPDATA 'Discord'
    if (Test-Path $discordDir) {
        try {
            $appDirs = Get-ChildItem -LiteralPath $discordDir -Directory -Filter 'app-*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending
            foreach ($d in $appDirs | Select-Object -First 3) {
                $exe = Join-Path $d.FullName 'Discord.exe'
                if (Test-Path $exe) { $paths.Add($exe) | Out-Null }
            }
        } catch { }
    }

    # Also try currently running processes (if any)
    foreach ($p in (Get-DiscordProcessSnapshot)) {
        try {
            $exe = $p.Path
            if ($exe -and (Test-Path $exe)) { $paths.Add($exe) | Out-Null }
        } catch { }
    }

    return @($paths) | Sort-Object -Unique
}

function Ensure-DiscordFirewallAllows {
    # Creates outbound allow rules for Discord binaries (best-effort).
    $bins = @(Get-DiscordBinaryPaths)
    if (-not $bins -or $bins.Count -eq 0) {
        Write-Log 'FirewallFix: no Discord binaries found to allow'
        return
    }

    foreach ($bin in $bins) {
        $name = "D-Gen Allow Discord Out: $([IO.Path]::GetFileName($bin))"
        try {
            $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Log "FirewallFix: rule already exists: $name"
                continue
            }
        } catch { }

        try {
            New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Allow -Program $bin -Enabled True -Profile Any | Out-Null
            Write-Log "FirewallFix: added outbound allow rule for $bin"
        } catch {
            Write-Log "FirewallFix: failed to add rule for ${bin}: $($_.Exception.Message)"
        }
    }
}

function AutoRecover-Tick {
    try {
        if (-not $autoRecoverChk.Checked) { return }
        if (-not $script:startState -or $script:startState -ne 'Running') { return }

        $procs = @(Get-DiscordProcessSnapshot)
        if (-not $procs -or $procs.Count -eq 0) {
            $script:autoRecoverFailCount = 0
            return
        }

        # throttle checks to avoid spamming network and logs
        $now = Get-Date
        if ($script:autoRecoverLastCheckAt -and ($now - $script:autoRecoverLastCheckAt).TotalSeconds -lt 5) { return }
        $script:autoRecoverLastCheckAt = $now

        $bad = Get-DiscordFailureHostsFromRecentLogs
        $badHosts = @()
        $badSample = $null
        if ($bad) {
            $badHosts = @($bad.Hosts)
            $badSample = $bad.Sample
        }

        if (-not $badHosts -or $badHosts.Count -eq 0) {
            # As a secondary signal, still keep an updater-manifest probe.
            $r = Test-DiscordUpdaterManifest
            if ($r.Ok) {
                $script:autoRecoverFailCount = 0
                return
            }
            $script:autoRecoverFailCount++
            Write-Log ("AutoRecover: updater check failed (n={0}) code={1} err={2}" -f $script:autoRecoverFailCount, $r.StatusCode, $r.Error)
        } else {
            $script:autoRecoverFailCount++
            $sampleSuffix = if ($badSample) { ' sample="' + $badSample + '"' } else { '' }
            Write-Log ("AutoRecover: detected Discord network failures (n={0}) hosts={1}{2}" -f $script:autoRecoverFailCount, ($badHosts -join ', '), $sampleSuffix)
        }

        # If a local loopback proxy is enabled but not reachable, Discord Desktop/Updater may fail with 10061.
        try {
            $proxy = Get-UserProxySettings
            if ($proxy.ProxyEnable -eq 1) {
                $ep = Get-LoopbackProxyEndpoint -proxyServer $proxy.ProxyServer
                if ($ep) {
                    $probe = Test-TcpConnect -hostName $ep.Host -port $ep.Port -timeoutMs 500
                    if (-not $probe.Ok) {
                        Write-Log ("Proxy warning: enabled but not reachable: {0}:{1} err={2}" -f $ep.Host, $ep.Port, $probe.Error)
                        if ($proxyFixChk.Checked) {
                            Disable-WindowsProxyTemporarily
                        }
                    }
                }
            }
        } catch {
            Write-Log "Proxy warning: check failed: $($_.Exception.Message)"
        }

        # action only after a few consecutive failures and with cooldown
        if ($script:autoRecoverFailCount -lt 3) { return }
        if ($script:autoRecoverLastActionAt -and ($now - $script:autoRecoverLastActionAt).TotalSeconds -lt 60) { return }

        $script:autoRecoverLastActionAt = $now
        $script:autoRecoverFailCount = 0

        Write-Log "AutoRecover: taking action (SmartMode + extend-from-errors + restart selection)"

        # If Discord logs claim updater failures but our own updater-manifest check is OK,
        # it's likely a process-specific block (e.g., Windows Firewall). Try to fix that.
        try {
            if ($fwFixChk.Checked) {
                $manifest = Test-DiscordUpdaterManifest
                if ($manifest.Ok) {
                    Write-Log 'AutoRecover: manifest ok in launcher, attempting FirewallFix for Discord/Update'
                    Ensure-DiscordFirewallAllows
                }
            }
        } catch {
            Write-Log "AutoRecover: FirewallFix failed: $($_.Exception.Message)"
        }

        try {
            if ($smartModeChk.Checked) {
                SmartMode-UpdateDiscordLists
            }
        } catch {
            Write-Log "AutoRecover: SmartMode failed: $($_.Exception.Message)"
        }

        # Always extend lists from the actual failing hosts extracted from logs.
        try {
            $badNow = Get-DiscordFailureHostsFromRecentLogs
            $badHostsNow = @()
            if ($badNow) { $badHostsNow = @($badNow.Hosts) }
            if ($badHostsNow -and $badHostsNow.Count -gt 0) {
                $addedDomains = Add-UniqueLines -path $listGeneralPath -lines $badHostsNow -encoding "UTF8"
                $addedIps = Update-IpsetAllFromHosts -hosts $badHostsNow
                Write-Log "AutoRecover: extended lists from errors: hosts=$($badHostsNow.Count) addedDomains=$addedDomains addedIps=$addedIps"
            }
        } catch {
            Write-Log "AutoRecover: extend-from-errors failed: $($_.Exception.Message)"
        }

        # restart strategy selection (keep generator output as-is; focus on winws)
        # Make sure we don't leave a strategy runner holding log file handles.
        if ($script:strategyRunnerProc -and (-not $script:strategyRunnerProc.HasExited)) {
            try { Kill-ProcessTree -processId $script:strategyRunnerProc.Id } catch { }
        }
        $script:strategyRunnerProc = $null

        Stop-Winws
        $script:strategies = @(Get-StrategyFiles)
        $script:strategyIndex = 0
        $script:waitUntil = $null
        $script:strategyRunnerProc = $null
        $script:startState = 'Selecting'
        Update-ToggleButton
        Write-Log "AutoRecover: restarted strategy selection"
    } catch {
        Write-Log "AutoRecover internal error: $($_.Exception.Message)"
    }
}

function Write-Log {
    param([string]$msg)
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    "$stamp | $msg" | Add-Content -Path $script:activeLogPath -Encoding UTF8
}

function Reset-TextLog {
    param([string]$path)
    "" | Set-Content -Path $path -Encoding UTF8
}

function Read-LogTail {
    param(
        [string]$path,
        [int]$maxChars = 250000
    )

    if (-not (Test-Path $path)) { return "" }

    try {
        $text = Get-Content -Path $path -Raw -ErrorAction Stop
    } catch {
        return ""
    }

    if ($null -eq $text) { return "" }
    if ($text.Length -le $maxChars) { return $text }

    # Show a preview that includes the beginning (often most valuable for debugging),
    # plus the end (latest lines). This avoids the "can't see the start" problem when the
    # log grows beyond a small tail window.
    $marker = "`r`n... [log truncated: showing beginning and end; open log file for full content] ...`r`n"
    $headLen = [Math]::Max(0, [int]($maxChars * 0.6))
    $tailLen = [Math]::Max(0, $maxChars - $headLen - $marker.Length)
    if ($tailLen -lt 0) { $tailLen = 0 }

    $head = $text.Substring(0, [Math]::Min($headLen, $text.Length))
    $tail = if ($tailLen -gt 0) { $text.Substring($text.Length - $tailLen) } else { "" }
    return $head + $marker + $tail
}

function Can-OverwriteTextBox {
    param($tb)
    try {
        if (-not $tb) { return $false }
        if (-not $tb.Focused) { return $true }
        # If user is actively selecting / scrolling in the box, don't fight them with timer refreshes.
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

    Start-Process -FilePath $powershellExe -ArgumentList $selfArgs -Verb RunAs -WindowStyle Hidden | Out-Null
}

$script:isAdmin = Test-IsAdmin

# UX: If elevation is required, request it immediately on launcher start (not on Start click).
if (-not $script:isAdmin -and -not $NoElevate) {
    Restart-Elevated
    exit
}

# Helps confirm which launcher.ps1 build is actually running when users paste logs.
Write-Log "Launcher build: 2025-12-30 (updater-manifest http-check + detailed diagnostics)"

if (-not (Test-Path $generatorPath)) { Fail "Generator not found: $generatorPath" }
if (-not (Test-Path $strategiesDir)) { Fail "Strategies folder not found: $strategiesDir" }

if (-not (Test-Path $configPath)) {
    $default = @{
        domains = @("discord.com", "youtube.com")
        targetDescription = "D-Gen launcher default"
        strategy = "strategies\\general.bat"
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

function Kill-ProcessTree {
    param([int]$processId)
    & taskkill.exe /PID $processId /T /F | Out-Null
}

function Stop-Winws {
    $pids = @(Get-Process -Name "winws" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    foreach ($procId in $pids) {
        try { Kill-ProcessTree -processId $procId } catch { }
    }
}

function Test-HttpUrl {
    param(
        [string]$url,
        [int]$timeoutMs = 6000
    )

    $client = $null
    try {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromMilliseconds($timeoutMs)

        $resp = $client.GetAsync($url).GetAwaiter().GetResult()
        $code = [int]$resp.StatusCode

        return [pscustomobject]@{ Ok = $true; StatusCode = $code; Error = "" }
    } catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg = $msg + " | inner=" + $_.Exception.InnerException.Message }
        return [pscustomobject]@{ Ok = $false; StatusCode = 0; Error = $msg }
    } finally {
        if ($client) { try { $client.Dispose() } catch { } }
    }
}

function Test-TargetsDetailed {
    param([string[]]$Urls)

    foreach ($u in $Urls) {
        try {
            $uri = [Uri]$u
            $h = $uri.DnsSafeHost
            $p = $uri.Port

            $r = Test-HttpUrl -url $u
            if (-not $r.Ok) {
                return [pscustomobject]@{
                    Ok = $false
                    Url = $u
                    Host = $h
                    Port = $p
                    StatusCode = $r.StatusCode
                    Error = $r.Error
                }
            }

            # For diagnostics (visible in dgen-launch.log via per-strategy logging)
            Write-Log ("Target ok: url={0} code={1}" -f $u, $r.StatusCode)
        } catch {
            return [pscustomobject]@{
                Ok = $false
                Url = $u
                Host = ""
                Port = 0
                StatusCode = 0
                Error = $_.Exception.Message
            }
        }
    }

    return [pscustomobject]@{ Ok = $true }
}

function Test-Targets {
    param([string[]]$Urls)
    return (Test-TargetsDetailed -Urls $Urls).Ok
}

function Run-Generator {
    param(
        $cfg,
        [string]$runId
    )

    if (-not $runId) { throw "runId is required for generator logs." }

    $script:generatorOutPath = Join-Path $logsDir "dgen-generator.$runId.stdout.log"
    $script:generatorErrPath = Join-Path $logsDir "dgen-generator.$runId.stderr.log"

    New-Item -ItemType File -Path $script:generatorOutPath -Force | Out-Null
    New-Item -ItemType File -Path $script:generatorErrPath -Force | Out-Null

    $args = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", $generatorPath,
        "-Domains"
    )

    if ($cfg.domains) { $args += $cfg.domains }
    if ($cfg.targetDescription) { $args += @("-TargetDescription", $cfg.targetDescription) }

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

function Update-IpsetAllFromHosts {
    param([string[]]$hosts)

    if (-not $hosts -or $hosts.Count -eq 0) { return 0 }
    if (-not (Test-Path $ipsetAllPath)) { "" | Out-File -FilePath $ipsetAllPath -Encoding ASCII }

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
                $cidr = if ($type -eq 'A') { "$ip/32" } else { "$ip/128" }
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

        Write-Log "Smart Mode: hostsFromLogs=$($hosts.Count), addedDomains=$addedDomains, addedIps=$addedIps"
    } catch {
        Write-Log "Smart Mode error: $($_.Exception.Message)"
    }
}

function Get-StrategyFiles {
    Get-ChildItem -Path $strategiesDir -Filter "general*.bat" -File | Sort-Object Name
}

function Start-StrategyFile {
    param(
        [System.IO.FileInfo]$strategyFile,
        [int]$attemptIndex,
        [string]$runId
    )

    if (-not $runId) { throw "runId is required for strategy logs." }

    # Use a monotonically increasing attempt id for log filenames.
    # AutoRecover can restart selection and re-use attemptIndex=0; this avoids log-file locking collisions.
    $attemptTag = ("{0:D4}" -f [int]$script:strategyAttemptSeq)
    $script:strategyAttemptSeq++

    $script:strategyOutPath = Join-Path $logsDir ("dgen-strategy.{0}.try{1}.stdout.log" -f $runId, $attemptTag)
    $script:strategyErrPath = Join-Path $logsDir ("dgen-strategy.{0}.try{1}.stderr.log" -f $runId, $attemptTag)

    New-Item -ItemType File -Path $script:strategyOutPath -Force | Out-Null
    New-Item -ItemType File -Path $script:strategyErrPath -Force | Out-Null

    Write-Log "Starting strategy: $($strategyFile.FullName) (try=$attemptTag)"
    $cmdExe = Join-Path $env:SystemRoot "System32\cmd.exe"
    $cmdArgs = @("/c", "`"$($strategyFile.FullName)`"")
    $proc = Start-Process -FilePath $cmdExe -ArgumentList $cmdArgs -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput $script:strategyOutPath -RedirectStandardError $script:strategyErrPath
    return $proc
}

function Start-BestStrategy {
    param($cfg)

    $strategies = @(Get-StrategyFiles)
    if (-not $strategies -or $strategies.Count -eq 0) {
        throw "No strategy files found in $strategiesDir"
    }

    $chosen = $null

    if (-not $script:runId) {
        $script:runId = New-RunId
        Write-Log "New run: $($script:runId)"
    }

    $attempt = 0
    foreach ($s in $strategies) {
        $statusLabel.Text = "Trying: $($s.Name)"
        [System.Windows.Forms.Application]::DoEvents()

        Stop-Winws
        Start-StrategyFile -strategyFile $s -attemptIndex $attempt -runId $script:runId
        $attempt++

        for ($i = 0; $i -lt 8; $i++) {
            Start-Sleep -Seconds 1
            [System.Windows.Forms.Application]::DoEvents()
        }

        if (Test-Targets -Urls $targetUrls) {
            $chosen = $s
            break
        }
    }

    if ($chosen) {
        Write-Log "Selected strategy: $($chosen.Name)"
        return $chosen
    }

    Write-Log "No strategy passed HTTP checks; leaving last started."
    return $strategies[-1]
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

function Stop-All {
    Write-Log "Stop requested"

    Stop-Winws

    Remove-ServiceIfExists -serviceName "zapret"
    Remove-ServiceIfExists -serviceName "WinDivert"
    Remove-ServiceIfExists -serviceName "WinDivert14"

    Stop-Winws

    Restore-WindowsProxyIfNeeded
}

function Refresh-Views {
    # Status view has been removed; guard against missing controls.
    if (-not $procList -or -not $serviceList) { return }

    # Processes: winws.exe
    $procList.Items.Clear()

    $procs = @()
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='winws.exe'" | Select-Object ProcessId, ExecutablePath, CommandLine
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

    # Avoid the "striped" look.
    try { $procList.GridLines = $false } catch { }
    if ($script:procEmptyLbl) {
        $empty = ($procList.Items.Count -eq 0)
        $script:procEmptyLbl.Visible = $empty
        $procList.Visible = -not $empty
        if ($empty) { try { $script:procEmptyLbl.BringToFront() } catch { } }
    }

    # Services
    $serviceList.Items.Clear()
    foreach ($name in @("zapret", "WinDivert", "WinDivert14")) {
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
            $statusLabel.Text = "Ready (debug: not elevated). winws: $($procs.Count)"
        } else {
            $statusLabel.Text = "Ready. winws processes: $($procs.Count)"
        }
    }

    try { Resize-StatusColumns } catch { }
}

function Refresh-Logs {
    $launcherText = Read-LogTail -path $script:activeLogPath
    if ((Can-OverwriteTextBox $launcherLogBox) -and ($launcherLogBox.Text -ne $launcherText)) { $launcherLogBox.Text = $launcherText }

    $genOut = Read-LogTail -path $script:generatorOutPath
    $genErr = Read-LogTail -path $script:generatorErrPath
    $genText = $genOut
    if ($genErr) { $genText = $genText + "`r`n`r`n--- STDERR ---`r`n" + $genErr }
    if ((Can-OverwriteTextBox $generatorLogBox) -and ($generatorLogBox.Text -ne $genText)) { $generatorLogBox.Text = $genText }

    $strOut = Read-LogTail -path $script:strategyOutPath
    $strErr = Read-LogTail -path $script:strategyErrPath
    $strText = $strOut
    if ($strErr) { $strText = $strText + "`r`n`r`n--- STDERR ---`r`n" + $strErr }
    if ((Can-OverwriteTextBox $strategyLogBox) -and ($strategyLogBox.Text -ne $strText)) { $strategyLogBox.Text = $strText }
}

# UI
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

$header = New-Object System.Windows.Forms.Panel
$header.Dock = [System.Windows.Forms.DockStyle]::Top
$header.AutoSize = $true
$header.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$header.Height = 0
$header.BackColor = $uiPanel
$header.Padding = New-Object System.Windows.Forms.Padding(16, 10, 16, 10)
$form.Controls.Add($header)

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

$closeBtn = New-Object System.Windows.Forms.Button
$closeBtn.Text = "Close"
$closeBtn.Size = New-Object System.Drawing.Size(90, 30)
$closeBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$closeBtn.FlatAppearance.BorderSize = 0
$closeBtn.BackColor = $uiPanel
$closeBtn.ForeColor = $uiMuted
$closeBtn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)

# View buttons will be inserted into $script:headerNav later (Status/Logs)
[void]$script:headerNav.Controls.Add($advancedBtn)
[void]$script:headerNav.Controls.Add($closeBtn)

$optionsPanel = New-Object System.Windows.Forms.Panel
$optionsPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$optionsPanel.Height = 44
$optionsPanel.BackColor = $uiPanel
$optionsPanel.Visible = $false
$form.Controls.Add($optionsPanel)

$optsFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$optsFlow.Dock = [System.Windows.Forms.DockStyle]::Fill
$optsFlow.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 8)
$optsFlow.WrapContents = $true
$optsFlow.AutoScroll = $true
$optsFlow.BackColor = $uiPanel
$optionsPanel.Controls.Add($optsFlow)

function Style-CheckBox($cb) {
    $cb.AutoSize = $true
    $cb.ForeColor = $uiFg
    $cb.BackColor = $uiPanel
    $cb.Margin = New-Object System.Windows.Forms.Padding(0, 0, 18, 0)
}

$smartModeChk = New-Object System.Windows.Forms.CheckBox
$smartModeChk.Text = "Smart Mode (Discord)"
$smartModeChk.Checked = $true
Style-CheckBox $smartModeChk
$optsFlow.Controls.Add($smartModeChk) | Out-Null

$autoRecoverChk = New-Object System.Windows.Forms.CheckBox
$autoRecoverChk.Text = "Auto-recover"
$autoRecoverChk.Checked = $true
Style-CheckBox $autoRecoverChk
$optsFlow.Controls.Add($autoRecoverChk) | Out-Null

$fwFixChk = New-Object System.Windows.Forms.CheckBox
$fwFixChk.Text = "Firewall allow (Discord)"
$fwFixChk.Checked = $true
Style-CheckBox $fwFixChk
$optsFlow.Controls.Add($fwFixChk) | Out-Null

$proxyFixChk = New-Object System.Windows.Forms.CheckBox
$proxyFixChk.Text = "Disable Windows Proxy (restore on Stop)"
$proxyFixChk.Checked = $false
Style-CheckBox $proxyFixChk
$optsFlow.Controls.Add($proxyFixChk) | Out-Null

# If a loopback system proxy is enabled but not reachable, Discord can fail (timeouts / 10061).
# Don't change system settings automatically; just pre-check the option to make Start a one-click recovery.
try {
    $px = Get-UserProxySettings
    if ($px.ProxyEnable -eq 1) {
        $ep = Get-LoopbackProxyEndpoint -proxyServer $px.ProxyServer
        if ($ep) {
            $probe = Test-TcpConnect -hostName $ep.Host -port $ep.Port -timeoutMs 500
            if (-not $probe.Ok) {
                $proxyFixChk.Checked = $true
                Write-Log ("Proxy: loopback proxy enabled but not reachable ({0}:{1}); pre-checking Disable Windows Proxy option" -f $ep.Host, $ep.Port)
            }
        }
    }
} catch { }

$advancedBtn.Add_Click({
    $optionsPanel.Visible = -not $optionsPanel.Visible
    $advancedBtn.ForeColor = if ($optionsPanel.Visible) { $uiAccent } else { $uiMuted }
})

$mainTabs = New-Object System.Windows.Forms.TabControl
$mainTabs.Dock = [System.Windows.Forms.DockStyle]::Fill

# Hide native tabs (they don't theme well in dark UI). We navigate via header buttons.
$mainTabs.Appearance = [System.Windows.Forms.TabAppearance]::FlatButtons
$mainTabs.ItemSize = New-Object System.Drawing.Size(0, 1)
$mainTabs.SizeMode = [System.Windows.Forms.TabSizeMode]::Fixed
$mainTabs.Multiline = $true

$form.Controls.Add($mainTabs)

$logsTab = New-Object System.Windows.Forms.TabPage
$logsTab.Text = "Logs"
$logsTab.BackColor = $uiBg
$logsTab.ForeColor = $uiFg
$mainTabs.TabPages.Add($logsTab) | Out-Null

# Status view removed (it wasn't providing useful info). Logs is the primary screen.
try { $mainTabs.SelectedTab = $logsTab } catch { }

# Quick Start panel (shown on clean machines; advanced options remain hidden under "Advanced")
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

# Placeholders for empty tables (prevents the "striped" empty grid look)
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
    $lines.Add("AutoRecover: " + [string]$autoRecoverChk.Checked) | Out-Null
    $lines.Add("FirewallFix: " + [string]$fwFixChk.Checked) | Out-Null
    $lines.Add("DisableProxy: " + [string]$proxyFixChk.Checked) | Out-Null
    try {
        $proxy = Get-UserProxySettings
        $lines.Add(("WindowsProxy: enable={0} server={1}" -f $proxy.ProxyEnable, $proxy.ProxyServer)) | Out-Null
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

# (Status view removed)
$logTabs = New-Object System.Windows.Forms.TabControl
$logTabs.Dock = [System.Windows.Forms.DockStyle]::Fill

$logsActions = New-Object System.Windows.Forms.Panel
$logsActions.Dock = [System.Windows.Forms.DockStyle]::Top
$logsActions.Height = 38
$logsActions.BackColor = $uiPanel
$logsTab.Controls.Add($logsActions)

# Logs action bar (prevents header overlap)
$logsActionsFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$logsActionsFlow.Dock = [System.Windows.Forms.DockStyle]::Fill
$logsActionsFlow.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4)
$logsActionsFlow.WrapContents = $false
$logsActionsFlow.AutoScroll = $true
$logsActionsFlow.BackColor = $uiPanel
$logsActions.Controls.Add($logsActionsFlow)

foreach ($b in @($openLogsBtn, $copyDiagBtn)) {
    try { $b.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0) } catch { }
    $logsActionsFlow.Controls.Add($b) | Out-Null
}

$clearLogsBtn = New-Object System.Windows.Forms.Button
$clearLogsBtn.Text = "Truncate logs"
$clearLogsBtn.Size = New-Object System.Drawing.Size(110, 28)
$clearLogsBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$clearLogsBtn.FlatAppearance.BorderSize = 0
$clearLogsBtn.BackColor = $uiPanel
$clearLogsBtn.ForeColor = $uiFg
$clearLogsBtn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
$logsActionsFlow.Controls.Add($clearLogsBtn) | Out-Null

$clearCacheBtn = New-Object System.Windows.Forms.Button
$clearCacheBtn.Text = "Clear Discord cache"
$clearCacheBtn.Size = New-Object System.Drawing.Size(150, 28)
$clearCacheBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$clearCacheBtn.FlatAppearance.BorderSize = 0
$clearCacheBtn.BackColor = $uiPanel
$clearCacheBtn.ForeColor = $uiFg
$clearCacheBtn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
$logsActionsFlow.Controls.Add($clearCacheBtn) | Out-Null

$clearLogsBtn.Add_Click({
    try { Clear-CurrentLogs } catch { }
})

$clearCacheBtn.Add_Click({
    try { Clear-DiscordCache } catch { }
})

$logsTab.Controls.Add($logTabs)

# Ensure actions bar stays visible above the log tabs (Dock + z-order)
try { $logsActions.BringToFront() } catch { }

$launcherLogTab = New-Object System.Windows.Forms.TabPage
$launcherLogTab.Text = "Launcher"
$logTabs.TabPages.Add($launcherLogTab) | Out-Null

$generatorLogTab = New-Object System.Windows.Forms.TabPage
$generatorLogTab.Text = "Generator"
$logTabs.TabPages.Add($generatorLogTab) | Out-Null

$strategyLogTab = New-Object System.Windows.Forms.TabPage
$strategyLogTab.Text = "Strategy"
$logTabs.TabPages.Add($strategyLogTab) | Out-Null

$launcherLogBox = New-Object System.Windows.Forms.TextBox
$launcherLogBox.Multiline = $true
$launcherLogBox.ReadOnly = $true
$launcherLogBox.ScrollBars = "Both"
$launcherLogBox.WordWrap = $false
$launcherLogBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$launcherLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$launcherLogBox.BackColor = $uiBg
$launcherLogBox.ForeColor = $uiFg
$launcherLogBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$launcherLogTab.Controls.Add($launcherLogBox)

$generatorLogBox = New-Object System.Windows.Forms.TextBox
$generatorLogBox.Multiline = $true
$generatorLogBox.ReadOnly = $true
$generatorLogBox.ScrollBars = "Both"
$generatorLogBox.WordWrap = $false
$generatorLogBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$generatorLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$generatorLogBox.BackColor = $uiBg
$generatorLogBox.ForeColor = $uiFg
$generatorLogBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$generatorLogTab.Controls.Add($generatorLogBox)

$strategyLogBox = New-Object System.Windows.Forms.TextBox
$strategyLogBox.Multiline = $true
$strategyLogBox.ReadOnly = $true
$strategyLogBox.ScrollBars = "Both"
$strategyLogBox.WordWrap = $false
$strategyLogBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$strategyLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$strategyLogBox.BackColor = $uiBg
$strategyLogBox.ForeColor = $uiFg
$strategyLogBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$strategyLogTab.Controls.Add($strategyLogBox)

$script:startState = "Idle"
$script:runId = $null
$script:generatorOutPath = $defaultGeneratorOutPath
$script:generatorErrPath = $defaultGeneratorErrPath
$script:strategyOutPath = $defaultStrategyOutPath
$script:strategyErrPath = $defaultStrategyErrPath
$script:generatorProc = $null
$script:strategies = @()
$script:strategyIndex = 0
$script:waitUntil = $null
$script:strategyRunnerProc = $null
$script:currentStrategyFile = $null

# Monotonic counter to avoid strategy log filename collisions when AutoRecover restarts selection.
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
            if (-not $script:generatorProc.HasExited) { return }

            $script:generatorProc = $null

            $statusLabel.Text = "Starting strategy..."
            $script:strategies = @(Get-StrategyFiles)
            if (-not $script:strategies -or $script:strategies.Count -eq 0) { throw "No strategy files found in $strategiesDir" }
            $script:strategyIndex = 0
            $script:waitUntil = $null
            $script:startState = "Selecting"
            return
        }

        if ($script:startState -eq "Selecting") {
            if ($script:strategyIndex -ge $script:strategies.Count) {
                $last = $script:strategies[-1]
                Write-Log "No strategy passed HTTP checks; leaving last started."
                $statusLabel.Text = "Running: $($last.Name)"
                Write-Log "Start done: $($last.Name)"
                $script:startState = "Running"
                Update-ToggleButton
                return
            }

            if ($null -eq $script:waitUntil) {
                $s = $script:strategies[$script:strategyIndex]
                $statusLabel.Text = "Trying: $($s.Name)"

                Stop-Winws
                if (-not $script:runId) {
                    $script:runId = New-RunId
                    Write-Log "New run: $($script:runId)"
                }
                $script:strategyRunnerProc = Start-StrategyFile -strategyFile $s -attemptIndex $script:strategyIndex -runId $script:runId
                $script:currentStrategyFile = $s
                $script:waitUntil = (Get-Date).AddSeconds(8)
                return
            }

            if ((Get-Date) -lt $script:waitUntil) { return }

            $check = Test-TargetsDetailed -Urls $targetUrls
            if ($check.Ok) {
                $chosen = $script:strategies[$script:strategyIndex]
                Write-Log "Selected strategy: $($chosen.Name)"
                $statusLabel.Text = "Running: $($chosen.Name)"
                Write-Log "Start done: $($chosen.Name)"

                $script:currentStrategyFile = $chosen

                $script:startState = "Running"
                Update-ToggleButton
                $script:waitUntil = $null
                return
            }

            if (-not $check.Ok) {
                Write-Log ("Target check failed: url={0} host={1}:{2} code={3} err={4}" -f $check.Url, $check.Host, $check.Port, $check.StatusCode, $check.Error)
            }

            $script:strategyIndex++
            $script:waitUntil = $null
            return
        }
    } catch {
        $msg = $_.Exception.Message
        $statusLabel.Text = "Error: $msg"
        Write-Log "Start error: $msg"
        [System.Windows.Forms.MessageBox]::Show($msg, "D-Gen", 'OK', 'Error') | Out-Null

        $script:startState = "Idle"
        $script:generatorProc = $null
        $script:strategies = @()
        $script:strategyIndex = 0
        $script:waitUntil = $null
        $script:strategyRunnerProc = $null

        $script:currentStrategyFile = $null
        $script:autoRecoverFailCount = 0
        $script:autoRecoverLastActionAt = $null
        $script:autoRecoverLastCheckAt = $null
        $toggleBtn.Enabled = $true
        Update-ToggleButton
    }
}

$toggleBtn.Add_Click({
    $toggleBtn.Enabled = $false

    try {
        if (-not $script:startState -or $script:startState -eq "Idle") {
            # New run id + per-run launcher log (clean logs per run)
            $script:runId = New-RunId
            # Keep a single active launcher log file and truncate it on each Start.
            # This keeps Logs view stable and prevents log files from accumulating.
            $script:activeLogPath = $logPath
            try { Reset-TextLog -path $script:activeLogPath } catch { }

            # Clean log views / current run log files
            try { Clear-CurrentLogs } catch { }

            # By this point we are already elevated (see startup Ensure-Admin behavior above).

            # Optional: if user-proxy is enabled but local proxy is down, Discord updater can fail (10061).
            # We only change system settings when explicitly requested.
            if ($proxyFixChk.Checked) {
                try {
                    Disable-WindowsProxyTemporarily
                } catch {
                    Write-Log "Proxy: disable failed: $($_.Exception.Message)"
                }
            }

            if ($smartModeChk.Checked) {
                $statusLabel.Text = "Smart Mode: updating lists..."
                [System.Windows.Forms.Application]::DoEvents()
                SmartMode-UpdateDiscordLists
            }
            Write-Log "New run: $($script:runId)"

            $statusLabel.Text = "Generating..."
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

        # Stop-All already restores proxy if we changed it, but do a best-effort restore anyway.
        try { Restore-WindowsProxyIfNeeded } catch { }

        $statusLabel.Text = "Stopped"
        Update-ToggleButton
    } catch {
        $msg = $_.Exception.Message
        $statusLabel.Text = "Error: $msg"
        Write-Log "Toggle error: $msg"
        [System.Windows.Forms.MessageBox]::Show($msg, "D-Gen", 'OK', 'Error') | Out-Null
        $script:startState = "Idle"
        Update-ToggleButton
    } finally {
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
        Stop-All
    } catch {
        # ignore on close
    }
})

$form.Add_Shown({
    # Make sure the window is brought to foreground (users reported "launcher doesn't open").
    try {
        $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        $form.ShowInTaskbar = $true
        $form.Text = "D-Gen Launcher"

        # If the window somehow ends up off-screen, move it back into the primary working area.
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
$timer.Add_Tick({ Refresh-Views; Refresh-Logs; Tick-StartState; AutoRecover-Tick })
$timer.Start()

[System.Windows.Forms.Application]::EnableVisualStyles()
Refresh-Views
Refresh-Logs
[System.Windows.Forms.Application]::Run($form)

} catch {
    $full = ($_ | Out-String)
    $msg = $full
    if ($msg.Length -gt 900) { $msg = $msg.Substring(0, 900) + "..." }

    # Best-effort: persist the full crash for debugging.
    try {
        $logsDir = Join-Path $PSScriptRoot 'logs'
        if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir | Out-Null }
        $errPath = Join-Path $logsDir 'launcher-startup.error.log'
        Add-Content -LiteralPath $errPath -Encoding UTF8 -Value ("`r`n==== " + (Get-Date -Format o) + " ====`r`n" + $full)
    } catch { }

    # Best-effort: surface the short message to the user.
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show($msg, 'D-Gen', 'OK', 'Error') | Out-Null
    } catch { }

    exit 1
}
