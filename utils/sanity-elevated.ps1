$ErrorActionPreference = 'Stop'

# Ensure System.Net.Http types are available in Windows PowerShell 5.1
try { Add-Type -AssemblyName System.Net.Http } catch { }

function Test-IsAdmin {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    $root = Split-Path -Parent $PSScriptRoot
    $powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $launcherArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`""
    )

    try {
        $p = Start-Process -FilePath $powershellExe -ArgumentList $launcherArgs -WorkingDirectory $root -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        exit $p.ExitCode
    } catch {
        throw ("Sanity: elevation was cancelled or failed.`r`n`r`n" + $_.Exception.Message)
    }
}

$root = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $root 'D-Gen\logs'
if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$stdoutLog = Join-Path $logDir "sanity-$ts.stdout.log"
$stderrLog = Join-Path $logDir "sanity-$ts.stderr.log"
$summaryLog = Join-Path $logDir "sanity-$ts.summary.txt"

function Write-Summary([string]$line) {
    $line | Out-File -FilePath $summaryLog -Encoding UTF8 -Append
}

Write-Summary ("[time] " + (Get-Date -Format o))
Write-Summary "[root] $root"
Write-Summary "[logs] $logDir"
Write-Summary "[out] stdout=$stdoutLog"
Write-Summary "[out] stderr=$stderrLog"

# Stop existing DGen instances (we'll run a clean sanity pass).
$existing = Get-Process -Name 'DGen' -ErrorAction SilentlyContinue
if ($existing) {
    Write-Summary "[dgen] stopping_existing count=$($existing.Count)"
    try { $existing | Stop-Process -Force } catch { Write-Summary "[dgen] stop_existing_error $($_.Exception.Message)" }
    Start-Sleep -Seconds 1
} else {
    Write-Summary "[dgen] stopping_existing count=0"
}

$exe = Join-Path $root 'bin\DGen.exe'
$binDir = Join-Path $root 'bin'
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Summary "[error] DGen.exe not found: $exe"
    exit 2
}

Write-Summary "[dgen] starting exe=$exe"

# Mimic launcher defaults so sanity exercises the real under-hood behavior.
try { $policyLua = Join-Path $root 'D-Gen\\policy.lua' } catch { $policyLua = '' }
if ($policyLua -and (Test-Path -LiteralPath $policyLua)) {
    $env:DGEN_POLICY_LUA = ([string]$policyLua).Replace('"', '')
}
$env:DGEN_AUTOPICK_SAVE = '1'
$env:DGEN_SKIP_UPDATE_CHECK = '1'

$proc = Start-Process -FilePath $exe -ArgumentList '--profile','auto' -WorkingDirectory $binDir -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru -WindowStyle Hidden
Write-Summary "[dgen] pid=$($proc.Id)"

# Wait for core signals.
$deadline = (Get-Date).AddSeconds(110)
$seenDecision = $false
$seenCapture = $false
while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $stderrLog) {
        $tail = Get-Content -LiteralPath $stderrLog -Tail 250 -ErrorAction SilentlyContinue
        if ($tail -match 'autopick: decision') { $seenDecision = $true }
    }
    if (Test-Path -LiteralPath $stdoutLog) {
        $tail2 = Get-Content -LiteralPath $stdoutLog -Tail 250 -ErrorAction SilentlyContinue
        if ($tail2 -match 'capture is started') { $seenCapture = $true }
    }
    if ($seenDecision -and $seenCapture) { break }
    Start-Sleep -Milliseconds 500
}
Write-Summary "[wait] decision=$seenDecision capture=$seenCapture"

# Dump last interesting autopick lines.
Write-Summary "[autopick.tail]"
if (Test-Path -LiteralPath $stderrLog) {
    $tail = Get-Content -LiteralPath $stderrLog -Tail 400 -ErrorAction SilentlyContinue
    $sig = $tail | Select-String -Pattern '[DGen] autopick:' -SimpleMatch | ForEach-Object { $_.Line }
    foreach ($l in ($sig | Select-Object -Last 80)) { Write-Summary $l }
} else {
    Write-Summary "<no stderr log>"
}

function Iwr-Head([string]$url) {
    try {
        $resp = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 10 -UseBasicParsing
        return "OK status=$($resp.StatusCode)"
    } catch {
        # IWR throws on non-2xx (e.g. 404). Treat any HTTP response as reachable.
        $ex = $_.Exception
        $resp = $null
        try { $resp = $ex.Response } catch {}
        if ($resp -and ($resp -is [System.Net.HttpWebResponse])) {
            return "OK status=$([int]$resp.StatusCode)"
        }
        return "FAIL err=$($ex.Message)"
    }
}

function HttpClient-Head([string]$url, [int]$timeoutSec = 10) {
    # Prefer HttpClient when available; it uses a different path than Invoke-WebRequest and often helps
    # to pinpoint WinINet/proxy issues.
    $handler = $null
    $client = $null
    try {
        if (-not ('System.Net.Http.HttpClient' -as [type])) {
            throw "System.Net.Http is not available"
        }

        $handler = New-Object System.Net.Http.HttpClientHandler
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds($timeoutSec)

        $msg = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Head, $url)
        $t = $client.SendAsync($msg)
        $resp = $t.GetAwaiter().GetResult()
        $code = 0
        try { $code = [int]$resp.StatusCode } catch { $code = 0 }
        return "OK status=$code"
    }
     catch {
        # Fallback: raw HttpWebRequest (still Schannel, but avoids IWR internals)
        try {
            $req = [System.Net.WebRequest]::Create($url)
            $req.Method = 'HEAD'
            $req.Timeout = [int]($timeoutSec * 1000)
            $req.ReadWriteTimeout = [int]($timeoutSec * 1000)
            $req.Proxy = [System.Net.WebRequest]::DefaultWebProxy
            $resp = $req.GetResponse()
            try {
                $code = 0
                try { $code = [int]([System.Net.HttpWebResponse]$resp).StatusCode } catch { $code = 0 }
                return "OK status=$code"
            } finally {
                try { $resp.Close() } catch { }
            }
        } catch {
            return "FAIL err=$($_.Exception.Message)"
        }
    } finally {
        if ($client) { try { $client.Dispose() } catch { } }
        if ($handler) { try { $handler.Dispose() } catch { } }
    }
}

$targets = @(
    @{ name = 'msft'; url = 'https://www.msftconnecttest.com/connecttest.txt' },
    @{ name = 'yt_web'; url = 'https://www.youtube.com/' },
    @{ name = 'yt_redirector'; url = 'https://redirector.googlevideo.com/' },
    @{ name = 'discord_app'; url = 'https://discord.com/app' },
    @{ name = 'discord_gw'; url = 'https://gateway.discord.gg/' },
    @{ name = 'tg_web'; url = 'https://web.telegram.org/' },
    @{ name = 'tg_core'; url = 'https://core.telegram.org/' },
    @{ name = 'tg_tme'; url = 'https://t.me/' },
    @{ name = 'tg_cdn'; url = 'https://cdn.telegram.org/' }
)

Write-Summary "[iwr]"
foreach ($t in $targets) {
    $res = Iwr-Head $t.url
    Write-Summary ("{0} {1}" -f $t.name, $res)
}

Write-Summary "[httpclient]"
foreach ($t in $targets) {
    $res = HttpClient-Head $t.url 10
    Write-Summary ("{0} {1}" -f $t.name, $res)
}

# Stop DGen.
Write-Summary "[dgen] stopping pid=$($proc.Id)"
try { Stop-Process -Id $proc.Id -Force } catch { Write-Summary "[dgen] stop_error $($_.Exception.Message)" }

Write-Summary "[done]"
Write-Output "Wrote: $summaryLog"