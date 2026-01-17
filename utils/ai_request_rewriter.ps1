[CmdletBinding()]
param(
    [string[]]$Domains,
    [string]$TargetDescription = "",
    [switch]$EnableRemote,
    [string]$ApiKey = $env:OPENAI_API_KEY,
    [string]$Model = $(if ($env:OPENAI_MODEL) { $env:OPENAI_MODEL } else { "gpt-4o-mini" }),
    [Uri]$BaseUri = $(if ($env:OPENAI_BASE_URL) { [Uri]$env:OPENAI_BASE_URL } else { [Uri]"https://api.openai.com/v1" }),
    [string[]]$DecoyPool = @(
        "www.google.com","www.cloudflare.com","www.microsoft.com","cdn.discordapp.com","www.youtube.com",
        "www.bing.com","www.amazon.com","www.apple.com","www.wikipedia.org","www.reddit.com"
    )
)

function Write-Info($msg) { Write-Host $msg -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-ErrQuit($msg) { Write-Host $msg -ForegroundColor Red; exit 1 }

if ((-not $Domains) -and (-not $TargetDescription)) { Write-ErrQuit "Pass -Domains or -TargetDescription." }

$listsDir    = Join-Path $PSScriptRoot "..\lists"
$aiListPath  = Join-Path $listsDir "list-ai.txt"
$generalPath = Join-Path $listsDir "list-general.txt"

function Get-LocalDecoys([string[]]$domains, [string[]]$pool) {
    $out = [System.Collections.Generic.List[string]]::new()
    $shuffle = $pool | Sort-Object { Get-Random }
    if (-not $domains -or $domains.Count -eq 0) { $domains = @("generic") }

    foreach ($d in $domains) {
        $clean = $d.ToLower().Trim()
        foreach ($p in $shuffle) {
            if ($p -eq $clean) { continue }
            if (-not $out.Contains($p)) { $out.Add($p); break }
        }
    }

    foreach ($p in $shuffle) { if ($out.Count -ge 3) { break }; if (-not $out.Contains($p)) { $out.Add($p) } }
    return $out | Sort-Object -Unique
}

$localEntries = Get-LocalDecoys -domains $Domains -pool $DecoyPool
$entries = [System.Collections.Generic.List[string]]::new()
$localEntries | ForEach-Object { $entries.Add($_) }

if ($EnableRemote) {
    if (-not $ApiKey) {
        Write-Warn "Remote mode requested but no ApiKey; keeping offline suggestions."
    } else {
        $payload = @{
            model = $Model
            messages = @(
                @{ role = "system"; content = "You generate camouflage hostnames for DPI evasion. Return JSON {spoof_host, add_host_entries[]}" }
                @{ role = "user"; content = "Targets: $($Domains -join ', ')`nContext: $TargetDescription" }
            )
            temperature = 0.2
            response_format = @{ type = "json_object" }
        }
        $headers = @{
            "Content-Type"  = "application/json"
            "Authorization" = "Bearer $ApiKey"
        }
        $uri = ($BaseUri.AbsoluteUri.TrimEnd('/')) + "/chat/completions"
        try {
            $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($payload | ConvertTo-Json -Depth 8)
            $content = $resp.choices[0].message.content
            if ($content) {
                try {
                    $parsed = $content | ConvertFrom-Json
                    $remote = @()
                    if ($parsed.spoof_host) { $remote += $parsed.spoof_host }
                    if ($parsed.add_host_entries) { $remote += $parsed.add_host_entries }
                    $remote = $remote | Where-Object { $_ } | ForEach-Object { $_.ToString().ToLower().Trim() } | Sort-Object -Unique
                    $remote | ForEach-Object { if (-not $entries.Contains($_)) { $entries.Add($_) } }
                    Write-Info "Remote suggestions merged: $($remote -join ', ')"
                } catch {
                    Write-Warn "Failed to parse remote JSON, keeping offline set."
                }
            } else {
                Write-Warn "Remote call returned empty content; using offline set."
            }
        } catch {
            Write-Warn "Remote call failed: $($_.Exception.Message). Using offline set."
        }
    }
}

if ($entries.Count -eq 0) { Write-ErrQuit "No hostnames generated." }
$entries = $entries | Sort-Object -Unique

$existing = @()
foreach ($path in @($generalPath, $aiListPath)) {
    if (Test-Path $path) {
        $existing += Get-Content $path | Where-Object { $_ -and (-not $_.StartsWith('#')) } | ForEach-Object { $_.ToLower().Trim() }
    }
}
$existing = $existing | Sort-Object -Unique
$toAdd = $entries | Where-Object { $existing -notcontains $_ }

if ($toAdd.Count -eq 0) {
    Write-Warn "No new hostnames to add; already present."; exit 0
}

if (-not (Test-Path $aiListPath)) {
    if (-not (Test-Path $listsDir)) { New-Item -ItemType Directory -Path $listsDir | Out-Null }
    @(
        "# list-ai.txt - D-Gen camouflage hostnames (offline by default)",
        "# Managed by utils/ai_request_rewriter.ps1",
        "# One hostname per line."
    ) | Set-Content -Path $aiListPath -Encoding UTF8
}

Add-Content -Path $aiListPath -Encoding UTF8 -Value ""
Add-Content -Path $aiListPath -Encoding UTF8 -Value "# Added $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by D-Gen"
Add-Content -Path $aiListPath -Encoding UTF8 -Value ($toAdd -join "`n")

Write-Info "D-Gen offline suggestions: $($localEntries -join ', ')"
if ($EnableRemote -and $ApiKey) { Write-Info "Remote mode attempted; see above for merge status." }
Write-Info "Added $($toAdd.Count) host(s) to $aiListPath"
