<#
.SYNOPSIS
Open binary file via IDA HTTP API (bypass MCP schema issue)
.PARAMETER Path
Binary file path (required)
.PARAMETER SessionId
Session ID (optional, auto-generated)
.PARAMETER NoAutoAnalysis
Skip automatic analysis (faster open for large files)
.PARAMETER TimeoutSeconds
Open timeout in seconds, returns timeout instead of blocking forever
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Path,
    [string]$SessionId = "",
    [switch]$NoAutoAnalysis = $false,
    [int]$TimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [string]::IsNullOrWhiteSpace($env:IDADIR)) {
    $env:IDADIR = $env:IDADIR
}
else {
    # Fallback: check common IDA installation paths
    $idaCandidates = @(
        'C:\Program Files\IDA Pro',
        'C:\IDA Pro',
        'D:\IDA',
        (Join-Path $env:USERPROFILE 'Tools\IDA')
    )
    $foundIda = $idaCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($foundIda) {
        $env:IDADIR = $foundIda
    } else {
        Write-Error "ERR:IDADIR not set and IDA Pro not found at common paths. Set IDADIR environment variable to your IDA installation directory."
        exit 1
    }
}
$Port = 13337
$TempDir = Join-Path $env:TEMP 'reverse-skill'
if (-not (Test-Path -LiteralPath $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
}
$PollIntervalMs = 2000
$ProgressIntervalSeconds = 10

function Get-OpenReadySession {
    param(
        [string]$ExpectedSessionId,
        [string]$ExpectedPath,
        [int]$RequestPort
    )

    $listBody = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"idalib_list","arguments":{}}}'
    $listResult = Invoke-RestMethod "http://127.0.0.1:$RequestPort/mcp" -Method Post -Body $listBody `
        -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop

    $sessions = @($listResult.result.structuredContent.sessions)
    foreach ($candidate in $sessions) {
        if (-not $candidate) {
            continue
        }

        $sameSession = $candidate.session_id -eq $ExpectedSessionId
        $samePath = $candidate.input_path -eq $ExpectedPath
        $sameFile = [System.IO.Path]::GetFileName($candidate.input_path) -eq [System.IO.Path]::GetFileName($ExpectedPath)
        if (($sameSession -or $samePath -or $sameFile) -and $candidate.is_analyzing -eq $false) {
            return $candidate
        }
    }

    return $null
}

if (-not (Test-Path $Path)) {
    Write-Output "ERR:file_not_found"
    exit 1
}

if ($TimeoutSeconds -le 0) {
    Write-Output "ERR:invalid_timeout"
    exit 1
}

# Determine whether a temporary copy is already in use (avoids recursive copying)
$isTempCopy = $Path.StartsWith($TempDir, [StringComparison]::OrdinalIgnoreCase)

# Files in System32 are automatically copied to Temp
if (-not $isTempCopy -and $Path -match "C:\\Windows\\System32") {
    $Filename = [System.IO.Path]::GetFileName($Path)
    $TempPath = "$TempDir\$Filename"
    Copy-Item $Path $TempPath -Force -ErrorAction SilentlyContinue
    if ($?) {
        $Path = $TempPath
        $isTempCopy = $true
    }
}

# Clean up old database files with the same name (only attempted when not a Temp copy)
if (-not $isTempCopy) {
    $dir = [System.IO.Path]::GetDirectoryName($Path)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $oldExts = @(".id0", ".id1", ".id2", ".nam", ".til", ".i64")
    $hasLocked = $false
    foreach ($ext in $oldExts) {
        $f = Join-Path $dir "$base$ext"
        if (Test-Path $f) {
            Remove-Item $f -Force -ErrorAction SilentlyContinue
            if (Test-Path $f) { $hasLocked = $true }
        }
    }
    # The old database file is locked, so fall back to a Temp copy automatically
    if ($hasLocked) {
        $guid = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
        $newName = "$guid-$([System.IO.Path]::GetFileName($Path))"
        $TempPath = "$TempDir\$newName"
        Copy-Item $Path $TempPath -Force
        $Path = $TempPath
        $isTempCopy = $true
    }
}

$autoAnalysis = if ($NoAutoAnalysis) { "false" } else { "true" }
$escapedPath = $Path -replace '\\', '\\'

# Always use an explicit session ID so that on timeout we can poll the session state to see whether the open actually succeeded
if (-not $SessionId) {
    $SessionId = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
}

 $body = @"
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"idalib_open","arguments":{"input_path":"$escapedPath","run_auto_analysis":$autoAnalysis,"session_id":null}}}
"@
if ($SessionId) {
    $body = @"
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"idalib_open","arguments":{"input_path":"$escapedPath","run_auto_analysis":$autoAnalysis,"session_id":"$SessionId"}}}
"@
}

# Run the open request in the background so a long stalled HTTP response does not block the whole script
$openJob = Start-Job -ScriptBlock {
    param($RequestBody, $RequestPort)
    try {
        Invoke-RestMethod "http://127.0.0.1:$RequestPort/mcp" -Method Post -Body $RequestBody `
            -ContentType "application/json" -ErrorAction Stop
    } catch {
        $_.Exception.Message
    }
} -ArgumentList $body, $Port

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$openCompleted = $false
$startTime = Get-Date
$lastProgressAt = $startTime.AddSeconds(-$ProgressIntervalSeconds)

try {
    while ((Get-Date) -lt $deadline) {
        if (Wait-Job -Job $openJob -Timeout 1) {
            $openCompleted = $true
            break
        }

        try {
            $session = Get-OpenReadySession -ExpectedSessionId $SessionId -ExpectedPath $Path -RequestPort $Port
            if ($session) {
                $tag = if ($isTempCopy) { " (temp copy)" } else { "" }
                Stop-Job -Job $openJob -ErrorAction SilentlyContinue
                Remove-Job -Job $openJob -Force -ErrorAction SilentlyContinue
                Write-Output "OK:$($session.filename):$($session.session_id)$tag"
                exit 0
            }
        } catch {}

        $now = Get-Date
        if (($now - $lastProgressAt).TotalSeconds -ge $ProgressIntervalSeconds) {
            $elapsed = [math]::Floor(($now - $startTime).TotalSeconds)
            Write-Output "INFO:opening:$elapsed/${TimeoutSeconds}s"
            $lastProgressAt = $now
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    if (-not $openCompleted) {
        Stop-Job -Job $openJob -ErrorAction SilentlyContinue
        Remove-Job -Job $openJob -Force -ErrorAction SilentlyContinue

        try {
            $session = Get-OpenReadySession -ExpectedSessionId $SessionId -ExpectedPath $Path -RequestPort $Port
            if ($session) {
                $tag = if ($isTempCopy) { " (temp copy)" } else { "" }
                Write-Output "OK:$($session.filename):$($session.session_id)$tag"
                exit 0
            }
        } catch {}

        Write-Output "ERR:open_timeout_${TimeoutSeconds}s"
        exit 1
    }

    $jobResult = Receive-Job -Job $openJob
    Remove-Job -Job $openJob -Force -ErrorAction SilentlyContinue

    if ($jobResult -is [string]) {
        Write-Output "ERR:$jobResult"
        exit 1
    }

    if ($jobResult.result.structuredContent.success -eq $true) {
        $session = $jobResult.result.structuredContent.session
        $tag = if ($isTempCopy) { " (temp copy)" } else { "" }
        Write-Output "OK:$($session.filename):$($session.session_id)$tag"
    } else {
        # Automatic fallback: when the non-Temp copy fails, copy to Temp and retry
        if (-not $isTempCopy) {
            $guid = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
            $newName = "$guid-$([System.IO.Path]::GetFileName($Path))"
            $TempPath = "$TempDir\$newName"
            Copy-Item $Path $TempPath -Force
            & $PSCommandPath -Path $TempPath -SessionId $SessionId -NoAutoAnalysis:$NoAutoAnalysis -TimeoutSeconds $TimeoutSeconds
        } else {
            Write-Output "ERR:$($jobResult.result.structuredContent.error)"
        }
    }
} finally {
    if ($openJob) {
        Stop-Job -Job $openJob -ErrorAction SilentlyContinue
        Remove-Job -Job $openJob -Force -ErrorAction SilentlyContinue
    }
}
