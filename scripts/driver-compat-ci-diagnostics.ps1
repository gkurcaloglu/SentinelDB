#!/usr/bin/env pwsh
# scripts/driver-compat-ci-diagnostics.ps1
#
# Used only by the CI driver-compat job's failure path
# (.github/workflows/ci.yml) to capture SentinelDB logs and run the exact
# same privacy scan scripts/driver-compat.ps1 itself uses - both dot-source
# scripts/lib/driver-compat-privacy.ps1, so there is one shared source of
# truth for the marker catalog and the "never print unverified/leaked
# content" decision logic, never a separate bash reimplementation that
# could drift out of sync.
#
# Writes GitHub Actions step outputs (showtail, logpath) so the workflow
# can decide whether to upload the captured log as an artifact - this
# script itself never uploads anything; it only prints a tail (and only
# when the privacy scan actually passed) and exits non-zero when privacy
# could not be verified as clean.

param(
    [Parameter(Mandatory = $true)][string]$ProjectName,
    [Parameter(Mandatory = $true)][string]$ComposeFile,
    [string]$ServiceName = "sentineldb",
    [string]$PgPassword = "pgxcompat_demo_only_change_me",
    [int]$TailLines = 300
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "lib/driver-compat-privacy.ps1")

$logPath = New-DriverCompatLogPath -RepoRoot $repoRoot
$markers = Get-DriverCompatMarkerCatalog -PgPassword $PgPassword

$diagnostics = Invoke-DriverCompatDiagnostics -ComposeFile $ComposeFile -ProjectName $ProjectName -ServiceName $ServiceName -LogPath $logPath -Markers $markers
$decision = Get-DriverCompatFailureDiagnostic -Diagnostics $diagnostics

Write-Host $decision.Message

if ($decision.ShowTail) {
    Write-Host "----- $logPath (tail, privacy-scanned, not sanitized/redacted) -----"
    Get-Content -Path $logPath -Tail $TailLines -ErrorAction SilentlyContinue
}

if ($env:GITHUB_OUTPUT) {
    $showTailValue = "false"
    if ($decision.ShowTail) { $showTailValue = "true" }
    Add-Content -Path $env:GITHUB_OUTPUT -Value "showtail=$showTailValue"
    Add-Content -Path $env:GITHUB_OUTPUT -Value "logpath=$logPath"
}

if ($diagnostics.Passed) {
    exit 0
}
exit 1
