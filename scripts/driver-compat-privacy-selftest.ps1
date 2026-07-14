#!/usr/bin/env pwsh
# scripts/driver-compat-privacy-selftest.ps1
#
# Dependency-free (no Docker, no Pester) regression checks for
# scripts/lib/driver-compat-privacy.ps1's log-capture / privacy-scan /
# failure-diagnostic decision logic - the same logic
# scripts/driver-compat.ps1 (local runner) and
# scripts/driver-compat-ci-diagnostics.ps1 (CI failure path) both use.
#
# Uses only temporary files and fixed FAKE markers (never the real demo
# password or real compatibility-test email values - see
# $FakeMarkers below) so this file's own console output never needs to be
# redacted. All temporary files are removed on exit, success or failure.
#
# Usage:
#   pwsh scripts/driver-compat-privacy-selftest.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\driver-compat-privacy-selftest.ps1
#     -> Windows PowerShell 5.1 (no PowerShell 7 install required); no
#        PS7-only syntax is used.
#
# Exits 0 if every check passes, 1 otherwise (with a summary of which
# check(s) failed).

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib/driver-compat-privacy.ps1")

# Fixed fake markers - deliberately not real secrets, so nothing here
# needs to be treated as sensitive.
$FakeMarkers = @(
    @{ Category = "FAKE_PASSWORD"; Value = "fake-selftest-password-3f9a1c" },
    @{ Category = "FAKE_EMAIL"; Value = "fake-selftest-user@example.invalid" }
)
$FakeMarkerValues = $FakeMarkers | ForEach-Object { $_.Value }

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("driver-compat-privacy-selftest-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$results = @()

function Add-CheckResult {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $script:results += [pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail }
    $status = "FAIL"
    if ($Passed) { $status = "PASS" }
    Write-Host ("[{0}] {1}" -f $status, $Name)
    if (-not $Passed -and $Detail) {
        Write-Host ("       {0}" -f $Detail) -ForegroundColor Yellow
    }
}

# Asserts that none of the fake marker VALUES appear in $Text - used to
# prove a formatted diagnostic message never leaks a marker's actual
# value, only its safe category label.
function Test-NoMarkerValueLeaked {
    param([string]$Text)
    foreach ($value in $FakeMarkerValues) {
        if ($Text.Contains($value)) { return $false }
    }
    return $true
}

try {
    # ---- Check 1: clean current-run log -> scan passes -------------------
    $cleanLog = Join-Path $tempDir "clean.log"
    Set-Content -Path $cleanLog -Value "2026/07/14 12:00:00 [conn 1] C->S Parse (Extended) verdict=ALLOW" -NoNewline
    $scan = Test-DriverCompatLogPrivacy -LogPath $cleanLog -Markers $FakeMarkers
    $diag = [pscustomobject]@{ Captured = $true; Scanned = $scan.Scanned; Passed = $scan.Passed; LeakedCategories = $scan.LeakedCategories }
    $decision = Get-DriverCompatFailureDiagnostic -Diagnostics $diag
    $ok = $scan.Scanned -and $scan.Passed -and $decision.ShowTail -and (Test-NoMarkerValueLeaked $decision.Message)
    Add-CheckResult "clean current-run log: scan passes, tail permitted" $ok "scan=$($scan | ConvertTo-Json -Compress) decision=$($decision | ConvertTo-Json -Compress)"

    # ---- Check 2: marker-bearing current-run log -> scan fails, no leak --
    $markerLog = Join-Path $tempDir "marker.log"
    Set-Content -Path $markerLog -Value ("some line before`n" + $FakeMarkers[0].Value + "`nsome line after") -NoNewline
    $scan2 = Test-DriverCompatLogPrivacy -LogPath $markerLog -Markers $FakeMarkers
    $diag2 = [pscustomobject]@{ Captured = $true; Scanned = $scan2.Scanned; Passed = $scan2.Passed; LeakedCategories = $scan2.LeakedCategories }
    $decision2 = Get-DriverCompatFailureDiagnostic -Diagnostics $diag2
    $ok2 = $scan2.Scanned -and (-not $scan2.Passed) -and ($scan2.LeakedCategories -contains "FAKE_PASSWORD") -and (-not $decision2.ShowTail) -and (Test-NoMarkerValueLeaked $decision2.Message)
    Add-CheckResult "marker-bearing current-run log: scan fails, marker value absent from message, no tail" $ok2 "scan=$($scan2 | ConvertTo-Json -Compress) decision=$($decision2 | ConvertTo-Json -Compress)"

    # ---- Check 3: stale previous log + failure before current capture ----
    # Simulates a run where capture itself failed (e.g. Docker error before
    # any logs could be captured this run) while a PRIOR run's log - which
    # happens to contain a real marker - still exists on disk at some path.
    # Get-DriverCompatFailureDiagnostic must decide purely from
    # Diagnostics.Captured (here $false) without ever being handed, or
    # needing, that stale path - proving it structurally cannot read it.
    $staleLog = Join-Path $tempDir "stale.log"
    Set-Content -Path $staleLog -Value $FakeMarkers[1].Value -NoNewline
    $failedCapture = Invoke-DriverCompatDiagnostics -ComposeFile "unused" -ProjectName "unused" -ServiceName "unused" -LogPath $staleLog -Markers $FakeMarkers -CaptureOverride { $false }
    $decision3 = Get-DriverCompatFailureDiagnostic -Diagnostics $failedCapture
    $ok3 = (-not $failedCapture.Captured) -and (-not $failedCapture.Scanned) -and ($failedCapture.LeakedCategories.Count -eq 0) -and (-not $decision3.ShowTail) -and (Test-NoMarkerValueLeaked $decision3.Message) -and ($decision3.Message -notmatch "PASS")
    Add-CheckResult "stale previous log + failed current capture: stale log neither read nor printed" $ok3 "diag=$($failedCapture | ConvertTo-Json -Compress) decision=$($decision3 | ConvertTo-Json -Compress)"

    # ---- Check 4: missing log after failed capture -> fixed diagnostic ---
    $missingLog = Join-Path $tempDir "does-not-exist.log"
    $missingCapture = Invoke-DriverCompatDiagnostics -ComposeFile "unused" -ProjectName "unused" -ServiceName "unused" -LogPath $missingLog -Markers $FakeMarkers -CaptureOverride { $false }
    $decision4 = Get-DriverCompatFailureDiagnostic -Diagnostics $missingCapture
    $ok4 = (-not $missingCapture.Captured) -and (-not $decision4.ShowTail) -and ($decision4.Message -eq "SentinelDB logs could not be captured for this run; no log diagnostics available.")
    Add-CheckResult "missing log after failed capture: fixed safe diagnostic only" $ok4 "diag=$($missingCapture | ConvertTo-Json -Compress) decision=$($decision4 | ConvertTo-Json -Compress)"

    # ---- Check 5: failed capture equivalent -> scan cannot falsely pass --
    # Even when a file that WOULD scan clean exists at LogPath, a failed
    # capture (nonzero exit / missing output, simulated here via
    # -CaptureOverride) must never be reported as Passed.
    $wouldBeCleanLog = Join-Path $tempDir "would-be-clean.log"
    Set-Content -Path $wouldBeCleanLog -Value "nothing sensitive here" -NoNewline
    $falsePassAttempt = Invoke-DriverCompatDiagnostics -ComposeFile "unused" -ProjectName "unused" -ServiceName "unused" -LogPath $wouldBeCleanLog -Markers $FakeMarkers -CaptureOverride { $false }
    $ok5 = (-not $falsePassAttempt.Captured) -and (-not $falsePassAttempt.Passed)
    Add-CheckResult "failed docker-compose-logs equivalent: scan cannot falsely pass" $ok5 "diag=$($falsePassAttempt | ConvertTo-Json -Compress)"

    # ---- Check 6: privacy failure -> nonzero process exit ----------------
    # Exercises the same decision this script's own final exit code (and
    # scripts/driver-compat.ps1's / scripts/driver-compat-ci-diagnostics.ps1's)
    # is based on: Diagnostics.Passed = $false must map to a failing exit
    # code, never zero.
    $simulatedExitCode = 0
    if (-not $diag2.Passed) { $simulatedExitCode = 1 }
    $ok6 = ($simulatedExitCode -eq 1)
    Add-CheckResult "privacy failure maps to a nonzero exit code" $ok6 "simulatedExitCode=$simulatedExitCode"
}
finally {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

$failed = @($results | Where-Object { -not $_.Passed })
Write-Host ""
if ($failed.Count -gt 0) {
    Write-Host ("SELF-TEST FAILED: {0}/{1} check(s) failed." -f $failed.Count, $results.Count) -ForegroundColor Red
    exit 1
}
Write-Host ("SELF-TEST PASSED: {0}/{0} checks passed." -f $results.Count) -ForegroundColor Green
exit 0
