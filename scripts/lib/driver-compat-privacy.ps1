#!/usr/bin/env pwsh
# scripts/lib/driver-compat-privacy.ps1
#
# Dependency-free (no Docker, no Pester), dot-sourced library implementing
# scripts/driver-compat.ps1's log-capture / privacy-scan / failure-
# diagnostic decision logic as small, independently testable functions.
#
# This file is the SINGLE source of truth for that logic - it is dot-sourced
# by:
#   - scripts/driver-compat.ps1 (the real local runner, against a live
#     Docker stack)
#   - scripts/driver-compat-ci-diagnostics.ps1 (the CI failure-path
#     diagnostics wrapper, .github/workflows/ci.yml's driver-compat job)
#   - scripts/driver-compat-privacy-selftest.ps1 (deterministic,
#     Docker-free regression checks for this exact logic)
#
# so the marker catalog and the "never print unverified/leaked content"
# rules are never duplicated (and therefore never able to drift out of
# sync) between the local runner and CI.
#
# Design invariant that makes a stale or marker-bearing log impossible to
# leak: Get-DriverCompatFailureDiagnostic - the function that decides
# whether it is safe to show a log tail, and what message to print - takes
# ONLY an already-computed diagnostics result (Captured/Scanned/Passed/
# LeakedCategories). It never receives a log path and never touches disk,
# so it is structurally incapable of reading (and therefore printing) any
# log content itself. Callers may only read/print a log's tail when that
# function's ShowTail is $true, which it only ever returns when
# Captured -and Scanned -and Passed are all $true for the diagnostics
# object passed to it.

# Get-DriverCompatMarkerCatalog returns the real, fixed set of sensitive
# test markers that must never appear in SentinelDB's own logs - see
# integration/pgxcompat for where each one originates. Each entry is a
# hashtable with a safe Category label (printable) and the actual Value to
# scan for (never printed).
function Get-DriverCompatMarkerCatalog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PgPassword
    )
    return @(
        @{ Category = "PASSWORD"; Value = $PgPassword },
        @{ Category = "EMAIL"; Value = "alice.distinctive@example.com" },
        @{ Category = "EMAIL"; Value = "bob.other@example.com" },
        @{ Category = "EMAIL"; Value = "binary.target@example.com" },
        @{ Category = "MASKED_VALUE"; Value = "al****@example.com" },
        @{ Category = "MASKED_VALUE"; Value = "bo****@example.com" },
        @{ Category = "BLOCKED_QUERY_TEXT"; Value = "pgxcompat_policy_" },
        @{ Category = "KEY_FIELD"; Value = "SecretKey" },
        @{ Category = "KEY_FIELD"; Value = "secretKey" }
    )
}

# New-DriverCompatLogPath returns a filename that is unique to this
# process invocation (GUID-suffixed), under RepoRoot. Because the name is
# fresh every call, a file left behind by an earlier run can never be
# mistaken for the current run's capture - there is no fixed path a stale
# log could occupy that this run would ever read from.
function New-DriverCompatLogPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )
    $unique = [guid]::NewGuid().ToString("N")
    return Join-Path $RepoRoot ("driver-compat-sentineldb-{0}.log" -f $unique)
}

# Invoke-DriverCompatLogCapture captures ServiceName's Compose logs to
# OutPath and returns $true only if the capture command exited 0 AND
# OutPath exists afterward. A nonzero exit code or a missing output file
# is always treated as capture failure - never as an empty-but-safe log.
# Any pre-existing content at OutPath is removed first (defense in depth;
# New-DriverCompatLogPath already makes collisions practically impossible)
# so a stale file can never be silently reused as "this run's" capture.
# Internal failures (e.g. docker not found) are caught and also resolve to
# $false rather than propagating - callers can always trust the boolean
# return value without their own try/catch.
function Invoke-DriverCompatLogCapture {
    param(
        [Parameter(Mandatory = $true)][string]$ComposeFile,
        [Parameter(Mandatory = $true)][string]$ProjectName,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$OutPath
    )
    try {
        if (Test-Path $OutPath) { Remove-Item -Path $OutPath -Force -ErrorAction SilentlyContinue }
        docker compose -f $ComposeFile -p $ProjectName logs $ServiceName --no-color > $OutPath
        $captureExit = $LASTEXITCODE
        if ($captureExit -ne 0) { return $false }
        if (-not (Test-Path $OutPath)) { return $false }
        return $true
    }
    catch {
        return $false
    }
}

# Test-DriverCompatLogPrivacy scans LogPath's full content for each
# Markers entry's Value and returns a result object:
#   Scanned          - whether the scan actually ran (i.e. the file could
#                       be read)
#   Passed           - $true only when Scanned is $true AND no marker
#                       matched
#   LeakedCategories - the safe Category labels (never Values) of any
#                       markers found
# Callers must only trust Passed when Scanned is also $true - a Scanned
# = $false result means privacy could not be verified at all, which is
# not the same thing as "verified clean".
function Test-DriverCompatLogPrivacy {
    param(
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][array]$Markers
    )
    try {
        if (-not (Test-Path $LogPath)) {
            return [pscustomobject]@{ Scanned = $false; Passed = $false; LeakedCategories = @() }
        }
        $content = Get-Content -Path $LogPath -Raw -ErrorAction Stop
        if ($null -eq $content) { $content = "" }
        $leaked = @()
        foreach ($marker in $Markers) {
            if ($content.Contains($marker.Value)) { $leaked += $marker.Category }
        }
        $passed = ($leaked.Count -eq 0)
        return [pscustomobject]@{ Scanned = $true; Passed = $passed; LeakedCategories = $leaked }
    }
    catch {
        return [pscustomobject]@{ Scanned = $false; Passed = $false; LeakedCategories = @() }
    }
}

# Invoke-DriverCompatDiagnostics combines a fresh capture attempt with a
# privacy scan into a single result object: Captured, Scanned, Passed,
# LeakedCategories. It never throws - any internal failure resolves to
# Captured/Scanned = $false rather than propagating.
#
# CaptureOverride, when supplied, replaces the real Docker-based capture
# call with the given scriptblock (which must return $true/$false exactly
# like Invoke-DriverCompatLogCapture). This exists ONLY so
# scripts/driver-compat-privacy-selftest.ps1 can deterministically
# exercise capture-failure handling (including "a stale/marker-bearing
# file exists at LogPath but capture still fails, so it must never be
# scanned or printed") without starting Docker.
function Invoke-DriverCompatDiagnostics {
    param(
        [string]$ComposeFile,
        [string]$ProjectName,
        [string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][array]$Markers,
        [scriptblock]$CaptureOverride
    )
    if ($CaptureOverride) {
        $captured = & $CaptureOverride
    }
    else {
        $captured = Invoke-DriverCompatLogCapture -ComposeFile $ComposeFile -ProjectName $ProjectName -ServiceName $ServiceName -OutPath $LogPath
    }
    if (-not $captured) {
        return [pscustomobject]@{ Captured = $false; Scanned = $false; Passed = $false; LeakedCategories = @() }
    }
    $scan = Test-DriverCompatLogPrivacy -LogPath $LogPath -Markers $Markers
    return [pscustomobject]@{ Captured = $true; Scanned = $scan.Scanned; Passed = $scan.Passed; LeakedCategories = $scan.LeakedCategories }
}

# Get-DriverCompatFailureDiagnostic decides, from an ALREADY-COMPUTED
# diagnostics result, whether it is safe to show a log tail and what
# fixed, safe message to print - see the file-header doc comment for why
# this function's signature (no log path, no log content) is what
# structurally guarantees a stale or marker-bearing log can never be
# printed by a caller that follows its ShowTail decision.
function Get-DriverCompatFailureDiagnostic {
    param(
        [Parameter(Mandatory = $true)]$Diagnostics
    )
    if (-not $Diagnostics.Captured) {
        return [pscustomobject]@{
            ShowTail = $false
            Message  = "SentinelDB logs could not be captured for this run; no log diagnostics available."
        }
    }
    if (-not $Diagnostics.Scanned) {
        return [pscustomobject]@{
            ShowTail = $false
            Message  = "Captured SentinelDB logs could not be read for the privacy scan; no log diagnostics available."
        }
    }
    if (-not $Diagnostics.Passed) {
        $count = $Diagnostics.LeakedCategories.Count
        $plural = "ies"
        if ($count -eq 1) { $plural = "y" }
        $categories = $Diagnostics.LeakedCategories -join ", "
        return [pscustomobject]@{
            ShowTail = $false
            Message  = "privacy scan FAILED: captured logs contain $count sensitive marker categor$plural that must never be logged (categories: $categories) - log content is not printed or uploaded."
        }
    }
    return [pscustomobject]@{
        ShowTail = $true
        Message  = "privacy scan: PASS (no sensitive markers found)."
    }
}
