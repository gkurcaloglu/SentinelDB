#!/usr/bin/env pwsh
# scripts/driver-compat.ps1
#
# Runs SentinelDB's real pgx v5 driver-compatibility suite
# (integration/pgxcompat) against the dedicated
# deploy/driver-compat Docker Compose stack: SentinelDB with the opt-in
# Extended Query gateway enabled, proxying a real PostgreSQL 16 or 18
# server.
#
# This is NOT scripts/e2e-demo.ps1 (the Simple Query masking demo against
# the root docker-compose.yml stack). This script never starts, stops, or
# touches the root stack, its ports (5432/5433/8080/9090/9091/3000/5173),
# or its `pgdata` named volume - the driver-compat stack uses a dedicated
# Compose project name, dedicated ports (25432/25433), and a dedicated,
# ephemeral volume.
#
# Kimlik bilgileri: bu betikteki TUM parolalar yalnizca bu dedicated test
# yiginina aittir (bkz. deploy/driver-compat/docker-compose.yml). Gercek/
# production kimlik bilgisi degildir ve konsola HICBIR ZAMAN yazilmaz -
# yalnizca `go test` alt surecine ortam degiskeni olarak gecilir.
#
# Log/privacy safety: this script never prints a log tail (or claims logs
# are clean) unless a fresh, THIS-RUN capture of SentinelDB's logs has
# been privacy-scanned and found clean - see
# scripts/lib/driver-compat-privacy.ps1's file-header comment for the
# exact design invariant, and scripts/driver-compat-privacy-selftest.ps1
# for the deterministic (Docker-free) regression checks proving it.
#
# Usage:
#   pwsh scripts/driver-compat.ps1                        # PostgreSQL 16, leaves the stack running afterwards
#   pwsh scripts/driver-compat.ps1 -PostgresVersion 18     # PostgreSQL 18
#   pwsh scripts/driver-compat.ps1 -Cleanup                # tears the dedicated stack + volume down when done
#   powershell -ExecutionPolicy Bypass -File .\scripts\driver-compat.ps1 -Cleanup
#     -> Windows PowerShell 5.1 (no PowerShell 7 install required); this
#        script uses no PS7-only syntax (no &&/||, no ternary/null-coalescing
#        operators).

param(
    [ValidateSet("16", "18")]
    [string]$PostgresVersion = "16",
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

. (Join-Path $PSScriptRoot "lib/driver-compat-privacy.ps1")

$ComposeFile = "deploy/driver-compat/docker-compose.yml"
$ProjectName = "sentineldb-driver-compat"
$ServiceName = "sentineldb"

# DEMO/TEST ONLY - must match deploy/driver-compat/docker-compose.yml and
# deploy/driver-compat/config.yaml exactly. Never a real credential; never
# printed to the console via Write-Host - only assembled into a DSN passed
# to the `go test` child process as an environment variable, and passed to
# Get-DriverCompatMarkerCatalog so the privacy scan can detect it if it
# ever leaked.
$PgUser = "pgxcompat"
$PgPassword = "pgxcompat_demo_only_change_me"
$PgDb = "pgxcompat"

$GatewayHostPort = 25432
$DirectHostPort = 25433

$env:POSTGRES_IMAGE = "postgres:$PostgresVersion-alpine"

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

# Wait-Healthy polls `docker inspect`'s health status deterministically
# (bounded retries with a short interval) instead of a single fixed sleep -
# the same pattern scripts/e2e-demo.ps1 already uses for the root stack.
function Wait-Healthy {
    param(
        [string]$ContainerName,
        [int]$TimeoutSeconds = 90
    )
    $waited = 0
    while ($true) {
        $status = (docker inspect --format '{{.State.Health.Status}}' $ContainerName 2>$null)
        if ($status) { $status = $status.Trim() }
        if ($status -eq "healthy") { return }
        if ($waited -ge $TimeoutSeconds) {
            throw "$ContainerName did not become healthy within $TimeoutSeconds seconds (last status: $status)"
        }
        Start-Sleep -Seconds 2
        $waited += 2
    }
}

# logFile is unique to THIS process invocation (see
# New-DriverCompatLogPath) - a file left behind by an earlier run can
# never be read or printed by this one.
$logFile = New-DriverCompatLogPath -RepoRoot $repoRoot
$markers = Get-DriverCompatMarkerCatalog -PgPassword $PgPassword

# $diagnostics is populated the first time this run actually attempts a
# capture+scan (either during the normal flow below, or - if the normal
# flow never got that far - as a best-effort fallback at the top of the
# catch block). Left $null until then, so the catch block can tell "have
# we already captured/scanned this run" apart from "not yet attempted".
$diagnostics = $null
$exitCode = 0

try {
    Write-Section "1/5 Selecting dedicated Compose project ($ProjectName), PostgreSQL $PostgresVersion"
    docker compose -f $ComposeFile -p $ProjectName up -d --build
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

    Write-Section "2/5 Waiting for postgres and sentineldb to be healthy"
    $postgresContainer = (docker compose -f $ComposeFile -p $ProjectName ps -q postgres).Trim()
    $gatewayContainer = (docker compose -f $ComposeFile -p $ProjectName ps -q $ServiceName).Trim()
    if (-not $postgresContainer) { throw "postgres container not found" }
    if (-not $gatewayContainer) { throw "sentineldb container not found" }
    Wait-Healthy -ContainerName $postgresContainer
    Write-Host "  postgres  : healthy" -ForegroundColor Green
    Wait-Healthy -ContainerName $gatewayContainer
    Write-Host "  sentineldb: healthy" -ForegroundColor Green

    Write-Section "3/5 Running the real pgx driver-compatibility suite (PostgreSQL $PostgresVersion)"
    $driverDsn = "postgres://" + $PgUser + ":" + $PgPassword + "@127.0.0.1:" + $GatewayHostPort + "/" + $PgDb + "?sslmode=disable&application_name=pgxcompat_driver_compat_ps1&connect_timeout=10"
    $directDsn = "postgres://" + $PgUser + ":" + $PgPassword + "@127.0.0.1:" + $DirectHostPort + "/" + $PgDb + "?sslmode=disable&application_name=pgxcompat_driver_compat_ps1_direct&connect_timeout=10"
    $expectLongKey = "false"
    if ($PostgresVersion -eq "18") { $expectLongKey = "true" }

    Push-Location "integration/pgxcompat"
    try {
        $env:SENTINELDB_DRIVER_DSN = $driverDsn
        $env:SENTINELDB_DIRECT_DSN = $directDsn
        $env:SENTINELDB_EXPECT_LONG_CANCEL_KEY = $expectLongKey
        go test ./... -count=1 -v
        $testExit = $LASTEXITCODE
    }
    finally {
        Remove-Item Env:\SENTINELDB_DRIVER_DSN -ErrorAction SilentlyContinue
        Remove-Item Env:\SENTINELDB_DIRECT_DSN -ErrorAction SilentlyContinue
        Remove-Item Env:\SENTINELDB_EXPECT_LONG_CANCEL_KEY -ErrorAction SilentlyContinue
        Pop-Location
    }

    # Capture + privacy-scan ALWAYS runs, regardless of whether the suite
    # itself passed - a privacy leak must fail the run even if every test
    # passed, and diagnostics must be ready before any throw below.
    Write-Section "4/5 Capturing SentinelDB logs and running privacy scan"
    $diagnostics = Invoke-DriverCompatDiagnostics -ComposeFile $ComposeFile -ProjectName $ProjectName -ServiceName $ServiceName -LogPath $logFile -Markers $markers
    if (-not $diagnostics.Captured) {
        throw "SentinelDB logs could not be captured for this run; cannot verify the privacy scan, treating as failure."
    }
    if (-not $diagnostics.Scanned) {
        throw "Captured SentinelDB logs could not be read for the privacy scan; treating as failure."
    }
    if (-not $diagnostics.Passed) {
        $decision = Get-DriverCompatFailureDiagnostic -Diagnostics $diagnostics
        throw $decision.Message
    }
    Write-Host "  privacy scan: PASS (no password/email/blocked-query-text/masked-value/key markers found)" -ForegroundColor Green

    if ($testExit -ne 0) { throw "pgx driver-compatibility suite failed (go test exit code $testExit)" }
    Write-Host "  pgx compatibility suite: PASS (PostgreSQL $PostgresVersion)" -ForegroundColor Green

    Write-Section "5/5 Done"
    Write-Host "PostgreSQL $PostgresVersion driver-compatibility run PASSED." -ForegroundColor Green
}
catch {
    $exitCode = 1
    Write-Host ""
    Write-Host "DRIVER-COMPAT RUN FAILED: $($_.Exception.Message)" -ForegroundColor Red

    # If the run never reached (or never completed) its own capture+scan
    # above - e.g. `docker compose up` or the health wait itself failed -
    # attempt one now, purely for diagnostics. This is always a FRESH
    # capture of the current run's logs (never a stale file - see
    # New-DriverCompatLogPath), and the same privacy scan gates whether
    # any of it may be shown below.
    if (-not $diagnostics) {
        $diagnostics = Invoke-DriverCompatDiagnostics -ComposeFile $ComposeFile -ProjectName $ProjectName -ServiceName $ServiceName -LogPath $logFile -Markers $markers
    }

    $decision = Get-DriverCompatFailureDiagnostic -Diagnostics $diagnostics
    Write-Host ""
    Write-Host $decision.Message -ForegroundColor Yellow
    if ($decision.ShowTail) {
        Write-Host ""
        Write-Host "-- last 100 lines of $logFile (privacy-scanned, not sanitized/redacted) --" -ForegroundColor Yellow
        Get-Content -Path $logFile -Tail 100 -ErrorAction SilentlyContinue
    }
}
finally {
    if ($Cleanup) {
        Write-Section "Cleanup: tearing down the dedicated stack + volume ($ProjectName)"
        docker compose -f $ComposeFile -p $ProjectName down -v
    }
    else {
        Write-Host ""
        Write-Host "Note: the dedicated stack ($ProjectName) is still running on 127.0.0.1:$GatewayHostPort / 127.0.0.1:$DirectHostPort." -ForegroundColor Yellow
        Write-Host "      Tear it down with: docker compose -f $ComposeFile -p $ProjectName down -v" -ForegroundColor Yellow
        Write-Host "      (or re-run this script with -Cleanup)." -ForegroundColor Yellow
    }
    Remove-Item Env:\POSTGRES_IMAGE -ErrorAction SilentlyContinue
}

exit $exitCode
