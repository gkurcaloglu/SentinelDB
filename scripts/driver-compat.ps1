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

$ComposeFile = "deploy/driver-compat/docker-compose.yml"
$ProjectName = "sentineldb-driver-compat"

# DEMO/TEST ONLY - must match deploy/driver-compat/docker-compose.yml and
# deploy/driver-compat/config.yaml exactly. Never a real credential; never
# printed to the console via Write-Host - only assembled into a DSN passed
# to the `go test` child process as an environment variable.
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

# Sensitive test markers that must NEVER appear in SentinelDB's own logs -
# see integration/pgxcompat for where each one originates:
#   - $PgPassword                    : the dedicated stack's demo password
#   - the three raw emails           : Bind parameter values used by the
#                                      masking tests (never SQL text - real
#                                      Bind values)
#   - the two masked-value strings   : DataRow cell values, which
#                                      SentinelDB must never log either
#   - "pgxcompat_policy_"            : the static prefix of the table name
#                                      used only inside the blocked DROP
#                                      TABLE statement
#                                      (TestParseTimePolicyRejectionAndRecovery)
#                                      - if this appears anywhere in the
#                                      gateway's logs it means the actual
#                                      blocked SQL TEXT leaked. Note this is
#                                      deliberately NOT the literal string
#                                      "DROP TABLE": SentinelDB safely and
#                                      intentionally logs the *configured*
#                                      blocked-phrase name as part of its
#                                      policy-decision reason (e.g. `neden=...
#                                      (yasaklı ifade: "DROP TABLE")`) - a
#                                      known constant from config.yaml, not
#                                      client-supplied data - so scanning for
#                                      that alone would always false-positive.
#   - "SecretKey"/"secretKey"        : PID/cancellation-key values are never
#                                      read into any printable Go value in
#                                      the first place (see
#                                      internal/gateway/startup_handoff.go
#                                      and integration/pgxcompat/cancel_test.go),
#                                      so there is no literal byte sequence to
#                                      scan for - these two tokens instead
#                                      catch any *accidental* future
#                                      debug-logging of the field itself.
$SensitiveMarkers = @(
    $PgPassword,
    "alice.distinctive@example.com",
    "bob.other@example.com",
    "binary.target@example.com",
    "al****@example.com",
    "bo****@example.com",
    "pgxcompat_policy_",
    "SecretKey",
    "secretKey"
)

$logFile = Join-Path $repoRoot "driver-compat-sentineldb.log"
$exitCode = 0

try {
    Write-Section "1/6 Selecting dedicated Compose project ($ProjectName), PostgreSQL $PostgresVersion"
    docker compose -f $ComposeFile -p $ProjectName up -d --build
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

    Write-Section "2/6 Waiting for postgres and sentineldb to be healthy"
    $postgresContainer = (docker compose -f $ComposeFile -p $ProjectName ps -q postgres).Trim()
    $gatewayContainer = (docker compose -f $ComposeFile -p $ProjectName ps -q sentineldb).Trim()
    if (-not $postgresContainer) { throw "postgres container not found" }
    if (-not $gatewayContainer) { throw "sentineldb container not found" }
    Wait-Healthy -ContainerName $postgresContainer
    Write-Host "  postgres  : healthy" -ForegroundColor Green
    Wait-Healthy -ContainerName $gatewayContainer
    Write-Host "  sentineldb: healthy" -ForegroundColor Green

    Write-Section "3/6 Running the real pgx driver-compatibility suite (PostgreSQL $PostgresVersion)"
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
    if ($testExit -ne 0) { throw "pgx driver-compatibility suite failed (go test exit code $testExit)" }
    Write-Host "  pgx compatibility suite: PASS (PostgreSQL $PostgresVersion)" -ForegroundColor Green

    Write-Section "4/6 Capturing SentinelDB logs"
    docker compose -f $ComposeFile -p $ProjectName logs sentineldb --no-color 2>&1 | Out-File -FilePath $logFile -Encoding utf8
    Write-Host "  logs captured: $logFile"

    Write-Section "5/6 Scanning logs for sensitive test markers"
    $logContent = Get-Content -Path $logFile -Raw -ErrorAction SilentlyContinue
    if (-not $logContent) { $logContent = "" }
    $leaked = @()
    foreach ($marker in $SensitiveMarkers) {
        if ($logContent.Contains($marker)) { $leaked += $marker }
    }
    if ($leaked.Count -gt 0) {
        throw "privacy scan FAILED: SentinelDB logs contain $($leaked.Count) sensitive marker(s) that must never be logged (see $logFile for sanitized review - do not share this file as-is)"
    }
    Write-Host "  privacy scan: PASS (no password/email/blocked-SQL/masked-value/key markers found)" -ForegroundColor Green

    Write-Section "6/6 Done"
    Write-Host "PostgreSQL $PostgresVersion driver-compatibility run PASSED." -ForegroundColor Green
}
catch {
    $exitCode = 1
    Write-Host ""
    Write-Host "DRIVER-COMPAT RUN FAILED: $($_.Exception.Message)" -ForegroundColor Red
    if (Test-Path $logFile) {
        Write-Host ""
        Write-Host "-- last 100 lines of $logFile (already scanned for sensitive markers above) --" -ForegroundColor Yellow
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
