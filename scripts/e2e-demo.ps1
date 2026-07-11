#!/usr/bin/env pwsh
# scripts/e2e-demo.ps1
#
# SentinelDB'nin PII maskeleme ozelligini uctan uca kanitlayan demo/dogrulama
# script'i:
#   1) docker compose yigini ayaga kaldirilir,
#   2) postgres ve sentineldb saglikli olana kadar beklenir,
#   3) minimal bir demo tablosu olusturulup tek bir email satiri eklenir,
#   4) AYNI Simple Query Protocol SELECT sorgusu iki farkli host portundan
#      calistirilir: 5433 (dogrudan gercek PostgreSQL) ve 5432 (SentinelDB
#      gateway),
#   5) dogrudan sonucun "john@example.com", gateway sonucunun ise
#      "jo****@example.com" icerdigi dogrulanir.
#
# Sorgular, `psql -c` (libpq PQexec -> Simple Query Protocol) ile
# calistirilir; SentinelDB V1 yalnizca bu protokolu destekler (bkz. root
# README "V1 Sinirlamalari").
#
# Kullanim:
#   pwsh scripts/e2e-demo.ps1            # demo calisir, yigin AYAKTA kalir
#   pwsh scripts/e2e-demo.ps1 -Cleanup   # demo sonunda yigini durdurur (docker compose down)

param(
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

# DEMO ONLY - docker-compose.yml'deki postgres servisiyle birebir ayni
# olmali. Gercek/production kimlik bilgisi degildir.
$PgUser     = "sentineldb_demo"
$PgPassword = "demo_only_change_me"
$PgDb       = "sentineldb_demo"

$DirectHost  = "host.docker.internal"
$DirectPort  = 5433
$GatewayPort = 5432

$DemoTable = "e2e_demo_users"

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

function Invoke-PsqlInContainer {
    param([string]$Sql)
    docker compose exec -T postgres psql -U $PgUser -d $PgDb -c $Sql | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "postgres container icinde psql komutu basarisiz oldu: $Sql" }
}

function Invoke-PsqlFromHost {
    param([string]$HostPort, [string]$Sql)
    # Ayri, tek kullanimlik bir postgres imaji konteyneri uzerinden HOST'ta
    # yayinlanan porta (host.docker.internal) baglanir; boylece sorgu
    # gercekten "disaridan", Docker'in yayinladigi porttan gecer (bkz.
    # gorev F: "5433/5432 uzerinden").
    $out = docker run --rm -e PGPASSWORD=$PgPassword postgres:16-alpine `
        psql -h $DirectHost -p $HostPort -U $PgUser -d $PgDb -t -A -c $Sql
    if ($LASTEXITCODE -ne 0) {
        throw "host portu $HostPort uzerinden psql basarisiz oldu"
    }
    return ($out -join "`n")
}

$exitCode = 0

try {
    Write-Section "1/8 Docker Compose yigini baslatiliyor"
    docker compose up -d --build
    if ($LASTEXITCODE -ne 0) { throw "docker compose up basarisiz oldu" }

    Write-Section "2/8 postgres ve sentineldb saglikli olana kadar bekleniyor"
    foreach ($svc in @("postgres", "sentineldb")) {
        $cid = (docker compose ps -q $svc).Trim()
        if (-not $cid) { throw "$svc container'i bulunamadi" }

        $maxWaitSeconds = 90
        $waited = 0
        while ($true) {
            $status = (docker inspect --format '{{.State.Health.Status}}' $cid 2>$null).Trim()
            if ($status -eq "healthy") { break }
            if ($waited -ge $maxWaitSeconds) {
                throw "$svc bekleme suresi icinde saglikli olmadi (son durum: $status)"
            }
            Start-Sleep -Seconds 2
            $waited += 2
        }
        Write-Host "  $svc : healthy" -ForegroundColor Green
    }

    Write-Section "3/8 Demo tablosu olusturuluyor ve tek satir ekleniyor"
    Invoke-PsqlInContainer "DROP TABLE IF EXISTS $DemoTable;"
    Invoke-PsqlInContainer "CREATE TABLE $DemoTable (id serial primary key, email text);"
    Invoke-PsqlInContainer "INSERT INTO $DemoTable (email) VALUES ('john@example.com');"
    Write-Host "  tablo hazir: $DemoTable (1 satir)" -ForegroundColor Green

    $selectSql = "SELECT email FROM $DemoTable;"

    Write-Section "4/8 Dogrudan PostgreSQL sorgusu (host port $DirectPort, Simple Query Protocol)"
    $directResult = Invoke-PsqlFromHost -HostPort $DirectPort -Sql $selectSql

    Write-Section "5/8 SentinelDB gateway sorgusu (host port $GatewayPort, Simple Query Protocol)"
    $gatewayResult = Invoke-PsqlFromHost -HostPort $GatewayPort -Sql $selectSql

    Write-Section "6/8 Sonuclar"
    Write-Host "  Dogrudan PostgreSQL (5433) : $($directResult.Trim())"
    Write-Host "  SentinelDB Gateway  (5432) : $($gatewayResult.Trim())"

    Write-Section "7/8 Dogrudan sonuc dogrulaniyor"
    # Not: [string]::Contains bilerek kullanilir - PowerShell'in -like
    # operatoru '*' karakterini joker (wildcard) olarak yorumlar, oysa
    # burada dogrulanmasi gereken '****' TAM OLARAK dort literal yildiz
    # karakteridir (maskeleme ciktisi).
    if (-not $directResult.Contains("john@example.com")) {
        throw "DOGRULAMA BASARISIZ: dogrudan sonuc 'john@example.com' icermiyor (alinan: $directResult)"
    }
    Write-Host "  OK: dogrudan sonuc maskelenmemis 'john@example.com' iceriyor" -ForegroundColor Green

    Write-Section "8/8 Gateway sonucu dogrulaniyor"
    if (-not $gatewayResult.Contains("jo****@example.com")) {
        throw "DOGRULAMA BASARISIZ: gateway sonucu 'jo****@example.com' icermiyor (alinan: $gatewayResult)"
    }
    Write-Host "  OK: gateway sonucu maskelenmis 'jo****@example.com' iceriyor" -ForegroundColor Green

    Invoke-PsqlInContainer "DROP TABLE IF EXISTS $DemoTable;"
    Write-Host ""
    Write-Host "E2E DEMO BASARILI: SentinelDB gateway, email sutununu dogru sekilde maskeliyor." -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "E2E DEMO BASARISIZ: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
finally {
    if ($Cleanup) {
        Write-Section "Cleanup: docker compose yigini durduruluyor (-Cleanup verildi)"
        docker compose down
    }
    else {
        Write-Host ""
        Write-Host "Not: yigin CALISMAYA DEVAM EDIYOR. Durdurmak icin: docker compose down" -ForegroundColor Yellow
        Write-Host "     (ya da bu script'i '-Cleanup' bayragiyla tekrar calistirin)." -ForegroundColor Yellow
    }
}

exit $exitCode
