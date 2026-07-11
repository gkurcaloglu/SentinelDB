#!/usr/bin/env pwsh
# scripts/e2e-demo.ps1
#
# SentinelDB'nin PII maskeleme ozelligini uctan uca kanitlayan demo/dogrulama
# script'i:
#   1) docker compose yigini ayaga kaldirilir,
#   2) postgres ve sentineldb saglikli olana kadar beklenir,
#   3) minimal bir demo tablosu olusturulup tek bir email satiri eklenir,
#   4) AYNI Simple Query Protocol SELECT sorgusu, mevcut Compose network'u
#      ICINDEN, iki farkli hedefe karsi calistirilir: "postgres" (gercek
#      PostgreSQL) ve "sentineldb" (SentinelDB gateway) servis adlari,
#   5) dogrudan sonucun "john@example.com", gateway sonucunun ise
#      "jo****@example.com" icerdigi dogrulanir.
#
# Sorgular, `psql -c` (libpq PQexec -> Simple Query Protocol) ile
# calistirilir; SentinelDB V1 yalnizca bu protokolu destekler (bkz. root
# README "V1 Sinirlamalari").
#
# Neden host portlari (host.docker.internal) yerine Compose network'u:
# host portlari artik yalniza 127.0.0.1'e baglanir (bkz. root README
# "Guvenlik Uyarisi" / gorev A); host.docker.internal her Docker ortaminda
# host'un loopback'ine baglanan bir container'a geri erisim saglamayabilir.
# Bu yuzden dogrulama, postgres container'indaki psql client'i Compose
# network'u uzerinden servis adlariyla ("postgres", "sentineldb") kullanir.
# Host portlari yine de MANUEL kullanim icin acik kalir (bkz. README).
#
# Kullanim:
#   pwsh scripts/e2e-demo.ps1
#     -> PowerShell 7+ ile calistirir; demo calisir, yigin AYAKTA kalir.
#   powershell -ExecutionPolicy Bypass -File .\scripts\e2e-demo.ps1
#     -> Windows PowerShell 5.1 ile calistirir (PowerShell 7 kurulu
#        olmasi GEREKMEZ); script PS 7'ye ozel hicbir sozdizimi kullanmaz.
#   ... -Cleanup
#     -> demo sonunda yigini durdurur (docker compose down). Named volume
#        (pgdata) SILINMEZ; bir sonraki calistirmada veri kalici olur.

param(
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

# DEMO ONLY - docker-compose.yml'deki postgres servisiyle birebir ayni
# olmali. Gercek/production kimlik bilgisi degildir. Bu deger konsola HICBIR
# ZAMAN yazilmaz; yalnizca `docker compose exec -e` ile alt process'in ortam
# degiskeni olarak gecilir.
$PgUser     = "sentineldb_demo"
$PgPassword = "demo_only_change_me"
$PgDb       = "sentineldb_demo"

# Compose network'undeki servis adlari (bkz. docker-compose.yml).
$DirectServiceHost  = "postgres"
$GatewayServiceHost = "sentineldb"
$PgPort = 5432

$DemoTable = "e2e_demo_users"

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

function Invoke-PsqlInContainer {
    param([string]$Sql)
    # Unix socket uzerinden yerel baglanti (peer/trust auth); sifre
    # gerekmez.
    docker compose exec -T postgres psql -U $PgUser -d $PgDb -c $Sql | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "postgres container icinde psql komutu basarisiz oldu: $Sql" }
}

function Invoke-PsqlOverNetwork {
    param([string]$TargetServiceHost, [string]$Sql)
    # postgres container'indaki psql client'ini kullanarak, Compose
    # network'u uzerinden hostname ile (postgres ya da sentineldb) TCP
    # baglantisi kurar. TCP baglantilari scram-sha-256 gerektirdigi icin
    # sifre, yalniza exec edilen process'e `-e` ile ortam degiskeni olarak
    # gecilir; asla Write-Host ile yazdirilmaz.
    $out = docker compose exec -T -e PGPASSWORD=$PgPassword postgres `
        psql -h $TargetServiceHost -p $PgPort -U $PgUser -d $PgDb -t -A -c $Sql
    if ($LASTEXITCODE -ne 0) {
        throw "$TargetServiceHost`:$PgPort uzerinden psql basarisiz oldu"
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

    Write-Section "4/8 Dogrudan PostgreSQL sorgusu (Compose network: $DirectServiceHost`:$PgPort, Simple Query Protocol)"
    $directResult = Invoke-PsqlOverNetwork -TargetServiceHost $DirectServiceHost -Sql $selectSql

    Write-Section "5/8 SentinelDB gateway sorgusu (Compose network: $GatewayServiceHost`:$PgPort, Simple Query Protocol)"
    $gatewayResult = Invoke-PsqlOverNetwork -TargetServiceHost $GatewayServiceHost -Sql $selectSql

    Write-Section "6/8 Sonuclar"
    Write-Host "  Dogrudan PostgreSQL ($DirectServiceHost)  : $($directResult.Trim())"
    Write-Host "  SentinelDB Gateway  ($GatewayServiceHost) : $($gatewayResult.Trim())"

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

    Write-Host ""
    Write-Host "E2E DEMO BASARILI: SentinelDB gateway, email sutununu dogru sekilde maskeliyor." -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "E2E DEMO BASARISIZ: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
finally {
    # Demo tablosunu temizlemek best-effort'tur: dogrulama basarisiz olsa
    # bile calisir, ancak buradaki bir hata orijinal basarisizligi ASLA
    # gizlemez - $exitCode zaten yukaridaki catch'te belirlendi ve burada
    # degistirilmez.
    try {
        Invoke-PsqlInContainer "DROP TABLE IF EXISTS $DemoTable;"
    }
    catch {
        Write-Host ""
        Write-Host "Uyari: demo tablosu ($DemoTable) temizlenemedi: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    if ($Cleanup) {
        Write-Section "Cleanup: docker compose yigini durduruluyor (-Cleanup verildi)"
        # -v BAYRAGI YOK: pgdata named volume korunur.
        docker compose down
    }
    else {
        Write-Host ""
        Write-Host "Not: yigin CALISMAYA DEVAM EDIYOR. Durdurmak icin: docker compose down" -ForegroundColor Yellow
        Write-Host "     (ya da bu script'i '-Cleanup' bayragiyla tekrar calistirin)." -ForegroundColor Yellow
    }
}

exit $exitCode
