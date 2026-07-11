#!/usr/bin/env pwsh
# scripts/benchmark.ps1
#
# Runs SentinelDB's Go microbenchmarks (RowDescription/DataRow parsing,
# DataRow rebuilding, response-side email masking, Wasm plugin
# mask_value/evaluate_query invocation) using only standard `go test -bench`
# tooling - no external benchmark tools.
#
# These are LOCAL MICROBENCHMARKS of isolated hot-path functions, not a
# production throughput/SLA measurement - see docs/benchmarks.md.
#
# Kullanim:
#   pwsh scripts/benchmark.ps1
#     -> PowerShell 7+.
#   powershell -ExecutionPolicy Bypass -File .\scripts\benchmark.ps1
#     -> Windows PowerShell 5.1 (PowerShell 7 kurulu olmasi GEREKMEZ).
#   ... -OutFile results.txt
#     -> raw `go test` output is also written to results.txt (in addition
#        to being shown on screen).
#   ... -BenchTime 3s
#     -> forwarded to `go test -benchtime` (default: 1s per benchmark).
#   ... -Run 'BenchmarkParseDataRow'
#     -> forwarded to `go test -bench` to run a subset (default: all).

param(
    [string]$OutFile,
    [string]$BenchTime = "1s",
    [string]$Run = "."
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

# Only packages containing the benchmarks required for this release: no
# network/Docker startup is involved in any of them (bkz. gorev E:
# "Do not include network startup in microbenchmarks").
$packages = @(
    "./internal/protocol/...",
    "./internal/masking/...",
    "./internal/wasm/..."
)

Write-Host "Running Go benchmarks (bench=$Run, benchtime=$BenchTime)..." -ForegroundColor Cyan

$goArgs = @("test", "-run", "^$", "-bench", $Run, "-benchmem", "-benchtime", $BenchTime) + $packages

if ($OutFile) {
    & go @goArgs | Tee-Object -FilePath $OutFile
} else {
    & go @goArgs
}

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "BENCHMARKS BASARISIZ (exit code $LASTEXITCODE)." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Benchmarks completed successfully." -ForegroundColor Green
if ($OutFile) {
    Write-Host "Raw output written to: $OutFile" -ForegroundColor Green
}
exit 0
