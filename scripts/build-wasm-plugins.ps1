#!/usr/bin/env pwsh
# plugins/firewall kaynagini, gateway'in yukledigi v2.wasm eklenti
# ikilisine derler. Kaynak degistikce yeniden calistirilmali.
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$env:GOOS = "wasip1"
$env:GOARCH = "wasm"
try {
    go build -o plugins/firewall/v2.wasm ./plugins/firewall
} finally {
    Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
}

Write-Host "plugins/firewall/v2.wasm derlendi."
