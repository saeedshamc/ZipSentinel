#requires -Version 5.1
<#
.SYNOPSIS
    Smoke-test the built zipsentinel.exe: generate -> scan -> extract.
.EXAMPLE
    .\scripts\demo-windows.ps1
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'target\release\zipsentinel.exe'
if (-not (Test-Path $exe)) { $exe = Join-Path $root 'target\debug\zipsentinel.exe' }
if (-not (Test-Path $exe)) { Write-Error 'Binary not found — run scripts\build-windows.ps1 first.' }

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("zipsentinel-demo-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Write-Host '==> generate high-compression sample' -ForegroundColor Cyan
    & $exe generate --profile high-compression --size 512KiB --output (Join-Path $work 'bomb.zip')

    Write-Host '==> scan (expect HIGH RISK, exit code 2)' -ForegroundColor Cyan
    & $exe scan (Join-Path $work 'bomb.zip')
    Write-Host "scan exit code: $LASTEXITCODE"

    Write-Host '==> generate + extract standard sample' -ForegroundColor Cyan
    & $exe generate --profile standard --entries 4 --output (Join-Path $work 'standard.zip')
    & $exe extract (Join-Path $work 'standard.zip') --output (Join-Path $work 'out')

    Write-Host '==> benchmark' -ForegroundColor Cyan
    & $exe benchmark $work
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
Write-Host 'Demo complete.' -ForegroundColor Green
