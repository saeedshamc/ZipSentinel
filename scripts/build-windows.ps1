#requires -Version 5.1
<#
.SYNOPSIS
    Build ZipSentinel on Windows (PowerShell).
.DESCRIPTION
    Verifies the Rust toolchain, builds the release binary, and prints the
    path to zipsentinel.exe. Run from the repository root or any directory —
    the script locates the repo root automatically.
.EXAMPLE
    .\scripts\build-windows.ps1
    .\scripts\build-windows.ps1 -Tests
#>
param(
    # Also run the test suite after building.
    [switch]$Tests,
    # Build in debug mode (faster, unoptimized).
    [switch]$Debug
)

$ErrorActionPreference = 'Stop'

# Locate repo root (directory containing Cargo.toml with [workspace]).
$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $root 'Cargo.toml'))) {
    $root = Get-Location
}
Set-Location $root
Write-Host "==> Repo root: $root" -ForegroundColor Cyan

# Toolchain check
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "cargo not found. Install Rust from https://rustup.rs (rustup-init.exe) and restart your shell."
}
cargo --version
rustc --version

# Build
if ($Debug) {
    Write-Host '==> cargo build (debug)' -ForegroundColor Cyan
    cargo build -p zipsentinel-cli
    $exe = Join-Path $root 'target\debug\zipsentinel.exe'
} else {
    Write-Host '==> cargo build --release' -ForegroundColor Cyan
    cargo build --release -p zipsentinel-cli
    $exe = Join-Path $root 'target\release\zipsentinel.exe'
}

if (-not (Test-Path $exe)) { Write-Error "Build finished but $exe was not produced." }

# Verify
Write-Host '==> Verifying binary' -ForegroundColor Cyan
& $exe --version
& $exe --help | Select-Object -First 12

if ($Tests) {
    Write-Host '==> cargo test --workspace' -ForegroundColor Cyan
    cargo test --workspace
}

Write-Host ''
Write-Host "Done. Binary: $exe" -ForegroundColor Green
Write-Host "Add to PATH or invoke directly, e.g.:`n  & `"$exe`" scan archive.zip"
