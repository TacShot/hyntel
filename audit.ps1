$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "[hyntel] Rust/Cargo is required. Install from https://rustup.rs/ and reopen PowerShell."
}
$Binary = Join-Path $Root "target\release\hyntel.exe"
if (-not (Test-Path $Binary)) {
    Write-Host "[hyntel] Building the Rust CLI..."
    cargo build --release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
& $Binary @args
exit $LASTEXITCODE
