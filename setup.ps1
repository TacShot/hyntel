$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
Write-Host "[setup] Hyntel Rust CLI"
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "[setup] Rust/Cargo is not installed. Install the stable toolchain from https://rustup.rs/ then rerun .\setup.ps1."
    exit 1
}
rustc --version
cargo --version
Write-Host "[setup] Building Hyntel..."
cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "[setup] Setup complete. Run .\audit.ps1"
