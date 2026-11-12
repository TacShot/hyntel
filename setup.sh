#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
echo "[setup] Hyntel Rust CLI"
if ! command -v cargo >/dev/null 2>&1; then
  echo "[setup] Rust/Cargo is not installed."
  echo "[setup] Install the stable toolchain from https://rustup.rs/ then rerun ./setup.sh."
  exit 1
fi
rustc --version
cargo --version
echo "[setup] Building Hyntel..."
cargo build --release
echo "[setup] Setup complete."
echo "[setup] Run: ./audit.sh"
