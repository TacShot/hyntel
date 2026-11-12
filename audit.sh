#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if ! command -v cargo >/dev/null 2>&1; then
  echo "[hyntel] Rust/Cargo is required. Install via https://rustup.rs/ and reopen the terminal." >&2
  exit 1
fi
if [[ ! -x "$ROOT/target/release/hyntel" ]]; then
  echo "[hyntel] Building the Rust CLI..."
  cargo build --release
fi
exec "$ROOT/target/release/hyntel" "$@"
