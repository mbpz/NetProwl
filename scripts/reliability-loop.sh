#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> rs-core unit tests"
RUSTFLAGS="${RUSTFLAGS:-} -Dwarnings" cargo test --manifest-path "$ROOT_DIR/rs-core/Cargo.toml"

echo "==> Tauri backend unit tests"
RUSTFLAGS="${RUSTFLAGS:-} -Dwarnings" cargo test --manifest-path "$ROOT_DIR/netprowl-pc/src-tauri/Cargo.toml"

echo "==> PC frontend typecheck and build"
npm --prefix "$ROOT_DIR/netprowl-pc" run build

echo "==> Reliability loop passed"
