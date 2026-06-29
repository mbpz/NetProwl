#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MINI_DIR="$ROOT_DIR/netprowl-mini"

if [[ ! -d "$MINI_DIR/node_modules" ]]; then
  echo "netprowl-mini dependencies are missing. Run: cd netprowl-mini && npm install --force" >&2
  exit 1
fi

npm --prefix "$MINI_DIR" run build:weapp
