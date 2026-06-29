#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
check_count=0

pass() {
  echo "PASS [$1] $2"
}

fail() {
  echo "FAIL [$1] $2" >&2
  exit 1
}

require_file() {
  local label="$1"
  local file="$2"
  check_count=$((check_count + 1))
  [[ -f "$ROOT_DIR/$file" ]] || fail "$label" "missing file: $file"
  pass "$label" "$file"
}

require_text() {
  local label="$1"
  local file="$2"
  local text="$3"
  require_file "$label" "$file" >/dev/null
  check_count=$((check_count + 1))
  rg -q --fixed-strings "$text" "$ROOT_DIR/$file" \
    || fail "$label" "expected text not found in $file: $text"
  pass "$label" "$file contains: $text"
}

reject_text() {
  local label="$1"
  local file="$2"
  local text="$3"
  require_file "$label" "$file" >/dev/null
  check_count=$((check_count + 1))
  if rg -q --fixed-strings "$text" "$ROOT_DIR/$file"; then
    fail "$label" "forbidden text found in $file: $text"
  fi
  pass "$label" "$file does not contain: $text"
}

echo "==> Baseline feature completeness"
"$ROOT_DIR/scripts/feature-completeness-loop.sh"

echo "==> README and roadmap truthfulness"
reject_text "README no blanket completion claim" "README.md" "Phase 1-4 全部完成"
reject_text "README no mandatory testssl claim" "README.md" "rustls + testssl.sh"
require_text "README evidence-gated status" "README.md" "当前状态以本地/CI loop 的验证结果为准"
require_text "README roadmap caveat" "README.md" "Roadmap 是目标规划，不等同于完成度声明"
require_text "README review loop documented" "README.md" "./scripts/roadmap-readme-code-review-loop.sh"
require_text "README mini history status" "README.md" "✅ Storage"
require_text "README optional testssl status" "README.md" "✅ rustls（testssl.sh 可选）"
require_text "Roadmap phase 1 exists" "roadmap.md" "Phase 1 · 局域网服务发现"
require_text "Roadmap acceptance remains target" "roadmap.md" "MVP 验收标准"

echo "==> Source completion review guards"
reject_text "PC mDNS is not a stub" "netprowl-pc/src-tauri/src/scanner/mdns.rs" "mDNS discovery stub"
reject_text "PC mDNS has no TODO implementation marker" "netprowl-pc/src-tauri/src/scanner/mdns.rs" "TODO: implement"
require_text "PC mDNS reuses shared core" "netprowl-pc/src-tauri/src/scanner/mdns.rs" "rs_core::scanner::mdns::discover_mdns"
require_text "Core mDNS binds service socket" "rs-core/src/scanner/mdns.rs" "SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)"
require_text "PC mDNS reports runtime failure" "netprowl-pc/src-tauri/src/scanner/mdns.rs" "mDNS discovery unavailable"
require_text "Mini mDNS uses native API" "netprowl-mini/src/services/mdns.ts" "startLocalServiceDiscovery"
require_text "Mini SSDP uses native API" "netprowl-mini/src/services/ssdp.ts" "createUDPSocket"
require_text "Mini TCP uses native API" "netprowl-mini/src/services/tcp.ts" "createTCPSocket"

tmp_file="$(mktemp)"
rg -n "TODO: implement|unimplemented!|todo!|panic!\\(\"not implemented|mDNS discovery stub" \
  "$ROOT_DIR/netprowl-pc/src-tauri/src" \
  "$ROOT_DIR/netprowl-pc/src" \
  "$ROOT_DIR/netprowl-mini/src" >"$tmp_file" || true

if [[ -s "$tmp_file" ]]; then
  cat "$tmp_file" >&2
  rm -f "$tmp_file"
  fail "Unexpected implementation marker" "active source contains unfinished implementation markers"
fi
rm -f "$tmp_file"
pass "Unexpected implementation marker" "active source has no hard unfinished implementation markers"

echo "==> Roadmap/README/code-review loop passed ($check_count checks)"
