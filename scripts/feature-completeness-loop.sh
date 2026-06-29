#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

check_count=0

require_file() {
  local label="$1"
  local file="$2"
  check_count=$((check_count + 1))
  if [[ ! -f "$ROOT_DIR/$file" ]]; then
    echo "FAIL [$label] missing file: $file" >&2
    exit 1
  fi
  echo "PASS [$label] $file"
}

require_text() {
  local label="$1"
  local file="$2"
  local text="$3"
  require_file "$label" "$file" >/dev/null
  check_count=$((check_count + 1))
  if ! rg -q --fixed-strings "$text" "$ROOT_DIR/$file"; then
    echo "FAIL [$label] expected text not found in $file: $text" >&2
    exit 1
  fi
  echo "PASS [$label] $file contains: $text"
}

echo "==> Baseline reliability loop"
"$ROOT_DIR/scripts/reliability-loop.sh"

echo "==> Feature completeness evidence"

# Shared Rust core
require_text "Core mDNS export" "rs-core/src/scanner/mod.rs" "pub use mdns::{discover_mdns_sync, MDNSConfig};"
require_text "Core SSDP export" "rs-core/src/scanner/mod.rs" "pub use ssdp::{discover_ssdp_sync, SSDPConfig};"
require_text "Core TCP export" "rs-core/src/scanner/mod.rs" "pub use tcp::probe_tcp_ports_sync;"
require_text "Core banner export" "rs-core/src/scanner/mod.rs" "pub use banner::grab_banner_sync;"
require_text "Core service fingerprint export" "rs-core/src/scanner/mod.rs" "pub use registry::guess_service;"
require_text "Core WASM subnet binding" "rs-core/src/lib.rs" "pub fn expand_subnet"
require_text "Core AI binding" "rs-core/src/lib.rs" "pub fn wasm_diagnose_network"
require_text "Core security report" "rs-core/src/security/report.rs" "pub fn generate_security_report"
require_text "Core TLS audit rules" "rs-core/src/security/tls_audit.rs" "pub fn build_tls_report"
require_text "Core recon aggregate" "rs-core/src/recon/mod.rs" "pub fn run_recon"

# PC backend and UI
require_text "PC scan command" "netprowl-pc/src-tauri/src/lib.rs" "start_scan,"
require_text "PC command registration" "netprowl-pc/src-tauri/src/lib.rs" "tauri::generate_handler!"
require_text "PC tool pipeline command" "netprowl-pc/src-tauri/src/lib.rs" "start_pipeline,"
require_text "PC tool discovery" "netprowl-pc/src-tauri/src/scanner/tool_discovery.rs" "pub fn check_all_tools"
require_text "PC external scanner wrappers" "netprowl-pc/src-tauri/src/tool_commands.rs" "pub fn run_masscan"
require_text "PC TLS audit command" "netprowl-pc/src-tauri/src/lib.rs" "tls_audit,"
require_text "PC history schema" "netprowl-pc/src-tauri/src/history/schema.rs" "CREATE TABLE IF NOT EXISTS scan_sessions"
require_text "PC report export" "netprowl-pc/src-tauri/src/report.rs" "pub fn export_html"
require_text "PC AI commands" "netprowl-pc/src-tauri/src/lib.rs" "ai_commands::ai_diagnose_network"
require_text "PC recon commands" "netprowl-pc/src-tauri/src/lib.rs" "recon_commands::recon_full"
require_text "PC pipeline UI" "netprowl-pc/src/components/PipelinePanel.tsx" "invoke('start_pipeline'"
require_text "PC recon UI" "netprowl-pc/src/components/ReconPanel.tsx" "invoke<CombinedReconResult>('recon_full'"
require_text "PC history UI" "netprowl-pc/src/stores/historyStore.ts" "invoke<ScanSession[]>('get_scan_history'"
require_text "PC export UI" "netprowl-pc/src/components/ExportPanel.tsx" "export function ExportPanel"

# Mini program
require_text "Mini scan orchestrator" "netprowl-mini/src/services/scanner.ts" "export async function runFullScan"
require_text "Mini mDNS native API" "netprowl-mini/src/services/mdns.ts" "startLocalServiceDiscovery"
require_text "Mini SSDP native API" "netprowl-mini/src/services/ssdp.ts" "createUDPSocket"
require_text "Mini TCP native API" "netprowl-mini/src/services/tcp.ts" "createTCPSocket"
require_text "Mini scan history persistence" "netprowl-mini/src/stores/deviceStore.ts" "netprowl_scan_history"
require_text "Mini history page" "netprowl-mini/src/app.config.ts" "pages/history/index"
require_text "Mini topology canvas" "netprowl-mini/src/components/TopoCanvas.tsx" "class TopoCanvas"
require_text "Mini WASM adapter caveat" "netprowl-mini/src/wasm/netprowl_core.ts" "MUST use WeChat native APIs"

echo "==> Feature completeness loop passed ($check_count checks)"
