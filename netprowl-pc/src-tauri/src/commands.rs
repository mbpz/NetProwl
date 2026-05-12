//! Legacy command stubs — used by main.rs until full migration is complete.

use crate::{Device, Port, PortState};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanOptions {
    pub subnet: String,
    pub concurrency: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub full_ports: Option<bool>,
}

#[tauri::command]
pub async fn scan_network(opts: ScanOptions) -> Result<Vec<Device>, String> {
    // Delegate to lib.rs implementation via ScannerState
    // This stub will be removed once main.rs is updated to use lib.rs directly
    Err("use start_scan command from lib.rs".to_string())
}

#[tauri::command]
pub fn get_local_ip() -> Result<String, String> {
    local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .map_err(|e| e.to_string())
}
