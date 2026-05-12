//! Tauri commands backed by netprowl-core (Rust).

use netprowl_core::{discover_lan, DiscoveryOptions};

#[tauri::command]
pub async fn scan_network() -> Result<netprowl_core::ScanResult, String> {
    discover_lan(DiscoveryOptions::default())
        .await
        .map_err(|e| e.to_string())
}

// TODO: netprowl-core does not yet export scanner::get_local_ip.
// Until it does, fall back to the local-ip-address crate.
#[tauri::command]
pub fn get_local_ip() -> Result<String, String> {
    local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .map_err(|e| e.to_string())
}
