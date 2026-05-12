//! Tauri commands backed by netprowl-core (Rust).

use netprowl_core::{discover_lan, DiscoveryOptions, scanner::get_local_ip};

#[tauri::command]
pub async fn scan_network() -> Result<netprowl_core::ScanResult, String> {
    discover_lan(DiscoveryOptions::default())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_local_ip() -> Result<String, String> {
    get_local_ip()
        .ok_or_else(|| "Could not determine local IP".to_string())
}
