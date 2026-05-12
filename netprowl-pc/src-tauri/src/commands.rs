//! Tauri commands backed by netprowl-core (Rust).

use netprowl_core::{discover_lan, DiscoveryOptions, scanner::get_local_ip};

mod tool_commands;
pub use tool_commands::{
    run_ffuf, run_feroxbuster, run_masscan, run_nmap, run_nuclei, run_rustscan,
};

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
