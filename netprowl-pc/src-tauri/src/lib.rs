mod scanner;

use scanner::{WHITE_PORTS, FULL_PORTS};
use std::sync::Mutex;

pub use scanner::PortState;

// ---------------------------------------------------------------------------
// Local types (frontend-compatible)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Router,
    PC,
    Camera,
    NAS,
    Phone,
    Printer,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Port {
    pub port: u16,
    pub state: PortState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Device {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<DeviceType>,
    pub ports: Vec<Port>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sources: Vec<String>,
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

pub struct ScannerState {
    pub devices: Mutex<Vec<Device>>,
}

impl Default for ScannerState {
    fn default() -> Self {
        Self { devices: Mutex::new(Vec::new()) }
    }
}

// ---------------------------------------------------------------------------
// Convert netprowl_core types → local types
// ---------------------------------------------------------------------------

fn convert_port(core_port: netprowl_core::types::Port) -> Port {
    Port {
        port: core_port.port,
        state: core_port.state,
        service: core_port.service,
        banner: core_port.banner,
    }
}

fn convert_device(core_dev: netprowl_core::types::Device) -> Device {
    let dt = match core_dev.device_type {
        netprowl_core::types::DeviceType::Router => DeviceType::Router,
        netprowl_core::types::DeviceType::PC => DeviceType::PC,
        netprowl_core::types::DeviceType::Camera => DeviceType::Camera,
        netprowl_core::types::DeviceType::NAS => DeviceType::NAS,
        netprowl_core::types::DeviceType::Phone => DeviceType::Phone,
        netprowl_core::types::DeviceType::Printer => DeviceType::Printer,
        netprowl_core::types::DeviceType::Unknown => DeviceType::Unknown,
    };
    Device {
        ip: core_dev.ip,
        mac: core_dev.mac,
        hostname: core_dev.hostname,
        vendor: core_dev.vendor,
        device_type: Some(dt),
        ports: core_dev.open_ports.into_iter().map(convert_port).collect(),
        sources: core_dev
            .sources
            .iter()
            .map(|s| format!("{:?}", s).to_lowercase())
            .collect::<Vec<_>>(),
    }
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
pub struct ScanOptions {
    pub subnet: String,
    pub concurrency: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub full_ports: Option<bool>,
}

#[tauri::command]
async fn start_scan(
    opts: ScanOptions,
    state: tauri::State<'_, ScannerState>,
) -> Result<Vec<Device>, String> {
    let timeout_ms = opts.timeout_ms.unwrap_or(2000);
    let concurrency = opts.concurrency.unwrap_or(100);

    let ports = if opts.full_ports.unwrap_or(false) {
        FULL_PORTS.to_vec()
    } else {
        WHITE_PORTS.to_vec()
    };

    // Launch SSDP + mDNS discovery concurrently
    let ssdp_handle =
        tokio::spawn(async move { scanner::ssdp::discover_ssdp(timeout_ms).await });
    let mdns_handle =
        tokio::spawn(async move { scanner::mdns::discover_mdns(timeout_ms).await });

    // TCP subnet scan
    let tcp_core_devices: Vec<netprowl_core::types::Device> =
        scanner::tcp::scan_subnet(&opts.subnet, ports, timeout_ms, concurrency).await;

    // Collect SSDP results
    let mut ssdp_devices = Vec::new();
    if let Ok(Ok(ssdp_result)) = ssdp_handle.await {
        ssdp_devices = ssdp_result;
    }

    // Collect mDNS results
    let mut mdns_devices = Vec::new();
    if let Ok(Ok(mdns_result)) = mdns_handle.await {
        mdns_devices = mdns_result;
    }

    // Merge all devices — deduplicate by IP
    let mut all_devices: Vec<Device> = tcp_core_devices
        .into_iter()
        .map(convert_device)
        .collect();

    for ssdp_dev in ssdp_devices {
        let flat = convert_device(ssdp_dev);
        if !all_devices.iter().any(|d| d.ip == flat.ip) {
            all_devices.push(flat);
        }
    }

    for mdns_dev in mdns_devices {
        let flat = convert_device(mdns_dev);
        if !all_devices.iter().any(|d| d.ip == flat.ip) {
            all_devices.push(flat);
        }
    }

    let mut state_devices = state
        .devices
        .lock()
        .map_err(|e: std::sync::PoisonError<_>| e.to_string())?;
    *state_devices = all_devices.clone();

    Ok(all_devices)
}

#[tauri::command]
fn get_devices(state: tauri::State<'_, ScannerState>) -> Result<Vec<Device>, String> {
    let devices = state
        .devices
        .lock()
        .map_err(|e: std::sync::PoisonError<_>| e.to_string())?;
    Ok(devices.clone())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(ScannerState::default())
        .invoke_handler(tauri::generate_handler![start_scan, get_devices])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
