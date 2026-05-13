mod scanner;

pub use scanner::{
    Device, Port, PortState, WHITE_PORTS, FULL_PORTS,
    ip::expand_subnet,
    tcp::{self, TcpConfig},
    ssdp, mdns,
    registry::match_service,
    tool_discovery::{ToolStatus, check_all_tools},
};
use std::sync::Mutex;

#[derive(Debug, serde::Deserialize)]
pub struct ScanOptions {
    pub subnet: String,
    pub concurrency: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub full_ports: Option<bool>,
}

pub struct ScannerState {
    pub devices: Mutex<Vec<Device>>,
}

impl Default for ScannerState {
    fn default() -> Self {
        Self { devices: Mutex::new(Vec::new()) }
    }
}

#[tauri::command]
async fn start_scan(opts: ScanOptions, state: tauri::State<'_, ScannerState>) -> Result<Vec<Device>, String> {
    let cfg = TcpConfig {
        ports: if opts.full_ports.unwrap_or(false) {
            FULL_PORTS.to_vec()
        } else {
            WHITE_PORTS.to_vec()
        },
        concurrency: opts.concurrency.unwrap_or(100) as usize,
        timeout_ms: opts.timeout_ms.unwrap_or(2000) as u64,
    };

    let ips = expand_subnet(&opts.subnet);
    if ips.is_empty() {
        return Err("unsupported subnet format (only /24 supported)".into());
    }

    // SSDP + mDNS 并发
    let ssdp_handle = tokio::spawn(async move { ssdp::discover_ssdp(5000).await });
    let mdns_handle = tokio::spawn(async move { mdns::discover_mdns(5000).await });

    // TCP 扫描每个 IP
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(cfg.concurrency));
    let mut handles = Vec::new();

    for ip in ips {
        let permit = semaphore.clone().acquire_owned().await;
        let cfg = cfg.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let ports = tcp::probe_ports(&ip, cfg).await;
            if ports.is_empty() {
                None
            } else {
                let ports = ports.into_iter().map(|mut p| {
                    let (svc, _) = match_service(p.port, p.banner.as_deref());
                    p.service = Some(svc.to_string());
                    p
                }).collect();
                Some((ip, ports))
            }
        }));
    }

    let mut tcp_devices = Vec::new();
    for h in handles {
        if let Ok(Some((ip, ports))) = h.await {
            tcp_devices.push(Device {
                ip,
                mac: None,
                hostname: None,
                vendor: None,
                device_type: None,
                ports,
                sources: vec!["tcp".into()],
            });
        }
    }

    let mut all_devices = tcp_devices;

    if let Ok(ssdp) = ssdp_handle.await {
        all_devices.extend(ssdp);
    }
    if let Ok(mdns) = mdns_handle.await {
        all_devices.extend(mdns);
    }

    let mut state_devices = state.devices.lock().map_err(|e: std::sync::PoisonError<_>| e.to_string())?;
    *state_devices = all_devices.clone();

    Ok(all_devices)
}

#[tauri::command]
fn get_devices(state: tauri::State<'_, ScannerState>) -> Result<Vec<Device>, String> {
    let devices = state.devices.lock().map_err(|e: std::sync::PoisonError<_>| e.to_string())?;
    Ok(devices.clone())
}

#[tauri::command]
fn check_tool_status() -> Vec<ToolStatus> {
    check_all_tools()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(ScannerState::default())
        .invoke_handler(tauri::generate_handler![start_scan, get_devices, check_tool_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
