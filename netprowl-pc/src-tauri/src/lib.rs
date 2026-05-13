use std::sync::Mutex;

mod commands;
mod pipeline;
mod history;
mod report;
mod scanner;
mod tls;
mod tool_commands;

pub use scanner::{Device, FULL_PORTS, WHITE_PORTS};
pub use scanner::ip::expand_subnet;
pub use scanner::registry::match_service;
pub use scanner::tcp::TcpConfig;
pub use scanner::tool_discovery::{ToolStatus, check_all_tools};
pub use history::{HistoryDb, ScanSession, SessionDetail, VulnRecord};
pub use pipeline::{CancelToken, PipelineOptions, PipelineResult};
pub use report::{ScanReport, DeviceReport, PortReport, ReportSummary};
pub use tool_commands::{
    run_ffuf, run_feroxbuster, run_masscan, run_nmap, run_nuclei, run_rustscan,
};
pub use commands::{
    start_scan_session, end_scan_session, insert_scan_vulnerability,
    get_scan_history, get_session_detail, delete_scan_session,
    clear_scan_history, cleanup_scan_history, save_scan,
};

#[derive(Debug, serde::Deserialize)]
pub struct ScanOptions {
    pub subnet: String,
    pub concurrency: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub full_ports: Option<bool>,
}

pub struct ScannerState {
    pub devices: Mutex<Vec<Device>>,
    pub cancel_token: Mutex<Option<CancelToken>>,
    pub db: Mutex<HistoryDb>,
}

impl Default for ScannerState {
    fn default() -> Self {
        let db = Self::init_db();
        Self {
            devices: Mutex::new(Vec::new()),
            cancel_token: Mutex::new(None),
            db: Mutex::new(db),
        }
    }
}

impl ScannerState {
    fn init_db() -> HistoryDb {
        let db_path = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("netprowl-pc")
            .join("history.db");
        HistoryDb::new(&db_path).expect("failed to open history DB")
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

    // SSDP + mDNS concurrently
    let ssdp_handle = tokio::spawn(async move { crate::scanner::ssdp::discover_ssdp(5000).await });
    let mdns_handle = tokio::spawn(async move { crate::scanner::mdns::discover_mdns(5000).await });

    // TCP scan each IP
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(cfg.concurrency));
    let mut handles = Vec::new();

    for ip in ips {
        let permit = semaphore.clone().acquire_owned().await;
        let cfg = cfg.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let ports = crate::scanner::tcp::probe_ports(&ip, cfg).await;
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

#[tauri::command]
async fn start_pipeline(opts: PipelineOptions, state: tauri::State<'_, ScannerState>) -> Result<Vec<PipelineResult>, String> {
    let cancel = CancelToken::new();
    {
        let mut token = state.cancel_token.lock().map_err(|e: std::sync::PoisonError<_>| e.to_string())?;
        *token = Some(cancel.clone());
    }
    let result = pipeline::run_pipeline(opts, cancel).await;
    {
        let mut token = state.cancel_token.lock().map_err(|e: std::sync::PoisonError<_>| e.to_string())?;
        *token = None;
    }
    result
}

#[tauri::command]
fn cancel_scan(state: tauri::State<'_, ScannerState>) -> Result<(), String> {
    let token = state.cancel_token.lock().map_err(|e: std::sync::PoisonError<_>| e.to_string())?;
    if let Some(t) = token.as_ref() {
        t.cancel();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Report export command
// ---------------------------------------------------------------------------

fn with_history_db<T, F>(state: &ScannerState, f: F) -> Result<T, String>
where
    F: FnOnce(&HistoryDb) -> Result<T, String>,
{
    let guard = state.db.lock().map_err(|e| e.to_string())?;
    f(&guard)
}

#[tauri::command]
async fn export_report(scan_id: i64, format: String, state: tauri::State<'_, ScannerState>) -> Result<String, String> {
    with_history_db(&state, |db| {
        let full_report = report::build_report(db, scan_id)?;
        match format.as_str() {
            "json" => Ok(report::export_json(&full_report)),
            "html" => Ok(report::export_html(&full_report)),
            "csv" => Ok(report::export_csv(&full_report)),
            _ => Err("unsupported format, use json|html|csv".to_string()),
        }
    })
}

#[tauri::command]
async fn export_session_json(session_id: i64, state: tauri::State<'_, ScannerState>) -> Result<String, String> {
    with_history_db(&state, |db| {
        let detail = db.get_session_detail(session_id)?;
        serde_json::to_string_pretty(&detail).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn tls_audit(host: String, port: u16) -> Result<tls::TLSAuditResult, String> {
    let cert = tls::fetch_cert_info(&host, port)
        .map_err(|e| e.to_string())?;
    let config = tls::check_tls_config(&host, port)
        .map_err(|e| e.to_string())?;
    let vulns = tls::rules::check_vulnerabilities(&config, &cert);
    Ok(tls::TLSAuditResult {
        host,
        port,
        cert,
        config,
        vulnerabilities: vulns,
        testssl_used: false,
    })
}

#[tauri::command]
async fn parse_banner_ai(banner: String, api_key: String) -> Result<rs_core::ai::BannerResult, String> {
    rs_core::ai::banner_parser::parse_banner_with_ai(&banner, &api_key).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(ScannerState::default())
        .invoke_handler(tauri::generate_handler![
            start_scan,
            get_devices,
            check_tool_status,
            start_pipeline,
            cancel_scan,
            tls_audit,
            parse_banner_ai,
            save_scan,
            export_report,
            export_session_json,
            start_scan_session,
            end_scan_session,
            insert_scan_vulnerability,
            get_scan_history,
            get_session_detail,
            delete_scan_session,
            clear_scan_history,
            cleanup_scan_history,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}