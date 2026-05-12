use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::process::Command;
use std::time::Duration;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Device {
    #[serde(rename = "ip")]
    pub ip: String,
    #[serde(rename = "mac")]
    pub mac: Option<String>,
    #[serde(rename = "hostname")]
    pub hostname: Option<String>,
    #[serde(rename = "vendor")]
    pub vendor: Option<String>,
    #[serde(rename = "openPorts")]
    pub ports: Vec<Port>,
    #[serde(rename = "sources")]
    pub sources: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Port {
    #[serde(rename = "port")]
    pub port: u16,
    #[serde(rename = "state")]
    pub state: String,
    #[serde(rename = "service")]
    pub service: Option<String>,
    #[serde(rename = "banner")]
    pub banner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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

const WHITE_PORTS: &[u16] = &[80, 443, 8080, 8443, 554, 5000, 9000, 49152];
const FULL_PORTS: &[u16] = &[21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017];

fn get_service_name(port: u16) -> Option<String> {
    let map: HashMap<u16, &str> = [
        (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
        (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
        (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"), (995, "POP3S"),
        (1433, "MSSQL"), (1521, "Oracle"), (1723, "PPTP"), (3306, "MySQL"),
        (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"), (6379, "Redis"),
        (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (5000, "UPnP"), (9000, "Sonar"),
        (49152, "Windows"), (554, "RTSP"), (9200, "Elasticsearch"), (27017, "MongoDB"),
    ].iter().cloned().collect();
    map.get(&port).map(|s| s.to_string())
}

fn run_go_cli(args: &[&str]) -> Result<String, String> {
    let go_bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .map(|mut p| { p.push("../../../core/bin/netprowl"); p })
        .unwrap_or_else(|| std::path::PathBuf::from("../../../core/bin/netprowl"));

    let output = Command::new(&go_bin)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run go cli: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn discover_go_devices(kind: &str) -> Result<Vec<Device>, String> {
    let flag = match kind {
        "mdns" => "--mdns",
        "ssdp" => "--ssdp",
        _ => return Err(format!("unknown discovery kind: {}", kind)),
    };

    let output = run_go_cli(&[flag])?;
    let devices: Vec<Device> = serde_json::from_str(&output)
        .map_err(|e| format!("failed to parse {} devices: {}", kind, e))?;
    Ok(devices)
}

fn get_banner(ip: &str, port: u16, timeout: Duration) -> Option<String> {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        if let Ok(mut stream) = TcpStream::connect_timeout(&std::net::SocketAddr::new(addr, port), timeout) {
            stream.set_read_timeout(Some(timeout)).ok();
            // Send HTTP request for web ports
            if [80, 8080, 8443, 5000, 9000].contains(&port) {
                let _ = stream.write_all(b"GET / HTTP/1.0\r\nHost: 0.0.0.0\r\n\r\n");
            }
            let mut buf = [0u8; 512];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    if !banner.is_empty() {
                        return Some(banner);
                    }
                }
            }
        }
    }
    None
}

fn probe_port(ip: &str, port: u16, timeout: Duration) -> Option<Port> {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        let timeout_adj = Duration::from_millis(timeout.as_millis() as u64);
        if TcpStream::connect_timeout(&std::net::SocketAddr::new(addr, port), timeout_adj).is_ok() {
            let banner = get_banner(ip, port, timeout_adj);
            let service = get_service_name(port);
            return Some(Port { port, state: "open".to_string(), service, banner });
        }
    }
    None
}

#[tauri::command]
async fn start_scan(opts: ScanOptions, state: tauri::State<'_, ScannerState>) -> Result<Vec<Device>, String> {
    let timeout = Duration::from_millis(opts.timeout_ms.unwrap_or(2000));
    let concurrency = opts.concurrency.unwrap_or(100) as usize;
    let ports: Vec<u16> = if opts.full_ports.unwrap_or(false) {
        FULL_PORTS.to_vec()
    } else {
        WHITE_PORTS.to_vec()
    };

    // Parse subnet — simplified /24 expansion
    let subnet_base = opts.subnet
        .strip_suffix("/24")
        .unwrap_or(&opts.subnet)
        .trim_end_matches('.');

    let mut handles = Vec::new();
    let mut discovered: Vec<Device> = Vec::new();

    for i in 1..=254 {
        let ip = format!("{}.{}", subnet_base, i);
        let ports_clone = ports.clone();
        let timeout_clone = timeout;

        handles.push(tokio::spawn(async move {
            let mut open_ports = Vec::new();
            for port in ports_clone {
                if let Some(p) = probe_port(&ip, port, timeout_clone) {
                    open_ports.push(p);
                }
            }
            if !open_ports.is_empty() {
                Some(Device {
                    ip,
                    mac: None,
                    hostname: None,
                    vendor: None,
                    ports: open_ports,
                    sources: vec!["tcp".to_string()],
                })
            } else {
                None
            }
        }));
    }

    for h in handles {
        if let Ok(Some(device)) = h.await {
            discovered.push(device);
        }
    }

    // Run mDNS discovery via Go CLI
    if let Ok(mdns_devices) = discover_go_devices("mdns") {
        for mdns_dev in mdns_devices {
            if !discovered.iter().any(|d| d.ip == mdns_dev.ip) {
                discovered.push(mdns_dev);
            }
        }
    }

    // Run SSDP discovery via Go CLI
    if let Ok(ssdp_devices) = discover_go_devices("ssdp") {
        for ssdp_dev in ssdp_devices {
            if !discovered.iter().any(|d| d.ip == ssdp_dev.ip) {
                discovered.push(ssdp_dev);
            }
        }
    }

    let mut state_devices = state.devices.lock().map_err(|e| e.to_string())?;
    *state_devices = discovered.clone();

    Ok(discovered)
}

#[tauri::command]
fn get_devices(state: tauri::State<'_, ScannerState>) -> Result<Vec<Device>, String> {
    let devices = state.devices.lock().map_err(|e| e.to_string())?;
    Ok(devices.clone())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(ScannerState::default())
        .invoke_handler(tauri::generate_handler![start_scan, get_devices])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}