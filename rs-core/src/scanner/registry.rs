use crate::types::DeviceType;

#[cfg(not(target_arch = "wasm32"))]
use crate::cve::{query, CveResult};
#[cfg(not(target_arch = "wasm32"))]
use rusqlite::Connection;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Mutex;
#[cfg(not(target_arch = "wasm32"))]
use once_cell::sync::Lazy;

#[cfg(not(target_arch = "wasm32"))]
static CVE_CONN: Lazy<Mutex<Option<Connection>>> = Lazy::new(|| Mutex::new(None));

#[cfg(not(target_arch = "wasm32"))]
pub fn init_cve_db() -> Result<(), String> {
    let conn = crate::cve::init_db().map_err(|e| format!("Failed to init CVE DB: {}", e))?;
    let mut guard = CVE_CONN.lock().map_err(|e| e.to_string())?;
    *guard = Some(conn);
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn lookup_cve(software: &str, version: &str) -> Vec<CveResult> {
    let guard = match CVE_CONN.lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };
    let conn = match guard.as_ref() {
        Some(c) => c,
        None => return Vec::new(),
    };
    query(conn, software, version).unwrap_or_default()
}

pub struct ServiceRule {
    pub id: &'static str,
    pub port: u16,
    pub banner_contains: Option<&'static str>,
    pub service: &'static str,
    pub device_type: DeviceType,
}

static RULES: once_cell::sync::Lazy<Vec<ServiceRule>> = once_cell::sync::Lazy::new(|| {
    vec![
        ServiceRule { id: "http", port: 80, banner_contains: None, service: "HTTP", device_type: DeviceType::Unknown },
        ServiceRule { id: "https", port: 443, banner_contains: None, service: "HTTPS", device_type: DeviceType::Unknown },
        ServiceRule { id: "ssh", port: 22, banner_contains: Some("SSH"), service: "SSH", device_type: DeviceType::Unknown },
        ServiceRule { id: "ftp", port: 21, banner_contains: Some("FTP"), service: "FTP", device_type: DeviceType::Unknown },
        ServiceRule { id: "hikvision-camera", port: 554, banner_contains: Some("Hikvision"), service: "Hikvision Camera", device_type: DeviceType::Camera },
        ServiceRule { id: "synology-nas", port: 5000, banner_contains: Some("Synology"), service: "Synology NAS", device_type: DeviceType::Nas },
        ServiceRule { id: "rtsp", port: 554, banner_contains: Some("RTSP"), service: "RTSP Stream", device_type: DeviceType::Camera },
        ServiceRule { id: "http-proxy", port: 8080, banner_contains: None, service: "HTTP Proxy", device_type: DeviceType::Unknown },
        ServiceRule { id: "upnp", port: 1900, banner_contains: Some("UPnP"), service: "UPnP", device_type: DeviceType::Unknown },
    ]
});

pub fn match_service(port: u16, banner: &str) -> (&'static str, DeviceType) {
    for rule in RULES.iter() {
        if rule.port != port {
            continue;
        }
        match &rule.banner_contains {
            Some(pattern) if banner.contains(pattern) => return (rule.service, rule.device_type),
            None => return (rule.service, DeviceType::Unknown),
            _ => {}
        }
    }
    ("unknown", DeviceType::Unknown)
}

pub fn guess_service(port: u16) -> String {
    match_service(port, "").0.to_string()
}
