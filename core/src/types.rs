use wasm_bindgen::prelude::*;

#[derive(serde::Serialize)]
pub struct Device {
    pub id: String,
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: String,
    pub os: String,
    pub open_ports: Vec<Port>,
    pub discovered_at: u64,
    pub sources: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct Port {
    pub port: u16,
    pub service: String,
    pub state: String,
    pub banner: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ScanResult {
    pub devices: Vec<Device>,
    pub duration_ms: u64,
}

#[derive(serde::Serialize)]
pub struct BannerConfig {
    pub timeout_ms: u32,
    pub include_deep_scan: bool,
    pub include_rtspsdp: bool,
}

#[derive(serde::Serialize)]
pub struct RTSPStreamInfo {
    pub server: String,
    pub stream_url: String,
    pub camera_brand: String,
    pub auth: String,
}

#[derive(serde::Serialize)]
pub struct HTTPHeaders {
    pub server: String,
    pub x_powered_by: String,
    pub x_generator: String,
    pub title: String,
    pub cms: String,
    pub paths_found: Vec<String>,
}