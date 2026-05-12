use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: String,
    pub os: String,
    pub open_ports: Vec<Port>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Port {
    pub port: u16,
    pub service: String,
    pub state: String,
}

#[tauri::command]
pub fn scan_network() -> Result<Vec<Device>, String> {
    // TODO: 调用 Go core WASM
    // 暂时返回空列表，后续集成
    Ok(vec![])
}

#[tauri::command]
pub fn get_local_ip() -> Result<String, String> {
    // TODO: 获取本机 IP
    Ok("192.168.1.1".to_string())
}
