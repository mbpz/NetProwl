//! Core types for agent communication protocol.

use serde::{Deserialize, Serialize};

// ── Commands (mini-program → agent) ──

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd")]
pub enum Command {
    #[serde(rename = "start_scan")]
    StartScan {
        id: String,
        ip_range: String,
        ports: Vec<u16>,
        #[serde(default = "default_timeout")]
        timeout_ms: u64,
    },
    #[serde(rename = "stop_scan")]
    StopScan { id: String },
    #[serde(rename = "get_devices")]
    GetDevices,
    #[serde(rename = "get_banner")]
    GetBanner { ip: String, port: u16 },
    #[serde(rename = "ping")]
    Ping,
}

fn default_timeout() -> u64 { 2000 }

// ── Events (agent → mini-program) ──

#[derive(Debug, Serialize)]
#[serde(tag = "event")]
pub enum Event {
    #[serde(rename = "device_found")]
    DeviceFound { request_id: String, data: DeviceData },
    #[serde(rename = "port_open")]
    PortOpen { request_id: String, ip: String, port: u16, banner: String, banner_hash: String },
    #[serde(rename = "scan_complete")]
    ScanComplete { request_id: String, devices_found: usize, duration_ms: u64 },
    #[serde(rename = "banner_result")]
    BannerResult { ip: String, port: u16, banner: String },
    #[serde(rename = "error")]
    Error { request_id: String, message: String },
    #[serde(rename = "pong")]
    Pong { hostname: String, port: u16 },
}

// ── Device data ──

#[derive(Debug, Clone, Serialize)]
pub struct DeviceData {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    pub ports: Vec<PortData>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortData {
    pub port: u16,
    pub service: String,
    pub banner: String,
}
