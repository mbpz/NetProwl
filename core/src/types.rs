//! Shared domain types for NetProwl scanner core.

use serde::{Deserialize, Serialize};

/// Device type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for DeviceType {
    fn default() -> Self {
        DeviceType::Unknown
    }
}

/// Operating system type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OSType {
    Linux,
    Windows,
    Network,
    Unknown,
}

impl Default for OSType {
    fn default() -> Self {
        OSType::Unknown
    }
}

/// Discovery source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoverySource {
    MDNS,
    SSDP,
    TCP,
}

/// Port state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Filtered,
    Closed,
}

/// Single port scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    #[serde(rename = "port")]
    pub port: u16,
    #[serde(rename = "service", skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(rename = "state")]
    pub state: PortState,
    #[serde(rename = "banner", skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

impl Port {
    pub fn new(port: u16, state: PortState) -> Self {
        Self { port, service: None, state, banner: None }
    }
}

/// Discovered network device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "ip")]
    pub ip: String,
    #[serde(rename = "mac", skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(rename = "hostname", skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(rename = "vendor", skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(rename = "deviceType", default)]
    pub device_type: DeviceType,
    #[serde(rename = "os", default)]
    pub os: OSType,
    #[serde(rename = "openPorts", default)]
    pub open_ports: Vec<Port>,
    #[serde(rename = "discoveredAt")]
    pub discovered_at_ms: i64,
    #[serde(rename = "sources", default)]
    pub sources: Vec<DiscoverySource>,
    #[serde(rename = "ttl", skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

impl Device {
    pub fn new(ip: String) -> Self {
        Self {
            id: None,
            ip,
            mac: None,
            hostname: None,
            vendor: None,
            device_type: DeviceType::Unknown,
            os: OSType::Unknown,
            open_ports: Vec::new(),
            discovered_at_ms: current_time_ms(),
            sources: Vec::new(),
            ttl: None,
        }
    }
}

/// Full scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    #[serde(rename = "devices")]
    pub devices: Vec<Device>,
    #[serde(rename = "durationMs")]
    pub duration_ms: i64,
    #[serde(rename = "mdnsUnavailable", default)]
    pub mdns_unavailable: bool,
}

/// Scan configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub subnet: String,
    pub target_ips: Vec<String>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub white_ports_only: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            subnet: String::new(),
            target_ips: Vec::new(),
            concurrency: 100,
            timeout_ms: 2000,
            white_ports_only: false,
        }
    }
}

fn current_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}