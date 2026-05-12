use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub port: u16,
    pub service: Option<String>,
    pub state: PortState,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Filtered,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    #[serde(rename = "mac")]
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    #[serde(rename = "deviceType")]
    pub device_type: DeviceType,
    pub os: OSType,
    #[serde(rename = "openPorts")]
    pub open_ports: Vec<Port>,
    pub sources: Vec<DiscoverySource>,
    #[serde(rename = "discoveredAt")]
    pub discovered_at: Option<Duration>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Router,
    Pc,
    Camera,
    Nas,
    Phone,
    Printer,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OSType {
    Linux,
    Windows,
    Network,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DiscoverySource {
    Mdns,
    Ssdp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub devices: Vec<Device>,
    #[serde(rename = "durationMs")]
    pub duration_ms: i64,
    #[serde(rename = "mdnsUnavailable")]
    pub mdns_unavailable: bool,
}