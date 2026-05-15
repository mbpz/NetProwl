use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub port: u16,
    #[serde(rename = "state")]
    pub state: PortState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(rename = "deviceType")]
    pub device_type: DeviceType,
    pub os: OSType,
    #[serde(rename = "openPorts")]
    pub open_ports: Vec<Port>,
    pub sources: Vec<DiscoverySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerConfig {
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: u64,
    #[serde(rename = "includeDeepScan")]
    pub include_deep_scan: bool,
    #[serde(rename = "includeRtspsdp")]
    pub include_rtspsdp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RTSPStreamInfo {
    pub server: String,
    #[serde(rename = "streamUrl")]
    pub stream_url: String,
    #[serde(rename = "cameraBrand")]
    pub camera_brand: String,
    pub auth: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTTPHeaders {
    pub server: String,
    #[serde(rename = "xPoweredBy")]
    pub x_powered_by: String,
    #[serde(rename = "xGenerator")]
    pub x_generator: String,
    pub title: String,
    pub cms: String,
    #[serde(rename = "pathsFound")]
    pub paths_found: Vec<String>,
}

pub const WHITE_PORTS: &[u16] = &[80, 443, 8080, 8443, 554, 5000, 9000, 49152];

// SSDP multicast
pub const SSDP_MULTICAST_ADDR: &str = "239.255.255.250";
pub const SSDP_PORT: u16 = 1900;

// mDNS multicast
pub const MDNS_MULTICAST_ADDR: &str = "224.0.255.253";
pub const MDNS_PORT: u16 = 5353;
