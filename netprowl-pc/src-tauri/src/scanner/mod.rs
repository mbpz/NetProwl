//! NetProwl Core Scanner Module

pub mod ip;
pub mod oui;
pub mod tcp;
pub mod banner;
pub mod registry;
pub mod mdns;
pub mod ssdp;
pub mod tool_discovery;
pub mod os_fingerprint;

pub use os_fingerprint::{OsFingerprint, OsType, detect_os};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub port: u16,
    pub state: PortState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<DeviceType>,
    pub ports: Vec<Port>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sources: Vec<String>,
}

pub const WHITE_PORTS: &[u16] = &[80, 443, 8080, 8443, 554, 5000, 9000, 49152];

pub const FULL_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 9200, 27017,
];
