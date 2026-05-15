//! NetProwl Core Scanner Module
//!
//! Types Port / PortState / DeviceType are re-exported from rs-core (single authority).
//! Device is PC-specific (different field contract).

pub mod ssdp;        // PC-native tokio UdpSocket implementation
pub mod mdns;        // stub — TODO: implement with rs-core or trust-dns-resolver
pub mod tool_discovery;
pub mod os_fingerprint;

pub use os_fingerprint::{OsFingerprint, OsType, detect_os};

// ── Re-export from rs-core (single authority) ──

pub use rs_core::types::{Port, PortState, DeviceType, DiscoverySource};

// ── PC-specific Device (keeps existing field names for Tauri IPC compat) ──

use serde::{Deserialize, Serialize};

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

// ── Port lists ──

pub const WHITE_PORTS: &[u16] = &[80, 443, 8080, 8443, 554, 5000, 9000, 49152];

pub const FULL_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 9200, 27017,
];
