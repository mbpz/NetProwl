//! SSDP discovery — WASM stub
//!
//! SSDP 发现由小程序 wx.createUDPSocket() API 承担。

use crate::types::Device;

pub async fn discover_ssdp(_timeout_ms: u64) -> Vec<Device> {
    vec![]
}
