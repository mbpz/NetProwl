//! mDNS discovery — WASM stub
//!
//! mDNS 发现由小程序 wx.startLocalServiceDiscovery() API 承担。

use crate::types::Device;

pub async fn discover_mdns(_timeout_ms: u64) -> Vec<Device> {
    vec![]
}
