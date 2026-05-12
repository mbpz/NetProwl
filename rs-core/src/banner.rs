//! Banner grabbing — WASM stub
//!
//! Banner抓取由小程序 wx.createTCPSocket() API 承担。

use crate::types::Port;

pub async fn grab_banner(_ip: &str, _port: u16) -> Option<String> {
    None
}

pub async fn grab_banners(ips: &[String], ports: &[u16], _timeout_ms: u64) -> Vec<Port> {
    let _ = (ips, ports);
    vec![]
}
