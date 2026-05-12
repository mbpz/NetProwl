//! TCP scanner stub
//!
//! WASM 环境不能直接进行 TCP 扫描。
//! 微信小程序使用 wx.createTCPSocket() API，不依赖此函数。

use crate::types::{Port, Device};

pub struct TcpConfig {
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
}

/// WASM stub — TCP 扫描由小程序 wx API 承担
pub async fn probe_ports(_ip: &str, _cfg: TcpConfig) -> Vec<Port> {
    vec![]
}

pub async fn scan_subnet(_subnet: &str, _ports: Vec<u16>, _timeout_ms: u64) -> Vec<Device> {
    vec![]
}
