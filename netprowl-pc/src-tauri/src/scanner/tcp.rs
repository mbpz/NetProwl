//! TCP port scanner — thin wrapper delegating to rs-core

use crate::scanner::Port;
use rs_core::scanner::tcp::TCPConfig;

pub use rs_core::scanner::tcp::TCPConfig as TcpConfig;

/// Scan TCP ports on a single IP. Delegates to rs-core async scanner.
pub async fn probe_ports(ip: &str, cfg: TcpConfig) -> Vec<Port> {
    rs_core::scanner::tcp::probe_tcp_ports(ip, cfg)
        .await
        .unwrap_or_default()
}
