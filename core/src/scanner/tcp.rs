// TODO: implement TCP scanning

use crate::types::Port;

pub struct TCPConfig {
    pub timeout_ms: u64,
    pub concurrency: u32,
}

pub async fn probe_tcp_ports(ip: &str, ports: &[u16], _config: TCPConfig) -> Vec<Port> {
    let _ = (ip, ports);
    Vec::new()
}

pub async fn probe_tcp_port(ip: &str, port: u16, timeout_ms: u64) -> Option<Port> {
    let _ = (ip, port, timeout_ms);
    None
}