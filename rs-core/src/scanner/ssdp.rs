use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::types::{Device, DeviceType, DiscoverySource, OSType};

const SSDP_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
const M_SEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";

#[derive(Debug, Clone)]
pub struct SSDPConfig {
    pub timeout: Duration,
}

impl Default for SSDPConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }
}

pub async fn discover_ssdp(cfg: SSDPConfig) -> Result<Vec<Device>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(discover_ssdp_sync(cfg.timeout.as_millis() as u64))
}

pub fn discover_ssdp_sync(timeout_ms: u64) -> Vec<Device> {
    let timeout = Duration::from_millis(timeout_ms);
    let socket = match UdpSocket::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    if socket.set_read_timeout(Some(timeout)).is_err() { return vec![]; }
    if socket.send_to(M_SEARCH, SocketAddr::from((SSDP_ADDR, SSDP_PORT))).is_err() { return vec![]; }

    let mut devices = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                let response = String::from_utf8_lossy(&buf[..n]).to_string();
                if let Some(mut dev) = parse_ssdp_response(&response, src.ip().to_string()) {
                    dev.sources = vec![DiscoverySource::Ssdp];
                    devices.push(dev);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
    devices
}

fn parse_ssdp_response(banner: &str, ip: String) -> Option<Device> {
    let mut hostname = None;
    for line in banner.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("server:") {
            if let Some((_, val)) = line.split_once(':') {
                hostname = Some(val.trim().to_string());
            }
        }
    }

    Some(Device {
        ip,
        mac: None,
        hostname,
        vendor: None,
        device_type: DeviceType::Unknown,
        os: OSType::Unknown,
        open_ports: vec![],
        sources: vec![],
        discovered_at: None,
        ttl: None,
    })
}