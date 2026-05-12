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
    let socket = UdpSocket::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))?;
    socket.set_read_timeout(Some(cfg.timeout))?;
    socket.send_to(M_SEARCH, SocketAddr::from((SSDP_ADDR, SSDP_PORT)))?;

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
    Ok(devices)
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