use crate::types::{Device, DeviceType, DiscoverySource, OSType, Port, PortState};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

#[derive(Debug, Clone)]
pub struct MDNSConfig {
    pub service_types: Vec<String>,
    pub timeout: Duration,
}

impl Default for MDNSConfig {
    fn default() -> Self {
        Self {
            service_types: vec![
                "_http._tcp".to_string(),
                "_ftp._tcp".to_string(),
                "_ssh._tcp".to_string(),
                "_smb._tcp".to_string(),
                "_airplay._tcp".to_string(),
                "_googlecast._tcp".to_string(),
                "_ipp._tcp".to_string(),
            ],
            timeout: Duration::from_secs(5),
        }
    }
}

// ── Async version (native, uses tokio::net::UdpSocket) ──

#[cfg(not(target_arch = "wasm32"))]
pub async fn discover_mdns(cfg: MDNSConfig) -> Result<Vec<Device>, Box<dyn std::error::Error + Send + Sync>> {
    use std::net::UdpSocket;
    use tokio::net::UdpSocket as TokioUdpSocket;

    // Bind + configure via std socket, then convert to tokio for async I/O
    let std_socket = UdpSocket::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))?;
    std_socket.join_multicast_v4(&MDNS_ADDR, &std::net::Ipv4Addr::UNSPECIFIED)?;
    std_socket.set_nonblocking(true)?;
    let socket = TokioUdpSocket::from_std(std_socket)?;

    // Send queries
    for st in &cfg.service_types {
        let query = build_mdns_query(st);
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            socket.send_to(&query, SocketAddr::from((MDNS_ADDR, MDNS_PORT))),
        )
        .await;
    }

    // Collect responses with timeout
    let mut devices = Vec::new();
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Instant::now() + cfg.timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                if let Some(dev) = parse_mdns_response(&buf[..n], src.ip().to_string()) {
                    devices.push(dev);
                }
            }
            _ => break,
        }
    }

    Ok(devices)
}

// ── Sync version (fallback / WASM) ──

pub fn discover_mdns_sync(cfg: MDNSConfig) -> Vec<Device> {
    let socket = match std::net::UdpSocket::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    if socket.set_read_timeout(Some(cfg.timeout)).is_err() {
        return vec![];
    }
    if socket.join_multicast_v4(&MDNS_ADDR, &std::net::Ipv4Addr::UNSPECIFIED).is_err() {
        return vec![];
    }

    let mut devices = Vec::new();

    for st in &cfg.service_types {
        let query = build_mdns_query(st);
        if socket
            .send_to(&query, SocketAddr::from((MDNS_ADDR, MDNS_PORT)))
            .is_err()
        {
            continue;
        }
    }

    let mut buf = [0u8; 65536];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(dev) = parse_mdns_response(&buf[..n], src.ip().to_string()) {
                    devices.push(dev);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
    devices
}

// ── DNS helpers ──

fn build_mdns_query(service_type: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(&[0, 0]); // Transaction ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
    buf.extend_from_slice(&[0, 1]); // Questions: 1
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // Answers, Authority, Additional: 0

    for part in service_type.split('.') {
        buf.push(part.len() as u8);
        buf.extend_from_slice(part.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&[0, 12]); // QTYPE: PTR
    buf.extend_from_slice(&[0, 1]); // QCLASS: IN

    buf
}

fn parse_mdns_response(data: &[u8], _src_ip: String) -> Option<Device> {
    if data.len() < 12 {
        return None;
    }

    let mut ip = String::new();
    let mut hostname = String::new();
    let mut port = 0u16;

    let mut offset = 12;

    while offset < data.len() && data[offset] != 0 {
        offset += 1 + data[offset] as usize;
    }
    if offset < data.len() {
        offset += 5;
    }

    while offset + 12 <= data.len() {
        if data[offset] & 0xC0 == 0xC0 {
            break;
        }

        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        offset += 6;
        let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + rdlength > data.len() {
            break;
        }

        let rdata = &data[offset..offset + rdlength];
        offset += rdlength;

        match qtype {
            1 if rdlength == 4 => {
                ip = format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
            }
            33 => {
                if rdlength >= 6 {
                    port = u16::from_be_bytes([rdata[4], rdata[5]]);
                    hostname = read_dns_name(rdata, 6).unwrap_or_default();
                }
            }
            _ => {}
        }
    }

    if ip.is_empty() {
        return None;
    }

    let open_ports = if port > 0 {
        vec![Port {
            port,
            service: None,
            state: PortState::Open,
            banner: None,
        }]
    } else {
        vec![]
    };

    Some(Device {
        ip,
        mac: None,
        hostname: if hostname.is_empty() {
            None
        } else {
            Some(hostname)
        },
        vendor: None,
        device_type: DeviceType::Unknown,
        os: OSType::Unknown,
        open_ports,
        sources: vec![DiscoverySource::Mdns],
        discovered_at: None,
        ttl: None,
    })
}

fn read_dns_name(data: &[u8], offset: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut pos = offset;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            break;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}
