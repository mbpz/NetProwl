//! UDP SSDP discovery

use crate::scanner::{Device, DeviceType, Port, PortState};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

const SSDP_MULTICAST: &str = "239.255.255.250:1900";
const M_SEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";

pub async fn discover_ssdp(timeout_ms: u64) -> Vec<Device> {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let mcast_addr: SocketAddr = SSDP_MULTICAST.parse().unwrap();
    if socket.send_to(M_SEARCH, mcast_addr).await.is_err() {
        return vec![];
    }

    let mut buf = vec![0u8; 4096];
    let mut devices = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);

    while tokio::time::Instant::now() < deadline {
        let read_timeout = deadline.saturating_duration_since(tokio::time::Instant::now());

        match timeout(read_timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                if let Some(device) = parse_ssdp(&buf[..n], from.ip().to_string()) {
                    devices.push(device);
                }
            }
            _ => break,
        }
    }

    devices
}

fn parse_ssdp(data: &[u8], ip: String) -> Option<Device> {
    let resp = String::from_utf8_lossy(data);
    if !resp.contains("HTTP") && !resp.contains("NOTIFY") {
        return None;
    }

    let hostname = extract_header(&resp, "SERVER")
        .or_else(|| extract_header(&resp, "Server"));
    let vendor = extract_header(&resp, "SERVER")
        .map(|s| s.split('/').next().unwrap_or(&s).to_string())
        .filter(|s| !s.is_empty());

    Some(Device {
        ip,
        mac: None,
        hostname,
        vendor,
        device_type: Some(DeviceType::Unknown),
        ports: vec![Port {
            port: 1900,
            state: PortState::Open,
            service: Some("SSDP".into()),
            banner: None,
        }],
        sources: vec!["ssdp".into()],
    })
}

fn extract_header(resp: &str, key: &str) -> Option<String> {
    for line in resp.lines() {
        if line.to_uppercase().starts_with(&format!("{}:", key)) {
            let val = line.splitn(2, ':').nth(1)?.trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}
