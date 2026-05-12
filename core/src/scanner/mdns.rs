use std::time::Duration;

use tokio::net::UdpSocket;

use crate::types::{Device, DeviceType, DiscoverySource};

const MDNS_ADDR: &str = "224.0.0.251";
const MDNS_PORT: u16 = 5353;

/// Discover devices via mDNS
pub async fn discover_mdns(timeout_ms: u64) -> Result<Vec<Device>, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind socket: {}", e))?;

    let timeout = Duration::from_millis(timeout_ms);

    // Query for _http._tcp.local
    let query = build_mdns_query("_http._tcp.local");
    socket
        .send_to(&query, &format!("{}:{}", MDNS_ADDR, MDNS_PORT))
        .await
        .map_err(|e| format!("Failed to send mDNS query: {}", e))?;

    let mut devices = Vec::new();
    let mut buf = [0u8; 4096];

    let deadline = tokio::time::Instant::now() + timeout;

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                let src_ip = src.ip().to_string();
                if let Some(mut device) = parse_mdns_response(&buf[..n], &src_ip) {
                    device.sources.push(DiscoverySource::MDNS);
                    devices.push(device);
                }
            }
            Ok(Err(e)) => {
                eprintln!("mDNS recv error: {}", e);
            }
            Err(_) => break,
        }
    }

    Ok(devices)
}

/// Build mDNS DNS query packet
pub fn build_mdns_query(service: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    // Transaction ID (2 bytes, set to 0 for simplicity)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Flags: standard query (2 bytes)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Questions: 1 (2 bytes)
    packet.extend_from_slice(&[0x00, 0x01]);

    // Answer RRs: 0 (2 bytes)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Authority RRs: 0 (2 bytes)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Additional RRs: 0 (2 bytes)
    packet.extend_from_slice(&[0x00, 0x00]);

    // QNAME for service
    for part in service.split('.') {
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0x00);

    // QTYPE: PTR (12) (2 bytes)
    packet.extend_from_slice(&[0x00, 0x0c]);

    // QCLASS: IN (1) with QU bit set (0x8001) (2 bytes)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

/// Parse mDNS response and extract device info
pub fn parse_mdns_response(buf: &[u8], src_ip: &str) -> Option<Device> {
    // Basic mDNS response parsing
    // This is a simplified parser - real implementation would fully parse DNS packets

    if buf.len() < 12 {
        return None;
    }

    // Check transaction ID and flags
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = (flags >> 15) & 0x01; // QR bit: 1 for response

    if qr != 1 {
        // Not a response
        return None;
    }

    let mut device = Device::new(src_ip.to_string());
    device.device_type = DeviceType::Unknown;

    // Try to extract hostname from PTR records in response
    // This is simplified - full implementation would parse DNS name compression

    // Look for common device type indicators in the packet
    let data = String::from_utf8_lossy(buf);

    if data.contains("airplay") || data.contains("AirPlay") {
        device.device_type = DeviceType::Unknown; // Apple TV or similar
    }

    if data.contains("chromecast") || data.contains("Chromecast") {
        device.device_type = DeviceType::Unknown;
    }

    if data.contains("_device-info") || data.contains("_companion-link") {
        device.device_type = DeviceType::Unknown;
    }

    Some(device)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_mdns_query() {
        let query = build_mdns_query("_http._tcp.local");
        assert!(!query.is_empty());
        assert!(query.len() > 12);
    }
}
