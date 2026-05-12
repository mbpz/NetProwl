use std::time::Duration;

use tokio::net::UdpSocket;

use crate::types::{Device, DeviceType, DiscoverySource};

const SSDP_ADDR: &str = "239.255.255.250";
const SSDP_PORT: u16 = 1900;

const M_SEARCH: &str = "M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 3\r\n\
ST: ssdp:all\r\n\r\n";

/// Discover devices via SSDP
pub async fn discover_ssdp(timeout_ms: u64) -> Result<Vec<Device>, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind socket: {}", e))?;

    socket
        .set_broadcast(true)
        .map_err(|e| format!("Failed to enable broadcast: {}", e))?;

    let timeout = Duration::from_millis(timeout_ms);

    // Send M-SEARCH
    socket
        .send_to(M_SEARCH.as_bytes(), &format!("{}:{}", SSDP_ADDR, SSDP_PORT))
        .await
        .map_err(|e| format!("Failed to send SSDP query: {}", e))?;

    let mut devices = Vec::new();
    let mut buf = [0u8; 4096];

    let deadline = tokio::time::Instant::now() + timeout;

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                let response = std::str::from_utf8(&buf[..n])
                    .map_err(|e| format!("Invalid SSDP response: {}", e))?;

                if let Some(mut device) = parse_ssdp_response(response, src.ip().to_string().as_str()) {
                    device.sources.push(DiscoverySource::SSDP);
                    devices.push(device);
                }
            }
            Ok(Err(e)) => {
                eprintln!("SSDP recv error: {}", e);
            }
            Err(_) => break,
        }
    }

    Ok(devices)
}

/// Parse SSDP response into a Device
pub fn parse_ssdp_response(banner: &str, ip: &str) -> Option<Device> {
    let mut device = Device::new(ip.to_string());
    device.device_type = DeviceType::Unknown;

    for line in banner.lines() {
        let line_lower = line.to_lowercase();

        if line_lower.starts_with("server:") || line_lower.starts_with("server :") {
            let val = line.split(':').nth(1)?.trim();
            if val.contains("Router") || val.contains("router") {
                device.device_type = DeviceType::Router;
            }
        }

        if line_lower.starts_with("cache-control:") {
            if let Some(ttl_str) = line.split(':').nth(1) {
                if let Ok(max_age) = ttl_str.split('=').nth(1).unwrap_or("0").parse::<u32>() {
                    device.ttl = Some(max_age);
                }
            }
        }

        if line_lower.starts_with("st:") || line_lower.starts_with("st :") {
            let val = line.split(':').nth(1)?.trim();
            if val.contains("InternetGatewayDevice") {
                device.device_type = DeviceType::Router;
            }
        }
    }

    // Assume router for SSDP devices in local network
    if device.device_type == DeviceType::Unknown {
        device.device_type = DeviceType::Router;
    }

    Some(device)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssdp_response() {
        let response = "HTTP/1.1 200 OK\r\n\
CACHE-CONTROL: max-age=300\r\n\
EXT:\r\n\
LOCATION: http://192.168.1.1:80/description.xml\r\n\
SERVER: Linux/2.6 UPnP/1.0 Router\r\n\
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
\r\n";

        let device = parse_ssdp_response(response, "192.168.1.1");
        assert!(device.is_some());

        let device = device.unwrap();
        assert_eq!(device.device_type, DeviceType::Router);
    }
}
