use std::collections::HashMap;
use std::time::Duration;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::types::{Device, Port, PortState};

lazy_static::lazy_static! {
    static ref SERVICE_MAP: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        m.insert(21, "ftp");
        m.insert(22, "ssh");
        m.insert(23, "telnet");
        m.insert(25, "smtp");
        m.insert(53, "dns");
        m.insert(80, "http");
        m.insert(110, "pop3");
        m.insert(143, "imap");
        m.insert(443, "https");
        m.insert(554, "rtsp");
        m.insert(5000, "upnp");
        m.insert(8080, "http-proxy");
        m.insert(8443, "https-alt");
        m.insert(3306, "mysql");
        m.insert(5432, "postgresql");
        m.insert(6379, "redis");
        m.insert(27017, "mongodb");
        m.insert(9200, "elasticsearch");
        m
    };
}

/// Scan a single TCP port with timeout
async fn scan_port(
    ip: &str,
    port: u16,
    timeout: Duration,
) -> Port {
    let addr = format!("{}:{}", ip, port);
    let state = match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(_)) => PortState::Closed,
        Err(_) => PortState::Filtered,
    };

    let service = SERVICE_MAP.get(&port).map(|s: &&'static str| s.to_string());

    Port {
        port,
        state,
        service,
        banner: None,
    }
}

/// Scan multiple TCP ports with concurrency control
pub async fn scan_tcp(
    ip: &str,
    ports: &[u16],
    timeout_ms: u64,
    concurrency: u32,
) -> Vec<Port> {
    let timeout = Duration::from_millis(timeout_ms);
    let semaphore = Arc::new(Semaphore::new(concurrency as usize));
    let mut handles = Vec::new();

    for &port in ports {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let ip_owned = ip.to_string();

        let handle = tokio::spawn(async move {
            let port_result = scan_port(&ip_owned, port, timeout).await;
            drop(permit);
            port_result
        });

        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(port) = handle.await {
            results.push(port);
        }
    }

    results.sort_by_key(|p| p.port);
    results
}

/// Scan a subnet for open ports
pub async fn scan_subnet(
    subnet: &str,
    ports: Vec<u16>,
    timeout_ms: u64,
    concurrency: u32,
) -> Vec<Device> {
    let base = if subnet.ends_with(".0") || subnet.ends_with(".0/24") {
        &subnet[..subnet.len() - 2]
    } else {
        subnet
    };

    let mut devices = Vec::new();

    for i in 1..=254 {
        let ip = format!("{}.{}", base, i);
        let ip_clone = ip.clone();
        let ports_clone = ports.clone();

        let handle = tokio::spawn(async move {
            let open_ports = scan_tcp(&ip_clone, &ports_clone, timeout_ms, concurrency).await;
            let open_ports: Vec<_> = open_ports.into_iter().filter(|p| p.state == PortState::Open).collect();

            if !open_ports.is_empty() {
                let mut device = Device::new(ip_clone);
                device.open_ports = open_ports;
                Some(device)
            } else {
                None
            }
        });

        if let Ok(Some(device)) = handle.await {
            devices.push(device);
        }
    }

    devices
}

/// Get service name for a port
pub fn get_service_name(port: u16) -> Option<String> {
    SERVICE_MAP.get(&port).map(|s: &&'static str| s.to_string())
}

/// Grab banner from an open port
pub async fn grab_banner(
    ip: &str,
    port: u16,
    timeout: Duration,
) -> Option<String> {
    let addr = format!("{}:{}", ip, port);

    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Send HTTP HEAD for web ports
    if matches!(port, 80 | 8080 | 8443 | 5000 | 554) {
        let _ = stream
            .write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await;
    }

    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };

    if n > 0 {
        let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
        if !banner.is_empty() {
            return Some(banner);
        }
    }

    None
}
