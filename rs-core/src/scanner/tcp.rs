use crate::types::{Port, PortState};
use std::collections::HashMap;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WHITE_PORTS: &[u16] = &[80, 443, 8080, 8443, 554, 5000, 9000, 49152];

#[derive(Debug, Clone)]
pub struct TCPConfig {
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout_ms: u64,
}

impl Default for TCPConfig {
    fn default() -> Self {
        Self {
            ports: WHITE_PORTS.to_vec(),
            concurrency: 100,
            timeout_ms: 2000,
        }
    }
}

pub async fn probe_tcp_ports(ip: &str, cfg: TCPConfig) -> Result<Vec<Port>, Box<dyn std::error::Error + Send + Sync>> {
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let ports: Vec<u16> = cfg.ports;
    let mut handles = Vec::new();

    for port in ports {
        let ip = ip.to_string();
        let timeout = timeout;
        handles.push(tokio::spawn(async move {
            probe_port(&ip, port, timeout).await
        }));
    }

    let mut open_ports = Vec::new();
    for handle in handles {
        if let Ok(port) = handle.await {
            if port.state == PortState::Open {
                open_ports.push(port);
            }
        }
    }
    Ok(open_ports)
}

async fn probe_port(ip: &str, port: u16, timeout: Duration) -> Port {
    let addr = format!("{}:{}", ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(mut conn)) => {
            let banner = grab_banner(&mut conn, port).await;
            Port {
                port,
                service: Some(guess_service(port)),
                state: PortState::Open,
                banner: Some(banner),
            }
        }
        _ => Port {
            port,
            service: Some(guess_service(port)),
            state: PortState::Closed,
            banner: None,
        },
    }
}

async fn grab_banner(conn: &mut TcpStream, port: u16) -> String {
    match port {
        80 | 8080 | 8443 => {
            let _ = conn.write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n").await;
        }
        _ => {}
    }
    let mut buf = [0u8; 1024];
    let read_future = conn.read(&mut buf);
    match tokio::time::timeout(Duration::from_secs(1), read_future).await {
        Ok(Ok(n)) => String::from_utf8_lossy(&buf[..n]).to_string(),
        _ => String::new(),
    }
}

static SERVICE_MAP: once_cell::sync::Lazy<HashMap<u16, &'static str>> = once_cell::sync::Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(80, "http");
    m.insert(443, "https");
    m.insert(22, "ssh");
    m.insert(21, "ftp");
    m.insert(25, "smtp");
    m.insert(110, "pop3");
    m.insert(143, "imap");
    m.insert(135, "msrpc");
    m.insert(139, "netbios");
    m.insert(445, "smb");
    m.insert(3389, "rdp");
    m.insert(8080, "http-alt");
    m.insert(8443, "https-alt");
    m.insert(5000, "upnp");
    m.insert(9000, "cslistener");
    m.insert(554, "rtsp");
    m
});

fn guess_service(port: u16) -> String {
    SERVICE_MAP.get(&port).copied().unwrap_or("unknown").to_string()
}