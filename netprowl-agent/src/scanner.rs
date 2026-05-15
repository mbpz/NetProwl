//! TCP port scanner and banner grabber.

use sha2::{Sha256, Digest};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::types::PortData;

/// Probe a single TCP port. Returns true if open.
pub async fn probe_port(ip: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{}:{}", ip, port);
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr),
    ).await {
        Ok(Ok(_stream)) => true,
        _ => false,
    }
}

/// Grab banner from an open port.
pub async fn grab_banner(ip: &str, port: u16, timeout_ms: u64) -> String {
    let addr = format!("{}:{}", ip, port);
    let stream = match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr),
    ).await {
        Ok(Ok(s)) => s,
        _ => return String::new(),
    };

    let (mut reader, mut writer) = stream.into_split();

    // Send protocol-specific probe
    if let Some(probe) = probe_for_port(port) {
        let _ = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            writer.write_all(probe),
        ).await;
    }

    // Read response
    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        reader.read(&mut buf),
    ).await {
        Ok(Ok(n)) => n,
        _ => return String::new(),
    };

    String::from_utf8_lossy(&buf[..n]).trim().to_string()
}

/// Protocol probe bytes for known ports.
fn probe_for_port(port: u16) -> Option<&'static [u8]> {
    match port {
        80 | 8080 | 8443 | 443 | 3000 | 5000 | 9000 => Some(b"GET / HTTP/1.0\r\n\r\n"),
        _ => None,
    }
}

/// Infer service name from port + banner.
pub fn infer_service(port: u16, banner: &str) -> String {
    if banner.is_empty() {
        return default_service(port).to_string();
    }

    let bl = banner.to_lowercase();
    if bl.starts_with("ssh-") { return "ssh".into(); }
    if bl.starts_with("http/") || bl.contains("<!doctype") || bl.contains("<html") { return "http".into(); }
    if bl.starts_with("220") && bl.contains("ftp") { return "ftp".into(); }
    if bl.starts_with("220") && bl.contains("smtp") { return "smtp".into(); }
    if bl.starts_with("+ok") { return "pop3".into(); }
    if bl.starts_with("* ok") { return "imap".into(); }
    if bl.contains("mysql") || bl.contains("mariadb") { return "mysql".into(); }
    if bl.contains("postgres") { return "postgresql".into(); }
    if bl.contains("redis") { return "redis".into(); }
    if bl.contains("elasticsearch") { return "elasticsearch".into(); }
    if bl.contains("nginx") { return "nginx".into(); }
    if bl.contains("apache") { return "apache".into(); }

    default_service(port).to_string()
}

fn default_service(port: u16) -> &'static str {
    match port {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp",
        53 => "dns", 80 => "http", 110 => "pop3", 135 => "msrpc",
        139 => "netbios", 143 => "imap", 443 => "https", 445 => "smb",
        993 => "imaps", 995 => "pop3s", 1433 => "mssql", 1521 => "oracle",
        3306 => "mysql", 3389 => "rdp", 5432 => "postgresql", 5900 => "vnc",
        6379 => "redis", 8080 => "http-proxy", 8443 => "https-alt",
        9200 => "elasticsearch", 27017 => "mongodb", 554 => "rtsp",
        _ => "unknown",
    }
}

/// Hash a banner for caching.
pub fn hash_banner(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Scan a single IP across multiple ports.
pub struct Scanner {
    concurrency: usize,
    timeout_ms: u64,
}

impl Scanner {
    pub fn new(concurrency: usize, timeout_ms: u64) -> Self {
        Self { concurrency, timeout_ms }
    }

    /// Scan one IP across given ports. Returns (ip, ports_found).
    pub async fn scan_ip(&self, ip: &str, ports: &[u16]) -> Vec<PortData> {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        for &port in ports {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let ip = ip.to_string();
            let timeout = self.timeout_ms;

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                if !probe_port(&ip, port, timeout).await {
                    return None;
                }
                let banner = grab_banner(&ip, port, timeout).await;
                let service = infer_service(port, &banner);
                Some(PortData { port, service, banner })
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            if let Ok(Some(port_data)) = h.await {
                results.push(port_data);
            }
        }
        results
    }
}

/// Parse CIDR to IP list (simplified: only /24 and /32).
pub fn parse_targets(ip_range: &str) -> Vec<String> {
    if let Some((prefix, mask)) = ip_range.split_once('/') {
        let mask: u8 = mask.parse().ok().unwrap_or(24);
        if mask != 24 {
            return vec![]; // Only /24 supported for now
        }
        let parts: Vec<u8> = prefix.split('.').filter_map(|s| s.parse().ok()).collect();
        if parts.len() != 4 { return vec![]; }
        (1..=254).map(|i| format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], i)).collect()
    } else {
        // Single IP
        vec![ip_range.to_string()]
    }
}
