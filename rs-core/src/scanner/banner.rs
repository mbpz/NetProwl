use std::io::{Read, Write};
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(target_arch = "wasm32"))]
use tokio::net::TcpStream;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::{timeout as tokio_timeout, Duration as TDuration};

#[derive(Debug, Clone)]
pub struct BannerConfig {
    pub timeout_ms: u64,
    pub include_deep_scan: bool,
    pub include_rtsp_sdp: bool,
}

impl Default for BannerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 3000,
            include_deep_scan: true,
            include_rtsp_sdp: true,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn grab_banner(ip: &str, port: u16, cfg: BannerConfig) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let timeout_dur = TDuration::from_millis(cfg.timeout_ms);
    let addr = format!("{}:{}", ip, port);

    let mut conn = tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await??;

    match port {
        80 | 8080 | 8443 => grab_http_banner(&mut conn, timeout_dur, cfg.include_deep_scan).await,
        22 => grab_ssh_banner(&mut conn, timeout_dur).await,
        21 => grab_ftp_banner(&mut conn, timeout_dur).await,
        554 | 5000 => grab_rtsp_banner(&mut conn, timeout_dur, cfg.include_rtsp_sdp).await,
        _ => grab_generic_banner(&mut conn, timeout_dur).await,
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn grab_http_banner(conn: &mut TcpStream, _timeout_dur: TDuration, deep_scan: bool) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let _ = conn.write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n").await;
    let mut buf = vec![0u8; 4096];
    let n = conn.read(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();

    if deep_scan {
        let paths = vec!["/", "/admin", "/wp-login.php", "/phpmyadmin/", "/robots.txt"];
        let mut found = Vec::new();
        for path in paths {
            let peer = conn.peer_addr()?;
            match tokio_timeout(TDuration::from_millis(1000), TcpStream::connect(peer)).await {
                Ok(Ok(mut c)) => {
                    if c.write_all(format!("GET {} HTTP/1.0\r\nHost: localhost\r\n\r\n", path).as_bytes()).await.is_ok() {
                        let mut rb = [0u8; 256];
                        if let Ok(nn) = c.read(&mut rb).await {
                            let s = String::from_utf8_lossy(&rb[..nn]);
                            if s.contains("200") || s.contains("401") || s.contains("403") {
                                found.push(path.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if !found.is_empty() {
            return Ok(format!("{}\n[PATHS] {}", resp, found.join(",")));
        }
    }
    Ok(resp)
}

#[cfg(not(target_arch = "wasm32"))]
async fn grab_ssh_banner(conn: &mut TcpStream, _timeout_dur: TDuration) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 256];
    let n = conn.read(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn grab_ftp_banner(conn: &mut TcpStream, _timeout_dur: TDuration) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 256];
    let n = conn.read(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn grab_rtsp_banner(conn: &mut TcpStream, _timeout_dur: TDuration, get_sdp: bool) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let _ = conn.write_all(b"OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: 0\r\n\r\n").await;
    let mut buf = vec![0u8; 512];
    let n = conn.read(&mut buf).await?;
    let mut resp = String::from_utf8_lossy(&buf[..n]).to_string();

    if get_sdp && n > 0 {
        let _ = conn.write_all(b"DESCRIBE rtsp://localhost/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n").await;
        let mut buf2 = vec![0u8; 1024];
        if let Ok(n2) = conn.read(&mut buf2).await {
            let sdp = String::from_utf8_lossy(&buf2[..n2]);
            resp.push_str(&format!("\n[SDP]{}",
                parse_rtsp_sdp(&sdp)));
        }
    }
    Ok(resp)
}

fn parse_rtsp_sdp(sdp: &str) -> String {
    let mut brand = None;
    let mut stream_url = None;
    for line in sdp.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("a=control:") {
            stream_url = Some(line.split(':').nth(1).unwrap_or("").trim());
        } else if lower.contains("hikvision") {
            brand = Some("Hikvision");
        } else if lower.contains("dahua") {
            brand = Some("Dahua");
        }
    }
    let mut parts = Vec::new();
    if let Some(b) = brand { parts.push(format!("brand:{}", b)); }
    if let Some(u) = stream_url { parts.push(format!("url:{}", u)); }
    if parts.is_empty() { sdp.to_string() } else { parts.join(" ") }
}

#[cfg(not(target_arch = "wasm32"))]
async fn grab_generic_banner(conn: &mut TcpStream, _timeout_dur: TDuration) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 512];
    let n = conn.read(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

// Sync version for WASM exports
pub fn grab_banner_sync(ip: &str, port: u16, cfg: BannerConfig) -> String {
    let timeout = std::time::Duration::from_millis(cfg.timeout_ms);
    let addr = format!("{}:{}", ip, port);
    let mut conn = match std::net::TcpStream::connect_timeout(&addr.parse().unwrap_or_else(|_| "127.0.0.1:80".parse().unwrap()), timeout) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    conn.set_read_timeout(Some(timeout)).ok();
    conn.set_write_timeout(Some(timeout)).ok();

    match port {
        80 | 8080 | 8443 => {
            let _ = conn.write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n");
            let mut buf = vec![0u8; 4096];
            if let Ok(n) = conn.read(&mut buf) {
                return String::from_utf8_lossy(&buf[..n]).trim().to_string();
            }
        }
        22 => {
            let mut buf = vec![0u8; 256];
            if let Ok(n) = conn.read(&mut buf) {
                return String::from_utf8_lossy(&buf[..n]).trim().to_string();
            }
        }
        21 => {
            let mut buf = vec![0u8; 256];
            if let Ok(n) = conn.read(&mut buf) {
                return String::from_utf8_lossy(&buf[..n]).trim().to_string();
            }
        }
        554 | 5000 => {
            let _ = conn.write_all(b"OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: 0\r\n\r\n");
            let mut buf = vec![0u8; 512];
            if let Ok(n) = conn.read(&mut buf) {
                return String::from_utf8_lossy(&buf[..n]).to_string();
            }
        }
        _ => {
            let mut buf = vec![0u8; 512];
            if let Ok(n) = conn.read(&mut buf) {
                return String::from_utf8_lossy(&buf[..n]).trim().to_string();
            }
        }
    }
    String::new()
}
