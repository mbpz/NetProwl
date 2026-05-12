use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Grab banner from an open port
pub async fn grab_banner(
    ip: &str,
    port: u16,
    timeout_ms: u64,
) -> Option<String> {
    let timeout = Duration::from_millis(timeout_ms);
    let addr = format!("{}:{}", ip, port);

    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    match port {
        80 | 8080 | 8443 => {
            // HTTP HEAD request
            let _ = stream
                .write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await;
        }
        22 => {
            // SSH protocol - just read the banner
        }
        21 => {
            // FTP - just read the banner
        }
        554 => {
            // RTSP OPTIONS request
            let _ = stream
                .write_all(b"OPTIONS * RTSP/1.0\r\nHost: localhost\r\n\r\n")
                .await;
        }
        _ => {
            // Generic read for other ports - try to read without sending
        }
    }

    let mut buf = [0u8; 2048];
    let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };

    if n == 0 {
        return None;
    }

    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();

    if banner.is_empty() {
        None
    } else {
        Some(banner)
    }
}
