//! Banner grabbing

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const BANNER_TIMEOUT: Duration = Duration::from_millis(1500);

pub async fn grab_banner(ip: &str, port: u16) -> Option<String> {
    let addr = format!("{}:{}", ip, port);
    match timeout(BANNER_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(mut conn)) => {
            match port {
                80 | 8080 | 8443 => http_probe(&mut conn).await,
                22 => read_banner(&mut conn).await,
                21 => read_banner(&mut conn).await,
                25 | 587 => read_banner(&mut conn).await,
                _ => read_banner(&mut conn).await,
            }
        }
        _ => None,
    }
}

async fn http_probe(conn: &mut TcpStream) -> Option<String> {
    let req = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if conn.write_all(req).await.is_err() { return None; }
    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.ok()?;
    if n > 0 { Some(String::from_utf8_lossy(&buf[..n]).trim().to_string()) } else { None }
}

async fn read_banner(conn: &mut TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 512];
    let n = conn.read(&mut buf).await.ok()?;
    if n > 0 { Some(String::from_utf8_lossy(&buf[..n]).trim().to_string()) } else { None }
}
