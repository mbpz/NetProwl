//! NetProwl Probe Agent — LAN scanner with WebSocket streaming.
//!
//! Runs as a standalone binary on any machine in the LAN.
//! Mini-program discovers it via mDNS and connects via WebSocket
//! to trigger scans and receive real-time results.

mod cache;
mod mdns;
mod scanner;
mod server;
mod types;

use std::net::Ipv4Addr;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    env_logger::init();

    let port: u16 = std::env::var("AGENT_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9787);

    let concurrency: usize = std::env::var("AGENT_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    let hostname = hostname::get()
        .unwrap_or_else(|_| "netprowl-agent".into());

    // Initialize banner cache
    let db_path = std::env::var("AGENT_DB")
        .unwrap_or_else(|_| "agent-cache.db".to_string());
    let banner_cache = Arc::new(tokio::sync::Mutex::new(
        cache::BannerCache::new(&db_path)
            .unwrap_or_else(|e| {
                log::warn!("Failed to open banner cache at {}: {}, using in-memory only", db_path, e);
                cache::BannerCache::in_memory()
            })
    ));

    log::info!("NetProwl Agent v{} starting", env!("CARGO_PKG_VERSION"));
    log::info!("  Hostname: {}", hostname);
    log::info!("  Port: {}", port);
    log::info!("  Concurrency: {}", concurrency);

    // Start mDNS broadcast (non-blocking)
    let _mdns = mdns::register(port, &hostname);
    if let Err(e) = &_mdns {
        log::warn!("mDNS registration failed: {} (agent still works without discovery)", e);
    }

    // Start WebSocket server
    log::info!("WebSocket server listening on 0.0.0.0:{}", port);
    if let Err(e) = server::run_server(Ipv4Addr::UNSPECIFIED, port, concurrency, banner_cache).await {
        log::error!("Server error: {}", e);
    }
}

/// Fallback hostname detection for environments without the `hostname` crate
mod hostname {
    use std::env;

    pub fn get() -> Result<String, std::io::Error> {
        #[cfg(target_os = "macos")]
        {
            let output = std::process::Command::new("hostname").output()?;
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
            }
        }
        env::var("HOSTNAME").map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "hostname not found"))
    }
}
