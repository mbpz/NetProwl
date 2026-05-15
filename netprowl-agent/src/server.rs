//! WebSocket server — accepts commands from mini-program and streams results.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::cache::BannerCache;
use crate::scanner::{self, Scanner};
use crate::types::{Command, Event};

pub async fn run_server(
    host: Ipv4Addr,
    port: u16,
    concurrency: usize,
    cache: Arc<Mutex<BannerCache>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind((host, port)).await?;
    let devices = Arc::new(RwLock::new(HashMap::<String, Vec<crate::types::PortData>>::new()));

    loop {
        let (stream, addr) = listener.accept().await?;
        log::info!("Connection from {}", addr);

        let scanner = Arc::new(Scanner::new(concurrency, 2000));
        let devices = devices.clone();
        let cache = cache.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, scanner, devices, cache).await {
                log::error!("Client {} error: {}", addr, e);
            }
        });
    }
}

async fn handle_client(
    stream: tokio::net::TcpStream,
    scanner: Arc<Scanner>,
    devices: Arc<RwLock<HashMap<String, Vec<crate::types::PortData>>>>,
    cache: Arc<Mutex<BannerCache>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    let (tx, mut rx) = ws_stream.split();
    let tx = Arc::new(Mutex::new(tx));

    let active_scans = Arc::new(RwLock::new(HashMap::<String, bool>::new()));

    while let Some(msg) = rx.next().await {
        let msg = msg?;
        let text = match msg.to_text() {
            Ok(t) => t,
            Err(_) => continue,
        };

        let cmd: Command = match serde_json::from_str(text) {
            Ok(c) => c,
            Err(e) => {
                let err = Event::Error { request_id: String::new(), message: format!("parse error: {}", e) };
                let _ = tx.lock().await.send(Message::Text(serde_json::to_string(&err)?)).await;
                continue;
            }
        };

        match cmd {
            Command::StartScan { id, ip_range, ports, timeout_ms } => {
                let s = scanner.clone();
                let d = devices.clone();
                let c = cache.clone();
                let active = active_scans.clone();
                let tx = tx.clone();

                tokio::spawn(async move {
                    active.write().await.insert(id.clone(), true);
                    let start = Instant::now();
                    let targets = scanner::parse_targets(&ip_range);
                    let mut count = 0;

                    for ip in targets {
                        if !active.read().await.get(&id).copied().unwrap_or(false) {
                            break;
                        }
                        let ports_found = s.scan_ip(&ip, &ports).await;
                        if ports_found.is_empty() { continue; }
                        count += 1;

                        // Cache banners
                        {
                            let cache_guard = c.lock().await;
                            for p in &ports_found {
                                if !p.banner.is_empty() {
                                    let hash = scanner::hash_banner(&p.banner);
                                    let parsed = serde_json::json!({
                                        "software": p.service,
                                        "version": "",
                                        "os": "",
                                        "confidence": 0.5
                                    });
                                    let _ = cache_guard.save_parsed(&hash, &p.banner, &parsed);
                                }
                            }
                        }

                        let evt = Event::DeviceFound {
                            request_id: id.clone(),
                            data: crate::types::DeviceData {
                                ip: ip.clone(),
                                mac: None,
                                hostname: None,
                                vendor: None,
                                ports: ports_found.clone(),
                            },
                        };
                        let _ = tx.lock().await.send(Message::Text(
                            serde_json::to_string(&evt).unwrap_or_default()
                        )).await;

                        d.write().await.insert(ip, ports_found);
                    }

                    active.write().await.remove(&id);
                    let duration = start.elapsed().as_millis() as u64;
                    let evt = Event::ScanComplete { request_id: id, devices_found: count, duration_ms: duration };
                    let _ = tx.lock().await.send(Message::Text(
                        serde_json::to_string(&evt).unwrap_or_default()
                    )).await;
                });
            }

            Command::StopScan { id } => {
                active_scans.write().await.insert(id, false);
            }

            Command::GetDevices => {
                let dev_map = devices.read().await;
                let devices_list: Vec<_> = dev_map.iter().map(|(ip, ports)| {
                    crate::types::DeviceData {
                        ip: ip.clone(),
                        mac: None,
                        hostname: None,
                        vendor: None,
                        ports: ports.clone(),
                    }
                }).collect();
                let evt = serde_json::json!({ "event": "devices", "devices": devices_list });
                let _ = tx.lock().await.send(Message::Text(
                    serde_json::to_string(&evt).unwrap_or_default()
                )).await;
            }

            Command::GetBanner { ip, port } => {
                let banner = scanner::grab_banner(&ip, port, 3000).await;
                let evt = Event::BannerResult { ip, port, banner: banner.clone() };
                let _ = tx.lock().await.send(Message::Text(
                    serde_json::to_string(&evt).unwrap_or_default()
                )).await;
            }

            Command::Ping => {
                let evt = Event::Pong {
                    hostname: hostname::get().unwrap_or_default(),
                    port: 9787,
                };
                let _ = tx.lock().await.send(Message::Text(
                    serde_json::to_string(&evt).unwrap_or_default()
                )).await;
            }
        }
    }

    Ok(())
}

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
