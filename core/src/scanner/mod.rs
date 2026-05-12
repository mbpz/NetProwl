pub mod mdns;
pub mod ssdp;
pub mod tcp;
pub mod banner;
pub mod registry;

use crate::types::{Device, ScanResult};
use crate::util::ip::{infer_subnet, expand_subnet};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub concurrency: usize,
    pub timeout: std::time::Duration,
    pub include_mdns: bool,
    pub include_ssdp: bool,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            concurrency: 50,
            timeout: std::time::Duration::from_secs(10),
            include_mdns: true,
            include_ssdp: true,
        }
    }
}

pub async fn discover_lan(opts: DiscoveryOptions) -> Result<ScanResult, Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    let device_map: Arc<Mutex<HashMap<String, Device>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut handles = vec![];

    if opts.include_mdns {
        let cfg = mdns::MDNSConfig::default();
        handles.push(tokio::spawn(async move {
            mdns::discover_mdns(cfg).await.unwrap_or_default()
        }));
    }

    if opts.include_ssdp {
        let cfg = ssdp::SSDPConfig::default();
        handles.push(tokio::spawn(async move {
            ssdp::discover_ssdp(cfg).await.unwrap_or_default()
        }));
    }

    for handle in handles {
        if let Ok(devices) = handle.await {
            let mut map = device_map.lock().await;
            for dev in devices {
                map.insert(dev.ip.clone(), dev);
            }
        }
    }

    // Get local IP and scan subnet for TCP
    if let Some(local_ip) = get_local_ip() {
        if let Some(subnet) = infer_subnet(&local_ip) {
            let ips = expand_subnet(&subnet);
            let cfg = tcp::TCPConfig::default();

            let mut tasks = vec![];
            for ip in ips {
                if device_map.lock().await.contains_key(&ip) {
                    continue;
                }
                let ip_clone = ip.clone();
                let cfg = cfg.clone();
                tasks.push(tokio::spawn(async move {
                    tcp::probe_tcp_ports(&ip_clone, cfg).await.unwrap_or_default()
                }));
            }

            for task in tasks {
                if let Ok(ports) = task.await {
                    if !ports.is_empty() {
                        // TODO: create device from TCP scan results
                    }
                }
            }
        }
    }

    let devices: Vec<Device> = device_map.lock().await.values().cloned().collect();
    let duration_ms = start.elapsed().as_millis() as i64;

    Ok(ScanResult {
        devices,
        duration_ms,
        mdns_unavailable: false,
    })
}

pub fn get_local_ip() -> Option<String> {
    // Use UDP socket trick to determine local IP on Windows/Linux
    std::net::UdpSocket::bind("0.0.0.0:0")
        .ok()?
        .local_addr()
        .ok()
        .map(|addr| addr.ip().to_string())
}
