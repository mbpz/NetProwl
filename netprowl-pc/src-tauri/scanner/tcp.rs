//! TCP 端口扫描

use crate::scanner::{Port, PortState, WHITE_PORTS};

const DEFAULT_TIMEOUT_MS: u64 = 2000;

#[derive(Clone)]
pub struct TcpConfig {
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout_ms: u64,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            ports: WHITE_PORTS.to_vec(),
            concurrency: 100,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

/// 并发扫描单个 IP 的多个端口
pub async fn probe_ports(ip: &str, cfg: TcpConfig) -> Vec<Port> {
    let timeout_ms = cfg.timeout_ms.max(100);
    let ports = cfg.ports;
    let concurrency = cfg.concurrency.max(1).min(200);

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for port in ports {
        let permit = semaphore.clone().acquire_owned().await.ok();
        let ip = ip.to_string();

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            probe_port(&ip, port, timeout_ms).await
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        if let Ok(port) = h.await {
            if port.state == PortState::Open {
                results.push(port);
            }
        }
    }
    results
}

/// 探测单个端口
async fn probe_port(ip: &str, port: u16, timeout_ms: u64) -> Port {
    let addr = format!("{}:{}", ip, port);
    let timeout = std::time::Duration::from_millis(timeout_ms);

    let state = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => PortState::Open,
        _ => PortState::Closed,
    };

    Port {
        port,
        state,
        service: None,
        banner: None,
    }
}
