//! Pipeline orchestrator: runs scan tools and optionally fuzzing/vulnerability tools.

mod tls;

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct CancelToken {
    cancelled: Arc<AtomicBool>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self { cancelled: Arc::new(AtomicBool::new(false)) }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

use crate::tool_commands::{run_ffuf, run_feroxbuster, run_masscan, run_nmap, run_nuclei, run_rustscan, MasscanResult, NmapResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PipelineResult {
    Port { ip: String, port: u16, state: String },
    Service { ip: String, port: u16, service: String, banner: String },
    Vulnerability { template: String, severity: String, matched: String, host: String, port: u32 },
    Fuzz { url: String, method: String, status: u16 },
    TLS {
        host: String,
        port: u16,
        severity: String,
        message: String,
        cert_cn: String,
        vulnerabilities: Vec<tls::TLSVulnerability>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineOptions {
    pub target: String,
    pub scan_tool: String,
    pub auto_nuclei: bool,
    pub auto_ffuf: bool,
    pub auto_feroxbuster: bool,
    pub auto_tls_audit: bool,
    pub auto_tls_full: bool,
    pub port_range: Option<String>,
    pub rate: Option<u32>,
    pub wordlist: Option<String>,
}

#[derive(Debug, Clone)]
struct PortInfo {
    ip: String,
    port: u16,
}

fn https_url(ip: &str, port: u16) -> String {
    if port == 443 {
        format!("https://{}:{}", ip, port)
    } else {
        format!("http://{}:{}", ip, port)
    }
}

pub async fn run_pipeline(opts: PipelineOptions, cancel: CancelToken) -> Result<Vec<PipelineResult>, String> {
    let mut results = Vec::new();
    let port_range = opts.port_range.clone().unwrap_or_else(|| "1-1000".to_string());

    let open_ports: Vec<PortInfo> = match opts.scan_tool.as_str() {
        "masscan" => {
            let target = opts.target.clone();
            let rate = opts.rate.unwrap_or(1000);
            let scan_results: Vec<MasscanResult> = tokio::task::spawn_blocking(move || run_masscan(&target, &port_range, rate))
                .await
                .map_err(|e| format!("task join error: {}", e))?
                .map_err(|e| format!("masscan error: {}", e))?;
            scan_results.into_iter().filter(|r| r.state == "open").map(|r| PortInfo { ip: r.ip, port: r.port }).collect()
        },
        "rustscan" => {
            let target = opts.target.clone();
            let batch = opts.rate.unwrap_or(4500);
            let scan_results: Vec<MasscanResult> = tokio::task::spawn_blocking(move || run_rustscan(&target, &port_range, batch))
                .await
                .map_err(|e| format!("task join error: {}", e))?
                .map_err(|e| format!("rustscan error: {}", e))?;
            scan_results.into_iter().filter(|r| r.state == "open").map(|r| PortInfo { ip: r.ip, port: r.port }).collect()
        },
        "nmap" => {
            let target = opts.target.clone();
            let scan_results: Vec<NmapResult> = tokio::task::spawn_blocking(move || run_nmap(&target, &port_range))
                .await
                .map_err(|e| format!("task join error: {}", e))?
                .map_err(|e| format!("nmap error: {}", e))?;
            scan_results.into_iter().filter(|r| r.state == "open").map(|r| PortInfo { ip: r.ip, port: r.port }).collect()
        },
        _ => return Err(format!("Unknown scan tool: {}", opts.scan_tool)),
    };

    if cancel.is_cancelled() {
        return Err("cancelled".to_string());
    }

    for port_info in &open_ports {
        results.push(PipelineResult::Port {
            ip: port_info.ip.clone(),
            port: port_info.port,
            state: "open".to_string(),
        });
    }

    // TLS Audit stage
    if opts.auto_tls_audit && !open_ports.is_empty() {
        let cancel = cancel.clone();
        for port_info in &open_ports {
            if cancel.is_cancelled() {
                return Err("cancelled".to_string());
            }
            let ip = port_info.ip.clone();
            let port = port_info.port;

            let (cert_info, config_info) = tokio::task::spawn_blocking(move || {
                let cert = tls::fetch_cert_info(&ip, port);
                let config = tls::check_tls_config(&ip, port);
                (cert, config)
            })
            .await
            .map_err(|e| format!("task join error: {}", e))?
            .map_err(|e| format!("tls error: {}", e))?;

            if let (Ok(cert), Ok(config)) = (cert_info, config_info) {
                let vulns = tls::rules::check_vulnerabilities(&config, &cert);

                for vuln in &vulns {
                    results.push(PipelineResult::TLS {
                        host: ip.clone(),
                        port,
                        severity: vuln.severity.clone(),
                        message: format!("{}: {}", vuln.id, vuln.name),
                        cert_cn: cert.subject.clone(),
                        vulnerabilities: vulns.clone(),
                    });
                }
            }

            if cancel.is_cancelled() {
                return Err("cancelled".to_string());
            }
        }
    }

    let wordlist = opts.wordlist.clone().unwrap_or_else(|| {
        if cfg!(target_os = "macos") {
            "/usr/local/share/wordlists/dirb/common.txt".to_string()
        } else {
            "/usr/share/wordlists/dirb/common.txt".to_string()
        }
    });

    if opts.auto_nuclei && !open_ports.is_empty() {
        let cancel = cancel.clone();
        let mut all_handles: Vec<_> = open_ports.iter().map(|port_info| {
            let target_url = https_url(&port_info.ip, port_info.port);
            tokio::task::spawn_blocking(move || run_nuclei(&target_url))
        }).collect();

        for chunk in all_handles.chunks(20) {
            if cancel.is_cancelled() {
                return Err("cancelled".to_string());
            }
            for handle in chunk {
                if let Ok(Ok(nuclei)) = handle.await {
                    for n in nuclei {
                        results.push(PipelineResult::Vulnerability {
                            template: n.template,
                            severity: n.severity,
                            matched: n.matched,
                            host: n.host,
                            port: n.port,
                        });
                    }
                }
            }
        }
    }

    if cancel.is_cancelled() {
        return Err("cancelled".to_string());
    }

    if opts.auto_ffuf && !open_ports.is_empty() {
        let cancel = cancel.clone();
        let wl = wordlist.clone();
        let mut all_handles: Vec<_> = open_ports.iter().map(|port_info| {
            let url = format!("{}/", https_url(&port_info.ip, port_info.port));
            let wl = wl.clone();
            tokio::task::spawn_blocking(move || run_ffuf(&url, &wl))
        }).collect();

        for chunk in all_handles.chunks(20) {
            if cancel.is_cancelled() {
                return Err("cancelled".to_string());
            }
            for handle in chunk {
                if let Ok(Ok(ffuf)) = handle.await {
                    for fuzz in ffuf {
                        results.push(PipelineResult::Fuzz {
                            url: fuzz.url,
                            method: fuzz.method,
                            status: fuzz.status,
                        });
                    }
                }
            }
        }
    }

    if cancel.is_cancelled() {
        return Err("cancelled".to_string());
    }

    if opts.auto_feroxbuster && !open_ports.is_empty() {
        let cancel = cancel.clone();
        let mut all_handles: Vec<_> = open_ports.iter().map(|port_info| {
            let url = format!("{}/", https_url(&port_info.ip, port_info.port));
            tokio::task::spawn_blocking(move || run_feroxbuster(&url))
        }).collect();

        for chunk in all_handles.chunks(20) {
            if cancel.is_cancelled() {
                return Err("cancelled".to_string());
            }
            for handle in chunk {
                if let Ok(Ok(ferox)) = handle.await {
                    for fuzz in ferox {
                        results.push(PipelineResult::Fuzz {
                            url: fuzz.url,
                            method: fuzz.method,
                            status: fuzz.status,
                        });
                    }
                }
            }
        }
    }

    if cancel.is_cancelled() {
        return Err("cancelled".to_string());
    }

    Ok(results)
}