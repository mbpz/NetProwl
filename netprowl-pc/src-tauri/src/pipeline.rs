//! Pipeline orchestrator: runs scan tools and optionally fuzzing/vulnerability tools.

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

use crate::tool_commands::{run_ffuf, run_feroxbuster, run_masscan, run_nmap, run_nuclei, run_rustscan};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PipelineResult {
    Port { ip: String, port: u16, state: String },
    Service { ip: String, port: u16, service: String, banner: String },
    Vulnerability { template: String, severity: String, matched: String, host: String, port: u32 },
    Fuzz { url: String, method: String, status: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineOptions {
    pub target: String,
    pub scan_tool: String,
    pub auto_nuclei: bool,
    pub auto_ffuf: bool,
    pub auto_feroxbuster: bool,
    pub port_range: Option<String>,
    pub rate: Option<u32>,
    pub wordlist: Option<String>,
}

pub async fn run_pipeline(opts: PipelineOptions, cancel: CancelToken) -> Result<Vec<PipelineResult>, String> {
    let mut results = Vec::new();
    let port_range = opts.port_range.clone().unwrap_or_else(|| "1-1000".to_string());

    // Step 1: Run port scanner in blocking thread
    let scan_results = match opts.scan_tool.as_str() {
        "masscan" => {
            let target = opts.target.clone();
            let rate = opts.rate.unwrap_or(1000);
            tokio::task::spawn_blocking(move || run_masscan(&target, &port_range, rate))
                .await
                .map_err(|e| format!("task join error: {}", e))?
                .map_err(|e| format!("masscan error: {}", e))?
        },
        "rustscan" => {
            let target = opts.target.clone();
            let batch = opts.rate.unwrap_or(4500);
            tokio::task::spawn_blocking(move || run_rustscan(&target, &port_range, batch))
                .await
                .map_err(|e| format!("task join error: {}", e))?
                .map_err(|e| format!("rustscan error: {}", e))?
        },
        "nmap" => {
            let target = opts.target.clone();
            tokio::task::spawn_blocking(move || run_nmap(&target, &port_range))
                .await
                .map_err(|e| format!("task join error: {}", e))?
                .map_err(|e| format!("nmap error: {}", e))?
        },
        _ => return Err(format!("Unknown scan tool: {}", opts.scan_tool)),
    };

    if cancel.is_cancelled() {
        return Err("cancelled".to_string());
    }

    // Step 2: Convert scan results to PipelineResult::Port
    for result in scan_results {
        results.push(PipelineResult::Port {
            ip: result.ip,
            port: result.port,
            state: result.state,
        });
    }

    // Step 3: If auto_nuclei, run nuclei on each (ip, port)
    if opts.auto_nuclei {
        for port_result in &results {
            if cancel.is_cancelled() {
                return Err("cancelled".to_string());
            }
            if let PipelineResult::Port { ip, port, .. } = port_result {
                let target_url = format!("http://{}:{}", ip, port);
                let nuclei_results = tokio::task::spawn_blocking(move || run_nuclei(&target_url))
                    .await
                    .map_err(|e| format!("task join error: {}", e))?
                    .unwrap_or_default();
                for nuclei in nuclei_results {
                    results.push(PipelineResult::Vulnerability {
                        template: nuclei.template,
                        severity: nuclei.severity,
                        matched: nuclei.matched,
                        host: nuclei.host,
                        port: nuclei.port as u16,
                    });
                }
            }
        }
    }

    if cancel.is_cancelled() {
        return Err("cancelled".to_string());
    }

    // Step 4: If auto_ffuf, run ffuf on each discovered port
    if opts.auto_ffuf {
        let wordlist = opts.wordlist.unwrap_or_else(|| {
            if cfg!(target_os = "macos") {
                "/usr/local/share/wordlists/dirb/common.txt".to_string()
            } else {
                "/usr/share/wordlists/dirb/common.txt".to_string()
            }
        });
        for port_result in &results {
            if cancel.is_cancelled() {
                return Err("cancelled".to_string());
            }
            if let PipelineResult::Port { ip, port, .. } = port_result {
                let url = format!("http://{}:{}/", ip, port);
                let ffuf_results = tokio::task::spawn_blocking(move || run_ffuf(&url, &wordlist))
                    .await
                    .map_err(|e| format!("task join error: {}", e))?
                    .unwrap_or_default();
                for fuzz in ffuf_results {
                    results.push(PipelineResult::Fuzz {
                        url: fuzz.url,
                        method: fuzz.method,
                        status: fuzz.status,
                    });
                }
            }
        }
    }

    if cancel.is_cancelled() {
        return Err("cancelled".to_string());
    }

    // Step 5: If auto_feroxbuster, run feroxbuster on each discovered port
    if opts.auto_feroxbuster {
        for port_result in &results {
            if cancel.is_cancelled() {
                return Err("cancelled".to_string());
            }
            if let PipelineResult::Port { ip, port, .. } = port_result {
                let url = format!("http://{}:{}/", ip, port);
                let feroxbuster_results = tokio::task::spawn_blocking(move || run_feroxbuster(&url))
                    .await
                    .map_err(|e| format!("task join error: {}", e))?
                    .unwrap_or_default();
                for fuzz in feroxbuster_results {
                    results.push(PipelineResult::Fuzz {
                        url: fuzz.url,
                        method: fuzz.method,
                        status: fuzz.status,
                    });
                }
            }
        }
    }

    if cancel.is_cancelled() {
        return Err("cancelled".to_string());
    }

    Ok(results)
}