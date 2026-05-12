//! Pipeline orchestrator: runs scan tools and optionally fuzzing/vulnerability tools.

use serde::{Deserialize, Serialize};

use crate::tool_commands::{run_ffuf, run_feroxbuster, run_masscan, run_nuclei, run_rustscan};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PipelineResult {
    Port { ip: String, port: u16, state: String },
    Service { ip: String, port: u16, service: String, banner: String },
    Vulnerability { template: String, severity: String, matched: String, host: String },
    Fuzz { url: String, method: String, status: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineOptions {
    pub target: String,
    pub scan_tool: String,
    pub auto_nuclei: bool,
    pub auto_ffuf: bool,
    pub auto_feroxbuster: bool,
}

pub async fn run_pipeline(opts: PipelineOptions) -> Result<Vec<PipelineResult>, String> {
    let mut results = Vec::new();

    // Step 1: Run port scanner
    let scan_results = match opts.scan_tool.as_str() {
        "masscan" => run_masscan(&opts.target, "1-1000")?,
        "rustscan" => run_rustscan(&opts.target)?,
        _ => return Err(format!("Unknown scan tool: {}", opts.scan_tool)),
    };

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
            if let PipelineResult::Port { ip, port, .. } = port_result {
                let target_url = format!("http://{}:{}", ip, port);
                match run_nuclei(&target_url) {
                    Ok(nuclei_results) => {
                        for nuclei in nuclei_results {
                            results.push(PipelineResult::Vulnerability {
                                template: nuclei.template,
                                severity: nuclei.severity,
                                matched: nuclei.matched,
                                host: nuclei.host,
                            });
                        }
                    }
                    Err(e) => {
                        eprintln!("nuclei error for {}: {}", target_url, e);
                    }
                }
            }
        }
    }

    // Step 4: If auto_ffuf, run ffuf
    if opts.auto_ffuf {
        let ffuf_url = format!("http://{}/FUZZ", opts.target);
        let wordlist = "/usr/share/wordlists/dirb/common.txt";
        match run_ffuf(&ffuf_url, wordlist) {
            Ok(ffuf_results) => {
                for fuzz in ffuf_results {
                    results.push(PipelineResult::Fuzz {
                        url: fuzz.url,
                        method: fuzz.method,
                        status: fuzz.status,
                    });
                }
            }
            Err(e) => {
                eprintln!("ffuf error: {}", e);
            }
        }
    }

    // Step 5: If auto_feroxbuster, run feroxbuster
    if opts.auto_feroxbuster {
        let ferox_url = format!("http://{}", opts.target);
        match run_feroxbuster(&ferox_url) {
            Ok(ferox_results) => {
                for fuzz in ferox_results {
                    results.push(PipelineResult::Fuzz {
                        url: fuzz.url,
                        method: fuzz.method,
                        status: fuzz.status,
                    });
                }
            }
            Err(e) => {
                eprintln!("feroxbuster error: {}", e);
            }
        }
    }

    Ok(results)
}