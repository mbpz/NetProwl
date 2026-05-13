//! Command wrappers for external security tools: masscan, nmap, nuclei, ffuf, feroxbuster, rustscan.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Deserialize, Serialize)]
pub struct MasscanResult {
    pub ip: String,
    pub port: u16,
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapResult {
    pub ip: String,
    pub port: u16,
    pub state: String,
    pub service: String,
    pub product: String,
    pub version: String,
    pub banner: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NucleiResult {
    pub template: String,
    pub severity: String,
    pub matched: String,
    pub host: String,
    pub port: u32,
    pub info: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FuzzResult {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub length: usize,
    pub words: usize,
}

/// Run masscan and parse output lines like "Discovered open port 80/tcp on 1.2.3.4"
pub fn run_masscan(target: &str, ports: &str, rate: u32) -> Result<Vec<MasscanResult>, String> {
    let output = Command::new("masscan")
        .args(["-p", ports, target, "--rate", &rate.to_string(), "--wait", "0"])
        .output()
        .map_err(|e| format!("Failed to execute masscan: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();

    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("Discovered open port ") {
            // Format: "80/tcp on 1.2.3.4"
            if let Some(on_pos) = rest.find(" on ") {
                let port_proto = &rest[..on_pos];
                let ip = &rest[on_pos + 4..];

                if let Some(slash_pos) = port_proto.find('/') {
                    let port_str = &port_proto[..slash_pos];
                    if let Ok(port) = port_str.parse::<u16>() {
                        results.push(MasscanResult {
                            ip: ip.to_string(),
                            port,
                            state: "open".to_string(),
                            service: String::new(),
                        });
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Run nmap with grepable output and parse results
pub fn run_nmap(target: &str, ports: &str) -> Result<Vec<NmapResult>, String> {
    let out_file = std::env::temp_dir().join(
        format!("netprowl_nmap_{}", target.replace('.', "_").replace('/', "_"))
    );
    let out_str = out_file.to_string_lossy().to_string();
    let output = Command::new("nmap")
        .args(["-sT", "-sV", "-p", ports, "-oA", &out_str, target])
        .output()
        .map_err(|e| format!("nmap failed: {}", e))?;

    if !output.status.success() {
        let _ = std::fs::remove_file(out_file.with_extension("gnmap"));
        let _ = std::fs::remove_file(out_file.with_extension("nmap"));
        let _ = std::fs::remove_file(out_file.with_extension("xml"));
        return Err(String::from_utf8_lossy(&output.stderr).into());
    }

    let gnmap_path = out_file.with_extension("gnmap");
    let content = std::fs::read_to_string(&gnmap_path)
        .map_err(|e| format!("failed to read nmap output: {}", e))?;

    let mut results = Vec::new();
    for line in content.lines() {
        if !line.starts_with("Host:") {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        let ip = parts.get(0).and_then(|p| p.split_whitespace().nth(1)).unwrap_or("").to_string();

        if let Some(ports_part) = parts.get(1) {
            if let Some(ports_str) = ports_part.strip_prefix("Ports: ") {
                for port_entry in ports_str.split(',') {
                    let entry_parts: Vec<&str> = port_entry.split('/').collect();
                    if entry_parts.len() >= 3 {
                        let port: u16 = entry_parts[0].parse().unwrap_or(0);
                        let state = entry_parts[1];
                        let service = entry_parts.get(5).unwrap_or(&"");
                        results.push(NmapResult {
                            ip: ip.clone(),
                            port,
                            state: state.to_string(),
                            service: service.to_string(),
                            product: String::new(),
                            version: String::new(),
                            banner: String::new(),
                        });
                    }
                }
            }
        }
    }

    // Cleanup temp files
    let _ = std::fs::remove_file(&gnmap_path);
    let _ = std::fs::remove_file(out_file.with_extension("nmap"));
    let _ = std::fs::remove_file(out_file.with_extension("xml"));

    Ok(results)
}

/// Run nuclei and parse JSON output lines
pub fn run_nuclei(target: &str) -> Result<Vec<NucleiResult>, String> {
    let output = Command::new("nuclei")
        .args(["-u", target, "-json", "-silent", "-timeout", "10", "-rate-limit", "100"])
        .output()
        .map_err(|e| format!("Failed to execute nuclei: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();

    for line in stdout.lines() {
        if let Ok(nuclei) = serde_json::from_str::<NucleiResult>(line) {
            results.push(nuclei);
        }
    }

    Ok(results)
}

/// Run ffuf and parse JSON output lines
pub fn run_ffuf(url: &str, wordlist: &str) -> Result<Vec<FuzzResult>, String> {
    let output = Command::new("ffuf")
        .args(["-u", url, "-w", wordlist, "-of", "json", "-o", "-"])
        .output()
        .map_err(|e| format!("Failed to execute ffuf: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();

    for line in stdout.lines() {
        if let Ok(fuzz) = serde_json::from_str::<FuzzResult>(line) {
            results.push(fuzz);
        }
    }

    Ok(results)
}

/// Run feroxbuster and parse JSON output lines
pub fn run_feroxbuster(url: &str) -> Result<Vec<FuzzResult>, String> {
    let output = Command::new("feroxbuster")
        .args(["-u", url, "--json", "--timeout", "10", "--rate-limit", "100"])
        .output()
        .map_err(|e| format!("Failed to execute feroxbuster: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();

    for line in stdout.lines() {
        if let Ok(fuzz) = serde_json::from_str::<FuzzResult>(line) {
            results.push(fuzz);
        }
    }

    Ok(results)
}

/// Run rustscan and parse JSON output lines
pub fn run_rustscan(target: &str, port_range: &str, batch_size: u32) -> Result<Vec<MasscanResult>, String> {
    let output = Command::new("rustscan")
        .args(["-a", target, "-p", port_range, "-b", &batch_size.to_string(), "--json", "--ulimit", "5000", "-t", "2000"])
        .output()
        .map_err(|e| format!("Failed to execute rustscan: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();

    for line in stdout.lines() {
        if let Ok(scan_result) = serde_json::from_str::<serde_json::Value>(line) {
            if let (Some(ip), Some(port)) = (
                scan_result.get("ip").and_then(|v| v.as_str()),
                scan_result.get("port").and_then(|v| v.as_u64()),
            ) {
                results.push(MasscanResult {
                    ip: ip.to_string(),
                    port: port as u16,
                    state: "open".to_string(),
                    service: String::new(),
                });
            }
        }
    }

    Ok(results)
}
