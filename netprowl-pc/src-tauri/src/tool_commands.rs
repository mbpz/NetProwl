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
    pub port: String,
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
pub fn run_masscan(target: &str, ports: &str) -> Result<Vec<MasscanResult>, String> {
    let output = Command::new("masscan")
        .args(["-p", ports, target, "--wait", "0"])
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
                        });
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Run nmap with JSON output (stub implementation - returns empty results)
pub fn run_nmap(target: &str) -> Result<Vec<NmapResult>, String> {
    let output = Command::new("nmap")
        .args(["-oJ", "-p", "1-1000", target])
        .output()
        .map_err(|e| format!("Failed to execute nmap: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    // Stub: nmap JSON output parsing is complex; return empty for now
    Ok(vec![])
}

/// Run nuclei and parse JSON output lines
pub fn run_nuclei(target: &str) -> Result<Vec<NucleiResult>, String> {
    let output = Command::new("nuclei")
        .args(["-u", target, "-json", "-silent"])
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
        .args(["-u", url, "--json"])
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
pub fn run_rustscan(target: &str) -> Result<Vec<MasscanResult>, String> {
    let output = Command::new("rustscan")
        .args(["-a", target, "--json"])
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
                });
            }
        }
    }

    Ok(results)
}
