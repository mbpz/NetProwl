mod types;
mod ip;
mod oui;
mod tcp;
mod banner;
mod registry;
mod mdns;
mod ssdp;
pub mod scanner;
pub mod util;
pub mod consts;

#[cfg(not(target_arch = "wasm32"))]
pub mod cve;

#[cfg(not(target_arch = "wasm32"))]
pub mod security;

#[cfg(not(target_arch = "wasm32"))]
pub mod recon;

#[cfg(not(target_arch = "wasm32"))]
pub mod ai;

pub use types::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn lookup_vendor(mac: &str) -> Option<String> {
    oui::lookup_vendor(mac).map(|s| s.to_string())
}

#[wasm_bindgen]
pub fn infer_subnet(local_ip: &str) -> Option<String> {
    ip::infer_subnet(local_ip)
}

#[wasm_bindgen]
pub fn expand_subnet(subnet: &str) -> String {
    let ips = ip::expand_subnet(subnet);
    serde_json::to_string(&ips).unwrap_or_else(|_| "[]".to_string())
}

#[wasm_bindgen]
pub fn guess_gateway(local_ip: &str) -> String {
    ip::guess_gateway(local_ip)
}

#[wasm_bindgen]
pub fn is_private_ip(ip: &str) -> bool {
    ip::is_private_ip(ip)
}

// Scanner exports (sync wrappers around async impls)

#[wasm_bindgen]
pub fn discover_ssdp(timeout_ms: u64) -> String {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let devices = crate::scanner::ssdp::discover_ssdp_sync(timeout_ms);
        serde_json::to_string(&devices).unwrap_or_else(|_| "[]".to_string())
    }
    #[cfg(target_arch = "wasm32")]
    {
        "[]".to_string()
    }
}

#[wasm_bindgen]
pub fn discover_mdns(service_types: Vec<String>, timeout_ms: u64) -> String {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let cfg = crate::scanner::mdns::MDNSConfig {
            service_types,
            timeout: std::time::Duration::from_secs(timeout_ms / 1000),
        };
        let devices = crate::scanner::mdns::discover_mdns_sync(cfg);
        serde_json::to_string(&devices).unwrap_or_else(|_| "[]".to_string())
    }
    #[cfg(target_arch = "wasm32")]
    {
        "[]".to_string()
    }
}

#[wasm_bindgen]
pub fn probe_tcp_ports(ip: &str, ports: Vec<u16>, timeout_ms: u64) -> String {
    let cfg = crate::scanner::tcp::TCPConfig {
        ports,
        concurrency: 100,
        timeout_ms,
    };
    let ports = crate::scanner::tcp::probe_tcp_ports_sync(ip, cfg);
    serde_json::to_string(&ports).unwrap_or_else(|_| "[]".to_string())
}

#[wasm_bindgen]
pub fn grab_banner(ip: &str, port: u16, timeout_ms: u64) -> String {
    let cfg = crate::scanner::banner::BannerConfig {
        timeout_ms,
        include_deep_scan: true,
        include_rtsp_sdp: true,
    };
    crate::scanner::banner::grab_banner_sync(ip, port, cfg)
}

#[wasm_bindgen]
pub fn guess_service(port: u16) -> String {
    crate::scanner::registry::guess_service(port)
}

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ── Phase 2+ AI WASM bindings ──

/// Generate Chinese natural language network diagnosis report (WASM)
/// Input: JSON string with { devices: [...], findings: [...] }
/// Output: JSON string of DiagnosisReport
#[wasm_bindgen]
pub fn wasm_diagnose_network(input_json: &str) -> String {
    #[derive(serde::Deserialize)]
    struct Input {
        devices: Vec<crate::ai::diagnosis::DiagnosisDevice>,
        findings: Vec<crate::security::report::SecurityRisk>,
    }
    match serde_json::from_str::<Input>(input_json) {
        Ok(input) => {
            let report = crate::ai::diagnosis::diagnose_network(input.devices, input.findings);
            serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
        }
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// Generate fix suggestion for a security finding (WASM)
/// Input: JSON string of SecurityRisk
/// Output: JSON string of FixSuggestion
#[wasm_bindgen]
pub fn wasm_generate_fix(risk_json: &str) -> String {
    match serde_json::from_str::<crate::security::report::SecurityRisk>(risk_json) {
        Ok(risk) => {
            let fix = crate::ai::fix_suggest::generate_fix_suggestion(&risk, None);
            serde_json::to_string(&fix).unwrap_or_else(|_| "{}".to_string())
        }
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// Build attack chain from security findings (WASM)
/// Input: JSON string of Vec<SecurityRisk>
/// Output: JSON string of AttackChain
#[wasm_bindgen]
pub fn wasm_build_attack_chain(findings_json: &str) -> String {
    match serde_json::from_str::<Vec<crate::security::report::SecurityRisk>>(findings_json) {
        Ok(findings) => {
            let chain = crate::ai::attack_chain::build_attack_chain(findings);
            serde_json::to_string(&chain).unwrap_or_else(|_| "{}".to_string())
        }
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// Check if attack chain exists from security findings (WASM)
#[wasm_bindgen]
pub fn wasm_detect_attack_chain(findings_json: &str) -> bool {
    match serde_json::from_str::<Vec<crate::security::report::SecurityRisk>>(findings_json) {
        Ok(findings) => crate::ai::attack_chain::detect_attack_chain(&findings),
        Err(_) => false,
    }
}

/// Calculate risk distribution from findings (WASM)
#[wasm_bindgen]
pub fn wasm_risk_distribution(findings_json: &str) -> String {
    match serde_json::from_str::<Vec<crate::security::report::SecurityRisk>>(findings_json) {
        Ok(findings) => {
            let dist = crate::security::report::calculate_risk_distribution(&findings);
            serde_json::to_string(&dist).unwrap_or_else(|_| "{}".to_string())
        }
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}
