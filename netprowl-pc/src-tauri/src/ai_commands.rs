//! Tauri commands for AI-powered analysis (Phase 2+)
//!
//! Exposes rs-core AI layer as Tauri IPC commands:
//! - Network diagnosis (natural language)
//! - Attack chain reasoning
//! - Fix suggestion generation
//! - DeepSeek vulnerability diagnosis

use serde::{Deserialize, Serialize};
use rs_core::ai::diagnosis::{DiagnosisDevice, DiagnosisResult, diagnose_network};
use rs_core::ai::attack_chain::{build_attack_chain, detect_attack_chain};
use rs_core::security::report::{SecurityRisk, RiskLevel};

/// AI network diagnosis input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosisInput {
    pub devices: Vec<DeviceInfo>,
    pub risks: Vec<RiskInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub device_type: String,
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskInfo {
    pub ip: String,
    pub port: Option<u16>,
    pub risk_type: String,
    pub title: String,
    pub description: String,
    pub severity: String,
}

fn to_diagnosis_devices(devices: Vec<DeviceInfo>) -> Vec<DiagnosisDevice> {
    devices.into_iter().map(|d| DiagnosisDevice {
        ip: d.ip,
        hostname: d.hostname,
        device_type: d.device_type,
        open_ports: d.open_ports,
        services: d.services,
    }).collect()
}

fn to_security_risks(risks: Vec<RiskInfo>) -> Vec<SecurityRisk> {
    risks.into_iter().map(|r| SecurityRisk {
        ip: r.ip,
        port: r.port,
        risk_type: r.risk_type,
        title: r.title,
        description: r.description,
        cvss_score: None,
        evidence: std::collections::HashMap::new(),
        risk_level: match r.severity.to_lowercase().as_str() {
            "critical" => RiskLevel::Critical,
            "high" => RiskLevel::High,
            "medium" => RiskLevel::Medium,
            "low" => RiskLevel::Low,
            _ => RiskLevel::Info,
        },
    }).collect()
}

// ── Tauri Commands ──

/// Generate Chinese natural language network diagnosis report
///
/// Takes discovered devices and security findings, returns a structured
/// report with summary, categorized issues, and prioritized recommendations.
#[tauri::command]
pub fn ai_diagnose_network(input: DiagnosisInput) -> Result<rs_core::ai::diagnosis::DiagnosisReport, String> {
    let devices = to_diagnosis_devices(input.devices);
    let risks = to_security_risks(input.risks);

    Ok(diagnose_network(devices, risks))
}

/// Build attack chain from security findings
///
/// Analyzes relationships between vulnerabilities to construct
/// multi-step attack paths (e.g., Redis no-auth → SSH key write → host compromise).
#[tauri::command]
pub fn ai_build_attack_chain(risks: Vec<RiskInfo>) -> Result<rs_core::ai::attack_chain::AttackChain, String> {
    let findings = to_security_risks(risks);
    Ok(build_attack_chain(findings))
}

/// Check if security findings indicate an attack chain exists
#[tauri::command]
pub fn ai_detect_attack_chain(risks: Vec<RiskInfo>) -> Result<bool, String> {
    let findings = to_security_risks(risks);
    Ok(detect_attack_chain(&findings))
}

/// Generate fix suggestion for a single security finding
#[tauri::command]
pub fn ai_generate_fix(risk: RiskInfo) -> Result<rs_core::ai::fix_suggest::FixSuggestion, String> {
    let finding = SecurityRisk {
        ip: risk.ip,
        port: risk.port,
        risk_type: risk.risk_type,
        title: risk.title,
        description: risk.description,
        cvss_score: None,
        evidence: std::collections::HashMap::new(),
        risk_level: match risk.severity.to_lowercase().as_str() {
            "critical" => RiskLevel::Critical,
            "high" => RiskLevel::High,
            "medium" => RiskLevel::Medium,
            "low" => RiskLevel::Low,
            _ => RiskLevel::Info,
        },
    };

    Ok(rs_core::ai::fix_suggest::generate_fix_suggestion(&finding, None))
}

/// DeepSeek AI vulnerability diagnosis (async)
///
/// Sends device info + CVE to DeepSeek for expert analysis.
/// Requires a DeepSeek API key.
#[tauri::command]
pub async fn ai_diagnose_vulnerability(
    device_info: String,
    vuln_id: String,
    cvss: f32,
    api_key: String,
) -> Result<DiagnosisResult, String> {
    rs_core::ai::diagnosis::diagnose_vulnerability(&device_info, &vuln_id, cvss, &api_key).await
}
