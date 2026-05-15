//! Tauri commands for security report generation (Phase 2-3)
//!
//! Exposes rs-core security report layer as Tauri IPC commands:
//! - Risk distribution summary
//! - Fix priority list generation

use serde::{Deserialize, Serialize};

// ── Input type for the frontend ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRiskInfo {
    pub ip: String,
    pub port: Option<u16>,
    pub risk_type: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
}

// ── Tauri Commands ──

/// Get risk distribution summary (critical/high/medium/low/info counts)
#[tauri::command]
pub fn report_risk_summary(risks: Vec<ReportRiskInfo>) -> Result<rs_core::security::report::RiskDistribution, String> {
    let findings: Vec<rs_core::security::report::SecurityRisk> = risks.into_iter().map(|r| {
        rs_core::security::report::SecurityRisk {
            ip: r.ip,
            port: r.port,
            risk_type: r.risk_type,
            title: r.title,
            description: r.description,
            cvss_score: r.cvss_score.map(|s| rs_core::security::report::CvssScore {
                vector: String::new(),
                base_score: s,
                severity: String::new(),
            }),
            evidence: std::collections::HashMap::new(),
            risk_level: match r.severity.to_lowercase().as_str() {
                "critical" => rs_core::security::report::RiskLevel::Critical,
                "high" => rs_core::security::report::RiskLevel::High,
                "medium" => rs_core::security::report::RiskLevel::Medium,
                "low" => rs_core::security::report::RiskLevel::Low,
                _ => rs_core::security::report::RiskLevel::Info,
            },
        }
    }).collect();

    Ok(rs_core::security::report::calculate_risk_distribution(&findings))
}

/// Get fix priority list sorted by severity
#[tauri::command]
pub fn report_fix_priorities(risks: Vec<ReportRiskInfo>) -> Result<Vec<rs_core::security::report::FixPriority>, String> {
    let findings: Vec<rs_core::security::report::SecurityRisk> = risks.into_iter().map(|r| {
        rs_core::security::report::SecurityRisk {
            ip: r.ip,
            port: r.port,
            risk_type: r.risk_type,
            title: r.title,
            description: r.description,
            cvss_score: r.cvss_score.map(|s| rs_core::security::report::CvssScore {
                vector: String::new(),
                base_score: s,
                severity: String::new(),
            }),
            evidence: std::collections::HashMap::new(),
            risk_level: match r.severity.to_lowercase().as_str() {
                "critical" => rs_core::security::report::RiskLevel::Critical,
                "high" => rs_core::security::report::RiskLevel::High,
                "medium" => rs_core::security::report::RiskLevel::Medium,
                "low" => rs_core::security::report::RiskLevel::Low,
                _ => rs_core::security::report::RiskLevel::Info,
            },
        }
    }).collect();

    Ok(rs_core::security::report::generate_fix_priority(&findings))
}
