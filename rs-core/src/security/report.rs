//! F3-6: Risk report generation
//! Aggregate all findings from F3-1~5
//! Compute CVSS 2.0/3.1 scores
//! Risk distribution: critical/high/medium/low/info
//! Generate prioritized fix list

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::UNIX_EPOCH;

use super::credentials::{WeakCredential, CredentialRiskLevel};
use super::http_auth::{HttpAuthResult, RiskLevel as HttpAuthRiskLevel};
use super::tls_audit::{TlsReport, RiskLevel as TlsRiskLevel};
use super::unauthorized::{UnauthorizedEndpoint, RiskLevel as UnauthRiskLevel};
use super::firmware::{FirmwareRisk, RiskLevel as FirmwareRiskLevel};

/// Convert CredentialRiskLevel to RiskLevel
/// Note: Kept for API compatibility - WeakCredential.risk_level is already RiskLevel
#[allow(dead_code)]
fn convert_cred_risk(r: CredentialRiskLevel) -> RiskLevel {
    match r {
        CredentialRiskLevel::High => RiskLevel::High,
        CredentialRiskLevel::Medium => RiskLevel::Medium,
        CredentialRiskLevel::Low => RiskLevel::Low,
    }
}

/// Convert HttpAuthRiskLevel to RiskLevel
fn convert_http_risk(r: HttpAuthRiskLevel) -> RiskLevel {
    match r {
        HttpAuthRiskLevel::High => RiskLevel::High,
        HttpAuthRiskLevel::Medium => RiskLevel::Medium,
        HttpAuthRiskLevel::Low => RiskLevel::Low,
    }
}

/// Convert UnauthRiskLevel to RiskLevel
fn convert_unauth_risk(r: UnauthRiskLevel) -> RiskLevel {
    match r {
        UnauthRiskLevel::Critical => RiskLevel::Critical,
        UnauthRiskLevel::High => RiskLevel::High,
        UnauthRiskLevel::Medium => RiskLevel::Medium,
        UnauthRiskLevel::Low => RiskLevel::Low,
        UnauthRiskLevel::Info => RiskLevel::Info,
    }
}

/// Convert TlsRiskLevel to RiskLevel
fn convert_tls_risk(r: TlsRiskLevel) -> RiskLevel {
    match r {
        TlsRiskLevel::Critical => RiskLevel::Critical,
        TlsRiskLevel::High => RiskLevel::High,
        TlsRiskLevel::Medium => RiskLevel::Medium,
        TlsRiskLevel::Low => RiskLevel::Low,
        TlsRiskLevel::Info => RiskLevel::Info,
    }
}

/// Convert FirmwareRiskLevel to RiskLevel
fn convert_firmware_risk(r: FirmwareRiskLevel) -> RiskLevel {
    match r {
        FirmwareRiskLevel::Critical => RiskLevel::Critical,
        FirmwareRiskLevel::High => RiskLevel::High,
        FirmwareRiskLevel::Medium => RiskLevel::Medium,
        FirmwareRiskLevel::Low => RiskLevel::Low,
        FirmwareRiskLevel::Info => RiskLevel::Info,
    }
}

/// Base score component weights for simplified CVSS
#[derive(Debug, Clone)]
struct CvssComponents {
    attack_vector: f64,      // 0.0-1.0 (Network=1.0, Adjacent=0.646, Local=0.395, Physical=0.200)
    attack_complexity: f64,  // 0.0-1.0 (Low=0.77, High=0.44)
    privileges_required: f64,// 0.0-1.0 (None=0.85, Low=0.62, High=0.27)
    user_interaction: f64,    // 0.0-1.0 (None=0.85, Required=0.62)
    scope_unchanged: f64,    // 0.0-1.0 (Unchanged=1.0, Changed=1.15)
    confidentiality: f64,     // 0.0-1.0 (None=0, Low=0.22, High=0.56)
    integrity: f64,           // 0.0-1.0 (None=0, Low=0.22, High=0.56)
    availability: f64,        // 0.0-1.0 (None=0, Low=0.22, High=0.56)
}

/// CVSS score and severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssScore {
    pub vector: String,
    pub base_score: f64,
    pub severity: String,
}

/// A security risk finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRisk {
    pub ip: String,
    pub port: Option<u16>,
    pub risk_type: String,
    pub title: String,
    pub description: String,
    pub cvss_score: Option<CvssScore>,
    pub evidence: HashMap<String, String>,
    pub risk_level: RiskLevel,
}

/// Risk level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Priority fix item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixPriority {
    pub priority: u32,
    pub ip: String,
    pub risk_type: String,
    pub title: String,
    pub action: String,
    pub effort: String,
}

/// Risk distribution summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDistribution {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

/// Security scan summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScanSummary {
    pub targets_scanned: usize,
    pub duration_seconds: u64,
    pub scan_timestamp: u64,
}

/// Complete security report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub summary: SecurityScanSummary,
    pub risks: Vec<SecurityRisk>,
    pub cvss_score: Option<f64>,
    pub risk_distribution: RiskDistribution,
    pub fix_priority: Vec<FixPriority>,
    pub recommendations: Vec<String>,
}

/// Convert RiskLevel to numeric score (simplified)
impl RiskLevel {
    pub fn to_score(&self) -> f64 {
        match self {
            RiskLevel::Critical => 9.0,
            RiskLevel::High => 7.5,
            RiskLevel::Medium => 5.0,
            RiskLevel::Low => 2.5,
            RiskLevel::Info => 0.0,
        }
    }
}

/// Calculate simplified CVSS base score
pub fn calculate_cvss(
    attack_vector: &str,
    attack_complexity: &str,
    privileges_required: &str,
    user_interaction: &str,
    confidentiality_impact: &str,
    integrity_impact: &str,
    availability_impact: &str,
) -> CvssScore {
    let av = match attack_vector.to_lowercase().as_str() {
        "network" => 0.85,
        "adjacent" => 0.62,
        "local" => 0.55,
        "physical" => 0.20,
        _ => 0.85,
    };

    let ac = match attack_complexity.to_lowercase().as_str() {
        "low" => 0.77,
        "high" => 0.44,
        _ => 0.77,
    };

    let pr = match privileges_required.to_lowercase().as_str() {
        "none" => 0.85,
        "low" => 0.62,
        "high" => 0.27,
        _ => 0.85,
    };

    let ui = match user_interaction.to_lowercase().as_str() {
        "none" => 0.85,
        "required" => 0.62,
        _ => 0.85,
    };

    let c = match confidentiality_impact.to_lowercase().as_str() {
        "high" => 0.56,
        "low" => 0.22,
        "none" => 0.0,
        _ => 0.0,
    };

    let i = match integrity_impact.to_lowercase().as_str() {
        "high" => 0.56,
        "low" => 0.22,
        "none" => 0.0,
        _ => 0.0,
    };

    let a = match availability_impact.to_lowercase().as_str() {
        "high" => 0.56,
        "low" => 0.22,
        "none" => 0.0,
        _ => 0.0,
    };

    // CVSS 3.1 formula (simplified)
    let impact: f64 = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let exploitability: f64 = 8.22 * av * ac * pr * ui;

    let base_score: f64 = if impact <= 0.0 {
        0.0
    } else {
        let scope_unchanged: f64 = 1.0;
        let scope_changed: f64 = 1.15;

        let impact_factor: f64 = match scope_unchanged as i32 {
            1 => impact,
            _ => impact * scope_changed,
        };

        let _iss: f64 = (scope_unchanged + exploitability).min(10.0);
        let base: f64 = (impact_factor + exploitability).min(10.0);

        (base * 10.0).round() / 10.0
    };

    let severity = match base_score as u32 {
        0 => "None",
        1..=3 => "Low",
        4..=6 => "Medium",
        7..=8 => "High",
        9..=10 => "Critical",
        _ => "None",
    };

    let vector = format!(
        "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
        attack_vector.chars().next().unwrap_or('N').to_uppercase(),
        attack_complexity.chars().next().unwrap_or('L').to_uppercase(),
        privileges_required.chars().next().unwrap_or('N').to_uppercase(),
        user_interaction.chars().next().unwrap_or('N').to_uppercase(),
        "U", // Scope unchanged
        confidentiality_impact.chars().next().unwrap_or('N').to_uppercase(),
        integrity_impact.chars().next().unwrap_or('N').to_uppercase(),
        availability_impact.chars().next().unwrap_or('N').to_uppercase(),
    );

    CvssScore {
        vector,
        base_score,
        severity: severity.to_string(),
    }
}

/// Create a security risk from weak credentials finding
impl From<WeakCredential> for SecurityRisk {
    fn from(cred: WeakCredential) -> Self {
        let cvss = calculate_cvss(
            "network",
            "low",
            "none",
            "none",
            "high",
            "high",
            "high",
        );

        let mut evidence: HashMap<String, String> = HashMap::new();
        evidence.insert("service".to_string(), cred.service.clone());
        evidence.insert("default_user".to_string(), cred.default_user.clone());
        evidence.insert("default_password".to_string(), cred.default_pass.clone());
        if let Some(ref brand_val) = cred.brand {
            evidence.insert("brand".to_string(), brand_val.to_string());
        }

        SecurityRisk {
            ip: cred.ip,
            port: Some(cred.port),
            risk_type: "Default Credentials".to_string(),
            title: format!("Default credentials for {} ({})", cred.service, format!("{:?}", cred.risk_level).to_lowercase()),
            description: format!(
                "Device at port {} has default credentials: {}/{}",
                cred.port, cred.default_user, cred.default_pass
            ),
            cvss_score: Some(cvss),
            evidence,
            risk_level: cred.risk_level.clone(),
        }
    }
}

/// Create a security risk from HTTP auth finding
impl From<HttpAuthResult> for SecurityRisk {
    fn from(result: HttpAuthResult) -> Self {
        let cvss = if result.is_vulnerable {
            calculate_cvss(
                "network",
                "low",
                "none",
                "none",
                "high",
                "high",
                "high",
            )
        } else {
            calculate_cvss(
                "network",
                "low",
                "high",
                "none",
                "none",
                "none",
                "none",
            )
        };

        let risk_level = result.risk_level.map(convert_http_risk).unwrap_or(RiskLevel::Info);

        let mut evidence = HashMap::new();
        evidence.insert("attempts_made".to_string(), result.attempts_made.to_string());
        evidence.insert("locked_out".to_string(), result.locked_out.to_string());

        if let Some(cred) = &result.valid_credential {
            evidence.insert("username".to_string(), cred.username.clone());
            evidence.insert("password".to_string(), cred.password.clone());
        }

        let title = if result.is_vulnerable {
            "Weak HTTP Basic Auth credentials detected".to_string()
        } else {
            "HTTP Basic Auth protection present".to_string()
        };

        SecurityRisk {
            ip: result.ip,
            port: Some(result.port),
            risk_type: "HTTP Authentication".to_string(),
            title,
            description: if result.is_vulnerable {
                format!(
                    "HTTP service at port {} accepts weak credentials after {} attempts",
                    result.port, result.attempts_made
                )
            } else {
                format!(
                    "HTTP service at port {} appears to require authentication",
                    result.port
                )
            },
            cvss_score: Some(cvss),
            evidence,
            risk_level,
        }
    }
}

/// Create a security risk from TLS audit finding
impl From<TlsReport> for SecurityRisk {
    fn from(report: TlsReport) -> Self {
        let cvss = calculate_cvss(
            "network",
            "low",
            "none",
            "none",
            "high",
            "low",
            "low",
        );

        let mut evidence = HashMap::new();
        evidence.insert("cert_valid".to_string(), report.cert_valid.to_string());
        evidence.insert("self_signed".to_string(), report.self_signed.to_string());
        if let Some(days) = report.cert_expiry_days {
            evidence.insert("cert_expiry_days".to_string(), days.to_string());
        }
        evidence.insert("weak_ciphers_count".to_string(), report.weak_ciphers.len().to_string());
        evidence.insert("tls_versions".to_string(), format!("{:?}", report.tls_versions));

        SecurityRisk {
            ip: report.ip,
            port: Some(report.port),
            risk_type: "TLS Configuration".to_string(),
            title: format!("TLS configuration issue: {:?}", report.risk_level),
            description: format!(
                "TLS audit found {} weak cipher suites, self-signed: {}, cert valid: {}",
                report.weak_ciphers.len(),
                report.self_signed,
                report.cert_valid
            ),
            cvss_score: Some(cvss),
            evidence,
            risk_level: convert_tls_risk(report.risk_level),
        }
    }
}

/// Create a security risk from unauthorized access finding
impl From<UnauthorizedEndpoint> for SecurityRisk {
    fn from(endpoint: UnauthorizedEndpoint) -> Self {
        let cvss = if endpoint.is_vulnerable {
            calculate_cvss(
                "network",
                "low",
                "none",
                "none",
                "high",
                "high",
                "high",
            )
        } else {
            calculate_cvss(
                "network",
                "low",
                "high",
                "none",
                "none",
                "none",
                "none",
            )
        };

        SecurityRisk {
            ip: endpoint.ip,
            port: Some(endpoint.port),
            risk_type: "Unauthorized Access".to_string(),
            title: format!("{} - {}", endpoint.service, if endpoint.is_vulnerable { "UNAUTHENTICATED ACCESS" } else { "Protected" }),
            description: format!(
                "Service: {}, Test: {}, Result: {}",
                endpoint.service, endpoint.test_performed, endpoint.result
            ),
            cvss_score: Some(cvss),
            evidence: HashMap::new(),
            risk_level: convert_unauth_risk(endpoint.risk_level),
        }
    }
}

/// Create a security risk from firmware risk finding
impl From<FirmwareRisk> for SecurityRisk {
    fn from(fw: FirmwareRisk) -> Self {
        let cvss = calculate_cvss(
            "network",
            "high",
            "none",
            "none",
            "low",
            "medium",
            "low",
        );

        let mut evidence = HashMap::new();
        evidence.insert("device_type".to_string(), fw.device_type.clone());
        if let Some(brand) = &fw.brand {
            evidence.insert("brand".to_string(), brand.clone());
        }
        if let Some(version) = &fw.current_version {
            evidence.insert("current_version".to_string(), version.clone());
        }
        if let Some(eos) = &fw.eos_date {
            evidence.insert("eos_date".to_string(), eos.clone());
        }

        SecurityRisk {
            ip: fw.ip,
            port: None,
            risk_type: "Firmware/EOS".to_string(),
            title: format!("Firmware risk: {:?}", fw.risk_level),
            description: fw.recommendation.clone(),
            cvss_score: Some(cvss),
            evidence,
            risk_level: convert_firmware_risk(fw.risk_level),
        }
    }
}

/// Calculate risk distribution from a list of risks
pub fn calculate_risk_distribution(risks: &[SecurityRisk]) -> RiskDistribution {
    let mut dist = RiskDistribution {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: risks.len(),
    };

    for risk in risks {
        match risk.risk_level {
            RiskLevel::Critical => dist.critical += 1,
            RiskLevel::High => dist.high += 1,
            RiskLevel::Medium => dist.medium += 1,
            RiskLevel::Low => dist.low += 1,
            RiskLevel::Info => dist.info += 1,
        }
    }

    dist
}

/// Calculate overall CVSS score (highest risk)
pub fn calculate_overall_cvss(risks: &[SecurityRisk]) -> Option<f64> {
    risks
        .iter()
        .filter_map(|r| r.cvss_score.as_ref())
        .map(|s| s.base_score)
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
}

/// Generate prioritized fix list
pub fn generate_fix_priority(risks: &[SecurityRisk]) -> Vec<FixPriority> {
    let mut priorities: Vec<FixPriority> = risks
        .iter()
        .filter(|r| r.risk_level != RiskLevel::Info)
        .map(|r| {
            let (priority, action, effort) = match r.risk_level {
                RiskLevel::Critical => (1, "IMMEDIATE ACTION REQUIRED", "High"),
                RiskLevel::High => (2, "Fix within 24-48 hours", "High"),
                RiskLevel::Medium => (3, "Fix within 1-2 weeks", "Medium"),
                RiskLevel::Low => (4, "Schedule fix", "Low"),
                RiskLevel::Info => (5, "Monitor", "Minimal"),
            };

            FixPriority {
                priority,
                ip: r.ip.clone(),
                risk_type: r.risk_type.clone(),
                title: r.title.clone(),
                action: action.to_string(),
                effort: effort.to_string(),
            }
        })
        .collect();

    priorities.sort_by_key(|p| p.priority);
    priorities
}

/// Generate general recommendations based on findings
pub fn generate_recommendations(risks: &[SecurityRisk]) -> Vec<String> {
    let mut recs = Vec::new();

    let has_creds = risks.iter().any(|r| r.risk_type == "Default Credentials" && r.risk_level == RiskLevel::Critical);
    if has_creds {
        recs.push("URGENT: Change all default credentials immediately on affected devices".to_string());
    }

    let has_unauth = risks.iter().any(|r| r.risk_type == "Unauthorized Access" && r.risk_level == RiskLevel::Critical);
    if has_unauth {
        recs.push("CRITICAL: Enable authentication on exposed services (Redis, MongoDB, Docker)".to_string());
    }

    let has_tls = risks.iter().any(|r| r.risk_type == "TLS Configuration" &&
        matches!(r.risk_level, RiskLevel::Critical | RiskLevel::High));
    if has_tls {
        recs.push("Update TLS configuration: disable weak ciphers, upgrade from TLS 1.0/1.1".to_string());
    }

    let has_firmware = risks.iter().any(|r| r.risk_type == "Firmware/EOS" &&
        matches!(r.risk_level, RiskLevel::Critical | RiskLevel::High));
    if has_firmware {
        recs.push("Replace or update EOS (End of Support) devices with latest firmware".to_string());
    }

    if recs.is_empty() {
        recs.push("Continue monitoring for new vulnerabilities".to_string());
    }

    recs
}

/// Generate complete security report
pub fn generate_security_report(
    targets_scanned: usize,
    duration_seconds: u64,
    weak_credentials: Vec<WeakCredential>,
    http_auth_results: Vec<HttpAuthResult>,
    tls_reports: Vec<TlsReport>,
    unauthorized_endpoints: Vec<UnauthorizedEndpoint>,
    firmware_risks: Vec<FirmwareRisk>,
) -> SecurityReport {
    let mut all_risks: Vec<SecurityRisk> = Vec::new();

    // Convert all findings to security risks
    for cred in weak_credentials {
        all_risks.push(SecurityRisk::from(cred));
    }

    for http_result in http_auth_results {
        all_risks.push(SecurityRisk::from(http_result));
    }

    for tls_report in tls_reports {
        all_risks.push(SecurityRisk::from(tls_report));
    }

    for endpoint in unauthorized_endpoints {
        all_risks.push(SecurityRisk::from(endpoint));
    }

    for fw_risk in firmware_risks {
        all_risks.push(SecurityRisk::from(fw_risk));
    }

    let summary = SecurityScanSummary {
        targets_scanned,
        duration_seconds,
        scan_timestamp: std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let risk_distribution = calculate_risk_distribution(&all_risks);
    let cvss_score = calculate_overall_cvss(&all_risks);
    let fix_priority = generate_fix_priority(&all_risks);
    let recommendations = generate_recommendations(&all_risks);

    SecurityReport {
        summary,
        risks: all_risks,
        cvss_score,
        risk_distribution,
        fix_priority,
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_calculation_network_low_none() {
        let score = calculate_cvss("network", "low", "none", "none", "high", "high", "high");
        assert!(score.base_score >= 7.0); // Should be high
    }

    #[test]
    fn test_cvss_calculation_local_high_high() {
        let score = calculate_cvss("local", "high", "high", "required", "high", "high", "high");
        assert!(score.base_score <= 8.0); // Should be lower due to constraints
    }

    #[test]
    fn test_risk_level_to_score() {
        assert_eq!(RiskLevel::Critical.to_score(), 9.0);
        assert_eq!(RiskLevel::High.to_score(), 7.5);
        assert_eq!(RiskLevel::Medium.to_score(), 5.0);
        assert_eq!(RiskLevel::Low.to_score(), 2.5);
        assert_eq!(RiskLevel::Info.to_score(), 0.0);
    }

    #[test]
    fn test_calculate_risk_distribution() {
        let risks = vec![
            SecurityRisk {
                ip: "192.168.1.1".to_string(),
                port: Some(80),
                risk_type: "Test".to_string(),
                title: "Test".to_string(),
                description: "Test".to_string(),
                cvss_score: None,
                evidence: HashMap::new(),
                risk_level: RiskLevel::Critical,
            },
            SecurityRisk {
                ip: "192.168.1.2".to_string(),
                port: Some(80),
                risk_type: "Test".to_string(),
                title: "Test".to_string(),
                description: "Test".to_string(),
                cvss_score: None,
                evidence: HashMap::new(),
                risk_level: RiskLevel::High,
            },
            SecurityRisk {
                ip: "192.168.1.3".to_string(),
                port: Some(80),
                risk_type: "Test".to_string(),
                title: "Test".to_string(),
                description: "Test".to_string(),
                cvss_score: None,
                evidence: HashMap::new(),
                risk_level: RiskLevel::Medium,
            },
        ];

        let dist = calculate_risk_distribution(&risks);
        assert_eq!(dist.critical, 1);
        assert_eq!(dist.high, 1);
        assert_eq!(dist.medium, 1);
        assert_eq!(dist.total, 3);
    }

    #[test]
    fn test_generate_fix_priority() {
        let risks = vec![
            SecurityRisk {
                ip: "192.168.1.1".to_string(),
                port: Some(80),
                risk_type: "Default Credentials".to_string(),
                title: "Critical risk".to_string(),
                description: "Test".to_string(),
                cvss_score: None,
                evidence: HashMap::new(),
                risk_level: RiskLevel::Critical,
            },
            SecurityRisk {
                ip: "192.168.1.2".to_string(),
                port: Some(80),
                risk_type: "Firmware".to_string(),
                title: "Low risk".to_string(),
                description: "Test".to_string(),
                cvss_score: None,
                evidence: HashMap::new(),
                risk_level: RiskLevel::Low,
            },
        ];

        let priorities = generate_fix_priority(&risks);
        assert_eq!(priorities.len(), 2);
        assert_eq!(priorities[0].priority, 1); // Critical should be first
        assert_eq!(priorities[1].priority, 4); // Low should be last
    }

    #[test]
    fn test_generate_security_report() {
        let report = generate_security_report(
            10,
            60,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        );

        assert_eq!(report.summary.targets_scanned, 10);
        assert_eq!(report.summary.duration_seconds, 60);
        assert_eq!(report.risks.len(), 0);
        assert_eq!(report.risk_distribution.total, 0);
    }

    #[test]
    fn test_security_report_serialization() {
        let report = SecurityReport {
            summary: SecurityScanSummary {
                targets_scanned: 5,
                duration_seconds: 30,
                scan_timestamp: 0,
            },
            risks: vec![],
            cvss_score: Some(7.5),
            risk_distribution: RiskDistribution {
                critical: 0,
                high: 1,
                medium: 2,
                low: 1,
                info: 1,
                total: 5,
            },
            fix_priority: vec![],
            recommendations: vec!["Test recommendation".to_string()],
        };

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("targets_scanned"));
        assert!(json.contains("7.5"));
    }
}
