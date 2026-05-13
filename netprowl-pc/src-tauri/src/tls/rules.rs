use serde::Deserialize;
use crate::tls::TLSVulnerability;

#[derive(Debug, Deserialize)]
pub struct VulnRule {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub description: String,
}

const EMBEDDED_RULES: &str = include_str!("../tls_vuln_rules.json");

pub fn load_vuln_rules() -> Vec<VulnRule> {
    serde_json::from_str(EMBEDDED_RULES).unwrap_or_default()
}

pub fn check_vulnerabilities(config: &super::TLSConfigInfo, cert: &super::TLSCertInfo) -> Vec<TLSVulnerability> {
    let rules = load_vuln_rules();
    let mut vulns = Vec::new();

    // TLS 1.0/1.1 known issues
    if config.supports_tls10 {
        vulns.push(TLSVulnerability {
            id: "TLS10-EOL".into(),
            name: "TLS 1.0 Deprecated".into(),
            severity: "high".into(),
            description: "TLS 1.0 is deprecated (PCI DSS 7/2018)".into(),
        });
    }
    if config.supports_tls11 {
        vulns.push(TLSVulnerability {
            id: "TLS11-EOL".into(),
            name: "TLS 1.1 Deprecated".into(),
            severity: "high".into(),
            description: "TLS 1.1 is deprecated (PCI DSS 7/2018)".into(),
        });
    }

    // Weak cipher detection
    let weak_ciphers = ["DES", "3DES", "RC4", "MD5", "NULL"];
    for cipher in &config.supported_cipher_suites {
        if weak_ciphers.iter().any(|w| cipher.to_uppercase().contains(w)) {
            vulns.push(TLSVulnerability {
                id: "WEAK-CIPHER".into(),
                name: format!("Weak cipher: {}", cipher),
                severity: "medium".into(),
                description: "Cipher suite uses deprecated algorithm".into(),
            });
        }
    }

    // Certificate expiry detection
    let now = chrono::Utc::now().and_utc().timestamp();
    if let Ok(expiry) = chrono::NaiveDateTime::parse_from_str(&cert.not_after, "%Y-%m-%d %H:%M:%S") {
        if expiry.and_utc().timestamp() < now {
            vulns.push(TLSVulnerability {
                id: "CERT-EXPIRED".into(),
                name: "Certificate Expired".into(),
                severity: "critical".into(),
                description: "TLS certificate has expired".into(),
            });
        }
    }

    vulns
}