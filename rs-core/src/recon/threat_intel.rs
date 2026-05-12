use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// User-submitted threat report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    pub ip: String,
    pub service: String,
    pub description: String,
    pub submitted_by: String,
    pub timestamp: u64,
}

/// Community-contributed device fingerprint rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprintRule {
    pub pattern: String,
    pub description: String,
    pub severity: String,
    pub rule_type: String,
}

/// Community threat intelligence aggregated data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntel {
    pub blocked_ips: Vec<String>,
    pub community_reports: Vec<ThreatReport>,
    pub matching_rules: Vec<DeviceFingerprintRule>,
}

/// Known malicious IP blocklist (sample)
const KNOWN_MALICIOUS_IPS: &[&str] = &[
    "192.168.100.100",  // Example malicious internal IP
    "10.0.0.99",        // Example malicious internal IP
    "198.51.100.50",    // Example malicious IP (TEST-NET-2)
    "203.0.113.100",    // Example malicious IP (TEST-NET-3)
];

/// Scanner/ Honeypot IPs to flag
const SCANNER_IPS: &[&str] = &[
    "66.240.192.138",   // Known scanner
    "66.240.236.65",    // Known scanner
    "71.6.135.131",     // Known scanner
    "71.6.165.200",     // Known scanner
    "162.142.125.0/24", // Compound社会组织
    "167.94.146.0/24", // Compound社会组织
];

/// Internal-only IP ranges (should not be exposed to internet)
pub fn internal_ip_ranges() -> Vec<&'static str> {
    vec![
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    ]
}

/// Check if IP is in blocklist
pub fn is_ip_blocked(ip: &str) -> bool {
    let blocked_set: HashSet<&str> = KNOWN_MALICIOUS_IPS.iter().cloned().collect();
    blocked_set.contains(ip)
}

/// Check if IP is a known scanner
pub fn is_scanner_ip(ip: &str) -> bool {
    let scanner_set: HashSet<&str> = SCANNER_IPS.iter().cloned().collect();
    scanner_set.contains(ip)
}

/// Check if IP is in internal range (exposed to internet incorrectly)
pub fn is_exposed_internal(ip: &str) -> bool {
    use std::net::IpAddr;

    // Simple check for well-known internal ranges
    if ip.starts_with("10.") ||
       ip.starts_with("172.16.") || ip.starts_with("172.17.") ||
       ip.starts_with("172.18.") || ip.starts_with("172.19.") ||
       ip.starts_with("172.20.") || ip.starts_with("172.21.") ||
       ip.starts_with("172.22.") || ip.starts_with("172.23.") ||
       ip.starts_with("172.24.") || ip.starts_with("172.25.") ||
       ip.starts_with("172.26.") || ip.starts_with("172.27.") ||
       ip.starts_with("172.28.") || ip.starts_with("172.29.") ||
       ip.starts_with("172.30.") || ip.starts_with("172.31.") ||
       ip.starts_with("192.168.") {
        return true;
    }

    false
}

/// Default community rules for device fingerprinting
pub fn default_community_rules() -> Vec<DeviceFingerprintRule> {
    vec![
        DeviceFingerprintRule {
            pattern: r"RouterOS|routeros|MikroTik".to_string(),
            description: "MikroTik RouterOS detected - known for vulnerable default configurations".to_string(),
            severity: "中危".to_string(),
            rule_type: "device_type".to_string(),
        },
        DeviceFingerprintRule {
            pattern: r"D-Link|dlink|DLINK".to_string(),
            description: "D-Link device detected - multiple CVEs historically".to_string(),
            severity: "高危".to_string(),
            rule_type: "device_brand".to_string(),
        },
        DeviceFingerprintRule {
            pattern: r"TP-LINK|tplink|TP-Link".to_string(),
            description: "TP-Link device detected - historically weak encryption".to_string(),
            severity: "中危".to_string(),
            rule_type: "device_brand".to_string(),
        },
        DeviceFingerprintRule {
            pattern: r"Apache|nginx|Server:.*HTTP".to_string(),
            description: "Web server detected - ensure proper security headers".to_string(),
            severity: "低危".to_string(),
            rule_type: "service".to_string(),
        },
        DeviceFingerprintRule {
            pattern: r"Redis|MongoDB|Elasticsearch|Memcached".to_string(),
            description: "Database/Cache service detected - ensure no unauthenticated access".to_string(),
            severity: "高危".to_string(),
            rule_type: "service".to_string(),
        },
        DeviceFingerprintRule {
            pattern: r"Docker|kubernetes|Kubernetes".to_string(),
            description: "Container platform detected - ensure network isolation".to_string(),
            severity: "高危".to_string(),
            rule_type: "platform".to_string(),
        },
        DeviceFingerprintRule {
            pattern: r"Webcam|MJPEG|-camera|ipcam".to_string(),
            description: "IP Camera detected - ensure no default credentials".to_string(),
            severity: "中危".to_string(),
            rule_type: "device_type".to_string(),
        },
        DeviceFingerprintRule {
            pattern: r"SSH|OpenSSH|Dropbear".to_string(),
            description: "SSH service detected - ensure key-based auth only".to_string(),
            severity: "中危".to_string(),
            rule_type: "service".to_string(),
        },
    ]
}

/// Match banner against community rules
pub fn match_community_rules(banner: &str) -> Vec<DeviceFingerprintRule> {
    let mut matches = Vec::new();

    for rule in default_community_rules() {
        let pattern_re = regex::Regex::new(&rule.pattern);
        if let Ok(re) = pattern_re {
            if re.is_match(banner) {
                matches.push(rule);
            }
        }
    }

    matches
}

/// User submitted reports storage (in-memory for Phase 1)
lazy_static::lazy_static! {
    static ref USER_REPORTS: std::sync::Mutex<Vec<ThreatReport>> = std::sync::Mutex::new(Vec::new());
}

/// Add a user-submitted threat report
pub fn add_threat_report(report: ThreatReport) {
    if let Ok(mut reports) = USER_REPORTS.lock() {
        reports.push(report);
    }
}

/// Get all user-submitted threat reports
pub fn get_user_reports() -> Vec<ThreatReport> {
    USER_REPORTS.lock().map(|r| r.clone()).unwrap_or_default()
}

/// Clear all user-submitted reports (for testing)
#[allow(dead_code)]
pub fn clear_user_reports() {
    if let Ok(mut reports) = USER_REPORTS.lock() {
        reports.clear();
    }
}

/// Check if IP matches any threat intelligence
pub fn check_threat_intel(ip: &str) -> ThreatIntel {
    let mut blocked_ips = Vec::new();
    let community_reports = get_user_reports();
    let matching_rules = Vec::new();

    if is_ip_blocked(ip) {
        blocked_ips.push(ip.to_string());
    }

    if is_scanner_ip(ip) {
        blocked_ips.push(ip.to_string());
    }

    if is_exposed_internal(ip) {
        blocked_ips.push(ip.to_string());
    }

    ThreatIntel {
        blocked_ips,
        community_reports,
        matching_rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_ip_detection() {
        assert!(is_ip_blocked("192.168.100.100"));
        assert!(!is_ip_blocked("8.8.8.8"));
    }

    #[test]
    fn test_scanner_ip_detection() {
        assert!(is_scanner_ip("66.240.192.138"));
        assert!(!is_scanner_ip("1.1.1.1"));
    }

    #[test]
    fn test_exposed_internal_ip() {
        assert!(is_exposed_internal("10.0.0.1"));
        assert!(is_exposed_internal("192.168.1.1"));
        assert!(is_exposed_internal("172.16.0.1"));
        assert!(!is_exposed_internal("8.8.8.8"));
    }

    #[test]
    fn test_community_rule_matching() {
        let matches = match_community_rules("OpenSSH_6.6.1p1");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.rule_type == "service"));
    }

    #[test]
    fn test_threat_report_add_and_get() {
        clear_user_reports();
        let report = ThreatReport {
            ip: "10.0.0.99".to_string(),
            service: "SSH".to_string(),
            description: "Brute force attempts detected".to_string(),
            submitted_by: "test_user".to_string(),
            timestamp: 1715500000,
        };
        add_threat_report(report);
        let reports = get_user_reports();
        assert_eq!(reports.len(), 1);
        clear_user_reports();
    }
}
