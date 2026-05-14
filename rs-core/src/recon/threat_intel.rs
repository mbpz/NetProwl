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

/// Check if IP matches any threat intelligence (sync version)
pub fn check_threat_intel_sync(ip: &str) -> ThreatIntel {
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

/// Threat intelligence result for async API lookups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelResult {
    pub ip: String,
    pub is_malicious: bool,
    pub threat_actors: Vec<String>,
    pub attack_reports: Vec<String>,
    pub last_seen: Option<String>,
}

/// Check threat intelligence for an IP (async)
/// Queries VirusTotal/AlienVault OTX if API key is provided
/// Returns mock data (marked as unknown) if no API key
pub async fn check_threat_intel(ip: &str) -> Result<ThreatIntelResult, String> {
    // Check local blocklist first
    if is_ip_blocked(ip) {
        return Ok(ThreatIntelResult {
            ip: ip.to_string(),
            is_malicious: true,
            threat_actors: vec!["local_blocklist".to_string()],
            attack_reports: vec!["Known malicious IP in local blocklist".to_string()],
            last_seen: None,
        });
    }

    if is_scanner_ip(ip) {
        return Ok(ThreatIntelResult {
            ip: ip.to_string(),
            is_malicious: true,
            threat_actors: vec!["known_scanner".to_string()],
            attack_reports: vec!["Known scanner IP (Shodan/Censys)".to_string()],
            last_seen: None,
        });
    }

    // Try VirusTotal API if key is present
    if let Ok(api_key) = std::env::var("VIRUSTOTAL_API_KEY") {
        if !api_key.is_empty() {
            return check_virustotal(ip, &api_key).await;
        }
    }

    // Try AlienVault OTX if key is present
    if let Ok(api_key) = std::env::var("OTX_API_KEY") {
        if !api_key.is_empty() {
            return check_otx(ip, &api_key).await;
        }
    }

    // No API keys - return mock unknown data
    Ok(ThreatIntelResult {
        ip: ip.to_string(),
        is_malicious: false,
        threat_actors: vec!["unknown".to_string()],
        attack_reports: vec!["No API key configured for threat lookup".to_string()],
        last_seen: None,
    })
}

/// Query VirusTotal API for threat intelligence
async fn check_virustotal(ip: &str, api_key: &str) -> Result<ThreatIntelResult, String> {
    let client = reqwest::Client::new();
    let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);

    let response = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await
        .map_err(|e| format!("VirusTotal request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("VirusTotal API error: {}", response.status()));
    }

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse VirusTotal response: {}", e))?;

    let data = json.get("data").ok_or("Invalid VirusTotal response format")?;
    let attributes = data.get("attributes").ok_or("Missing attributes")?;

    let malicious = attributes
        .get("last_analysis_stats")
        .and_then(|s| s.get("malicious"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) > 0;

    let threat_actors: Vec<String> = attributes
        .get("threat_labels")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let last_stats = attributes.get("last_analysis_date").and_then(|v| v.as_str());

    Ok(ThreatIntelResult {
        ip: ip.to_string(),
        is_malicious: malicious,
        threat_actors,
        attack_reports: vec!["VirusTotal threat intelligence".to_string()],
        last_seen: last_stats.map(String::from),
    })
}

/// Query AlienVault OTX API for threat intelligence
async fn check_otx(ip: &str, api_key: &str) -> Result<ThreatIntelResult, String> {
    let client = reqwest::Client::new();
    let url = format!("https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general", ip);

    let response = client
        .get(&url)
        .header("X-OTX-API-KEY", api_key)
        .send()
        .await
        .map_err(|e| format!("OTX request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("AlienVault OTX API error: {}", response.status()));
    }

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse OTX response: {}", e))?;

    let pulse_count = json
        .get("pulse_info")
        .and_then(|p| p.get("count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let is_malicious = pulse_count > 0;

    let pulses: Vec<String> = json
        .get("pulse_info")
        .and_then(|p| p.get("pulses"))
        .and_then(|arr| arr.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
                .take(5)
                .collect()
        })
        .unwrap_or_default();

    let last_seen = json
        .get("pulse_info")
        .and_then(|p| p.get("pulses"))
        .and_then(|arr| arr.as_array())
        .and_then(|arr| arr.first())
        .and_then(|p| p.get("created"))
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(ThreatIntelResult {
        ip: ip.to_string(),
        is_malicious,
        threat_actors: pulses,
        attack_reports: format!("AlienVault OTX: {} pulses", pulse_count)
            .split(',')
            .map(String::from)
            .collect(),
        last_seen,
    })
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

    #[tokio::test]
    async fn test_async_check_threat_intel_mock() {
        // Without API keys, should return mock unknown data
        let result = check_threat_intel("1.1.1.1").await.unwrap();
        assert_eq!(result.ip, "1.1.1.1");
        assert!(!result.is_malicious);
        assert!(result.threat_actors.contains(&"unknown".to_string()));
    }

    #[tokio::test]
    async fn test_async_check_threat_intel_blocked() {
        // 192.168.100.100 is in the local blocklist
        let result = check_threat_intel("192.168.100.100").await.unwrap();
        assert!(result.is_malicious);
        assert!(result.threat_actors.contains(&"local_blocklist".to_string()));
    }

    #[tokio::test]
    async fn test_async_check_threat_intel_scanner() {
        // Known scanner IP
        let result = check_threat_intel("66.240.192.138").await.unwrap();
        assert!(result.is_malicious);
        assert!(result.threat_actors.contains(&"known_scanner".to_string()));
    }
}
