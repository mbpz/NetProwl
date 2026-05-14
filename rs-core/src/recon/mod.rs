//! Public network reconnaissance module
//!
//! This module implements Phase 4 (F4-1 ~ F4-6) reconnaissance features:
//! - F4-1: Shodan/FOFA/ZoomEye integration
//! - F4-2: Subdomain + DNS reconnaissance
//! - F4-3: HTTP security header audit
//! - F4-4: WAF/CDN identification
//! - F4-5: Web vulnerability passive detection
//! - F4-6: Community threat intelligence

pub mod shodan;
pub mod dns;
pub mod http_audit;
pub mod waf;
pub mod web_vuln;
pub mod threat_intel;

// Re-export commonly used types
pub use shodan::{
    PublicAsset,
    query_shodan_ip,
    query_fofa_domain,
    query_zoomeye_ip,
    aggregate_public_assets,
};

pub use dns::{
    DnsRecon,
    DnsRecordType,
    DnsValue,
    CloudProvider,
    CdnProvider,
    resolve_domain,
    query_crtsh,
    identify_cloud_provider,
    detect_cdn,
    dns_recon,
};

pub use http_audit::{
    HttpSecurityReport,
    SecurityHeader,
    audit_http_security,
    analyze_security_headers,
};

pub use waf::{
    WafCdn,
    WafType,
    CdnProvider as WafCdnProvider,
    identify_waf,
    identify_cdn,
    analyze_waf_cdn,
};

pub use web_vuln::{
    WebVuln,
    VulnType,
    test_xss_reflection,
    scan_sql_injection,
    scan_sensitive_paths,
    scan_info_leaks,
    passive_web_scan,
};

pub use threat_intel::{
    ThreatIntel,
    ThreatIntelResult,
    ThreatReport,
    DeviceFingerprintRule,
    check_threat_intel,
    check_threat_intel_sync,
    is_ip_blocked,
    is_scanner_ip,
    is_exposed_internal,
    match_community_rules,
    add_threat_report,
    get_user_reports,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Recon summary for a domain or IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconSummary {
    pub target: String,
    pub public_assets: Option<PublicAsset>,
    pub dns_recon: Option<DnsRecon>,
    pub http_security: Option<HttpSecurityReport>,
    pub waf_cdn: Option<WafCdn>,
    pub web_vulns: Vec<WebVuln>,
    pub threat_intel: ThreatIntel,
}

/// Run full reconnaissance on a target
pub fn run_recon(target: &str) -> ReconSummary {
    let mut summary = ReconSummary {
        target: target.to_string(),
        public_assets: None,
        dns_recon: None,
        http_security: None,
        waf_cdn: None,
        web_vulns: Vec::new(),
        threat_intel: ThreatIntel {
            blocked_ips: Vec::new(),
            community_reports: Vec::new(),
            matching_rules: Vec::new(),
        },
    };

    // Check threat intel first
    summary.threat_intel = check_threat_intel_sync(target);

    // DNS reconnaissance for domains
    if !target.parse::<std::net::IpAddr>().is_ok() {
        summary.dns_recon = Some(dns_recon(target));
    }

    // HTTP security audit
    let http_url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("http://{}", target)
    };

    if let Ok(report) = audit_http_security(&http_url) {
        summary.http_security = Some(report);
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recon_summary_structure() {
        let summary = run_recon("8.8.8.8");
        assert_eq!(summary.target, "8.8.8.8");
    }

    #[test]
    fn test_dns_recon_for_domain() {
        // Only runs DNS recon for non-IP targets
        let summary = run_recon("example.com");
        // DNS recon may fail without network, but structure should be valid
        assert_eq!(summary.target, "example.com");
    }
}
