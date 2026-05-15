//! Tauri commands for public network reconnaissance (Phase 4)
//!
//! Exposes rs-core recon layer as Tauri IPC commands:
//! - Shodan / FOFA public asset queries
//! - DNS / subdomain reconnaissance
//! - HTTP security header audit
//! - WAF / CDN identification
//! - Passive web vulnerability scanning
//! - Threat intelligence checks

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Shodan / FOFA ──

/// Query Shodan for public asset information on an IP (falls back to mock data)
#[tauri::command]
pub fn recon_query_shodan(api_key: String, ip: String) -> Result<rs_core::recon::shodan::PublicAsset, String> {
    rs_core::recon::shodan::query_shodan_ip(&api_key, &ip)
}

/// Query FOFA for subdomains and IPs associated with a domain (falls back to mock data)
#[tauri::command]
pub fn recon_query_fofa(api_key: String, email: String, domain: String) -> Result<Vec<(String, String)>, String> {
    rs_core::recon::shodan::query_fofa_domain(&api_key, &email, &domain)
}

// ── DNS / Subdomain ──

/// Full DNS reconnaissance (A/AAAA/CNAME/MX/TXT/NS + cloud/CDN detection)
#[tauri::command]
pub fn recon_dns_recon(target: String) -> Result<rs_core::recon::dns::DnsRecon, String> {
    Ok(rs_core::recon::dns::dns_recon(&target))
}

/// Enumerate subdomains using crt.sh Certificate Transparency logs
#[tauri::command]
pub async fn recon_enum_subdomains(domain: String) -> Result<Vec<String>, String> {
    let result = rs_core::recon::dns::enumerate_subdomains(&domain).await?;
    Ok(result.subdomains)
}

// ── HTTP Security Header Audit ──

/// Audit HTTP security headers, returns letter grade A-F
#[tauri::command]
pub fn recon_http_audit(url: String) -> Result<rs_core::recon::http_audit::HttpSecurityReport, String> {
    rs_core::recon::http_audit::audit_http_security(&url)
}

// ── WAF / CDN Detection ──

/// WAF/CDN detection input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafCdnInput {
    pub ip: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub status_code: u16,
}

/// Identify WAF and CDN from HTTP response headers and body
#[tauri::command]
pub fn recon_detect_waf_cdn(input: WafCdnInput) -> Result<rs_core::recon::waf::WafCdn, String> {
    Ok(rs_core::recon::waf::analyze_waf_cdn(&input.ip, input.headers, input.body, input.status_code))
}

// ── Passive Web Vulnerability Scan ──

/// Run passive web vulnerability scan (XSS, SQL error, sensitive paths, info leaks)
#[tauri::command]
pub fn recon_passive_web_scan(url: String) -> Result<Vec<rs_core::recon::web_vuln::WebVulnResult>, String> {
    let vulns = rs_core::recon::web_vuln::passive_web_scan(&url)?;
    Ok(vulns.into_iter().map(|v| v.into()).collect())
}

// ── Threat Intelligence ──

/// Check threat intelligence for an IP (local blocklist + community + VT/OTX)
#[tauri::command]
pub async fn recon_check_threat_intel(ip: String) -> Result<rs_core::recon::threat_intel::ThreatIntelResult, String> {
    rs_core::recon::threat_intel::check_threat_intel(&ip).await
}

/// Quick check: is IP in local blocklist?
#[tauri::command]
pub fn recon_is_ip_blocked(ip: String) -> Result<bool, String> {
    Ok(rs_core::recon::threat_intel::is_ip_blocked(&ip))
}

/// Quick check: is internal IP exposed to public internet?
#[tauri::command]
pub fn recon_is_exposed_internal(ip: String) -> Result<bool, String> {
    Ok(rs_core::recon::threat_intel::is_exposed_internal(&ip))
}

// ── Combined Recon ──

/// Combined reconnaissance input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconInput {
    pub target: String,
    pub shodan_api_key: Option<String>,
    pub fofa_api_key: Option<String>,
    pub fofa_email: Option<String>,
}

/// Combined reconnaissance result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedReconResult {
    pub target: String,
    pub dns: Option<rs_core::recon::dns::DnsRecon>,
    pub subdomains: Vec<String>,
    pub http_security: Option<rs_core::recon::http_audit::HttpSecurityReport>,
    pub public_asset: Option<rs_core::recon::shodan::PublicAsset>,
    pub threat_intel: Option<rs_core::recon::threat_intel::ThreatIntelResult>,
}

/// Run full reconnaissance on a target (DNS + subdomains + HTTP + threat intel)
#[tauri::command]
pub async fn recon_full(input: ReconInput) -> Result<CombinedReconResult, String> {
    let mut result = CombinedReconResult {
        target: input.target.clone(),
        dns: None,
        subdomains: Vec::new(),
        http_security: None,
        public_asset: None,
        threat_intel: None,
    };

    // DNS recon (sync)
    if !input.target.parse::<std::net::IpAddr>().is_ok() {
        result.dns = Some(rs_core::recon::dns::dns_recon(&input.target));

        if let Ok(subs) = rs_core::recon::dns::enumerate_subdomains(&input.target).await {
            result.subdomains = subs.subdomains;
        }
    }

    // HTTP security audit (sync)
    let http_url = if input.target.starts_with("http") {
        input.target.clone()
    } else {
        format!("https://{}", input.target)
    };
    result.http_security = rs_core::recon::http_audit::audit_http_security(&http_url).ok();

    // Shodan (sync, mock if no key)
    if let Some(key) = &input.shodan_api_key {
        result.public_asset = rs_core::recon::shodan::query_shodan_ip(key, &input.target).ok();
    }

    // Threat intel (async)
    result.threat_intel = rs_core::recon::threat_intel::check_threat_intel(&input.target).await.ok();

    Ok(result)
}
