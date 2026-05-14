use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// CDN/WAF type enum as specified in requirements
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CDNType {
    Cloudflare,
    Akamai,
    AliyunWAF,
    TencentWAF,
    None,
}

impl CDNType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CDNType::Cloudflare => "Cloudflare",
            CDNType::Akamai => "Akamai",
            CDNType::AliyunWAF => "Aliyun WAF",
            CDNType::TencentWAF => "Tencent WAF",
            CDNType::None => "None",
        }
    }
}

/// WAF and CDN provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WafType {
    Cloudflare,
    Aliyun,
    Tencent,
    BtPanel,
    ModSecurity,
    None,
}

impl WafType {
    pub fn as_str(&self) -> &'static str {
        match self {
            WafType::Cloudflare => "Cloudflare WAF",
            WafType::Aliyun => "Aliyun WAF",
            WafType::Tencent => "Tencent Cloud WAF",
            WafType::BtPanel => "BT Panel (宝塔面板)",
            WafType::ModSecurity => "ModSecurity WAF",
            WafType::None => "None",
        }
    }
}

/// CDN provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CdnProvider {
    Cloudflare,
    Aliyun,
    Tencent,
    Akamai,
    Fastly,
    Cloudfront,
    None,
}

impl CdnProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            CdnProvider::Cloudflare => "Cloudflare CDN",
            CdnProvider::Aliyun => "Aliyun CDN",
            CdnProvider::Tencent => "Tencent Cloud CDN",
            CdnProvider::Akamai => "Akamai CDN",
            CdnProvider::Fastly => "Fastly CDN",
            CdnProvider::Cloudfront => "AWS CloudFront",
            CdnProvider::None => "None",
        }
    }
}

/// WAF/CDN identification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafCdn {
    pub ip: String,
    pub waf_type: WafType,
    pub cdn_provider: CdnProvider,
    pub is_behind: bool,
    pub evidence: Vec<String>,
}

/// Identify WAF from HTTP response headers and body
pub fn identify_waf(headers: &HashMap<String, String>, body: &str, status_code: u16) -> WafType {
    // Check for Cloudflare
    if headers.contains_key("cf-ray") || headers.contains_key("cf-cache-status") {
        return WafType::Cloudflare;
    }

    // Check for Aliyun WAF
    if headers.get("x-powered-by").map(|v| v.contains("Alibaba")).unwrap_or(false) {
        return WafType::Aliyun;
    }
    if headers.get("x-powered-by").map(|v| v.contains("Aliyun")).unwrap_or(false) {
        return WafType::Aliyun;
    }
    // Aliyun error pages
    if body.contains("405 Not Allowed") && body.contains("Aliyun") {
        return WafType::Aliyun;
    }

    // Check for Tencent WAF
    if headers.contains_key("x-tencent-cn") || headers.contains_key("tencent-cdn") {
        return WafType::Tencent;
    }
    // Tencent-specific error codes
    if status_code == 520 || status_code == 521 || status_code == 522 {
        return WafType::Tencent;
    }

    // Check for BT Panel (宝塔面板)
    if body.contains("bt-waf") || body.contains("/BtSoft/") {
        return WafType::BtPanel;
    }
    if body.contains("防火墙") && body.contains("拦截") {
        return WafType::BtPanel;
    }
    if body.contains("抱歉，您的请求已被拦截") {
        return WafType::BtPanel;
    }

    // Check for ModSecurity
    if headers.get("server").map(|v| v.contains("ModSecurity")).unwrap_or(false) {
        return WafType::ModSecurity;
    }
    if body.contains("ModSecurity") || body.contains("mod_security") {
        return WafType::ModSecurity;
    }

    WafType::None
}

/// Identify CDN from HTTP response headers
pub fn identify_cdn(headers: &HashMap<String, String>, body: &str) -> CdnProvider {
    // Check for Cloudflare
    if headers.contains_key("cf-ray") {
        return CdnProvider::Cloudflare;
    }

    // Check for Aliyun CDN
    if headers.get("server").map(|v| v.contains("Tengine")).unwrap_or(false) ||
       headers.get("server").map(|v| v.contains("Aliyun")).unwrap_or(false) {
        return CdnProvider::Aliyun;
    }
    if body.contains("CNZZ") || body.contains(" Alicdn") {
        return CdnProvider::Aliyun;
    }

    // Check for Tencent CDN
    if headers.contains_key("tencent-cdn") ||
       headers.get("server").map(|v| v.contains("CDN")).unwrap_or(false) {
        return CdnProvider::Tencent;
    }

    // Check for Akamai
    if headers.get("server").map(|v| v.contains("Akamai")).unwrap_or(false) {
        return CdnProvider::Akamai;
    }
    if headers.get("x-akamai-request-id").is_some() {
        return CdnProvider::Akamai;
    }

    // Check for Fastly
    if headers.get("server").map(|v| v.contains("Fastly")).unwrap_or(false) {
        return CdnProvider::Fastly;
    }
    if headers.contains_key("fastly-debug-digest") {
        return CdnProvider::Fastly;
    }

    // Check for CloudFront
    if headers.get("server").map(|v| v.contains("CloudFront")).unwrap_or(false) {
        return CdnProvider::Cloudfront;
    }

    CdnProvider::None
}

/// Analyze IP, headers, and response to determine WAF/CDN
pub fn analyze_waf_cdn(ip: &str, headers: HashMap<String, String>, body: String, status_code: u16) -> WafCdn {
    let mut evidence = Vec::new();

    let waf_type = identify_waf(&headers, &body, status_code);
    if waf_type != WafType::None {
        evidence.push(format!("Detected WAF type: {}", waf_type.as_str()));
    }

    let cdn_provider = identify_cdn(&headers, &body);
    if cdn_provider != CdnProvider::None {
        evidence.push(format!("Detected CDN: {}", cdn_provider.as_str()));
    }

    // Check if behind WAF/CDN
    let is_behind = waf_type != WafType::None || cdn_provider != CdnProvider::None;

    if is_behind {
        if waf_type != WafType::None {
            evidence.push(format!("Host is behind {}", waf_type.as_str()));
        }
        if cdn_provider != CdnProvider::None {
            evidence.push(format!("Host is behind {}", cdn_provider.as_str()));
        }
    } else {
        evidence.push("No WAF/CDN detected".to_string());
    }

    WafCdn {
        ip: ip.to_string(),
        waf_type,
        cdn_provider,
        is_behind,
        evidence,
    }
}

/// Detect CDN/WAF type from HTTP response headers
pub fn detect_waf_cdn(headers: &HashMap<String, String>) -> CDNType {
    // Check for Cloudflare: CF-Ray header
    if headers.contains_key("cf-ray") || headers.contains_key("cf-cache-status") {
        return CDNType::Cloudflare;
    }

    // Check for Akamai: X-Akamai-* headers
    if headers.get("server").map(|v| v.contains("Akamai")).unwrap_or(false) {
        return CDNType::Akamai;
    }
    if headers.keys().any(|k| k.starts_with("x-akamai-")) {
        return CDNType::Akamai;
    }

    // Check for Aliyun WAF: X-Powered-By-Alibaba / specific error pages
    if headers.get("x-powered-by").map(|v| v.contains("Alibaba")).unwrap_or(false) {
        return CDNType::AliyunWAF;
    }
    if headers.get("x-powered-by").map(|v| v.contains("Aliyun")).unwrap_or(false) {
        return CDNType::AliyunWAF;
    }

    // Check for Tencent Cloud WAF: specific headers and response codes
    if headers.contains_key("x-tencent-cn") || headers.contains_key("tencent-cdn") {
        return CDNType::TencentWAF;
    }

    CDNType::None
}

/// Async function to detect WAF/CDN from a URL
pub async fn detect_waf_from_url(url: &str) -> Result<CDNType, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .get(url)
        .header("User-Agent", "Mozilla/5.0 (compatible; NetProwl/1.0)")
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    Ok(detect_waf_cdn(&headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_waf_cdn_cloudflare() {
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "abc123xyz".to_string());

        assert_eq!(detect_waf_cdn(&headers), CDNType::Cloudflare);
    }

    #[test]
    fn test_detect_waf_cdn_akamai() {
        let mut headers = HashMap::new();
        headers.insert("x-akamai-request-id".to_string(), "req123".to_string());

        assert_eq!(detect_waf_cdn(&headers), CDNType::Akamai);
    }

    #[test]
    fn test_detect_waf_cdn_aliyun() {
        let mut headers = HashMap::new();
        headers.insert("x-powered-by".to_string(), "Aliyun".to_string());

        assert_eq!(detect_waf_cdn(&headers), CDNType::AliyunWAF);
    }

    #[test]
    fn test_detect_waf_cdn_tencent() {
        let mut headers = HashMap::new();
        headers.insert("x-tencent-cn".to_string(), "1".to_string());

        assert_eq!(detect_waf_cdn(&headers), CDNType::TencentWAF);
    }

    #[test]
    fn test_detect_waf_cdn_none() {
        let headers = HashMap::new();
        assert_eq!(detect_waf_cdn(&headers), CDNType::None);
    }

    #[test]
    fn test_cdntype_as_str() {
        assert_eq!(CDNType::Cloudflare.as_str(), "Cloudflare");
        assert_eq!(CDNType::Akamai.as_str(), "Akamai");
        assert_eq!(CDNType::AliyunWAF.as_str(), "Aliyun WAF");
        assert_eq!(CDNType::TencentWAF.as_str(), "Tencent WAF");
        assert_eq!(CDNType::None.as_str(), "None");
    }

    #[test]
    fn test_cloudflare_detection() {
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "abc123xyz".to_string());

        let waf = identify_waf(&headers, "", 200);
        assert_eq!(waf, WafType::Cloudflare);

        let cdn = identify_cdn(&headers, "");
        assert_eq!(cdn, CdnProvider::Cloudflare);
    }

    #[test]
    fn test_aliyun_waf_detection() {
        let mut headers = HashMap::new();
        headers.insert("x-powered-by".to_string(), "Aliyun".to_string());

        let waf = identify_waf(&headers, "", 200);
        assert_eq!(waf, WafType::Aliyun);
    }

    #[test]
    fn test_tencent_waf_detection() {
        let mut headers = HashMap::new();
        headers.insert("x-tencent-cn".to_string(), "1".to_string());

        let waf = identify_waf(&headers, "", 200);
        assert_eq!(waf, WafType::Tencent);
    }

    #[test]
    fn test_bt_panel_detection() {
        let body = "抱歉，您的请求已被拦截，bt-waf";
        let waf = identify_waf(&HashMap::new(), body, 403);
        assert_eq!(waf, WafType::BtPanel);
    }

    #[test]
    fn test_analyze_returns_valid_structure() {
        let result = analyze_waf_cdn(
            "1.1.1.1",
            HashMap::new(),
            String::new(),
            200
        );
        assert_eq!(result.ip, "1.1.1.1");
        assert!(result.evidence.len() >= 1);
    }
}
