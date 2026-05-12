use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

#[cfg(test)]
mod tests {
    use super::*;

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
