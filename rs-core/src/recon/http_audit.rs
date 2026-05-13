use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HTTP security header audit report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSecurityReport {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub missing: Vec<String>,
    pub weak: Vec<String>,
    pub score: char,
    pub recommendations: Vec<String>,
}

/// Security header names
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityHeader {
    StrictTransportSecurity,
    ContentSecurityPolicy,
    XFrameOptions,
    XContentTypeOptions,
    ReferrerPolicy,
    PermissionsPolicy,
}

impl SecurityHeader {
    pub fn name(&self) -> &'static str {
        match self {
            SecurityHeader::StrictTransportSecurity => "Strict-Transport-Security",
            SecurityHeader::ContentSecurityPolicy => "Content-Security-Policy",
            SecurityHeader::XFrameOptions => "X-Frame-Options",
            SecurityHeader::XContentTypeOptions => "X-Content-Type-Options",
            SecurityHeader::ReferrerPolicy => "Referrer-Policy",
            SecurityHeader::PermissionsPolicy => "Permissions-Policy",
        }
    }
}

/// Fetch URL and analyze HTTP security headers
pub fn audit_http_security(url: &str) -> Result<HttpSecurityReport, String> {
    // Fetch the URL
    let resp = reqwest::blocking::Client::new()
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("Failed to fetch URL: {}", e))?;

    let headers: HashMap<String, String> = resp.headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let report = analyze_security_headers(url, headers);
    Ok(report)
}

/// Analyze security headers without fetching (for when we already have headers)
pub fn analyze_security_headers(url: &str, headers: HashMap<String, String>) -> HttpSecurityReport {
    let mut missing = Vec::new();
    let mut weak = Vec::new();
    let mut recommendations = Vec::new();
    let mut score: u32 = 100;

    // Check Strict-Transport-Security
    let hsts_header = SecurityHeader::StrictTransportSecurity.name();
    if let Some(value) = headers.get(hsts_header) {
        // Check max-age >= 31536000 (1 year)
        if let Some(max_age) = extract_max_age(value) {
            if max_age < 31536000 {
                weak.push(format!("{}: max-age is {} (should be >= 31536000)", hsts_header, max_age));
                score = score.saturating_sub(15);
                recommendations.push(format!("将 {} 的 max-age 设置为至少 31536000 秒（1年）", hsts_header));
            }
        }
        // Check for includeSubDomains
        if !value.contains("includeSubDomains") {
            weak.push(format!("{}: missing includeSubDomains directive", hsts_header));
            score = score.saturating_sub(5);
            recommendations.push("建议在 Strict-Transport-Security 中添加 includeSubDomains 指令".to_string());
        }
    } else {
        missing.push(hsts_header.to_string());
        score = score.saturating_sub(20);
        recommendations.push("添加 Strict-Transport-Security 头，建议值: max-age=31536000; includeSubDomains".to_string());
    }

    // Check Content-Security-Policy
    let csp_header = SecurityHeader::ContentSecurityPolicy.name();
    if let Some(value) = headers.get(csp_header) {
        if value.contains("unsafe-inline") || value.contains("unsafe-eval") {
            weak.push(format!("{}: contains unsafe-inline or unsafe-eval", csp_header));
            score = score.saturating_sub(20);
            recommendations.push("从 Content-Security-Policy 中移除 unsafe-inline 和 unsafe-eval".to_string());
        }
    } else {
        missing.push(csp_header.to_string());
        score = score.saturating_sub(20);
        recommendations.push("添加 Content-Security-Policy 头，限制脚本来源和内联脚本".to_string());
    }

    // Check X-Frame-Options
    let xfo_header = SecurityHeader::XFrameOptions.name();
    if let Some(value) = headers.get(xfo_header) {
        if value != "DENY" && value != "SAMEORIGIN" {
            weak.push(format!("{}: invalid value '{}', should be DENY or SAMEORIGIN", xfo_header, value));
            score = score.saturating_sub(10);
        }
    } else {
        missing.push(xfo_header.to_string());
        score = score.saturating_sub(15);
        recommendations.push("添加 X-Frame-Options: DENY 或 SAMEORIGIN 防止点击劫持".to_string());
    }

    // Check X-Content-Type-Options
    let xcto_header = SecurityHeader::XContentTypeOptions.name();
    if let Some(value) = headers.get(xcto_header) {
        if value != "nosniff" {
            weak.push(format!("{}: invalid value '{}', should be nosniff", xcto_header, value));
            score = score.saturating_sub(5);
        }
    } else {
        missing.push(xcto_header.to_string());
        score = score.saturating_sub(10);
        recommendations.push("添加 X-Content-Type-Options: nosniff 防止MIME类型嗅探".to_string());
    }

    // Check Referrer-Policy
    let rp_header = SecurityHeader::ReferrerPolicy.name();
    if let Some(value) = headers.get(rp_header) {
        let valid_values = [
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ];
        if !valid_values.contains(&value.as_str()) {
            weak.push(format!("{}: invalid value '{}'", rp_header, value));
            score = score.saturating_sub(5);
        } else if value != "strict-origin-when-cross-origin" && value != "no-referrer-when-downgrade" {
            weak.push(format!("{}: value '{}' is not the recommended strictest option", rp_header, value));
            score = score.saturating_sub(5);
        }
    } else {
        missing.push(rp_header.to_string());
        score = score.saturating_sub(10);
        recommendations.push("添加 Referrer-Policy: strict-origin-when-cross-origin 保护敏感URL".to_string());
    }

    // Check Permissions-Policy
    let pp_header = SecurityHeader::PermissionsPolicy.name();
    if headers.get(pp_header).is_none() {
        missing.push(pp_header.to_string());
        score = score.saturating_sub(10);
        recommendations.push("添加 Permissions-Policy 头，限制浏览器功能（如摄像头、麦克风）".to_string());
    }

    // Calculate final grade
    let grade = match score {
        90..=100 => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        40..=59 => 'E',
        _ => 'F',
    };

    if missing.is_empty() && weak.is_empty() {
        recommendations.push("安全 headers 配置良好，继续保持！".to_string());
    }

    HttpSecurityReport {
        url: url.to_string(),
        headers,
        missing,
        weak,
        score: grade,
        recommendations,
    }
}

/// Extract max-age value from HSTS header
fn extract_max_age(value: &str) -> Option<u64> {
    for directive in value.split(';') {
        let directive = directive.trim();
        if directive.starts_with("max-age=") {
            return directive[8..].parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_calculation_with_no_headers() {
        let headers = HashMap::new();
        let report = analyze_security_headers("https://example.com", headers);
        assert_eq!(report.missing.len(), 6); // All headers missing
        assert!(report.recommendations.len() >= 6);
    }

    #[test]
    fn test_score_calculation_with_good_headers() {
        let mut headers = HashMap::new();
        headers.insert("Strict-Transport-Security".to_string(), "max-age=31536000; includeSubDomains".to_string());
        headers.insert("Content-Security-Policy".to_string(), "default-src 'self'".to_string());
        headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        headers.insert("Referrer-Policy".to_string(), "strict-origin-when-cross-origin".to_string());
        headers.insert("Permissions-Policy".to_string(), "geolocation=()".to_string());

        let report = analyze_security_headers("https://example.com", headers);
        assert_eq!(report.score, 'A');
        assert!(report.missing.is_empty());
        assert!(report.weak.is_empty());
    }

    #[test]
    fn test_hsts_max_age_extraction() {
        assert_eq!(extract_max_age("max-age=31536000"), Some(31536000));
        assert_eq!(extract_max_age("max-age=0"), Some(0));
        assert_eq!(extract_max_age("max-age=31536000; includeSubDomains"), Some(31536000));
        assert_eq!(extract_max_age("includeSubDomains"), None);
    }

    #[test]
    fn test_weak_csp_detection() {
        let mut headers = HashMap::new();
        headers.insert("Content-Security-Policy".to_string(), "unsafe-inline 'unsafe-eval'".to_string());

        let report = analyze_security_headers("https://example.com", headers);
        assert!(report.weak.iter().any(|w| w.contains("unsafe-inline")));
    }
}
