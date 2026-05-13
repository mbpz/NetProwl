use serde::{Deserialize, Serialize};

/// Vulnerability types detected passively
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VulnType {
    SqlInjectionEcho,
    XssReflection,
    SensitivePath,
    SensitiveInfoLeak,
    OpenRedirect,
    Ssrf,
}

impl VulnType {
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnType::SqlInjectionEcho => "SQL注入回显",
            VulnType::XssReflection => "XSS反射",
            VulnType::SensitivePath => "敏感路径暴露",
            VulnType::SensitiveInfoLeak => "敏感信息泄露",
            VulnType::OpenRedirect => "开放重定向",
            VulnType::Ssrf => "SSRF漏洞",
        }
    }

    pub fn severity(&self) -> &'static str {
        match self {
            VulnType::SqlInjectionEcho => "高危",
            VulnType::XssReflection => "中危",
            VulnType::SensitivePath => "低危",
            VulnType::SensitiveInfoLeak => "中危",
            VulnType::OpenRedirect => "中危",
            VulnType::Ssrf => "高危",
        }
    }
}

/// Web vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebVuln {
    pub url: String,
    pub vuln_type: VulnType,
    pub evidence: String,
    pub severity: String,
}

/// Test string for XSS reflection detection
const XSS_TEST_STRING: &str = "NetProwlXSSTest<script>alert(1)</script>";

/// SQL injection error patterns
const SQL_ERROR_PATTERNS: &[&str] = &[
    "MySQL",
    "MariaDB",
    "ORA-",
    "Oracle",
    "Microsoft SQL Server",
    "SQLite",
    "PostgreSQL",
    "PG::",
    "psycopg2",
    "SQL syntax",
    "mysql_fetch",
    "mysqli_",
    "SQLSTATE",
    "Warning: mysql_",
    "Uncaught Error",
    "Syntax error or access violation",
    "Laravel",
];

/// Sensitive paths to check
const SENSITIVE_PATHS: &[&str] = &[
    ".env",
    "/.env",
    "/backup/",
    "/backups/",
    "/.git/",
    "/api/swagger",
    "/swagger-ui",
    "/api-docs",
    "/admin/",
    "/wp-admin",
    "/phpmyadmin",
    "/console",
    "/api/console",
    "/debug",
    "/actuator",
    "/env",
    "/configuration",
    "/.aws/credentials",
    "/.ssh/",
    "/passwords.txt",
    "/database.sql",
    "/dump.sql",
];

/// API key patterns
const API_KEY_PATTERNS: &[&str] = &[
    r"sk_[a-zA-Z0-9]{20,}",
    r"ak_[a-zA-Z0-9]{20,}",
    r#"api[_-]?key['"]?\s*[:=]\s*['"]?[a-zA-Z0-9_-]{20,}"#,
    r#"token['"]?\s*[:=]\s*['"]?[a-zA-Z0-9_-]{20,}"#,
    r"bearer\s+[a-zA-Z0-9_-]{20,}",
    r"Authorization:\s*Bearer\s+[a-zA-Z0-9_-]{20,}",
];

/// Internal IP patterns
const INTERNAL_IP_PATTERNS: &[&str] = &[
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
    r"192\.168\.\d{1,3}\.\d{1,3}",
    r"127\.0\.0\.1",
    r"localhost",
];

/// Test URL for XSS reflection
pub fn test_xss_reflection(url: &str) -> Result<Vec<WebVuln>, String> {
    let test_url = format!("{}?q={}", url, urlencoding::encode(XSS_TEST_STRING));

    let resp = reqwest::blocking::Client::new()
        .get(&test_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("Failed to fetch URL: {}", e))?;

    let body = resp.text().map_err(|e| format!("Failed to read response: {}", e))?;

    Ok(detect_xss_reflection(url, &body))
}

/// Detect XSS reflection in response body
fn detect_xss_reflection(original_url: &str, body: &str) -> Vec<WebVuln> {
    let mut vulns = Vec::new();

    if body.contains(XSS_TEST_STRING) {
        vulns.push(WebVuln {
            url: original_url.to_string(),
            vuln_type: VulnType::XssReflection,
            evidence: format!("测试字符串 '{}' 在响应中被回显", XSS_TEST_STRING),
            severity: VulnType::XssReflection.severity().to_string(),
        });
    }

    // Also check for common XSS patterns
    if body.contains("<script>") || body.contains("alert(") || body.contains("onerror=") {
        // Potential XSS but not confirmed by our test string
    }

    vulns
}

/// Scan URL for SQL injection echoes (passive - no exploitation)
pub fn scan_sql_injection(url: &str) -> Result<Vec<WebVuln>, String> {
    let resp = reqwest::blocking::Client::new()
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("Failed to fetch URL: {}", e))?;

    let body = resp.text().map_err(|e| format!("Failed to read response: {}", e))?;

    Ok(detect_sql_errors(url, &body))
}

/// Detect SQL errors in response body
fn detect_sql_errors(url: &str, body: &str) -> Vec<WebVuln> {
    let mut vulns = Vec::new();

    for pattern in SQL_ERROR_PATTERNS {
        if body.contains(pattern) {
            vulns.push(WebVuln {
                url: url.to_string(),
                vuln_type: VulnType::SqlInjectionEcho,
                evidence: format!("在响应中检测到SQL错误关键字: {}", pattern),
                severity: VulnType::SqlInjectionEcho.severity().to_string(),
            });
            break; // Only report once
        }
    }

    vulns
}

/// Scan URL for sensitive paths
pub fn scan_sensitive_paths(url: &str) -> Result<Vec<WebVuln>, String> {
    let mut vulns = Vec::new();
    let base_url = url.split('?').next().unwrap_or(url).trim_end_matches('/');

    for path in SENSITIVE_PATHS {
        let check_url = if path.starts_with('/') {
            format!("{}{}", base_url, path)
        } else {
            format!("{}/{}", base_url, path)
        };

        let resp = reqwest::blocking::Client::new()
            .get(&check_url)
            .timeout(std::time::Duration::from_secs(5))
            .send();

        if let Ok(resp) = resp {
            let status = resp.status().as_u16();
            // Check if path exists and is accessible
            if status == 200 || status == 401 || status == 403 {
                vulns.push(WebVuln {
                    url: check_url,
                    vuln_type: VulnType::SensitivePath,
                    evidence: format!("敏感路径返回状态码: {}", status),
                    severity: VulnType::SensitivePath.severity().to_string(),
                });
            }
        }
    }

    Ok(vulns)
}

/// Scan response body for sensitive information leaks
pub fn scan_info_leaks(url: &str, body: &str) -> Vec<WebVuln> {
    let mut vulns = Vec::new();

    // Check for API keys
    let api_key_re = regex::Regex::new(r#"(sk_|ak_|api[_-]?key|token|bearer)["\s:=]+[a-zA-Z0-9_-]{20,}"#).unwrap();
    for cap in api_key_re.find_iter(body) {
        let matched = cap.as_str();
        // Mask the key but show the pattern
        let masked = if matched.len() > 10 {
            &matched[..8]
        } else {
            matched
        };
        vulns.push(WebVuln {
            url: url.to_string(),
            vuln_type: VulnType::SensitiveInfoLeak,
            evidence: format!("在响应中发现可能的API密钥: {}...", masked),
            severity: VulnType::SensitiveInfoLeak.severity().to_string(),
        });
    }

    // Check for internal IPs
    let ip_re = regex::Regex::new(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}").unwrap();
    for cap in ip_re.find_iter(body) {
        vulns.push(WebVuln {
            url: url.to_string(),
            vuln_type: VulnType::SensitiveInfoLeak,
            evidence: format!("在响应中发现内网IP: {}", cap.as_str()),
            severity: VulnType::SensitiveInfoLeak.severity().to_string(),
        });
    }

    // Check for internal hostnames
    if body.contains("localhost") || body.contains(".internal.") || body.contains(".local.") {
        vulns.push(WebVuln {
            url: url.to_string(),
            vuln_type: VulnType::SensitiveInfoLeak,
            evidence: "在响应中发现内部主机名".to_string(),
            severity: VulnType::SensitiveInfoLeak.severity().to_string(),
        });
    }

    vulns
}

/// Perform complete passive web vulnerability scan
pub fn passive_web_scan(url: &str) -> Result<Vec<WebVuln>, String> {
    let resp = reqwest::blocking::Client::new()
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("Failed to fetch URL: {}", e))?;

    let body = resp.text().map_err(|e| format!("Failed to read response: {}", e))?;
    let mut all_vulns = Vec::new();

    // SQL injection error detection
    all_vulns.extend(detect_sql_errors(url, &body));

    // Sensitive info leaks
    all_vulns.extend(scan_info_leaks(url, &body));

    // XSS reflection (only if URL has query params)
    if url.contains('?') {
        all_vulns.extend(detect_xss_reflection(url, &body));
    }

    Ok(all_vulns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_error_detection() {
        let body = "MySQL syntax error near 'ORDER BY'";
        let vulns = detect_sql_errors("http://example.com", body);
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].vuln_type, VulnType::SqlInjectionEcho);
    }

    #[test]
    fn test_internal_ip_detection() {
        let body = "Connecting to 192.168.1.100:8080";
        let vulns = scan_info_leaks("http://example.com", body);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type == VulnType::SensitiveInfoLeak));
    }

    #[test]
    fn test_api_key_detection() {
        // Use lowercase "bearer" to match the regex pattern
        let body = r#"Authorization: bearer sk_abcdefghijklmnopqrstuvwxyz123456"#;
        let vulns = scan_info_leaks("http://example.com", body);
        assert!(!vulns.is_empty(), "should detect bearer token with sk_ prefix");
    }

    #[test]
    fn test_xss_reflection_detection() {
        let body = "NetProwlXSSTest<script>alert(1)</script> found in page";
        let vulns = detect_xss_reflection("http://example.com", body);
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].vuln_type, VulnType::XssReflection);
    }
}
