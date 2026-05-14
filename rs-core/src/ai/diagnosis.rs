use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::time::Duration;

/// Device in network diagnosis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosisDevice {
    pub ip: String,
    pub hostname: Option<String>,
    pub device_type: String,
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,
}

/// Critical security issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalIssue {
    pub ip: String,
    pub title: String,
    pub description: String,
    pub severity: String,
}

/// Medium security issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediumIssue {
    pub ip: String,
    pub title: String,
    pub description: String,
    pub severity: String,
}

/// Diagnosis report in natural language
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosisReport {
    pub summary: String,
    pub critical_issues: Vec<CriticalIssue>,
    pub medium_issues: Vec<MediumIssue>,
    pub recommendations: Vec<String>,
}

/// Result of DeepSeek vulnerability diagnosis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosisResult {
    pub summary: String,
    pub risk_level: String,
    pub immediate_actions: Vec<String>,
    pub technical_details: String,
}

/// Generate Chinese natural language diagnosis report
pub fn diagnose_network(
    devices: Vec<DiagnosisDevice>,
    findings: Vec<super::super::security::report::SecurityRisk>,
) -> DiagnosisReport {
    let mut critical_issues = Vec::new();
    let mut medium_issues = Vec::new();

    // Categorize findings by severity
    for finding in &findings {
        match finding.risk_level {
            super::super::security::report::RiskLevel::Critical => {
                critical_issues.push(CriticalIssue {
                    ip: finding.ip.clone(),
                    title: finding.title.clone(),
                    description: finding.description.clone(),
                    severity: "严重".to_string(),
                });
            },
            super::super::security::report::RiskLevel::High => {
                medium_issues.push(MediumIssue {
                    ip: finding.ip.clone(),
                    title: finding.title.clone(),
                    description: finding.description.clone(),
                    severity: "高危".to_string(),
                });
            },
            super::super::security::report::RiskLevel::Medium => {
                medium_issues.push(MediumIssue {
                    ip: finding.ip.clone(),
                    title: finding.title.clone(),
                    description: finding.description.clone(),
                    severity: "中危".to_string(),
                });
            },
            _ => {},
        };
    }

    // Generate natural language summary
    let summary = generate_summary(&devices, &critical_issues, &medium_issues);

    // Generate recommendations
    let recommendations = generate_recommendations(&critical_issues, &medium_issues, &devices);

    DiagnosisReport {
        summary,
        critical_issues,
        medium_issues,
        recommendations,
    }
}

/// Generate Chinese summary
fn generate_summary(
    devices: &[DiagnosisDevice],
    critical: &[CriticalIssue],
    medium: &[MediumIssue],
) -> String {
    let device_count = devices.len();
    let critical_count = critical.len();
    let medium_count = medium.len();

    let mut summary = String::new();

    // Device summary
    if device_count == 0 {
        summary.push_str("未发现任何设备。");
    } else {
        summary.push_str(&format!("扫描范围内发现 {} 台设备。", device_count));

        // Group by device type
        let mut router_count = 0;
        let mut camera_count = 0;
        let mut server_count = 0;

        for device in devices {
            match device.device_type.to_lowercase().as_str() {
                "router" => router_count += 1,
                "camera" => camera_count += 1,
                "server" | "pc" => server_count += 1,
                _ => {},
            }
        }

        if router_count > 0 {
            summary.push_str(&format!(" 其中包括 {} 台路由器", router_count));
        }
        if camera_count > 0 {
            summary.push_str(&format!("、{} 台摄像头", camera_count));
        }
        if server_count > 0 {
            summary.push_str(&format!("、{} 台服务器/PC", server_count));
        }
    }

    // Security summary
    if critical_count == 0 && medium_count == 0 {
        summary.push_str(" 安全状况良好，未发现高危漏洞。");
    } else {
        if critical_count > 0 {
            summary.push_str(&format!(" 发现 {} 个严重安全问题需要立即处理", critical_count));
        }
        if medium_count > 0 {
            summary.push_str(&format!("、{} 个中危安全问题需要关注", medium_count));
        }
        summary.push('。');
    }

    summary
}

/// Generate prioritized recommendations in Chinese
fn generate_recommendations(
    critical: &[CriticalIssue],
    medium: &[MediumIssue],
    devices: &[DiagnosisDevice],
) -> Vec<String> {
    let mut recs = Vec::new();

    // Critical issues get top priority
    if !critical.is_empty() {
        recs.push("【紧急】立即修复以下严重安全问题:".to_string());

        for (i, issue) in critical.iter().enumerate() {
            recs.push(format!("{}. {} (IP: {}) - {}", i + 1, issue.title, issue.ip, issue.description));
        }
    }

    // Default credentials are common critical issues
    let has_default_creds = critical.iter().any(|i| i.title.contains("默认") || i.title.contains("弱密码"));
    if has_default_creds {
        recs.push("操作建议: 立即更改所有设备的默认密码，使用强密码（至少12位，包含大小写字母、数字和特殊字符）".to_string());
    }

    // Unauthorized access issues
    let has_unauth = critical.iter().any(|i| i.title.contains("未授权") || i.title.contains("无认证"));
    if has_unauth {
        recs.push("操作建议: 立即启用服务认证或配置防火墙规则，限制未授权访问".to_string());
    }

    // TLS issues
    let has_tls = medium.iter().any(|i| i.title.contains("TLS") || i.title.contains("SSL"));
    if has_tls {
        recs.push("操作建议: 更新TLS配置，禁用TLS 1.0/1.1，使用TLS 1.2或更高版本".to_string());
    }

    // Medium issues
    if !medium.is_empty() {
        recs.push("【建议】按优先级处理以下安全问题:".to_string());

        for (i, issue) in medium.iter().take(5).enumerate() {
            recs.push(format!("{}. {} (IP: {})", i + 1, issue.title, issue.ip));
        }
    }

    // General recommendations based on device types
    let has_cameras = devices.iter().any(|d| d.device_type.to_lowercase() == "camera");
    if has_cameras {
        recs.push("摄像头建议: 更改默认密码，禁用RTSP默认端口，启用HTTPS".to_string());
    }

    let has_routers = devices.iter().any(|d| d.device_type.to_lowercase() == "router");
    if has_routers {
        recs.push("路由器建议: 检查WAN口设置，关闭远程管理，启用防火墙".to_string());
    }

    if recs.is_empty() {
        recs.push("继续保持当前安全配置，定期更新固件和软件".to_string());
    }

    recs
}

/// Diagnose a specific vulnerability using DeepSeek AI
///
/// # Arguments
/// * `device_info` - Device information string (e.g., "Router TP-Link TL-WR841N, OpenWrt 21.02, IP 192.168.1.1")
/// * `vuln_id` - Vulnerability identifier (e.g., "CVE-2021-43297")
/// * `cvss` - CVSS score of the vulnerability
/// * `api_key` - DeepSeek API key
///
/// # Returns
/// * `Ok(DiagnosisResult)` - AI-generated diagnosis with summary, risk level, immediate actions, and technical details
/// * `Err(String)` - Error message if the API call fails
pub async fn diagnose_vulnerability(
    device_info: &str,
    vuln_id: &str,
    cvss: f32,
    api_key: &str,
) -> Result<DiagnosisResult, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Build prompt for vulnerability diagnosis
    let prompt = format!(
        r#"你是一位网络安全专家。请分析以下漏洞并给出诊断结果。

设备信息: {}

漏洞ID: {}
CVSS评分: {:.1}

请以JSON格式返回诊断结果，包含以下字段:
- summary: 简要总结（50字以内）
- risk_level: 风险等级（低危/中危/高危/严重）
- immediate_actions: 立即采取的措施列表（3-5条）
- technical_details: 技术细节和修复建议（100字以内）

直接返回JSON，不要包含markdown代码块标记。"#,
        device_info, vuln_id, cvss
    );

    let request_body = serde_json::json!({
        "model": "deepseek-chat",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.3,
        "max_tokens": 500
    });

    let response = client
        .post("https://api.deepseek.com/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("API returned error {}: {}", status, body));
    }

    let api_response: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {}", e))?;

    let content = api_response["choices"][0]["message"]["content"]
        .as_str()
        .ok_or_else(|| "Invalid API response format: missing content".to_string())?;

    // Parse the JSON response from DeepSeek
    let result: DiagnosisResult = serde_json::from_str(content)
        .map_err(|e| format!("Failed to parse diagnosis result: {}. Content: {}", e, content))?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnosis_report_structure() {
        let devices = vec![
            DiagnosisDevice {
                ip: "192.168.1.1".to_string(),
                hostname: Some("router.local".to_string()),
                device_type: "Router".to_string(),
                open_ports: vec![80, 443, 22],
                services: vec!["HTTP".to_string(), "HTTPS".to_string(), "SSH".to_string()],
            },
        ];

        let findings = vec![];

        let report = diagnose_network(devices, findings);
        assert!(!report.summary.is_empty());
    }

    #[test]
    fn test_critical_issues_categorized() {
        let devices = vec![];
        let findings = vec![
            super::super::super::security::report::SecurityRisk {
                ip: "192.168.1.100".to_string(),
                port: Some(6379),
                risk_type: "redis_noauth".to_string(),
                title: "Redis未授权访问".to_string(),
                description: "Redis允许无认证访问".to_string(),
                cvss_score: None,
                evidence: std::collections::HashMap::new(),
                risk_level: super::super::super::security::report::RiskLevel::Critical,
            },
        ];

        let report = diagnose_network(devices, findings);
        assert_eq!(report.critical_issues.len(), 1);
        assert_eq!(report.critical_issues[0].severity, "严重");
    }

    #[test]
    fn test_recommendations_include_specific_fixes() {
        let devices = vec![];
        let findings = vec![
            super::super::super::security::report::SecurityRisk {
                ip: "192.168.1.100".to_string(),
                port: Some(22),
                risk_type: "ssh_default_creds".to_string(),
                title: "SSH默认密码".to_string(),
                description: "SSH使用出厂默认密码".to_string(),
                cvss_score: None,
                evidence: std::collections::HashMap::new(),
                risk_level: super::super::super::security::report::RiskLevel::High,
            },
        ];

        let report = diagnose_network(devices, findings);
        assert!(!report.recommendations.is_empty());
    }
}
