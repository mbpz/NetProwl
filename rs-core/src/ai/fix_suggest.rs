use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::security::report::SecurityRisk;

/// Fix suggestion for a security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixSuggestion {
    pub finding_id: String,
    pub explanation: String,
    pub steps: Vec<String>,
    pub verification: String,
    pub urgency: String,
}

/// Generate fix suggestion for a finding
pub fn generate_fix_suggestion(
    finding: &SecurityRisk,
    device_info: Option<&crate::types::Device>,
) -> FixSuggestion {
    let finding_type = finding.risk_type.to_lowercase();

    // Match by finding type and generate appropriate fix
    if finding_type.contains("default_cred") || finding_type.contains("weak_cred") {
        return fix_default_credentials(finding, device_info);
    }

    if finding_type.contains("noauth") || finding_type.contains("unauth") || finding_type.contains("unauthorized") {
        return fix_unauthorized_access(finding, device_info);
    }

    if finding_type.contains("tls") || finding_type.contains("ssl") || finding_type.contains("certificate") {
        return fix_tls_issues(finding, device_info);
    }

    if finding_type.contains("firmware") || finding_type.contains("eos") || finding_type.contains("eol") {
        return fix_firmware_eos(finding, device_info);
    }

    if finding_type.contains("http") || finding_type.contains("basic_auth") {
        return fix_http_auth(finding, device_info);
    }

    if finding_type.contains("redis") || finding_type.contains("memcached") || finding_type.contains("mongodb") {
        return fix_database_security(finding, device_info);
    }

    if finding_type.contains("docker") || finding_type.contains("kubernetes") || finding_type.contains("k8s") {
        return fix_container_security(finding, device_info);
    }

    // Default generic fix
    generic_fix(finding, device_info)
}

/// Fix default credentials issue
fn fix_default_credentials(finding: &SecurityRisk, _device_info: Option<&crate::types::Device>) -> FixSuggestion {
    let brand = detect_brand(&finding.title, &finding.description);

    let steps = match brand.as_str() {
        "D-Link" => vec![
            "1. 访问 http://{}/admin 或 http://{}:8080".to_string(),
            "2. 默认用户名admin，密码为空或admin".to_string(),
            "3. 进入系统设置 -> 管理员设置".to_string(),
            "4. 修改管理密码为强密码（12位以上）".to_string(),
            "5. 保存并重新登录验证".to_string(),
        ],
        "TP-Link" => vec![
            "1. 访问 http://{}:8080 或 http://tplinkwifi.net".to_string(),
            "2. 用户名admin，密码admin或空".to_string(),
            "3. 进入管理 -> 修改密码".to_string(),
            "4. 设置新密码并应用".to_string(),
        ],
        "MikroTik" => vec![
            "1. 使用Winbox或SSH连接路由器".to_string(),
            "2. 默认用户名admin，密码为空".to_string(),
            "3. 进入 System -> Users".to_string(),
            "4. 修改admin密码或创建新管理账户".to_string(),
            "5. 删除默认账户".to_string(),
        ],
        "Huawei" => vec![
            "1. 访问 http://{} 或 http://192.168.1.1".to_string(),
            "2. 默认用户名admin，密码通常印在设备标签上".to_string(),
            "3. 进入设置 -> 用户管理".to_string(),
            "4. 修改密码".to_string(),
        ],
        _ => vec![
            "1. 查找设备默认用户名密码（通常在设备底部标签或说明书）".to_string(),
            "2. 访问设备管理界面".to_string(),
            "3. 进入账户设置页面".to_string(),
            "4. 修改为强密码（12位以上，包含大小写、数字、特殊字符）".to_string(),
            "5. 记录新密码并妥善保管".to_string(),
        ],
    };

    FixSuggestion {
        finding_id: finding.risk_type.clone(),
        explanation: format!(
            "设备使用默认或弱密码，攻击者可利用此漏洞直接登录管理后台。\
            {} 品牌的设备历史上曾多次因默认密码被攻击。",
            brand
        ),
        steps,
        verification: "使用新密码尝试登录，确保旧密码无法使用".to_string(),
        urgency: "紧急".to_string(),
    }
}

/// Fix unauthorized access issue
fn fix_unauthorized_access(finding: &SecurityRisk, _device_info: Option<&crate::types::Device>) -> FixSuggestion {
    let service = if finding.risk_type.contains("redis") {
        "Redis"
    } else if finding.risk_type.contains("mongodb") {
        "MongoDB"
    } else if finding.risk_type.contains("elasticsearch") {
        "Elasticsearch"
    } else if finding.risk_type.contains("docker") {
        "Docker"
    } else if finding.risk_type.contains("memcached") {
        "Memcached"
    } else {
        "该服务"
    };

    FixSuggestion {
        finding_id: finding.risk_type.clone(),
        explanation: format!(
            "{} 服务未设置访问认证，任何人都可直接访问并操作数据。\
            这可能导致数据泄露、数据篡改或进一步攻击。",
            service
        ),
        steps: vec![
            format!("1. 为 {} 服务设置认证密码", service),
            "2. 在配置文件中设置 requirepass 参数（Redis）或启动参数（MongoDB）".to_string(),
            "3. 重启服务使配置生效".to_string(),
            "4. 更新所有连接此服务的应用程序的连接字符串".to_string(),
            "5. 在防火墙中限制访问来源，仅允许必要 IP 访问".to_string(),
        ],
        verification: "尝试无密码连接服务，确认连接被拒绝".to_string(),
        urgency: "紧急".to_string(),
    }
}

/// Fix TLS/SSL issues
fn fix_tls_issues(finding: &SecurityRisk, _device_info: Option<&crate::types::Device>) -> FixSuggestion {
    let issue_type = if finding.description.contains("过期") {
        "证书已过期"
    } else if finding.description.contains("自签名") {
        "使用自签名证书"
    } else if finding.description.contains("弱") {
        "使用弱密码套件"
    } else {
        "TLS配置不当"
    };

    FixSuggestion {
        finding_id: finding.risk_type.clone(),
        explanation: format!(
            "TLS/SSL配置存在问题（{}），可能导致中间人攻击。\
            攻击者可利用此漏洞截获或篡改通信内容。",
            issue_type
        ),
        steps: vec![
            "1. 获取受信任CA签发的SSL证书（如Let's Encrypt免费证书）".to_string(),
            "2. 配置Web服务器使用正式证书".to_string(),
            "3. 禁用SSLv2、SSLv3、TLS 1.0、1.1".to_string(),
            "4. 仅启用TLS 1.2或更高版本".to_string(),
            "5. 使用强密码套件（ECDHE-RSA-AES256-GCM-SHA384等）".to_string(),
        ],
        verification: "使用SSL Labs等工具在线检测，或使用openssl测试: openssl s_client -connect IP:port -tls1_2".to_string(),
        urgency: "高".to_string(),
    }
}

/// Fix firmware end-of-support issue
fn fix_firmware_eos(finding: &SecurityRisk, device_info: Option<&crate::types::Device>) -> FixSuggestion {
    let device_name = device_info
        .and_then(|d| d.hostname.clone())
        .unwrap_or_else(|| finding.ip.clone());

    FixSuggestion {
        finding_id: finding.risk_type.clone(),
        explanation: format!(
            "{} 运行的固件已超过支持期限（End-of-Life）。\
            厂商不再提供安全更新，存在已知漏洞被利用的风险。",
            device_name
        ),
        steps: vec![
            "1. 访问厂商官网，查找对应型号的最新固件".to_string(),
            "2. 下载固件文件（注意校验文件完整性）".to_string(),
            "3. 备份当前配置".to_string(),
            "4. 进入设备管理界面，上传新固件".to_string(),
            "5. 重启设备并验证功能正常".to_string(),
            "6. 恢复备份配置".to_string(),
        ],
        verification: "在设备管理界面确认固件版本为最新，检查厂商安全公告确认漏洞已修复".to_string(),
        urgency: "高".to_string(),
    }
}

/// Fix HTTP authentication issues
fn fix_http_auth(finding: &SecurityRisk, _device_info: Option<&crate::types::Device>) -> FixSuggestion {
    FixSuggestion {
        finding_id: finding.risk_type.clone(),
        explanation: "HTTP服务使用了弱认证机制，攻击者可尝试暴力破解或绕过认证。".to_string(),
        steps: vec![
            "1. 使用HTTPS替代HTTP".to_string(),
            "2. 实现强密码策略（最少8位，建议12位以上）".to_string(),
            "3. 限制登录尝试次数（如5次后锁定15分钟）".to_string(),
            "4. 启用账户锁定机制".to_string(),
            "5. 考虑使用双因素认证（2FA）".to_string(),
            "6. 定期审计登录日志".to_string(),
        ],
        verification: "尝试使用常见弱密码登录，确认被拒绝；检查登录日志无异常尝试".to_string(),
        urgency: "中".to_string(),
    }
}

/// Fix database security issues
fn fix_database_security(finding: &SecurityRisk, _device_info: Option<&crate::types::Device>) -> FixSuggestion {
    let db_type = if finding.risk_type.contains("redis") {
        "Redis"
    } else if finding.risk_type.contains("mongodb") {
        "MongoDB"
    } else if finding.risk_type.contains("elasticsearch") {
        "Elasticsearch"
    } else if finding.risk_type.contains("memcached") {
        "Memcached"
    } else {
        "数据库"
    };

    FixSuggestion {
        finding_id: finding.risk_type.clone(),
        explanation: format!(
            "{} 服务暴露且无认证保护，攻击者可访问、修改或删除所有数据。",
            db_type
        ),
        steps: vec![
            format!("1. 为 {} 设置强密码认证", db_type),
            "2. 绑定监听地址为127.0.0.1或内网IP，禁止公网访问".to_string(),
            "3. 在防火墙中限制来源IP".to_string(),
            "4. 启用日志记录，方便事后审计".to_string(),
            "5. 定期备份数据".to_string(),
        ],
        verification: "从外部IP尝试连接，确认被拒绝或需要认证".to_string(),
        urgency: "紧急".to_string(),
    }
}

/// Fix container platform security issues
fn fix_container_security(finding: &SecurityRisk, _device_info: Option<&crate::types::Device>) -> FixSuggestion {
    let platform = if finding.risk_type.contains("docker") {
        "Docker"
    } else if finding.risk_type.contains("kubernetes") {
        "Kubernetes"
    } else {
        "容器平台"
    };

    FixSuggestion {
        finding_id: finding.risk_type.clone(),
        explanation: format!(
            "{} API未授权访问，攻击者可创建容器、挂载主机目录、获取主机权限。\
            这可能导致完整的宿主机系统被攻陷。",
            platform
        ),
        steps: vec![
            format!("1. 在 {} 启动参数中添加 --authfile 或配置认证", platform),
            "2. 限制API监听地址为本地Unix socket或内网IP".to_string(),
            "3. 配置TLS双向认证".to_string(),
            "4. 在防火墙中屏蔽公网API端口".to_string(),
            "5. 使用更安全的编排工具替代直接API调用".to_string(),
        ],
        verification: "从外部IP尝试访问API，确认需要证书认证".to_string(),
        urgency: "紧急".to_string(),
    }
}

/// Generic fix for unknown finding types
fn generic_fix(finding: &SecurityRisk, _device_info: Option<&crate::types::Device>) -> FixSuggestion {
    FixSuggestion {
        finding_id: finding.risk_type.clone(),
        explanation: format!("发现安全问题: {}", finding.description),
        steps: vec![
            "1. 确认问题的具体原因和影响范围".to_string(),
            "2. 查看厂商安全公告或相关CVE".to_string(),
            "3. 制定修复计划".to_string(),
            "4. 在测试环境中验证修复方案".to_string(),
            "5. 在生产环境中实施修复".to_string(),
        ],
        verification: "修复后重新扫描确认问题已解决".to_string(),
        urgency: "中".to_string(),
    }
}

/// Detect device brand from title and description
fn detect_brand(title: &str, description: &str) -> String {
    let text = format!("{} {}", title, description).to_lowercase();

    if text.contains("d-link") || text.contains("dlink") {
        "D-Link".to_string()
    } else if text.contains("tp-link") || text.contains("tplink") {
        "TP-Link".to_string()
    } else if text.contains("mikrotik") || text.contains("routeros") {
        "MikroTik".to_string()
    } else if text.contains("huawei") {
        "Huawei".to_string()
    } else if text.contains("netgear") {
        "Netgear".to_string()
    } else if text.contains("asus") {
        "Asus".to_string()
    } else if text.contains("tenda") {
        "Tenda".to_string()
    } else if text.contains(" mercury") || text.contains("水星") {
        "水星(Mercury)".to_string()
    } else {
        "未知".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_suggestion_for_default_creds() {
        let finding = SecurityRisk {
            ip: "192.168.1.1".to_string(),
            port: Some(80),
            risk_type: "default_creds".to_string(),
            title: "D-Link路由器默认密码".to_string(),
            description: "设备使用出厂默认密码".to_string(),
            cvss_score: None,
            evidence: HashMap::new(),
            risk_level: super::super::super::security::report::RiskLevel::High,
        };

        let suggestion = generate_fix_suggestion(&finding, None);
        assert_eq!(suggestion.urgency, "紧急");
        assert!(!suggestion.steps.is_empty());
    }

    #[test]
    fn test_fix_suggestion_for_redis_noauth() {
        let finding = SecurityRisk {
            ip: "192.168.1.100".to_string(),
            port: Some(6379),
            risk_type: "redis_noauth".to_string(),
            title: "Redis未授权访问".to_string(),
            description: "Redis允许无密码访问".to_string(),
            cvss_score: None,
            evidence: HashMap::new(),
            risk_level: super::super::super::security::report::RiskLevel::Critical,
        };

        let suggestion = generate_fix_suggestion(&finding, None);
        assert_eq!(suggestion.urgency, "紧急");
        assert!(suggestion.explanation.contains("Redis"));
    }

    #[test]
    fn test_brand_detection() {
        assert_eq!(detect_brand("D-Link router", ""), "D-Link");
        assert_eq!(detect_brand("TP-Link camera", ""), "TP-Link");
        assert_eq!(detect_brand("unknown device", ""), "未知");
    }
}
