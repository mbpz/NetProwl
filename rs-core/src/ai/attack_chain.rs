use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Vulnerability for AI attack chain analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub ip: String,
    pub port: Option<u16>,
    pub vuln_type: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
}

/// Attack chain node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNode {
    pub id: String,
    pub finding_id: String,
    pub title: String,
    pub description: String,
    pub risk_level: String,
    pub prerequisites: Vec<String>,  // IDs of prerequisite nodes
}

/// Attack chain edge (relationship between findings)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEdge {
    pub from: String,
    pub to: String,
    pub relationship: String,  // "leads_to", "enables", "escalates_to"
}

/// Attack chain result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
    pub combined_risk: String,
    pub fix_priority: Vec<FixSuggestion>,
}

/// Priority fix suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixSuggestion {
    pub finding_id: String,
    pub title: String,
    pub action: String,
    pub effort: String,
}

/// Known attack chain patterns
/// Maps a vulnerability type to what it can lead to
const ATTACK_CHAIN_PATTERNS: &[(&str, &[(&str, &str)])] = &[
    // Redis attack chain
    ("redis_noauth", &[
        ("redis_slaveof", "Redis slaveof enables command redirection"),
        ("redis_write_key", "Write arbitrary keys for code execution"),
        ("ssh_key_write", "Write SSH authorized_keys for persistence"),
        ("ssh_access", "Gain SSH access to system"),
    ]),
    // Elasticsearch attack chain
    ("elasticsearch_noauth", &[
        ("elasticsearch_write", "Write documents to any index"),
        ("elasticsearch_read", "Read sensitive data from indices"),
    ]),
    // MongoDB attack chain
    ("mongodb_noauth", &[
        ("mongodb_read", "Read any database"),
        ("mongodb_write", "Write to databases"),
    ]),
    // Docker API attack chain
    ("docker_api_noauth", &[
        ("docker_container_create", "Create container with host access"),
        ("docker_escape", "Escape container to host"),
        ("host_compromise", "Full host compromise"),
    ]),
    // Kubernetes API attack chain
    ("kubernetes_noauth", &[
        ("kubernetes_secret_read", "Read secrets from Kubernetes"),
        ("kubernetes_pod_create", "Create privileged pod"),
        ("cluster_compromise", "Full cluster compromise"),
    ]),
    // SSH default credentials chain
    ("ssh_default_creds", &[
        ("ssh_access", "Direct SSH access"),
        ("lateral_movement", "Lateral movement to other systems"),
    ]),
    // Database default credentials
    ("mysql_noauth", &[
        ("mysql_read", "Read any data from MySQL"),
        ("mysql_write", "Write data or create backdoor"),
    ]),
    ("postgresql_noauth", &[
        ("postgresql_read", "Read any data"),
        ("postgresql_write", "Write data or execute code via dblink"),
    ]),
];

/// Build attack chain from security findings
pub fn build_attack_chain(findings: Vec<super::super::security::report::SecurityRisk>) -> AttackChain {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut node_ids: HashSet<String> = HashSet::new();

    // Create nodes from findings
    for finding in &findings {
        let node_id = format!("finding_{}", finding.ip.replace('.', "_"));
        if !node_ids.contains(&node_id) {
            nodes.push(AttackNode {
                id: node_id.clone(),
                finding_id: finding.risk_type.clone(),
                title: finding.title.clone(),
                description: finding.description.clone(),
                risk_level: format!("{:?}", finding.risk_level),
                prerequisites: Vec::new(),
            });
            node_ids.insert(node_id);
        }
    }

    // Build attack chains based on patterns
    for finding in &findings {
        let finding_type = finding.risk_type.to_lowercase();

        // Check if this finding matches an attack chain pattern
        for (pattern, chain) in ATTACK_CHAIN_PATTERNS {
            if finding_type.contains(&pattern.to_lowercase()) {
                let from_id = format!("finding_{}", finding.ip.replace('.', "_"));

                for (next_step, description) in *chain {
                    let to_id = format!("{}_{}", next_step, finding.ip.replace('.', "_"));

                    // Add node if not already exists
                    if !node_ids.contains(&to_id) {
                        nodes.push(AttackNode {
                            id: to_id.clone(),
                            finding_id: next_step.to_string(),
                            title: next_step.replace('_', " "),
                            description: description.to_string(),
                            risk_level: "High".to_string(),
                            prerequisites: vec![from_id.clone()],
                        });
                        node_ids.insert(to_id.clone());
                    }

                    // Add edge
                    edges.push(AttackEdge {
                        from: from_id.clone(),
                        to: to_id,
                        relationship: "enables".to_string(),
                    });
                }
            }
        }
    }

    // Calculate combined risk score
    let combined_risk = calculate_combined_risk(&findings, &nodes);

    // Generate fix priority (break the chain at critical points)
    let fix_priority = generate_fix_priority(&findings, &nodes);

    AttackChain {
        nodes,
        edges,
        combined_risk,
        fix_priority,
    }
}

/// Calculate combined risk score considering attack chains
fn calculate_combined_risk(findings: &[super::super::security::report::SecurityRisk], nodes: &[AttackNode]) -> String {
    if findings.is_empty() {
        return "Info".to_string();
    }

    // Count risk levels
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut chain_bonus = 0;

    for finding in findings {
        match finding.risk_level {
            super::super::security::report::RiskLevel::Critical => critical_count += 3,
            super::super::security::report::RiskLevel::High => high_count += 2,
            super::super::security::report::RiskLevel::Medium => medium_count += 1,
            _ => {}
        }
    }

    // If attack chain exists, increase combined risk
    if nodes.len() > findings.len() {
        chain_bonus = (nodes.len() - findings.len()) * 2;
    }

    let total_score = critical_count * 3 + high_count * 2 + medium_count + chain_bonus;

    match total_score {
        10..=usize::MAX => "Critical",
        6..=9 => "High",
        3..=5 => "Medium",
        1..=2 => "Low",
        _ => "Info",
    }.to_string()
}

/// Generate fix priority - break attack chain at most critical points
fn generate_fix_priority(findings: &[super::super::security::report::SecurityRisk], _nodes: &[AttackNode]) -> Vec<FixSuggestion> {
    let mut suggestions = Vec::new();

    // First, prioritize findings that start attack chains
    for finding in findings {
        let finding_type = finding.risk_type.to_lowercase();

        for (pattern, _) in ATTACK_CHAIN_PATTERNS {
            if finding_type.contains(&pattern.to_lowercase()) {
                suggestions.push(FixSuggestion {
                    finding_id: finding.risk_type.clone(),
                    title: finding.title.clone(),
                    action: format!("立即修复: {}", finding.title),
                    effort: "高".to_string(),
                });
                break;
            }
        }
    }

    // Then add other critical findings
    for finding in findings {
        if suggestions.iter().any(|s| s.finding_id == finding.risk_type) {
            continue;
        }

        match finding.risk_level {
            super::super::security::report::RiskLevel::Critical |
            super::super::security::report::RiskLevel::High => {
                suggestions.push(FixSuggestion {
                    finding_id: finding.risk_type.clone(),
                    title: finding.title.clone(),
                    action: format!("修复: {}", finding.title),
                    effort: "中".to_string(),
                });
            }
            _ => {}
        }
    }

    suggestions
}

/// Detect if findings form an attack chain (DAG)
pub fn detect_attack_chain(findings: &[super::super::security::report::SecurityRisk]) -> bool {
    for (pattern, _) in ATTACK_CHAIN_PATTERNS {
        for finding in findings {
            if finding.risk_type.to_lowercase().contains(&pattern.to_lowercase()) {
                return true;
            }
        }
    }
    false
}

/// Analyze attack chain using DeepSeek R1 for multi-step reasoning
///
/// # Arguments
/// * `vulns` - List of vulnerabilities to analyze
/// * `api_key` - DeepSeek API key
/// * `subnet` - Target subnet for context
///
/// # Returns
/// * `Ok(AttackChain)` - AI-generated attack chain with nodes, edges, overall rating, and fix priority
/// * `Err(String)` - Error message if analysis fails
pub async fn analyze_attack_chain(
    vulns: Vec<Vulnerability>,
    api_key: &str,
    subnet: &str,
) -> Result<AttackChain, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Build vulnerability summary for the prompt
    let vuln_summary: Vec<String> = vulns
        .iter()
        .map(|v| {
            format!(
                "- {}:{} [{}] {}{}",
                v.ip,
                v.port.map_or("*".to_string(), |p| p.to_string()),
                v.vuln_type,
                v.title,
                v.cvss_score.map_or(String::new(), |s| format!(" (CVSS {:.1})", s))
            )
        })
        .collect();

    let prompt = format!(
        r#"You are a cybersecurity expert analyzing attack chains in network security.

Given the following vulnerabilities found in subnet {}:

{}

Your task:
1. Identify how these vulnerabilities could form an attack chain
2. Determine prerequisite relationships between vulnerabilities
3. Assess the overall risk rating (Critical/High/Medium/Low)
4. Suggest fix priority to break the attack chain

Output ONLY a valid JSON object with this exact structure (no markdown, no explanation):
{{
  "nodes": [
    {{
      "id": "unique_node_id",
      "finding_id": "vulnerability_type",
      "title": "Node title",
      "description": "Detailed description",
      "risk_level": "High",
      "prerequisites": ["id1", "id2"]
    }}
  ],
  "edges": [
    {{
      "from": "node_id_1",
      "to": "node_id_2",
      "relationship": "leads_to|enables|escalates_to"
    }}
  ],
  "combined_risk": "Critical|High|Medium|Low",
  "fix_priority": [
    {{
      "finding_id": "vulnerability_type",
      "title": "Fix title",
      "action": "Concrete action to take",
      "effort": "High|Medium|Low"
    }}
  ]
}}

Rules:
- Use severity from provided CVSS scores when available
- Maximum 10 nodes in the attack chain
- Focus on the most critical attack paths
- Relationship types: "leads_to" (direct progression), "enables" (makes possible), "escalates_to" (privilege escalation)
- fix_priority should list the most impactful remediation steps in order"#,
        subnet,
        vuln_summary.join("\n")
    );

    let request_body = serde_json::json!({
        "model": "deepseek-reasoner",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    });

    let response = client
        .post("https://api.deepseek.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("DeepSeek API error ({}): {}", status, body));
    }

    let api_response: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    let content = api_response["choices"][0]["message"]["content"]
        .as_str()
        .ok_or("Invalid API response: missing content")?;

    // Parse the JSON response
    let chain: AttackChain = serde_json::from_str(content)
        .map_err(|e| format!("Failed to parse AI response as JSON: {} - Raw: {}", e, content))?;

    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::security::report::{RiskLevel, SecurityRisk};
    use std::collections::HashMap;

    #[test]
    fn test_build_attack_chain_simple() {
        let findings = vec![
            SecurityRisk {
                ip: "192.168.1.100".to_string(),
                port: Some(6379),
                risk_type: "redis_noauth".to_string(),
                title: "Redis未授权访问".to_string(),
                description: "Redis服务允许无认证访问".to_string(),
                cvss_score: None,
                evidence: HashMap::new(),
                risk_level: RiskLevel::Critical,
            },
        ];

        let chain = build_attack_chain(findings);
        assert!(!chain.nodes.is_empty());
        assert!(chain.combined_risk == "Critical" || chain.combined_risk == "High");
    }

    #[test]
    fn test_combined_risk_calculation() {
        let findings = vec![
            SecurityRisk {
                ip: "192.168.1.100".to_string(),
                port: Some(6379),
                risk_type: "redis_noauth".to_string(),
                title: "Redis未授权访问".to_string(),
                description: "Redis服务允许无认证访问".to_string(),
                cvss_score: None,
                evidence: HashMap::new(),
                risk_level: RiskLevel::Critical,
            },
            SecurityRisk {
                ip: "192.168.1.100".to_string(),
                port: Some(22),
                risk_type: "ssh_default_creds".to_string(),
                title: "SSH默认凭证".to_string(),
                description: "SSH使用默认密码".to_string(),
                cvss_score: None,
                evidence: HashMap::new(),
                risk_level: RiskLevel::High,
            },
        ];

        let nodes = vec![];
        let risk = calculate_combined_risk(&findings, &nodes);
        assert!(risk == "Critical" || risk == "High");
    }

    #[test]
    fn test_attack_chain_detection() {
        let findings = vec![
            SecurityRisk {
                ip: "192.168.1.100".to_string(),
                port: Some(6379),
                risk_type: "redis_noauth".to_string(),
                title: "Redis未授权访问".to_string(),
                description: "Redis服务允许无认证访问".to_string(),
                cvss_score: None,
                evidence: HashMap::new(),
                risk_level: RiskLevel::Critical,
            },
        ];

        assert!(detect_attack_chain(&findings));
    }
}
