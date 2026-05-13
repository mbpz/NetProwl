# Phase 3 Plan: 攻击链推理 (AI #2)

**Goal:** 多漏洞关联分析，找出可串联利用的攻击路径

---

## Task: 攻击链推理 (Attack Chain Reasoning)

**Files:**
- Create: `rs-core/src/ai/attack_chain.rs`
- Modify: `rs-core/src/ai/mod.rs`

**Requirements:**
```rust
pub struct Vulnerability {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub vuln_id: String,
    pub severity: String,       // critical/high/medium/low
    pub description: String,
}

pub struct AttackChain {
    pub nodes: Vec<ChainNode>,   // vulnerability details
    pub edges: Vec<ChainEdge>,  // relationships between nodes
    pub overall_rating: String, // critical/high/medium/low
    pub fix_priority: Vec<String>, // ordered fix recommendations
}

pub struct ChainNode {
    pub id: usize,
    pub vuln: Vulnerability,
}

pub struct ChainEdge {
    pub from: usize,
    pub to: usize,
    pub relationship: String,   // e.g., "auth bypass → RCE"
}

pub async fn analyze_attack_chain(vulns: Vec<Vulnerability>, api_key: &str) -> Result<AttackChain, String>
// Call DeepSeek R1 to analyze attack paths between vulnerabilities
```

**DeepSeek R1 prompt:**
```
System:
你是一名渗透测试专家。请分析以下漏洞列表，找出可以串联利用的攻击路径，
以 JSON 格式输出攻击链（nodes 和 edges），并给出综合风险评级和修复优先级。

输出格式：
{
  "nodes": [{"id": 0, "ip": "...", "port": ..., "vuln_id": "...", "severity": "..."}],
  "edges": [{"from": 0, "to": 1, "relationship": "描述"}],
  "overall_rating": "critical/high/medium/low",
  "fix_priority": ["先修复X", "再修复Y"]
}

User:
目标网络 {subnet}，发现如下漏洞：
{vuln_list_json}
```

**Implementation:**
- Use DeepSeek reasoner model (deepseek-reasoner) for multi-step logic
- Timeout 30s
- Parse JSON response into AttackChain struct

- [ ] **Step 1: Write rs-core/src/ai/attack_chain.rs**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Vulnerability {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub vuln_id: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainNode {
    pub id: usize,
    pub ip: String,
    pub port: u16,
    pub vuln_id: String,
    pub severity: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainEdge {
    pub from: usize,
    pub to: usize,
    pub relationship: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttackChain {
    #[serde(rename = "nodes")]
    pub nodes: Vec<ChainNode>,
    #[serde(rename = "edges")]
    pub edges: Vec<ChainEdge>,
    #[serde(rename = "overall_rating")]
    pub overall_rating: String,
    #[serde(rename = "fix_priority")]
    pub fix_priority: Vec<String>,
}

pub async fn analyze_attack_chain(vulns: Vec<Vulnerability>, api_key: &str, subnet: &str) -> Result<AttackChain, String> {
    if api_key.is_empty() {
        return Err("API key required".into());
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let vuln_json = serde_json::to_string(&vulns).map_err(|e| e.to_string())?;

    let prompt = format!(
        r#"You are a penetration testing expert. Analyze the following vulnerability list,
find exploitable attack paths, and output JSON with:
- nodes: vulnerability details with index id
- edges: relationships between nodes (e.g., "auth bypass → RCE")
- overall_rating: critical/high/medium/low
- fix_priority: ordered fix recommendations

Output ONLY JSON, no markdown or explanation.

Target network: {}

Vulnerabilities:
{}"#,
        subnet, vuln_json
    );

    let body = serde_json::json!({
        "model": "deepseek-reasoner",
        "messages": [
            {"role": "system", "content": "You are a penetration testing expert."},
            {"role": "user", "content": prompt}
        ]
    });

    let resp = client.post("https://api.deepseek.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("DeepSeek API error: {}", e))?;

    let json: serde_json::Value = resp.json().await
        .map_err(|e| format!("Parse error: {}", e))?;

    let content = json["choices"][0]["message"]["content"]
        .as_str()
        .ok_or("Invalid response")?;

    let json_str = content.trim().trim_start_matches("```json").trim().trim_start_matches("```").trim();

    serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {}", e))
}
```

- [ ] **Step 2: Update rs-core/src/ai/mod.rs**

```rust
pub mod banner_parser;
pub mod attack_chain;
pub use banner_parser::{BannerResult, parse_banner_with_ai};
pub use attack_chain::{Vulnerability, AttackChain, ChainNode, ChainEdge, analyze_attack_chain};
```

- [ ] **Step 3: Commit**

---

## Self-Review

1. **Spec coverage**: AI #2 攻击链推理 ✅
2. **Placeholder scan**: no TBD/TODO
3. **Type consistency**: Vulnerability, AttackChain, ChainNode, ChainEdge