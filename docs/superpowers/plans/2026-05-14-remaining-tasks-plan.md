# Phase 2+ 剩余任务清单

**已完成 (✓):**
- AI Banner 语义解析 ✓
- AI 攻击链推理 (in progress)
- CVE 数据库 ✓
- 默认凭据检测 ✓ (200+ rules)
- 未授权访问检测 ✓
- EOS/固件风险评估 ✓

**待实现 (🔲):**

| 功能 | 文件 |
|------|------|
| AI 诊断与修复建议 | `rs-core/src/ai/diagnosis.rs`, `fix_suggest.rs` |
| TLS 审计 (深度) | `rs-core/src/security/tls_audit.rs` |
| 公网侦察 (Shodan/FOFA) | `rs-core/src/recon/shodan.rs` |
| DNS/子域名枚举 | `rs-core/src/recon/dns.rs` |
| HTTP 安全头审计 | `rs-core/src/recon/http_audit.rs` |
| WAF/CDN 识别 | `rs-core/src/recon/waf.rs` |
| Web 漏洞被动检测 | `rs-core/src/recon/web_vuln.rs` |
| 威胁情报聚合 | `rs-core/src/recon/threat_intel.rs` |
| 安全报告生成 | `rs-core/src/security/report.rs` |

---

## Task: AI 诊断与修复建议 (diagnosis + fix_suggest)

**Files:**
- Create: `rs-core/src/ai/diagnosis.rs`
- Create: `rs-core/src/ai/fix_suggest.rs`
- Modify: `rs-core/src/ai/mod.rs`

```rust
pub struct DiagnosisResult {
    pub summary: String,           // 通俗易懂的总结
    pub risk_level: String,        // high/medium/low
    pub immediate_actions: Vec<String>,
    pub technical_details: String,
}

pub async fn diagnose_vulnerability(
    device_info: &str,     // e.g., "Synology NAS DS220+ DSM 7.1"
    vuln_id: &str,
    cvss: f32,
    api_key: &str
) -> Result<DiagnosisResult, String>
```

**Prompt:**
```
设备信息：{device_info}
漏洞：{vuln_id} (CVSS {cvss})
用户技术水平：初级

请提供：
1. 风险通俗解释（1句话）
2. 是否需要立即处理（是/否 + 理由）
3. 具体操作步骤（针对该设备，带截图路径描述）
4. 验证修复成功的方法
```

---

## Task: TLS 审计深度 (tls_audit.rs)

**Files:**
- Create: `rs-core/src/security/tls_audit.rs`
- Modify: `rs-core/src/security/mod.rs`

```rust
pub struct TLSAuditResult {
    pub supported_versions: Vec<String>,    // TLS 1.0/1.1/1.2/1.3
    pub weak_ciphers: Vec<String>,          // RC4/DES/MD5
    pub cert_issues: Vec<String>,           // expired/self-signed
    pub config_score: u8,                   // 0-100
    pub recommendations: Vec<String>,
}

pub async fn deep_tls_audit(ip: &str, port: u16) -> Result<TLSAuditResult, String>
// 深度 TLS 配置审计，检测：
// - 协议版本（TLS 1.0/1.1 标记为需升级）
// - 弱密码套件（RC4, DES, MD5）
// - 证书问题（过期/自签名）
// - 配置评分 0-100
```

---

## Task: 公网侦察 (Shodan/FOFA)

**Files:**
- Create: `rs-core/src/recon/shodan.rs`
- Modify: `rs-core/src/recon/mod.rs`

```rust
pub struct ReconResult {
    pub ip: String,
    pub ports: Vec<u16>,
    pub services: Vec<String>,
    pub vulns: Vec<String>,
    pub location: Option<String>,
}

pub async fn shodan_lookup(ip: &str, api_key: &str) -> Result<ReconResult, String>
pub async fn fofa_lookup(ip: &str, api_key: &str) -> Result<ReconResult, String>
```

---

## Task: DNS/子域名枚举

**Files:**
- Create: `rs-core/src/recon/dns.rs`
- Modify: `rs-core/src/recon/mod.rs`

```rust
pub struct SubdomainResult {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub records: Vec<DNSRecord>,
}

pub struct DNSRecord {
    pub rtype: String,   // A/AAAA/CNAME/MX/TXT
    pub value: String,
}

pub async fn enumerate_subdomains(domain: &str) -> Result<SubdomainResult, String>
// 使用 crt.sh API 枚举子域名
// GET https://crt.sh/?q=%.{domain}&output=json
```

---

## Task: HTTP 安全头审计

**Files:**
- Create: `rs-core/src/recon/http_audit.rs`
- Modify: `rs-core/src/recon/mod.rs`

```rust
pub struct HTTPHeaderResult {
    pub strict_transport_security: Option<bool>,  // HSTS
    pub content_security_policy: Option<bool>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<bool>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<bool>,
    pub score: u8,  // 0-100 A-F
    pub recommendations: Vec<String>,
}

pub async fn audit_http_headers(url: &str) -> Result<HTTPHeaderResult, String>
// 检测安全头：
// - HSTS: max-age ≥ 31536000
// - CSP: 无 unsafe-inline
// - X-Frame-Options: DENY/SAMEORIGIN
// - X-Content-Type-Options: nosniff
// 综合评分 A-F
```

---

## Task: WAF/CDN 识别

**Files:**
- Create: `rs-core/src/recon/waf.rs`
- Modify: `rs-core/src/recon/mod.rs`

```rust
pub enum CDNType {
    Cloudflare,
    Akamai,
    AliyunWAF,
    TencentWAF,
    None,
}

pub fn detect_waf_cdn(response_headers: &HashMap<String, String>) -> CDNType
// 通过响应头特征识别：
// - Cloudflare: CF-Ray header
// - 阿里云 WAF: X-Powered-By-Alibaba
// - 腾讯云 WAF: 特定错误页
```

---

## Task: Web 漏洞被动检测

**Files:**
- Create: `rs-core/src/recon/web_vuln.rs`
- Modify: `rs-core/src/recon/mod.rs`

```rust
pub struct WebVulnResult {
    pub vuln_type: String,   // sql_injection/xss/path_disclosure/api_key_leak
    pub url: String,
    pub evidence: String,
    pub severity: String,
}

pub async fn passive_web_scan(url: &str) -> Vec<WebVulnResult>
// 被动检测（不主动攻击）：
// - SQL 注入特征（响应含数据库错误）
// - XSS 反射特征
// - 敏感路径暴露（.env, /backup/, /.git/）
// - 敏感信息泄露（API Key 格式）
```

---

## Task: 威胁情报聚合

**Files:**
- Create: `rs-core/src/recon/threat_intel.rs`
- Modify: `rs-core/src/recon/mod.rs`

```rust
pub struct ThreatIntelResult {
    pub ip: String,
    pub is_malicious: bool,
    pub threat_actors: Vec<String>,
    pub attack_reports: Vec<String>,
    pub last_seen: Option<String>,
}

pub async fn check_threat_intel(ip: &str) -> Result<ThreatIntelResult, String>
// 查询已知恶意 IP 黑名单
// 整合 VirusTotal/AlienVault OTX 等情报源
```

---

## Task: 安全报告生成

**Files:**
- Modify: `rs-core/src/security/report.rs`
- Modify: `rs-core/src/security/mod.rs`

```rust
pub struct SecurityReport {
    pub title: String,
    pub generated_at: String,
    pub target_network: String,
    pub executive_summary: String,
    pub device_count: usize,
    pub vuln_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub devices: Vec<DeviceReport>,
}

pub struct DeviceReport {
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub os: Option<String>,
    pub open_ports: Vec<u16>,
    pub vulnerabilities: Vec<VulnSummary>,
}

pub async fn generate_report(
    devices: Vec<Device>,
    vulns: Vec<Vulnerability>,
    api_key: Option<&str>
) -> Result<SecurityReport, String>
// 生成双层次报告：
// - 执行摘要（管理层）
// - 技术详情（工程师）
// - 如果 api_key 提供，AI 生成自然语言总结
```

---

**执行顺序：** 按顺序 dispatch subagent 实现每个 task