# TLS Audit 设计

> **版本**：v1.0
> **日期**：2026-05-13
> **状态**：待评审

---

## 1. 目标

PC 版（Tauri）TLS 安全审计能力，检测目标 TLS 服务（证书/配置/漏洞），覆盖全面（Rust 基础检测 + testssl.sh 深度攻击检测）。

---

## 2. 架构

```
PipelineOptions.auto_tls_audit (bool)
         │
         ▼
┌──────────────────────────────────┐
│  Rust TLS 基础检测                 │
│  - 证书链抓取 + 解析              │
│  - 协议版本检测                   │
│  - Cipher suite 枚举             │
│  - HSTS/HPKP/CSP 头检测          │
│  - DNS CAA 查询                  │
│  - 服务指纹                      │
└──────────┬───────────────────────┘
            │ 可选（慢，深度）
            ▼
┌──────────────────────────────────┐
│  testssl.sh --full               │
│  - Heartbleed / POODLE / BEAST   │
│  - FREAK / Logjam / DROWN        │
│  - ROBOT / Ticketbleed           │
│  - 所有协议攻击变体               │
└──────────────────────────────────┘
            │
            ▼
PipelineResult::TLSAudit { ... }
```

---

## 3. Rust TLS 基础检测

### 3.1 依赖

```toml
rustls = "0.23"
x509-parser = "0.16"
dns-parser = "0.13"
```

### 3.2 TLS 检测结果模型

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSCertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub san: Vec<String>,        // Subject Alternative Names
    pub fingerprint_sha256: String,
    pub key_algorithm: String,    // RSA/ECDSA/ed25519
    pub key_size: u32,            // bit
    pub signature_algorithm: String,
    pub has_ocsp_stapling: bool,
    pub ct_logs: Vec<String>,     // Certificate Transparency
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSConfigInfo {
    pub supports_tls10: bool,
    pub supports_tls11: bool,
    pub supports_tls12: bool,
    pub supports_tls13: bool,
    pub supports_ssl2: bool,
    pub supports_ssl3: bool,
    pub supported_cipher_suites: Vec<String>,
    pub fallback_scsv: bool,
    pub renegotiation: String,    // "secure" / "insecure" / "not_supported"
    pub compression: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSVulnerability {
    pub id: String,               // e.g. "CVE-2014-0160"
    pub name: String,              // e.g. "Heartbleed"
    pub severity: String,          // "critical" / "high" / "medium" / "low"
    pub description: String,
    pub testssl_line: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSAuditResult {
    pub host: String,
    pub port: u16,
    pub cert: TLSCertInfo,
    pub config: TLSConfigInfo,
    pub headers: Option<HSTSInfo>,
    pub vulnerabilities: Vec<TLSVulnerability>,
    pub testssl_used: bool,
    pub raw_testssl_output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HSTSInfo {
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
    pub header: String,
}
```

---

## 4. Rust 检测实现

### 4.1 证书抓取

```rust
use rustls::ClientConnection;
use std::net::TcpStream;
use std::io::{Read, Write};

fn fetch_cert_chain(host: &str, port: u16) -> Result<TLSCertInfo, String> {
    // 使用 rustls 连接目标，读取证书链
    // 解析 DER/PEM 编码的证书
    // 提取 subject/issuer/有效期/SAN/fingerprint
}
```

### 4.2 协议版本检测

对每个版本（TLS 1.0 → 1.1 → 1.2 → 1.3）尝试握手，记录是否支持。SSLv2/SSLv3 单独检测。

### 4.3 Cipher 枚举

用 rustls 构造不同 cipher suite 的 ClientHello，枚举服务端支持的 suites。

### 4.4 HSTS/头检测

发 HTTP 请求，读 `Strict-Transport-Security` 等响应头。

### 4.5 漏洞规则库

简单的本地 JSON 文件 `tls_vuln_rules.json`：

```json
[
  {
    "id": "CVE-2014-0160",
    "name": "Heartbleed",
    "severity": "critical",
    "patterns": ["openssl 1.0.1", "heartbleed vulnerable"]
  }
]
```

Phase 2 对接 CVE 库。

---

## 5. testssl.sh 集成

### 5.1 检测逻辑

用户开启 `auto_tls_full` 时，Rust 基础检测完成后，对发现的高危配置（TLS 1.0/1.1 开启、cipher 弱等）再调 testssl.sh。

```rust
pub fn run_testssl(host: &str, port: u16) -> Result<Vec<TLSVulnerability>, String> {
    let output = Command::new("testssl.sh")
        .args(&["--quiet", "--uuid", "--format", "json", "-o", "JSON.dump"])
        .args(&["{}:{}"])
        .output()
        .map_err(|e| format!("testssl.sh failed: {}", e))?;

    // 解析 JSON 输出，提取 vulnerabilities
    parse_testssl_json(&String::from_utf8_lossy(&output.stdout))
}
```

### 5.2 安装

`install.sh` 已包含 testssl.sh 安装：
```bash
install_tool "testssl.sh" "git clone https://github.com/drwetter/testssl.sh.git"
```

---

## 6. Pipeline 集成

### 6.1 PipelineOptions 扩展

```rust
pub struct PipelineOptions {
    // ... existing fields
    pub auto_tls_audit: bool,       // Rust 基础检测
    pub auto_tls_full: bool,       // + testssl.sh 深度检测
}
```

### 6.2 PipelineResult 扩展

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PipelineResult {
    // ... existing
    TLS {
        host: String,
        port: u16,
        severity: String,          // "ok" / "warning" / "critical"
        message: String,
        cert: Option<TLSCertInfo>,
        vulnerabilities: Vec<TLSVulnerability>,
    },
}
```

---

## 7. 前端展示

| 组件 | 职责 |
|------|------|
| TLSResultPanel | 显示 TLS 审计结果，支持 filter severity |
| TLSDetailModal | 点击展开证书详情/漏洞描述 |
| ScanPage | PipelinePanel 加 tls 开关 |

---

## 8. 依赖添加

```toml
rustls = "0.23"
x509-parser = "0.16"
dns-parser = "0.13"
```

---

## 9. 验收标准

- [ ] TLS 1.0/1.1/1.2/1.3 检测正常
- [ ] 证书链解析正确（subject/issuer/expiry/SAN）
- [ ] HSTS 头检测正常
- [ ] 发现 TLS 1.0/1.1 时自动提示漏洞风险
- [ ] testssl.sh 可选触发，输出 JSON
- [ ] 工具未安装 testssl.sh 时提示清晰

---

*规格书版本：v1.0 · NetProwl TLS Audit*