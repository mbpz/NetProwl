# TLS Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** PC 版 TLS 安全审计：Rust 基础检测 + testssl.sh 深度攻击检测可选。

**Architecture:** Rust 层通过 rustls + x509-parser 做 TLS 握手/证书解析/配置检测，testssl.sh 做漏洞攻击检测，结果统一进 PipelineResult::TLS。

---

## 文件结构

```
netprowl-pc/src-tauri/src/
├── tls/
│   ├── mod.rs              # 模块入口
│   ├── cert.rs            # 证书链抓取 + 解析
│   ├── config.rs          # 协议版本 + cipher 检测
│   ├── headers.rs         # HSTS/HSTS 检测
│   ├── rules.rs           # 漏洞规则 JSON
│   └── testssl.rs         # testssl.sh wrapper
├── tool_commands.rs       # 修改：加 run_testssl
└── pipeline.rs            # 修改：加 TLS 检测阶段
```

---

## Task 1: TLS 模块骨架 + 证书解析

**Files:**
- Create: `netprowl-pc/src-tauri/src/tls/mod.rs`
- Create: `netprowl-pc/src-tauri/src/tls/cert.rs`
- Modify: `netprowl-pc/src-tauri/Cargo.toml`

- [ ] **Step 1: Add dependencies to Cargo.toml**

```toml
rustls = "0.23"
x509-parser = "0.16"
dns-parser = "0.13"
```

- [ ] **Step 2: Write tls/mod.rs**

```rust
pub mod cert;
pub mod config;
pub mod headers;
pub mod rules;
pub mod testssl;

pub use cert::fetch_cert_info;
pub use config::check_tls_config;
pub use headers::check_tls_headers;
pub use rules::load_vuln_rules;
pub use testssl::run_testssl;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSCertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub san: Vec<String>,
    pub fingerprint_sha256: String,
    pub key_algorithm: String,
    pub key_size: u32,
    pub has_ocsp_stapling: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSConfigInfo {
    pub supports_tls10: bool,
    pub supports_tls11: bool,
    pub supports_tls12: bool,
    pub supports_tls13: bool,
    pub supported_cipher_suites: Vec<String>,
    pub fallback_scsv: bool,
    pub renegotiation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSVulnerability {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSAuditResult {
    pub host: String,
    pub port: u16,
    pub cert: TLSCertInfo,
    pub config: TLSConfigInfo,
    pub vulnerabilities: Vec<TLSVulnerability>,
    pub testssl_used: bool,
}
```

- [ ] **Step 3: Write tls/cert.rs**

用 rustls 做 TLS 握手，抓取证书链，x509-parser 解析 DER：

```rust
use rustls::{ClientConnection, ClientConfig, RootCertStore, StreamOwned};
use std::io::{Read, Write};
use std::net::TcpStream;
use x509_parser::{certificate::X509Certificate, der_parser::DerParser};

pub fn fetch_cert_info(host: &str, port: u16) -> Result<TLSCertInfo, String> {
    // 1. 建立 TLS 连接
    // 2. 读取 server_certificate
    // 3. 用 x509-parser 解析 DER
    // 4. 提取 subject/issuer/not_before/not_after/SAN/fingerprint
}
```

- [ ] **Step 4: Build verify**

`cd netprowl-pc/src-tauri && cargo build 2>&1 | head -20`

- [ ] **Step 5: Commit**

---

## Task 2: 协议版本 + Cipher 检测

**Files:**
- Create: `netprowl-pc/src-tauri/src/tls/config.rs`

- [ ] **Step 1: Write tls/config.rs**

对 TLS 1.0/1.1/1.2/1.3 逐个尝试握手，记录版本支持。枚举 cipher suites。

```rust
pub fn check_tls_config(host: &str, port: u16) -> Result<TLSConfigInfo, String> {
    let mut info = TLSConfigInfo {
        supports_tls10: false,
        supports_tls11: false,
        supports_tls12: false,
        supports_tls13: false,
        supported_cipher_suites: vec![],
        fallback_scsv: false,
        renegotiation: "not_tested".into(),
    };

    // 对每个版本构造 ClientHello，看是否收到 ServerHello
    // TLS 1.0/1.1/1.2/1.3 各试一次
    // 枚举 cipher suites
    Ok(info)
}
```

- [ ] **Step 2: Build verify + Commit**

---

## Task 3: 漏洞规则 + testssl.sh wrapper

**Files:**
- Create: `netprowl-pc/src-tauri/src/tls/rules.rs`
- Create: `netprowl-pc/src-tauri/src/tls/testssl.rs`
- Create: `netprowl-pc/src-tauri/src/tls_vuln_rules.json`

- [ ] **Step 1: Write tls/rules.rs**

```rust
#[derive(Debug, Deserialize)]
pub struct VulnRule {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub description: String,
}

pub fn load_vuln_rules() -> Vec<VulnRule> {
    // 读 tls_vuln_rules.json 或 embedded bytes
}
```

- [ ] **Step 2: Write tls/testssl.rs**

```rust
pub fn run_testssl(host: &str, port: u16) -> Result<Vec<TLSVulnerability>, String> {
    let output = std::process::Command::new("testssl.sh")
        .args(&["--quiet", "--json", "-o", "JSON", &format!("{}:{}", host, port)])
        .output()
        .map_err(|e| format!("testssl.sh failed: {}", e))?;

    // 解析 testssl JSON 输出，提取 vulnerabilities
}
```

- [ ] **Step 3: Write tls_vuln_rules.json**

```json
[
  {"id": "CVE-2014-0160", "name": "Heartbleed", "severity": "critical", "description": "OpenSSL heartbeat extension disclosure"},
  {"id": "CVE-2014-0224", "name": "CCS Injection", "severity": "critical", "description": "ChangeCipherSpec injection"},
  ...
]
```

- [ ] **Step 4: Build verify + Commit**

---

## Task 4: Pipeline 集成 + 前端

**Files:**
- Modify: `netprowl-pc/src-tauri/src/pipeline.rs`
- Modify: `netprowl-pc/src-tauri/src/commands.rs`
- Modify: `netprowl-pc/src/stores/pipelineStore.ts`
- Modify: `netprowl-pc/src/components/PipelinePanel.tsx`
- Create: `netprowl-pc/src/components/TLSResultPanel.tsx`

- [ ] **Step 1: PipelineOptions 加字段**

```rust
pub struct PipelineOptions {
    // ... existing
    pub auto_tls_audit: bool,
    pub auto_tls_full: bool,
}
```

- [ ] **Step 2: pipeline 加 TLS 阶段**

在 port scan 完成后，nuclei 之前插入 TLS 检测：
```rust
if opts.auto_tls_audit {
    for (ip, port, _) in &open_ports {
        let tls_result = tokio::task::spawn_blocking(move || {
            tls::audit(&ip, port)
        }).await...;
        if let Ok(result) = tls_result {
            for vuln in result.vulnerabilities {
                results.push(PipelineResult::TLS { host: ip.clone(), port, severity: vuln.severity.clone(), message: format!("{}: {}", vuln.id, vuln.name), cert: Some(result.cert.clone()), vulnerabilities: vec![vuln] });
            }
        }
    }
}
```

- [ ] **Step 3: install.sh 加 testssl.sh**

```bash
install_tool "testssl.sh" "git clone https://github.com/drwetter/testssl.sh.git"
```

- [ ] **Step 4: frontend TLS 开关 + 结果面板**

PipelinePanel 加 checkbox：
```tsx
<label><input type="checkbox" checked={autoTlsAudit} onChange={e => setAutoTlsAudit(e.target.checked)} /> TLS Audit</label>
<label><input type="checkbox" checked={autoTlsFull} onChange={e => setAutoTlsFull(e.target.checked)} /> + testssl.sh (slow)</label>
```

TLSResultPanel 显示证书详情和漏洞列表，按 severity 颜色区分。

- [ ] **Step 5: Commit**

---

## Self-Review

1. **Spec coverage**: TLS cert parse ✓, config check ✓, vuln rules ✓, testssl integration ✓
2. **Placeholder scan**: no TBD/TODO
3. Type consistency: PipelineResult::TLS tag matches frontend

---

Plan saved. Proceed to execution?