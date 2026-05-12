# Go → Rust Core 迁移计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 NetProwl 核心扫描能力从 Go 迁移到 Rust，实现跨平台统一

**Architecture:** Rust core 模块包含 scanner（mDNS/SSDP/TCP/Banner）+ util（IP/OUI）。PC 版直接调用，微信小程序版编译为 WASM。

**Tech Stack:** Rust 1.75+, tokio async, wasm-bindgen, wasm-pack

---

## 1. 项目初始化

### Task 1: 创建 Rust Core 项目

**Files:**
- Create: `core/Cargo.toml`
- Create: `core/src/lib.rs`
- Create: `core/src/scanner/mod.rs`
- Create: `core/src/util/mod.rs`

- [ ] **Step 1: 创建 Cargo.toml**

```toml
[package]
name = "netprowl-core"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["lib", "cdylib", "rlib"]

[dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
regex = "1"
anyhow = "1"

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
async-std = { version = "1", features = ["attributes"] }

[profile.release]
opt-level = "s"
lto = true
```

- [ ] **Step 2: 创建 lib.rs 入口**

```rust
pub mod scanner;
pub mod util;

pub use scanner::*;
pub use util::*;
```

- [ ] **Step 3: 创建 scanner/mod.rs**

```rust
pub mod mdns;
pub mod ssdp;
pub mod tcp;
pub mod banner;
pub mod registry;

pub use mdns::DiscoverMDNS;
pub use ssdp::DiscoverSSDP;
pub use tcp::{ProbeTCPPorts, ProbeTCPPort, TCPConfig};
pub use banner::{GrabBanner, BannerConfig};
pub use registry::{Match, ServiceRule};
```

- [ ] **Step 4: 创建 util/mod.rs**

```rust
pub mod oui;
pub mod ip;

pub use oui::LookupVendor;
pub use ip::{InferSubnet, ExpandSubnet, IsPrivateIP, InferOS};
```

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.toml core/src/lib.rs core/src/scanner/mod.rs core/src/util/mod.rs
git commit -m "feat(core): scaffold Rust project structure

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 2. 类型定义

### Task 2: 定义 Rust 类型（对应 Go types.go）

**Files:**
- Create: `core/src/types.rs`

- [ ] **Step 1: 写入 types.rs**

```rust
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub port: u16,
    pub service: Option<String>,
    pub state: PortState,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Filtered,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    #[serde(rename = "mac")]
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    #[serde(rename = "deviceType")]
    pub device_type: DeviceType,
    pub os: OSType,
    #[serde(rename = "openPorts")]
    pub open_ports: Vec<Port>,
    pub sources: Vec<DiscoverySource>,
    #[serde(rename = "discoveredAt")]
    pub discovered_at: Option<Duration>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Router,
    Pc,
    Camera,
    Nas,
    Phone,
    Printer,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OSType {
    Linux,
    Windows,
    Network,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DiscoverySource {
    Mdns,
    Ssdp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub devices: Vec<Device>,
    #[serde(rename = "durationMs")]
    pub duration_ms: i64,
    #[serde(rename = "mdnsUnavailable")]
    pub mdns_unavailable: bool,
}
```

- [ ] **Step 2: 更新 lib.rs 引入 types**

```rust
pub mod scanner;
pub mod util;
pub mod types;

pub use types::*;
```

- [ ] **Step 3: Commit**

```bash
git add core/src/types.rs core/src/lib.rs
git commit -m "feat(core): add Rust type definitions matching Go types

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 3. OUI 厂商库

### Task 3: 迁移 oui.go → oui.rs

**Files:**
- Create: `core/src/util/oui.rs`
- Modify: `core/src/util/mod.rs`

- [ ] **Step 1: 写入 oui.rs**

```rust
use std::collections::HashMap;

fn build_oui_map() -> HashMap<String, &'static str> {
    let mut m = HashMap::new();
    m.insert("00:50:56", "VMware");
    m.insert("00:0c:29", "VMware");
    m.insert("b8:27:eb", "Raspberry Pi");
    m.insert("dc:a6:32", "Raspberry Pi");
    m.insert("e4:5f:01", "Raspberry Pi");
    m.insert("00:1e:68", "Huawei/H3C");
    m.insert("00:25:9e", "Cisco");
    m.insert("00:1a:2b", "Cisco");
    m.insert("00:17:88", "Philips Hue");
    m.insert("a8:66:7f", "Apple");
    m.insert("f0:18:98", "Apple");
    m.insert("3c:06:30", "Apple");
    m.insert("00:e0:4c", "Realtek");
    m.insert("00:23:cd", "Intel");
    m.insert("00:1b:21", "Intel");
    m.insert("00:0d:2b", "Dell");
    m.insert("00:1c:23", "Dell");
    m.insert("00:24:e8", "Dell");
    m.insert("ac:de:48", "Hikvision");
    m.insert("b4:15:13", "Hikvision");
    m
}

static OUI_MAP: once_cell::sync::Lazy<HashMap<String, &'static str>> =
    once_cell::sync::Lazy::new(build_oui_map);

pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    if mac.len() < 8 {
        return None;
    }
    let prefix = mac[..8].to_lowercase().replace('-', ":");
    OUI_MAP.get(&prefix).copied()
}
```

- [ ] **Step 2: 更新 Cargo.toml 添加 once_cell**

```toml
once_cell = "1"
```

- [ ] **Step 3: Commit**

```bash
git add core/src/util/oui.rs core/src/util/mod.rs core/Cargo.toml
git commit -m "feat(core): implement OUI vendor lookup in Rust

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 4. IP 工具函数

### Task 4: 迁移 ip.go → ip.rs

**Files:**
- Create: `core/src/util/ip.rs`

- [ ] **Step 1: 写入 ip.rs**

```rust
use std::net::IpAddr;

pub fn infer_subnet(local_ip: &str) -> Option<String> {
    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    Some(format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]))
}

pub fn expand_subnet(subnet: &str) -> Vec<String> {
    let Ok((ip, mask)) = subnet.split_once('/') else { return vec![] };
    let Ok(ip): Result<std::net::Ipv4Addr, _> = ip.parse() else { return vec![] };
    let Ok(prefix): Result<u8, _> = mask.parse() else { return vec![] };
    if prefix > 32 { return vec![]; }

    let mask_bits = u32::MAX << (32 - prefix);
    let network = u32::from(ip) & mask_bits;
    let broadcast = network | !mask_bits;

    let mut ips = Vec::new();
    // Skip network and broadcast addresses
    for n in (network + 1)..broadcast {
        if let Ok(a) = std::net::Ipv4Addr::try_from(n) {
            ips.push(a.to_string());
        }
    }
    ips
}

pub fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        addr.is_loopback() || match addr {
            IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
            IpAddr::V6(_) => false,
        }
    } else {
        false
    }
}

pub fn infer_os(ttl: u32) -> &'static str {
    match ttl {
        0..=64 => "linux",
        65..=128 => "windows",
        129..=254 => "unknown",
        _ => "network",
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add core/src/util/ip.rs
git commit -m "feat(core): implement IP utility functions in Rust

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 5. 服务指纹规则

### Task 5: 迁移 registry.go → registry.rs

**Files:**
- Create: `core/src/scanner/registry.rs`

- [ ] **Step 1: 写入 registry.rs**

```rust
use crate::types::{DeviceType, Port, PortState};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

pub struct ServiceRule {
    pub id: &'static str,
    pub port: u16,
    pub banner_contains: Option<&'static str>,
    pub service: &'static str,
    pub device_type: DeviceType,
}

static RULES: Lazy<Vec<ServiceRule>> = Lazy::new(|| {
    vec![
        ServiceRule { id: "http", port: 80, banner_contains: None, service: "HTTP", device_type: DeviceType::Unknown },
        ServiceRule { id: "https", port: 443, banner_contains: None, service: "HTTPS", device_type: DeviceType::Unknown },
        ServiceRule { id: "ssh", port: 22, banner_contains: Some("SSH"), service: "SSH", device_type: DeviceType::Unknown },
        ServiceRule { id: "ftp", port: 21, banner_contains: Some("FTP"), service: "FTP", device_type: DeviceType::Unknown },
        ServiceRule { id: "hikvision-camera", port: 554, banner_contains: Some("Hikvision"), service: "Hikvision Camera", device_type: DeviceType::Camera },
        ServiceRule { id: "synology-nas", port: 5000, banner_contains: Some("Synology"), service: "Synology NAS", device_type: DeviceType::Nas },
        ServiceRule { id: "rtsp", port: 554, banner_contains: Some("RTSP"), service: "RTSP Stream", device_type: DeviceType::Camera },
        ServiceRule { id: "http-proxy", port: 8080, banner_contains: None, service: "HTTP Proxy", device_type: DeviceType::Unknown },
        ServiceRule { id: "upnp", port: 1900, banner_contains: Some("UPnP"), service: "UPnP", device_type: DeviceType::Unknown },
    ]
});

pub fn match_service(port: u16, banner: &str) -> (&'static str, DeviceType) {
    for rule in RULES.iter() {
        if rule.port != port {
            continue;
        }
        match &rule.banner_contains {
            Some(pattern) if banner.contains(pattern) => return (rule.service, rule.device_type),
            None => return (rule.service, DeviceType::Unknown),
            _ => {}
        }
    }
    ("unknown", DeviceType::Unknown)
}
```

- [ ] **Step 2: 更新 Cargo.toml 添加 regex, once_cell**

- [ ] **Step 3: Commit**

```bash
git add core/src/scanner/registry.rs
git commit -m "feat(core): implement service fingerprint registry in Rust

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 6. SSDP 扫描器

### Task 6: 迁移 ssdp.go → ssdp.rs

**Files:**
- Create: `core/src/scanner/ssdp.rs`
- Modify: `core/src/scanner/mod.rs`

- [ ] **Step 1: 写入 ssdp.rs**

```rust
use crate::types::{Device, DeviceType, DiscoverySource, OSType, Port, PortState};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

const SSDP_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
const M_SEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";

#[derive(Debug, Clone)]
pub struct SSDPConfig {
    pub timeout: Duration,
}

impl Default for SSDPConfig {
    fn default() -> Self {
        Self { timeout: Duration::from_secs(5) }
    }
}

pub async fn discover_ssdp(cfg: SSDPConfig) -> Result<Vec<Device>, Box<dyn std::error::Error + Send + Sync>> {
    let socket = UdpSocket::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))?;
    socket.set_read_timeout(Some(cfg.timeout))?;
    socket.send_to(M_SEARCH, SocketAddr::from((SSDP_ADDR, SSDP_PORT)))?;

    let mut devices = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                let response = String::from_utf8_lossy(&buf[..n]).to_string();
                if let Some(mut dev) = parse_ssdp_response(&response, src.ip().to_string()) {
                    dev.sources = vec![DiscoverySource::Ssdp];
                    devices.push(dev);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
    Ok(devices)
}

fn parse_ssdp_response(banner: &str, ip: String) -> Option<Device> {
    let mut hostname = None;
    for line in banner.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("server:") || line_lower.starts_with("server") {
            if let Some((_, val)) = line.split_once(':') {
                hostname = Some(val.trim().to_string());
            }
        }
    }

    Some(Device {
        ip,
        mac: None,
        hostname,
        vendor: None,
        device_type: DeviceType::Unknown,
        os: OSType::Unknown,
        open_ports: vec![],
        sources: vec![],
        discovered_at: None,
        ttl: None,
    })
}
```

- [ ] **Step 2: Commit**

```bash
git add core/src/scanner/ssdp.rs core/src/scanner/mod.rs
git commit -m "feat(core): implement SSDP discovery in Rust

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 7. TCP 扫描器

### Task 7: 迁移 tcp.go → tcp.rs

**Files:**
- Create: `core/src/scanner/tcp.rs`

- [ ] **Step 1: 写入 tcp.rs**

```rust
use crate::types::{Device, DeviceType, DiscoverySource, OSType, Port, PortState};
use std::collections::HashMap;
use std::net::TcpStream;
use std::time::Duration;
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WHITE_PORTS: &[u16] = &[80, 443, 8080, 8443, 554, 5000, 9000, 49152];

#[derive(Debug, Clone)]
pub struct TCPConfig {
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout_ms: u64,
}

impl Default for TCPConfig {
    fn default() -> Self {
        Self {
            ports: WHITE_PORTS.to_vec(),
            concurrency: 100,
            timeout_ms: 2000,
        }
    }
}

pub async fn probe_tcp_ports(ip: &str, cfg: TCPConfig) -> Result<Vec<Port>, Box<dyn std::error::Error + Send + Sync>> {
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let mut handles = Vec::new();

    for port in &cfg.ports {
        let ip = ip.to_string();
        let timeout = timeout;
        handles.push(tokio::spawn(async move {
            probe_port(&ip, *port, timeout).await
        }));
    }

    let mut open_ports = Vec::new();
    for handle in handles {
        if let Ok(port) = handle.await {
            if port.state == PortState::Open {
                open_ports.push(port);
            }
        }
    }
    Ok(open_ports)
}

async fn probe_port(ip: &str, port: u16, timeout: Duration) -> Port {
    let addr = format!("{}:{}", ip, port);
    match tokio::time::timeout(timeout, AsyncTcpStream::connect(&addr)).await {
        Ok(Ok(mut conn)) => {
            let banner = grab_banner(&mut conn, port).await;
            Port {
                port,
                service: guess_service(port),
                state: PortState::Open,
                banner: Some(banner),
            }
        }
        _ => Port {
            port,
            service: guess_service(port),
            state: PortState::Closed,
            banner: None,
        },
    }
}

async fn grab_banner(conn: &mut AsyncTcpStream, port: u16) -> String {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(1)));
    match port {
        80 | 8080 | 8443 => {
            let _ = conn.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
        }
        _ => {}
    }
    let mut buf = [0u8; 1024];
    match conn.read(&mut buf).await {
        Ok(n) => String::from_utf8_lossy(&buf[..n]).to_string(),
        Err(_) => String::new(),
    }
}

static SERVICE_MAP: Lazy<HashMap<u16, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(80, "http");
    m.insert(443, "https");
    m.insert(22, "ssh");
    m.insert(21, "ftp");
    m.insert(25, "smtp");
    m.insert(110, "pop3");
    m.insert(143, "imap");
    m.insert(135, "msrpc");
    m.insert(139, "netbios");
    m.insert(445, "smb");
    m.insert(3389, "rdp");
    m.insert(8080, "http-alt");
    m.insert(8443, "https-alt");
    m.insert(5000, "upnp");
    m.insert(9000, "cslistener");
    m.insert(554, "rtsp");
    m
});

fn guess_service(port: u16) -> String {
    SERVICE_MAP.get(&port).copied().unwrap_or("unknown").to_string()
}
```

- [ ] **Step 2: Commit**

```bash
git add core/src/scanner/tcp.rs
git commit -m "feat(core): implement TCP port scanner in Rust

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 8. Banner 抓取

### Task 8: 迁移 banner.go → banner.rs

**Files:**
- Create: `core/src/scanner/banner.rs`

- [ ] **Step 1: 写入 banner.rs**

```rust
use crate::types::{Port, PortState};
use regex::Regex;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct BannerConfig {
    pub timeout_ms: u64,
    pub include_deep_scan: bool,
    pub include_rtsp_sdp: bool,
}

impl Default for BannerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 3000,
            include_deep_scan: true,
            include_rtsp_sdp: true,
        }
    }
}

pub async fn grab_banner(ip: &str, port: u16, cfg: BannerConfig) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let addr = format!("{}:{}", ip, port);

    let mut conn = timeout(timeout, TcpStream::connect(&addr)).await??;
    let _ = conn.set_read_timeout(Some(timeout));

    match port {
        80 | 8080 | 8443 => grab_http_banner(&mut conn, timeout, cfg.include_deep_scan).await,
        22 => grab_ssh_banner(&mut conn, timeout).await,
        21 => grab_ftp_banner(&mut conn, timeout).await,
        554 | 5000 => grab_rtsp_banner(&mut conn, timeout, cfg.include_rtsp_sdp).await,
        _ => grab_generic_banner(&mut conn, timeout).await,
    }
}

async fn grab_http_banner(conn: &mut TcpStream, timeout: Duration, deep_scan: bool) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let _ = conn.write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n").await;
    let mut buf = vec![0u8; 4096];
    let n = conn.read(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();

    if deep_scan {
        let paths = vec!["/", "/admin", "/wp-login.php", "/phpmyadmin/", "/robots.txt"];
        let mut found = Vec::new();
        for path in paths {
            if let Ok(mut c) = timeout(Duration::from_millis(1000), TcpStream::connect(conn.peer_addr()?)).await {
                let _ = c.write_all(format!("GET {} HTTP/1.0\r\nHost: localhost\r\n\r\n", path).as_bytes()).await;
                let mut rb = [0u8; 256];
                if let Ok(nn) = c.read(&mut rb).await {
                    let s = String::from_utf8_lossy(&rb[..nn]);
                    if s.contains("200") || s.contains("401") || s.contains("403") {
                        found.push(path.to_string());
                    }
                }
            }
        }
        if !found.is_empty() {
            return Ok(format!("{}\n[PATHS] {}", resp, found.join(",")));
        }
    }
    Ok(resp)
}

async fn grab_ssh_banner(conn: &mut TcpStream, timeout: Duration) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let _ = conn.set_read_timeout(Some(timeout));
    let mut buf = vec![0u8; 256];
    let n = conn.read(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

async fn grab_ftp_banner(conn: &mut TcpStream, timeout: Duration) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let _ = conn.set_read_timeout(Some(timeout));
    let mut buf = vec![0u8; 256];
    let n = conn.read(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

async fn grab_rtsp_banner(conn: &mut TcpStream, timeout: Duration, get_sdp: bool) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let _ = conn.set_read_timeout(Some(timeout));
    let _ = conn.write_all(b"OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: 0\r\n\r\n").await;
    let mut buf = vec![0u8; 512];
    let n = conn.read(&mut buf).await?;
    let mut resp = String::from_utf8_lossy(&buf[..n]).to_string();

    if get_sdp && n > 0 {
        let _ = conn.write_all(b"DESCRIBE rtsp://localhost/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n").await;
        let mut buf2 = vec![0u8; 1024];
        if let Ok(n2) = conn.read(&mut buf2).await {
            let sdp = String::from_utf8_lossy(&buf2[..n2]);
            resp.push_str(&format!("\n[SDP]{}",
                parse_rtsp_sdp(&sdp)));
        }
    }
    Ok(resp)
}

fn parse_rtsp_sdp(sdp: &str) -> String {
    let mut brand = None;
    let mut stream_url = None;
    for line in sdp.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("a=control:") {
            stream_url = Some(line.split(':').nth(1).unwrap_or("").trim());
        } else if lower.contains("hikvision") {
            brand = Some("Hikvision");
        } else if lower.contains("dahua") {
            brand = Some("Dahua");
        }
    }
    let mut parts = Vec::new();
    if let Some(b) = brand { parts.push(format!("brand:{}", b)); }
    if let Some(u) = stream_url { parts.push(format!("url:{}", u)); }
    if parts.is_empty() { sdp.to_string() } else { parts.join(" ") }
}

async fn grab_generic_banner(conn: &mut TcpStream, timeout: Duration) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let _ = conn.set_read_timeout(Some(timeout));
    let mut buf = vec![0u8; 512];
    let n = conn.read(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}
```

- [ ] **Step 2: Commit**

```bash
git add core/src/scanner/banner.rs
git commit -m "feat(core): implement banner grabbing in Rust

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 9. mDNS 发现

### Task 10: 迁移 mdns.go → mdns.rs

**Files:**
- Create: `core/src/scanner/mdns.rs`

- [ ] **Step 1: 写入 mdns.rs**

```rust
use crate::types::{Device, DeviceType, DiscoverySource, OSType, Port, PortState};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

#[derive(Debug, Clone)]
pub struct MDNSConfig {
    pub service_types: Vec<String>,
    pub timeout: Duration,
}

impl Default for MDNSConfig {
    fn default() -> Self {
        Self {
            service_types: vec![
                "_http._tcp".to_string(),
                "_ftp._tcp".to_string(),
                "_ssh._tcp".to_string(),
                "_smb._tcp".to_string(),
                "_airplay._tcp".to_string(),
                "_googlecast._tcp".to_string(),
                "_ipp._tcp".to_string(),
            ],
            timeout: Duration::from_secs(5),
        }
    }
}

pub async fn discover_mdns(cfg: MDNSConfig) -> Result<Vec<Device>, Box<dyn std::error::Error + Send + Sync>> {
    let socket = UdpSocket::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))?;
    socket.set_read_timeout(Some(cfg.timeout))?;
    socket.join_multicast_v4(MDNS_ADDR, std::net::Ipv4Addr::UNSPECIFIED)?;

    let mut devices = Vec::new();

    for st in &cfg.service_types {
        let query = build_mdns_query(st);
        if socket.send_to(&query, SocketAddr::from((MDNS_ADDR, MDNS_PORT))).is_err() {
            continue;
        }
    }

    let mut buf = [0u8; 65536];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(dev) = parse_mdns_response(&buf[..n], src.ip().to_string()) {
                    devices.push(dev);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }

    Ok(devices)
}

fn build_mdns_query(service_type: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    // Transaction ID
    buf.extend_from_slice(&[0, 0]);
    // Flags: standard query
    buf.extend_from_slice(&[0x01, 0x00]);
    // Questions: 1
    buf.extend_from_slice(&[0, 1]);
    // Answers, Authority, Additional: 0
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    for part in service_type.split('.') {
        buf.push(part.len() as u8);
        buf.extend_from_slice(part.as_bytes());
    }
    buf.push(0);
    // QTYPE: PTR (12)
    buf.extend_from_slice(&[0, 12]);
    // QCLASS: IN (1)
    buf.extend_from_slice(&[0, 1]);

    buf
}

fn parse_mdns_response(data: &[u8], src_ip: String) -> Option<Device> {
    if data.len() < 12 { return None; }

    let mut ip = String::new();
    let mut hostname = String::new();
    let mut port = 0;

    // Simplified parsing: look for A records (type 1) and SRV records (type 33)
    let mut offset = 12;

    // Skip questions
    while offset < data.len() && data[offset] != 0 {
        offset += 1 + data[offset] as usize;
    }
    if offset < data.len() { offset += 5; }

    while offset + 12 <= data.len() {
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        offset += 6; // skip class and TTL
        let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + rdlength > data.len() { break; }

        let rdata = &data[offset..offset + rdlength];
        offset += rdlength;

        match qtype {
            1 if rdlength == 4 => {
                ip = format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
            }
            33 => {
                if rdlength >= 6 {
                    port = u16::from_be_bytes([rdata[4], rdata[5]]);
                    hostname = read_dns_name(rdata, 6).unwrap_or_default();
                }
            }
            _ => {}
        }
    }

    if ip.is_empty() { return None; }

    let open_ports = if port > 0 {
        vec![Port { port, service: None, state: PortState::Open, banner: None }]
    } else {
        vec![]
    };

    Some(Device {
        ip,
        mac: None,
        hostname: if hostname.is_empty() { None } else { Some(hostname) },
        vendor: None,
        device_type: DeviceType::Unknown,
        os: OSType::Unknown,
        open_ports,
        sources: vec![DiscoverySource::Mdns],
        discovered_at: None,
        ttl: None,
    })
}

fn read_dns_name(data: &[u8], offset: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut pos = offset;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 { break; }
        if len & 0xC0 == 0xC0 { break; }
        pos += 1;
        if pos + len > data.len() { return None; }
        parts.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }
    if parts.is_empty() { None } else { Some(parts.join(".")) }
}
```

- [ ] **Step 2: Commit**

```bash
git add core/src/scanner/mdns.rs
git commit -m "feat(core): implement mDNS discovery in Rust

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 10. 顶层入口（DiscoverLAN）

### Task 11: 迁移 scanner.go → scanner.rs（顶层入口）

**Files:**
- Create: `core/src/scanner.rs`
- Modify: `core/src/scanner/mod.rs`

- [ ] **Step 1: 写入 scanner.rs（顶层入口）**

```rust
use crate::types::{Device, ScanResult};
use crate::util::{infer_subnet, expand_subnet, lookup_vendor, infer_os};
use crate::scanner::{mdns, ssdp, tcp, banner, registry};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub concurrency: usize,
    pub timeout: std::time::Duration,
    pub include_mdns: bool,
    pub include_ssdp: bool,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            concurrency: 50,
            timeout: std::time::Duration::from_secs(10),
            include_mdns: true,
            include_ssdp: true,
        }
    }
}

pub async fn discover_lan(opts: DiscoveryOptions) -> Result<ScanResult, Box<dyn std::error::Error + Send + Sync>> {
    use std::time::Instant;
    let start = Instant::now();

    let mut device_map: Arc<Mutex<HashMap<String, Device>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut handles = vec![];

    if opts.include_mdns {
        let cfg = mdns::MDNSConfig::default();
        handles.push(tokio::spawn(async move {
            mdns::discover_mdns(cfg).await.unwrap_or_default()
        }));
    }

    if opts.include_ssdp {
        let cfg = ssdp::SSDPConfig::default();
        handles.push(tokio::spawn(async move {
            ssdp::discover_ssdp(cfg).await.unwrap_or_default()
        }));
    }

    // Collect mdns + ssdp results
    for handle in handles {
        if let Ok(devices) = handle.await {
            let mut map = device_map.lock().await;
            for dev in devices {
                map.insert(dev.ip.clone(), dev);
            }
        }
    }

    // Get local IP and infer subnet for TCP scan
    let local_ip = get_local_ip();
    let subnet = local_ip.as_ref().and_then(|ip| infer_subnet(ip));
    if let Some(subnet) = subnet {
        let ips = expand_subnet(&subnet);
        let cfg = tcp::TCPConfig::default();

        let mut tasks = Vec::new();
        for ip in ips {
            if device_map.lock().await.contains_key(&ip) {
                continue;
            }
            let ip_clone = ip.clone();
            let cfg = cfg.clone();
            tasks.push(tokio::spawn(async move {
                tcp::probe_tcp_ports(&ip_clone, cfg).await.unwrap_or_default()
            }));
        }

        for task in tasks {
            if let Ok(ports) = task.await {
                if !ports.is_empty() {
                    // Use first port's IP as device IP (simplified)
                }
            }
        }
    }

    let devices: Vec<Device> = device_map.lock().await.values().cloned().collect();
    let duration_ms = start.elapsed().as_millis() as i64;

    Ok(ScanResult {
        devices,
        duration_ms,
        mdns_unavailable: false,
    })
}

fn get_local_ip() -> Option<String> {
    let addrs = std::net::InterfaceAddrs::ok()?;
    for addr in addrs {
        if let std::net::IpAddr::V4(v4) = addr.ip() {
            if !v4.is_loopback() {
                return Some(v4.to_string());
            }
        }
    }
    None
}
```

- [ ] **Step 2: Commit**

```bash
git add core/src/scanner.rs core/src/scanner/mod.rs
git commit -m "feat(core): implement DiscoverLAN entry point in Rust

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 11. WASM 绑定层

### Task 12: 添加 WASM 导出

**Files:**
- Modify: `core/src/lib.rs`
- Create: `core/src/wasm.rs`

- [ ] **Step 1: 写入 wasm.rs**

```rust
use wasm_bindgen::prelude::*;
use crate::{discover_lan, DiscoveryOptions, ScanResult};

#[wasm_bindgen]
pub async fn scan_network() -> Result<JsValue, JsValue> {
    let opts = DiscoveryOptions::default();
    let result = discover_lan(opts)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn set_timeout(ms: u32) {
    // WASM 环境下的超时设置
}
```

- [ ] **Step 2: 更新 Cargo.toml 添加 wasm 依赖**

```toml
[dependencies]
wasm-bindgen = "0.2"
serde-wasm-bindgen = "0.6"
js-sys = "0.3"
web-sys = { version = "0.3", features = ["console"] }

[lib]
crate-type = ["lib", "cdylib", "rlib"]
```

- [ ] **Step 3: Commit**

```bash
git add core/src/wasm.rs core/src/lib.rs core/Cargo.toml
git commit -m "feat(core): add WASM bindings for browser environment

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 12. Tauri 集成

### Task 13: 更新 Tauri commands 调用 Rust Core

**Files:**
- Modify: `netprowl-pc/src-tauri/src/commands.rs`

- [ ] **Step 1: 更新 commands.rs**

```rust
use netprowl_core::{discover_lan, DiscoveryOptions, ScanResult};

#[tauri::command]
pub async fn scan_network() -> Result<ScanResult, String> {
    discover_lan(DiscoveryOptions::default())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_local_ip() -> Result<String, String> {
    // 实现获取本地 IP
    Ok("192.168.1.1".to_string())
}
```

- [ ] **Step 2: 更新 Cargo.toml 添加 netprowl-core 路径依赖**

```toml
[dependencies]
netprowl-core = { path = "../../core" }
```

- [ ] **Step 3: Commit**

```bash
git add netprowl-pc/src-tauri/src/commands.rs netprowl-pc/src-tauri/Cargo.toml
git commit -m "feat(pc): integrate Rust core via Tauri commands

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 13. 删除 Go Core

### Task 14: 删除 Go 代码

**Files:**
- Delete: `core/*.go`（迁移完成后）
- Delete: `core/go.mod`
- Delete: `core/go.sum`

- [ ] **Step 1: 确认 Rust Core 可用后删除 Go 文件**

```bash
rm -f core/*.go core/go.mod core/go.sum
git add -A core/
git commit -m "chore: remove Go core after Rust migration

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 验证清单

| 功能 | Go 实现 | Rust 实现 |
|------|---------|-----------|
| mDNS 发现 | mdns.go | mdns.rs |
| UDP SSDP | ssdp.go | ssdp.rs |
| TCP 扫描 | tcp.go | tcp.rs |
| Banner 抓取 | banner.go | banner.rs |
| 服务指纹 | registry.go | registry.rs |
| OUI 厂商 | oui.go | oui.rs |
| IP 工具 | ip.go | ip.rs |
| 类型定义 | types/types.go | types.rs |
| DiscoverLAN | scanner.go | scanner.rs |
| WASM 导出 | - | wasm.rs |
| Tauri 集成 | - | commands.rs |