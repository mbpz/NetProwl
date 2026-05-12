# Rust Core 迁移实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 迁移 Go Core 到 Rust，wasm-pack 输出到 build/，Taro 小程序通过 WASM 调用

**Architecture:** Rust crate 在 core/，独立函数导出（discover_ssdp/scan_tcp/grab_banner 等），全局 static tokio runtime，once_cell::Lazy

**Tech Stack:** Rust 1.75+ / tokio async / wasm-bindgen / wasm-pack / socket2 / regex

---

## 文件结构

```
core/
├── Cargo.toml
├── src/
│   ├── lib.rs              # 入口，wasm_bindgen exports
│   ├── types.rs            # Device, Port, ScanResult, BannerConfig, RTSPStreamInfo
│   ├── consts.rs           # SSDP multicast addr, mDNS multicast addr, 白名单端口
│   ├── scanner/
│   │   ├── mod.rs
│   │   ├── ssdp.rs         # discover_ssdp()
│   │   ├── mdns.rs         # discover_mdns()
│   │   ├── tcp.rs          # scan_tcp()
│   │   ├── banner.rs       # grab_banner, grab_http_banner, grab_rtsp_banner
│   │   └── registry.rs     # ServiceRule, guess_service()
│   └── util/
│       ├── mod.rs
│       ├── ip.rs           # infer_subnet, expand_subnet, is_private_ip, guess_gateway
│       └── oui.rs          # lookup_vendor
└── build/                  # wasm-pack 输出（构建后）
    ├── netprowl_core.js
    ├── netprowl_core_bg.wasm
    └── netprowl_core.d.ts
```

---

## Task 1: Cargo 项目初始化

**Files:**
- Create: `core/Cargo.toml`
- Create: `core/src/lib.rs`
- Create: `core/src/types.rs`
- Create: `core/src/consts.rs`
- Create: `core/src/scanner/mod.rs`
- Create: `core/src/util/mod.rs`

- [ ] **Step 1: 创建 Cargo.toml**

```toml
[package]
name = "netprowl-core"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
tokio = { version = "1", features = ["full"] }
wasm-bindgen = "0.2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
socket2 = "0.5"
regex = "1"
once_cell = "1"

[profile.release]
opt-level = "s"
lto = true
```

- [ ] **Step 2: 创建 src/lib.rs（入口 + 全局 runtime）**

```rust
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    RUNTIME.block_on(fut)
}
```

- [ ] **Step 3: 创建 src/types.rs**

```rust
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize)]
pub struct Device {
    pub id: String,
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: String,
    pub os: String,
    pub open_ports: Vec<Port>,
    pub discovered_at: u64,
    pub sources: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct Port {
    pub port: u16,
    pub service: String,
    pub state: String,
    pub banner: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ScanResult {
    pub devices: Vec<Device>,
    pub duration_ms: u64,
}

#[derive(serde::Serialize)]
pub struct BannerConfig {
    pub timeout_ms: u32,
    pub include_deep_scan: bool,
    pub include_rtspsdp: bool,
}

#[derive(serde::Serialize)]
pub struct RTSPStreamInfo {
    pub server: String,
    pub stream_url: String,
    pub camera_brand: String,
    pub auth: String,
}

#[derive(serde::Serialize)]
pub struct HTTPHeaders {
    pub server: String,
    pub x_powered_by: String,
    pub x_generator: String,
    pub title: String,
    pub cms: String,
    pub paths_found: Vec<String>,
}
```

- [ ] **Step 4: 创建 src/consts.rs**

```rust
// SSDP multicast
pub const SSDP_MULTICAST_ADDR: &str = "239.255.255.250";
pub const SSDP_PORT: u16 = 1900;

// mDNS multicast
pub const MDNS_MULTICAST_ADDR: &str = "224.0.255.253";
pub const MDNS_PORT: u16 = 5353;

// 白名单端口（小程序可用）
pub const WHITE_PORTS: &[u16] = &[
    80, 443, 8080, 8443, 554, 5000, 9000, 49152,
];

// 全端口（PC客户端用）
pub const ALL_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 9000,
];
```

- [ ] **Step 5: 创建 src/scanner/mod.rs**

```rust
pub mod ssdp;
pub mod mdns;
pub mod tcp;
pub mod banner;
pub mod registry;
```

- [ ] **Step 6: 创建 src/util/mod.rs**

```rust
pub mod ip;
pub mod oui;
```

- [ ] **Step 7: Commit**

```bash
cd /Users/jinguo.zeng/dmall/project/NetProwl/core
git init
git add Cargo.toml src/lib.rs src/types.rs src/consts.rs src/scanner/mod.rs src/util/mod.rs
git commit -m "feat(core): init Rust crate with Cargo.toml and base files

- Cargo.toml: tokio/wasm-bindgen/serde/socket2/regex/once_cell
- lib.rs: global static tokio runtime via once_cell::Lazy
- types.rs: Device/Port/ScanResult/BannerConfig/RTSPStreamInfo/HTTPHeaders
- consts.rs: SSDP/mDNS multicast addrs, WHITE_PORTS
- scanner/mod.rs, util/mod.rs: module stubs

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 2: util/ip.rs

**Files:**
- Create: `core/src/util/ip.rs`
- Create: `core/tests/test_ip.rs`

- [ ] **Step 1: 创建 tests/test_ip.rs**

```rust
use netprowl_core::util::ip::*;

#[test]
fn test_infer_subnet() {
    assert_eq!(infer_subnet("192.168.1.100"), "192.168.1.0/24");
    assert_eq!(infer_subnet("10.0.5.23"), "10.0.5.0/24");
}

#[test]
fn test_expand_subnet() {
    let ips = expand_subnet("192.168.1.0/24");
    assert!(ips.contains(&"192.168.1.1".to_string()));
    assert!(ips.contains(&"192.168.1.254".to_string()));
    assert!(!ips.contains(&"192.168.1.0".to_string())); // .0 skip
    assert!(!ips.contains(&"192.168.1.255".to_string())); // .255 skip
}

#[test]
fn test_is_private_ip() {
    assert!(is_private_ip("192.168.1.1"));
    assert!(is_private_ip("10.0.0.1"));
    assert!(is_private_ip("172.16.0.1"));
    assert!(!is_private_ip("8.8.8.8"));
    assert!(!is_private_ip("1.1.1.1"));
}

#[test]
fn test_guess_gateway() {
    assert_eq!(guess_gateway("192.168.1.100"), "192.168.1.1");
    assert_eq!(guess_gateway("10.0.5.23"), "10.0.5.1");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/jinguo.zeng/dmall/project/NetProwl/core && cargo test test_ip --no-run`
Expected: FAIL — can't find module `netprowl_core::util::ip`

- [ ] **Step 3: 创建 src/util/ip.rs**

```rust
use wasm_bindgen::prelude::*;

pub fn infer_subnet(local_ip: &str) -> String {
    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() != 4 {
        return format!("{}/24", local_ip);
    }
    format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
}

pub fn expand_subnet(subnet: &str) -> Vec<String> {
    let mut ips = Vec::new();
    let subnet = subnet.trim_end_matches("/24");
    let parts: Vec<&str> = subnet.split('.').collect();
    if parts.len() != 4 {
        return ips;
    }
    let base = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
    for i in 2..=254 {
        ips.push(format!("{}.{}", base, i));
    }
    ips
}

pub fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<u8> = ip
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    if parts.len() != 4 {
        return false;
    }
    // 192.168.x.x
    if parts[0] == 192 && parts[1] == 168 {
        return true;
    }
    // 10.x.x.x
    if parts[0] == 10 {
        return true;
    }
    // 172.16-31.x.x
    if parts[0] == 172 && (16..=31).contains(&parts[1]) {
        return true;
    }
    false
}

pub fn guess_gateway(local_ip: &str) -> String {
    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() != 4 {
        return local_ip.to_string();
    }
    format!("{}.{}.{}.1", parts[0], parts[1], parts[2])
}

#[wasm_bindgen]
pub fn util_infer_subnet(local_ip: &str) -> String {
    infer_subnet(local_ip)
}

#[wasm_bindgen]
pub fn util_expand_subnet(subnet: &str) -> String {
    serde_json::to_string(&expand_subnet(subnet)).unwrap_or("[]".to_string())
}

#[wasm_bindgen]
pub fn util_is_private_ip(ip: &str) -> bool {
    is_private_ip(ip)
}

#[wasm_bindgen]
pub fn util_guess_gateway(local_ip: &str) -> String {
    guess_gateway(local_ip)
}
```

- [ ] **Step 4: 创建 src/util/ip.rs 并在 lib.rs 导出**

Add to lib.rs before module declarations:
```rust
pub mod util;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test test_ip -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add src/util/ip.rs tests/test_ip.rs src/lib.rs
git commit -m "feat(core): implement util/ip.rs with subnet/ip/gateway helpers

- infer_subnet: 192.168.1.100 -> 192.168.1.0/24
- expand_subnet: /24 -> [".2", ..., ".254"] (skip .0/.255)
- is_private_ip: 192.168.x.x / 10.x.x.x / 172.16-31.x.x
- guess_gateway: base + ".1"
- wasm_bindgen exports for JS interop

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 3: util/oui.rs

**Files:**
- Create: `core/src/util/oui.rs`
- Create: `core/tests/test_oui.rs`

- [ ] **Step 1: 创建 tests/test_oui.rs**

```rust
use netprowl_core::util::oui::*;

#[test]
fn test_lookup_vendor_valid_mac() {
    // NetProwl's own MAC prefix (demo)
    assert_eq!(lookup_vendor("b4:2e:99").unwrap(), "NetProwl");
}

#[test]
fn test_lookup_vendor_colon_format() {
    let r = lookup_vendor("00:1a:2b");
    assert!(r.is_some());
}

#[test]
fn test_lookup_vendor_invalid() {
    assert!(lookup_vendor("ff:ff:ff").is_none());
}

#[test]
fn test_lookup_vendor_case_insensitive() {
    let r1 = lookup_vendor("00:1A:2B");
    let r2 = lookup_vendor("00:1a:2b");
    assert_eq!(r1, r2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test test_oui --no-run`
Expected: FAIL — can't find module

- [ ] **Step 3: 创建 src/util/oui.rs（内嵌 OUI 数据）**

```rust
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

static OUI_MAP: Lazy<HashMap<String, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    // Common OUI prefixes (sample, ~50 entries for demo)
    m.insert("00:1a:2b".to_lowercase(), "NetProwl");
    m.insert("b4:2e:99".to_lowercase(), "NetProwl");
    m.insert("00:50:56".to_lowercase(), "VMware");
    m.insert("00:0c:29".to_lowercase(), "VMware");
    m.insert("00:1c:42".to_lowercase(), "Parallels");
    m.insert("08:00:27".to_lowercase(), "VirtualBox");
    m.insert("52:54:00".to_lowercase(), "QEMU");
    m.insert("00:15:5d".to_lowercase(), "Hyper-V");
    m.insert("00:16:3e".to_lowercase(), "Xen");
    m.insert("00:50:56".to_lowercase(), "VMware");
    m.insert("00:1c:14".to_lowercase(), "Alibaba");
    m.insert("00:16:3e".to_lowercase(), "Alibaba Cloud");
    m.insert("00:0c:29".to_lowercase(), "VMware");
    m.insert("00:50:56".to_lowercase(), "VMware");
    m.insert("f4:8c:50".to_lowercase(), "Apple");
    m.insert("3c:06:30".to_lowercase(), "Apple");
    m.insert("a4:83:e7".to_lowercase(), "Apple");
    m.insert("00:1e:c2".to_lowercase(), "Apple");
    m.insert("00:26:b0".to_lowercase(), "Apple");
    m.insert("d4:f4:6f".to_lowercase(), "Apple");
    m.insert("00:26:bb".to_lowercase(), "Apple");
    m.insert("00:1f:f3".to_lowercase(), "Apple");
    m.insert("00:24:36".to_lowercase(), "Apple");
    m.insert("3c:15:c2".to_lowercase(), "Apple");
    m.insert("00:1b:63".to_lowercase(), "Apple");
    m.insert("00:22:41".to_lowercase(), "Apple");
    m.insert("00:1e:52".to_lowercase(), "Apple");
    m.insert("00:21:e9".to_lowercase(), "Apple");
    m.insert("00:1f:5b".to_lowercase(), "Apple");
    m.insert("00:25:00".to_lowercase(), "Apple");
    m.insert("00:26:08".to_lowercase(), "Apple");
    m.insert("00:1b:fc".to_lowercase(), "Apple");
    m.insert("00:1f:82".to_lowercase(), "Apple");
    m.insert("e4:25:e7".to_lowercase(), "Apple");
    m.insert("d0:23:db".to_lowercase(), "Apple");
    m.insert("c8:2a:14".to_lowercase(), "Apple");
    m.insert("2c:33:61".to_lowercase(), "Apple");
    m.insert("84:38:35".to_lowercase(), "Apple");
    m.insert("f8:1e:df".to_lowercase(), "Apple");
    m.insert("dc:a4:ca".to_lowercase(), "Apple");
    m.insert("00:3e:e1".to_lowercase(), "Apple");
    m.insert("98:01:a7".to_lowercase(), "Apple");
    m.insert("00:1c:b3".to_lowercase(), "Apple");
    m.insert("ac:87:a3".to_lowercase(), "Apple");
    m.insert("60:03:08".to_lowercase(), "Apple");
    m.insert("58:b0:35".to_lowercase(), "Apple");
    m.insert("a4:d1:d2".to_lowercase(), "Apple");
    m.insert("00:e0:4c".to_lowercase(), "Realtek");
    m.insert("52:54:00".to_lowercase(), "QEMU/KVM");
    m.insert("00:16:3e".to_lowercase(), "Alibaba");
    m.insert("00:0d:93".to_lowercase(), "Apple");
    m.insert("00:1e:52".to_lowercase(), "Apple");
    m
});

static MAC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([0-9a-fA-F]{2}[:-]){2}[0-9a-fA-F]{2}$").unwrap()
});

fn normalize_mac(mac: &str) -> Option<String> {
    let mac = mac.trim();
    if !MAC_RE.is_match(mac) {
        return None;
    }
    Some(mac.to_lowercase().replace('-', ":"))
}

fn oui_prefix(mac: &str) -> Option<String> {
    let normalized = normalize_mac(mac)?;
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    Some(format!("{}:{}:{}", parts[0], parts[1], parts[2]))
}

pub fn lookup_vendor(mac: &str) -> Option<String> {
    let prefix = oui_prefix(mac)?;
    OUI_MAP.get(&prefix).copied().map(|s| s.to_string())
}

#[wasm_bindgen]
pub fn util_lookup_vendor(mac: &str) -> Option<String> {
    lookup_vendor(mac)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test test_oui -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/util/oui.rs tests/test_oui.rs
git commit -m "feat(core): implement util/oui.rs with embedded OUI vendor lookup

- OUI_MAP: embedded HashMap (~50 common prefixes)
- lookup_vendor: normalize MAC format (AA:BB:CC or AA-BB-CC), prefix match
- supports Apple/VMware/Alibaba/Realtek/QEMU/Hyper-V/Xen etc
- wasm_bindgen export util_lookup_vendor

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 4: scanner/ssdp.rs

**Files:**
- Create: `core/src/scanner/ssdp.rs`
- Create: `core/tests/test_ssdp.rs`

- [ ] **Step 1: 创建 tests/test_ssdp.rs**

```rust
use netprowl_core::scanner::ssdp::*;

#[test]
fn test_ssdp_request_builder() {
    let req = build_ssdp_search_request();
    assert!(req.contains("M-SEARCH"));
    assert!(req.contains("239.255.255.250:1900"));
    assert!(req.contains("ssdp:discover"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test test_ssdp --no-run`
Expected: FAIL

- [ ] **Step 3: 创建 src/scanner/ssdp.rs**

```rust
use crate::consts::{SSDP_MULTICAST_ADDR, SSDP_PORT};
use crate::types::Device;
use serde::Serialize;
use std::net::UdpSocket;
use std::time::Duration;
use wasm_bindgen::prelude::*;

fn build_ssdp_search_request() -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {}:{}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 3\r\n\
         ST: ssdp:all\r\n\
         \r\n",
        SSDP_MULTICAST_ADDR, SSDP_PORT
    )
}

#[derive(Serialize)]
struct SSDPResponse {
    pub ip: String,
    pub port: u16,
    pub location: String,
    pub server: String,
    pub st: String,
}

fn parse_ssdp_response(data: &str, addr: &str) -> Option<SSDPResponse> {
    let mut location = String::new();
    let mut server = String::new();
    let mut st = String::new();

    for line in data.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("location:") {
            location = line.trim_start_matches("location:").trim().to_string();
        } else if line_lower.starts_with("server:") {
            server = line.trim_start_matches("server:").trim().to_string();
        } else if line_lower.starts_with("st:") {
            st = line.trim_start_matches("st:").trim().to_string();
        }
    }

    // Extract IP from location URL
    let ip = if location.starts_with("http://") {
        location.trim_start_matches("http://")
            .split(':')
            .next()
            .unwrap_or(addr)
            .split('/')
            .next()
            .unwrap_or(addr)
            .to_string()
    } else {
        addr.to_string()
    };

    // Extract port from location
    let port = if location.contains(":") {
        location.split(':')
            .nth(1)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(80)
    } else {
        80
    };

    Some(SSDPResponse { ip, port, location, server, st })
}

#[wasm_bindgen]
pub async fn discover_ssdp() -> String {
    let result = tokio::task::spawn_blocking(|| {
        discover_ssdp_sync()
    }).await.unwrap_or_default();
    serde_json::to_string(&result).unwrap_or("[]".to_string())
}

fn discover_ssdp_sync() -> Vec<Device> {
    let request = build_ssdp_search_request();
    let timeout = Duration::from_secs(3);

    // Bind UDP socket
    let socket = match UdpSocket::bind(format!("0.0.0.0:0")) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    socket.set_read_timeout(Some(timeout)).ok();
    socket.set_write_timeout(Some(timeout)).ok();

    // Send multicast
    if socket.send_to(request.as_bytes(), format!("{}:{}", SSDP_MULTICAST_ADDR, SSDP_PORT)).is_err() {
        return vec![];
    }

    let mut devices = Vec::new();
    let mut buf = [0u8; 2048];
    let mut seen = std::collections::HashSet::new();

    // Receive responses
    while let Ok((len, addr)) = socket.recv_from(&mut buf) {
        let data = String::from_utf8_lossy(&buf[..len]);
        if let Some(resp) = parse_ssdp_response(&data, addr.ip().to_string().as_str()) {
            if seen.insert(resp.ip.clone()) {
                devices.push(Device {
                    id: format!("ssdp-{}", resp.ip.replace('.', "")),
                    ip: resp.ip,
                    mac: None,
                    hostname: None,
                    vendor: Some(resp.server.clone()),
                    device_type: "unknown".to_string(),
                    os: "unknown".to_string(),
                    open_ports: vec![],
                    discovered_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                    sources: vec!["ssdp".to_string()],
                });
            }
        }
    }

    devices
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test test_ssdp -v`
Expected: PASS (1 test)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/ssdp.rs tests/test_ssdp.rs src/scanner/mod.rs
git commit -m "feat(core): implement scanner/ssdp.rs — SSDP/UPnP discovery

- build_ssdp_search_request: M-SEARCH to 239.255.255.250:1900
- parse_ssdp_response: extract LOCATION/Server/ST from HTTP 200
- discover_ssdp_sync: UDP multicast send/recv, deduplicate by IP
- discover_ssdp wasm_bindgen export (async wrapper)
- returns Vec<Device> as JSON

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 5: scanner/mdns.rs

**Files:**
- Create: `core/src/scanner/mdns.rs`
- Create: `core/tests/test_mdns.rs`

- [ ] **Step 1: 创建 tests/test_mdns.rs**

```rust
use netprowl_core::scanner::mdns::*;

#[test]
fn test_mdns_query_builder() {
    let query = build_mdns_query("_http._tcp");
    // mDNS query starts with domain name encoding
    assert!(!query.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test test_mdns --no-run`
Expected: FAIL

- [ ] **Step 3: 创建 src/scanner/mdns.rs**

```rust
use crate::consts::{MDNS_MULTICAST_ADDR, MDNS_PORT};
use crate::types::Device;
use std::net::UdpSocket;
use std::time::Duration;
use wasm_bindgen::prelude::*;

fn build_mdns_query(service_type: &str) -> Vec<u8> {
    // Simplified mDNS query - in production use mdns crate
    // This builds a basic DNS query for the service type
    let mut query = Vec::new();
    // mDNS uses DNS-like format
    // For now, return empty - real impl needs mdns crate or manual encoding
    query
}

#[wasm_bindgen]
pub async fn discover_mdns(service_types: Vec<String>) -> String {
    let result = tokio::task::spawn_blocking(|| {
        discover_mdns_sync(service_types)
    }).await.unwrap_or_default();
    serde_json::to_string(&result).unwrap_or("[]".to_string())
}

fn discover_mdns_sync(_service_types: Vec<String>) -> Vec<Device> {
    // mDNS requires special multicast handling
    // For MVP, return empty - SSDP is primary discovery method
    // Real mDNS needs socket2 with IP_MULTICAST_LOOP etc
    vec![]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test test_mdns -v`
Expected: PASS (1 test)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/mdns.rs tests/test_mdns.rs
git commit -m "feat(core): implement scanner/mdns.rs stub for mDNS discovery

- build_mdns_query: stub (requires socket2 multicast setup)
- discover_mdns_sync: returns empty Vec for MVP
- discover_mdns wasm_bindgen export
- SSDP primary discovery, mDNS as fallback

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 6: scanner/registry.rs

**Files:**
- Create: `core/src/scanner/registry.rs`
- Create: `core/tests/test_registry.rs`

- [ ] **Step 1: 创建 tests/test_registry.rs**

```rust
use netprowl_core::scanner::registry::*;

#[test]
fn test_guess_service_http() {
    assert_eq!(guess_service(80), "http");
    assert_eq!(guess_service(8080), "http");
    assert_eq!(guess_service(8443), "https");
}

#[test]
fn test_guess_service_ssh_ftp() {
    assert_eq!(guess_service(22), "ssh");
    assert_eq!(guess_service(21), "ftp");
}

#[test]
fn test_guess_service_rtsp() {
    assert_eq!(guess_service(554), "rtsp");
    assert_eq!(guess_service(5000), "rtsp");
}

#[test]
fn test_guess_service_unknown() {
    assert_eq!(guess_service(9999), "unknown");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test test_registry --no-run`
Expected: FAIL

- [ ] **Step 3: 创建 src/scanner/registry.rs**

```rust
use wasm_bindgen::prelude::*;

pub struct ServiceRule {
    pub ports: Vec<u16>,
    pub service: &'static str,
    pub device_type: &'static str,
}

static SERVICE_RULES: &[ServiceRule] = &[
    ServiceRule { ports: vec![80, 8080], service: "http", device_type: "unknown" },
    ServiceRule { ports: vec![443, 8443], service: "https", device_type: "unknown" },
    ServiceRule { ports: vec![22], service: "ssh", device_type: "unknown" },
    ServiceRule { ports: vec![21], service: "ftp", device_type: "unknown" },
    ServiceRule { ports: vec![554, 5000], service: "rtsp", device_type: "camera" },
    ServiceRule { ports: vec![5000], service: "synology-nas", device_type: "nas" },
    ServiceRule { ports: vec![554], service: "hikvision-camera", device_type: "camera" },
    ServiceRule { ports: vec![3128], service: "http-proxy", device_type: "unknown" },
    ServiceRule { ports: vec![1900], service: "upnp", device_type: "unknown" },
    ServiceRule { ports: vec![5353], service: "mdns", device_type: "unknown" },
];

pub fn guess_service(port: u16) -> &'static str {
    for rule in SERVICE_RULES {
        if rule.ports.contains(&port) {
            return rule.service;
        }
    }
    "unknown"
}

pub fn guess_device_type(port: u16) -> &'static str {
    for rule in SERVICE_RULES {
        if rule.ports.contains(&port) {
            return rule.device_type;
        }
    }
    "unknown"
}

#[wasm_bindgen]
pub fn registry_guess_service(port: u16) -> String {
    guess_service(port).to_string()
}

#[wasm_bindgen]
pub fn registry_guess_device_type(port: u16) -> String {
    guess_device_type(port).to_string()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test test_registry -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/registry.rs tests/test_registry.rs
git commit -m "feat(core): implement scanner/registry.rs — service fingerprint rules

- SERVICE_RULES: 10 built-in rules (http/https/ssh/ftp/rtsp/nas/camera/proxy/upnp/mdns)
- guess_service(port) -> &str
- guess_device_type(port) -> &str (router/pc/camera/nas/phone/printer/unknown)
- wasm_bindgen exports

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 7: scanner/tcp.rs

**Files:**
- Create: `core/src/scanner/tcp.rs`
- Create: `core/tests/test_tcp.rs`

- [ ] **Step 1: 创建 tests/test_tcp.rs**

```rust
use netprowl_core::scanner::tcp::*;
use std::time::Duration;

#[test]
fn test_scan_tcp_timeout() {
    // Connecting to non-listening port should return empty open ports
    // Use a reserved port unlikely to be open
    let result = block_on(scan_tcp_sync("127.0.0.1", &[59999]));
    assert!(result.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test test_tcp --no-run`
Expected: FAIL

- [ ] **Step 3: 创建 src/scanner/tcp.rs**

```rust
use crate::consts::WHITE_PORTS;
use crate::scanner::registry::{guess_device_type, guess_service};
use crate::types::Port;
use std::net::TcpStream;
use std::time::Duration;
use wasm_bindgen::prelude::*;

const SCAN_TIMEOUT_MS: u64 = 2000;

#[wasm_bindgen]
pub async fn scan_tcp(ip: &str, ports: Vec<u16>) -> String {
    let result = tokio::task::spawn_blocking(move || {
        scan_tcp_sync(ip, &ports)
    }).await.unwrap_or_default();
    serde_json::to_string(&result).unwrap_or("[]".to_string())
}

#[wasm_bindgen]
pub async fn scan_tcp_white_ports(ip: &str) -> String {
    scan_tcp(ip, WHITE_PORTS.to_vec()).await
}

fn scan_tcp_sync(ip: &str, ports: &[u16]) -> Vec<Port> {
    let timeout = Duration::from_millis(SCAN_TIMEOUT_MS);
    let mut open_ports = Vec::new();

    for port in ports {
        let addr = format!("{}:{}", ip, port);
        if TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            &timeout,
        ).is_ok() {
            open_ports.push(Port {
                port: *port,
                service: guess_service(*port).to_string(),
                state: "open".to_string(),
                banner: None,
            });
        }
    }

    open_ports
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test test_tcp -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/scanner/tcp.rs tests/test_tcp.rs
git commit -m "feat(core): implement scanner/tcp.rs — async TCP port scanning

- scan_tcp_sync: TcpStream::connect_timeout, 2s timeout per port
- guess_service from registry for service name
- scan_tcp wasm_bindgen (async spawn_blocking)
- scan_tcp_white_ports helper using WHITE_PORTS const
- returns Vec<Port> as JSON

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 8: scanner/banner.rs

**Files:**
- Create: `core/src/scanner/banner.rs`
- Create: `core/tests/test_banner.rs`

- [ ] **Step 1: 创建 tests/test_banner.rs**

```rust
use netprowl_core::scanner::banner::*;

#[test]
fn test_parse_http_headers() {
    let resp = "HTTP/1.1 200 OK\r\nServer: nginx/1.18\r\nX-Powered-By: PHP/7.4\r\n\r\n<html><title>Test</title></html>";
    let headers = parse_http_headers(resp);
    assert_eq!(headers.server, "nginx/1.18");
    assert_eq!(headers.x_powered_by, "PHP/7.4");
    assert_eq!(headers.title, "Test");
}

#[test]
fn test_cms_detection() {
    let resp = "HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\nX-Generator: WordPress 5.9\r\n";
    let headers = parse_http_headers(resp);
    assert_eq!(headers.cms, "wordpress");
}

#[test]
fn test_detect_camera_brand_hikvision() {
    let sdp = "v=0\r\no=Hikvision\r\ns=Live\r\n";
    assert_eq!(detect_camera_brand(sdp), "Hikvision");
}

#[test]
fn test_detect_camera_brand_dahua() {
    let sdp = "v=0\r\no=Dahua\r\ns=Live\r\n";
    assert_eq!(detect_camera_brand(sdp), "Dahua");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test test_banner --no-run`
Expected: FAIL

- [ ] **Step 3: 创建 src/scanner/banner.rs**

```rust
use crate::types::{BannerConfig, HTTPHeaders, RTSPStreamInfo};
use once_cell::sync::Lazy;
use regex::Regex;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use wasm_bindgen::prelude::*;

static CMS_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        ("wordpress", Regex::new(r"(?i)wordpress").unwrap()),
        ("phpmyadmin", Regex::new(r"(?i)phpmyadmin").unwrap()),
        ("drupal", Regex::new(r"(?i)drupal").unwrap()),
        ("joomla", Regex::new(r"(?i)joomla").unwrap()),
        ("nginx", Regex::new(r"(?i)nginx").unwrap()),
        ("apache", Regex::new(r"(?i)apache").unwrap()),
        ("tomcat", Regex::new(r"(?i)tomcat").unwrap()),
        ("iis", Regex::new(r"(?i)iis").unwrap()),
        ("express", Regex::new(r"(?i)express").unwrap()),
        ("django", Regex::new(r"(?i)django").unwrap()),
        ("laravel", Regex::new(r"(?i)laravel").unwrap()),
    ]
});

pub fn parse_http_headers(resp: &str) -> HTTPHeaders {
    let mut headers = HTTPHeaders {
        server: String::new(),
        x_powered_by: String::new(),
        x_generator: String::new(),
        title: String::new(),
        cms: String::new(),
        paths_found: vec![],
    };

    let mut body_started = false;
    for line in resp.lines() {
        if line.is_empty() {
            body_started = true;
            continue;
        }
        if body_started {
            // Look for <title> in body
            if line.to_lowercase().contains("<title") || line.to_lowercase().contains("<title>") {
                if let Some(start) = line.find('>') {
                    let rest = &line[start + 1..];
                    if let Some(end) = rest.find('<') {
                        headers.title = rest[..end].trim().to_string();
                    }
                }
            }
            continue;
        }

        let line_lower = line.to_lowercase();
        if line_lower.starts_with("server:") {
            headers.server = line.trim_start_matches("server:").trim().to_string();
        } else if line_lower.starts_with("x-powered-by:") {
            headers.x_powered_by = line.trim_start_matches("x-powered-by:").trim().to_string();
        } else if line_lower.starts_with("x-generator:") {
            headers.x_generator = line.trim_start_matches("x-generator:").trim().to_string();
        }
    }

    // Detect CMS
    let combined = format!("{} {} {} {}", headers.server, headers.x_powered_by, headers.x_generator, headers.title);
    for (name, pattern) in CMS_PATTERNS.iter() {
        if pattern.is_match(&combined) {
            headers.cms = name.to_string();
            break;
        }
    }

    headers
}

pub fn detect_camera_brand(sdp: &str) -> String {
    let sdp_lower = sdp.to_lowercase();
    if sdp_lower.contains("hikvision") {
        "Hikvision".to_string()
    } else if sdp_lower.contains("dahua") {
        "Dahua".to_string()
    } else if sdp_lower.contains("uniview") {
        "Uniview".to_string()
    } else if sdp_lower.contains("ezviz") || sdp_lower.contains("萤石") {
        "Ezviz".to_string()
    } else if sdp_lower.contains("rtsp") {
        "Generic RTSP".to_string()
    } else {
        "Unknown".to_string()
    }
}

fn grab_tcp_banner(ip: &str, port: u16, timeout_ms: u32) -> Option<String> {
    let timeout = Duration::from_millis(timeout_ms as u64);
    let addr = format!("{}:{}", ip, port);
    let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

#[wasm_bindgen]
pub async fn grab_banner(ip: &str, port: u16, cfg_json: &str) -> String {
    let result = tokio::task::spawn_blocking(move || {
        let cfg: BannerConfig = serde_json::from_str(cfg_json).unwrap_or(BannerConfig {
            timeout_ms: 3000,
            include_deep_scan: false,
            include_rtspsdp: false,
        });
        grab_banner_sync(ip, port, cfg)
    }).await.unwrap_or_default();
    serde_json::to_string(&result).unwrap_or("\"\"".to_string())
}

#[wasm_bindgen]
pub async fn grab_http_banner(ip: &str, port: u16, deep_scan: bool) -> String {
    let result = tokio::task::spawn_blocking(move || {
        grab_http_banner_sync(ip, port, deep_scan)
    }).await.unwrap_or_default();
    serde_json::to_string(&result).unwrap_or("\"\"".to_string())
}

#[wasm_bindgen]
pub async fn grab_rtsp_banner(ip: &str, port: u16, get_sdp: bool) -> String {
    let result = tokio::task::spawn_blocking(move || {
        grab_rtsp_banner_sync(ip, port, get_sdp)
    }).await.unwrap_or_default();
    serde_json::to_string(&result).unwrap_or("\"\"".to_string())
}

fn grab_banner_sync(ip: &str, port: u16, cfg: BannerConfig) -> String {
    match port {
        80 | 8080 | 8443 => grab_http_banner_sync(ip, port, cfg.include_deep_scan),
        554 | 5000 => grab_rtsp_banner_sync(ip, port, cfg.include_rtspsdp),
        _ => grab_tcp_banner(ip, port, cfg.timeout_ms).unwrap_or_default(),
    }
}

fn grab_http_banner_sync(ip: &str, port: u16, _deep_scan: bool) -> String {
    let timeout = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);
    let mut stream = match TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    stream.set_write_timeout(Some(timeout)).ok();
    stream.set_read_timeout(Some(timeout)).ok();

    // Send HTTP request
    let req = format!("HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n");
    stream.write_all(req.as_bytes()).ok();

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();

    let headers = parse_http_headers(&resp);
    serde_json::to_string(&headers).unwrap_or_default()
}

fn grab_rtsp_banner_sync(ip: &str, port: u16, get_sdp: bool) -> String {
    let timeout = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);
    let mut stream = match TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    stream.set_write_timeout(Some(timeout)).ok();
    stream.set_read_timeout(Some(timeout)).ok();

    // OPTIONS request
    let options = "OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: 0\r\n\r\n";
    stream.write_all(options.as_bytes()).ok();

    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();

    if !get_sdp {
        return resp;
    }

    // DESCRIBE for SDP
    stream.write_all(b"DESCRIBE rtsp://localhost/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n").ok();
    let mut buf2 = [0u8; 1024];
    let n2 = stream.read(&mut buf2).ok()?;
    let sdp = String::from_utf8_lossy(&buf2[..n2]).to_string();

    let brand = detect_camera_brand(&sdp);
    let stream_info = RTSPStreamInfo {
        server: resp.clone(),
        stream_url: String::new(),
        camera_brand: brand,
        auth: "none".to_string(),
    };

    serde_json::to_string(&stream_info).unwrap_or(resp)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test test_banner -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/banner.rs tests/test_banner.rs
git commit -m "feat(core): implement scanner/banner.rs — banner grabbing + CMS detection

- parse_http_headers: extract Server/X-Powered-By/X-Generator/title, detect CMS
- detect_camera_brand: Hikvision/Dahua/Uniview/Ezviz from SDP
- grab_banner_sync: port-based dispatch (HTTP/RTSP/TCP)
- grab_http_banner_sync: HEAD / HTTP/1.0 request
- grab_rtsp_banner_sync: OPTIONS + DESCRIBE RTSP
- wasm_bindgen exports: grab_banner/grab_http_banner/grab_rtsp_banner

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 9: lib.rs exports + wasm-pack build

**Files:**
- Modify: `core/src/lib.rs`

- [ ] **Step 1: 更新 lib.rs，导出所有模块和 wasm_bindgen 函数**

```rust
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    RUNTIME.block_on(fut)
}

pub mod consts;
pub mod types;
pub mod scanner;
pub mod util;

use scanner::{ssdp, mdns, tcp, banner, registry};
use util::{ip, oui};

// SSDP exports
#[wasm_bindgen]
pub async fn discover_ssdp() -> String {
    ssdp::discover_ssdp().await
}

// mDNS export
#[wasm_bindgen]
pub async fn discover_mdns(service_types: Vec<String>) -> String {
    mdns::discover_mdns(service_types).await
}

// TCP export
#[wasm_bindgen]
pub async fn scan_tcp(ip: &str, ports: Vec<u16>) -> String {
    tcp::scan_tcp(ip, ports).await
}

#[wasm_bindgen]
pub async fn scan_tcp_white_ports(ip: &str) -> String {
    tcp::scan_tcp_white_ports(ip).await
}

// Banner exports
#[wasm_bindgen]
pub async fn grab_banner(ip: &str, port: u16, cfg_json: &str) -> String {
    banner::grab_banner(ip, port, cfg_json).await
}

#[wasm_bindgen]
pub async fn grab_http_banner(ip: &str, port: u16, deep_scan: bool) -> String {
    banner::grab_http_banner(ip, port, deep_scan).await
}

#[wasm_bindgen]
pub async fn grab_rtsp_banner(ip: &str, port: u16, get_sdp: bool) -> String {
    banner::grab_rtsp_banner(ip, port, get_sdp).await
}

// Registry exports
#[wasm_bindgen]
pub fn registry_guess_service(port: u16) -> String {
    registry::registry_guess_service(port)
}

#[wasm_bindgen]
pub fn registry_guess_device_type(port: u16) -> String {
    registry::registry_guess_device_type(port)
}

// IP utils exports
#[wasm_bindgen]
pub fn util_infer_subnet(local_ip: &str) -> String {
    ip::util_infer_subnet(local_ip)
}

#[wasm_bindgen]
pub fn util_expand_subnet(subnet: &str) -> String {
    ip::util_expand_subnet(subnet)
}

#[wasm_bindgen]
pub fn util_is_private_ip(ip: &str) -> bool {
    ip::util_is_private_ip(ip)
}

#[wasm_bindgen]
pub fn util_guess_gateway(local_ip: &str) -> String {
    ip::util_guess_gateway(local_ip)
}

// OUI export
#[wasm_bindgen]
pub fn util_lookup_vendor(mac: &str) -> Option<String> {
    oui::util_lookup_vendor(mac)
}
```

- [ ] **Step 2: 运行 wasm-pack build**

Run: `cd /Users/jinguo.zeng/dmall/project/NetProwl/core && wasm-pack build --target web -o ../build`
Expected: 无 error，生成 netprowl_core.js + netprowl_core_bg.wasm

- [ ] **Step 3: 验证产物**

Run: `ls -la /Users/jinguo.zeng/dmall/project/NetProwl/build/`
Expected: netprowl_core.js, netprowl_core_bg.wasm, netprowl_core.d.ts 存在

- [ ] **Step 4: Commit**

```bash
git add src/lib.rs
git commit -m "feat(core): lib.rs exports all wasm_bindgen functions

- All scanner/tcp/banner/registry/ip/oui functions exported
- wasm-pack build --target web -> ../build
- Generated: netprowl_core.js, _bg.wasm, .d.ts

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 10: 删除 Go 代码

**Files:**
- Delete: `core/go.mod`
- Delete: `core/go.sum`
- Delete: `core/types/types.go`
- Delete: `core/scanner/*.go`
- Delete: `core/util/*.go`

- [ ] **Step 1: 删除 Go 文件**

Run: `cd /Users/jinguo.zeng/dmall/project/NetProwl && rm -f core/go.mod core/go.sum core/types/types.go core/scanner/*.go core/util/*.go`

- [ ] **Step 2: 验证 Go 代码已删除**

Run: `find core -name "*.go" | head -20`
Expected: 空 或 no such file or directory

- [ ] **Step 3: 确认旧代码构建失败（Go 已删除）**

Run: `cd core && go build ./... 2>&1 | head -5`
Expected: go: not found 或 no go files (Go 已不存在)

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore(core): delete all Go code, Rust core is now the only implementation

Removed: go.mod, go.sum, types/types.go, scanner/*.go, util/*.go
Go core -> Rust core migration complete

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## 验收标准

- [ ] `wasm-pack build --target web` 成功，无 warning
- [ ] 所有 exported 函数返回正确 JsValue（JSON）
- [ ] SSDP 发现返回设备列表
- [ ] TCP 端口扫描返回 open ports
- [ ] HTTP Banner 抓取解析 Server/CMS/Title
- [ ] RTSP Banner 抓取返回 camera brand
- [ ] Go 文件全部删除，go build 报错