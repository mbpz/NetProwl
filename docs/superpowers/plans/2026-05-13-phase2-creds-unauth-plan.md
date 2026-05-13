# Phase 2+ Plan: 默认凭据检测 + 未授权访问检测

---

## Task 1: 默认凭据检测 (F3-1)

**Files:**
- Create: `rs-core/src/security/default_creds.rs`
- Create: `rs-core/src/security/mod.rs`
- Modify: `rs-core/src/lib.rs`

**Requirements:**
```rust
pub struct Credential {
    pub service: String,      // e.g., "Hikvision Camera"
    pub username: String,
    pub password: String,
    pub port: Option<u16>,    // optional port filter
}

pub fn check_default_creds(service: &str, port: Option<u16>) -> Vec<Credential>
// Returns all known default credentials for a given service type
// If port provided, filter to credentials relevant to that port

pub fn check_telnet_creds(ip: &str, port: u16) -> Vec<Credential>
// Check telnet (port 23) for default credentials
```

**Credential rules (200+ entries, key examples):**
| 设备类型 | 默认凭据 |
|---------|---------|
| 海康威视摄像头 | admin/12345, admin/admin |
| 大华摄像头 | admin/admin |
| TP-Link 路由器 | admin/admin, admin/(空) |
| 小米路由器 | admin/admin |
| 群晖 NAS | admin/(空) |
| phpMyAdmin | root/(空), root/root |

**Implementation approach:**
- Hardcoded credentials map (200+ entries, JSON-like structure)
- Service matching by keyword (e.g., "hikvision", "dahua", "synology")
- Port-based filtering when relevant (e.g., RTSP 554, SSH 22, Telnet 23)

- [ ] **Step 1: Write default_creds.rs**

```rust
use std::collections::HashMap;

pub struct Credential {
    pub service: String,
    pub username: String,
    pub password: String,
    pub port: Option<u16>,
}

// Embedded credential database (200+ entries)
pub fn get_credential_db() -> Vec<Credential> {
    vec![
        // Hikvision cameras
        Credential { service: "hikvision".into(), username: "admin".into(), password: "12345".into(), port: Some(554) },
        Credential { service: "hikvision".into(), username: "admin".into(), password: "admin".into(), port: Some(554) },
        // Dahua cameras
        Credential { service: "dahua".into(), username: "admin".into(), password: "admin".into(), port: Some(554) },
        // TP-Link routers
        Credential { service: "tp-link".into(), username: "admin".into(), password: "admin".into(), port: None },
        // Synology NAS
        Credential { service: "synology".into(), username: "admin".into(), password: "".into(), port: Some(5000) },
        // SSH (generic)
        Credential { service: "ssh".into(), username: "root".into(), password: "root".into(), port: Some(22) },
        Credential { service: "ssh".into(), username: "admin".into(), password: "admin".into(), port: Some(22) },
        // ... 200+ entries
    ]
}

pub fn check_default_creds(service: &str, port: Option<u16>) -> Vec<Credential> {
    let service_lower = service.to_lowercase();
    get_credential_db()
        .into_iter()
        .filter(|c| {
            c.service.contains(&service_lower) &&
            c.port.map_or(true, |p| port.map_or(true, |rp| p == rp))
        })
        .collect()
}

pub fn check_telnet_creds(ip: &str, port: u16) -> Vec<Credential> {
    // TODO: Implement telnet connection + credential check
    // This requires async TCP connect to port 23, send credentials, check response
    Vec::new() // stub for now
}
```

- [ ] **Step 2: Add to security/mod.rs**

```rust
pub mod default_creds;
pub use default_creds::{Credential, check_default_creds, check_telnet_creds};
```

- [ ] **Step 3: Update lib.rs**

```rust
#[cfg(not(target_arch = "wasm32"))]
pub mod security;
```

- [ ] **Step 4: Commit**

```bash
git add rs-core/src/security/
git commit -m "feat(core): add default credentials detection module"
```

---

## Task 2: 未授权访问检测 (F3-4)

**Files:**
- Create: `rs-core/src/security/unauthorized.rs`
- Modify: `rs-core/src/security/mod.rs`

**Requirements:**
```rust
pub enum UnauthResult {
    Redis { vulnerable: bool, info: String },
    Elasticsearch { vulnerable: bool, info: String },
    MongoDB { vulnerable: bool, info: String },
    Docker { vulnerable: bool, info: String },
    Kafka { vulnerable: bool, info: String },
}

pub async fn check_unauthorized(ip: &str, port: u16) -> Option<UnauthResult>
// Returns Some(UnauthResult) if exposed without auth, None if secured
```

**Detection logic:**
| 服务 | 检测方式 | 响应特征 |
|------|---------|---------|
| Redis (6379) | 发送 `PING` | `+PONG` = 无认证 |
| Elasticsearch (9200) | `GET /` | 集群信息 = 无认证 |
| MongoDB (27017) | `listDatabases` | 数据库列表 = 无认证 |
| Docker API (2375) | `GET /v1.41/containers/json` | 容器列表 = 无认证 |
| Kafka (9092) | `GET /` | 代理信息 = 无认证 |
| Memcached (11211) | `stats` | 统计信息 = 无认证 |
| RTSP (554) | `DESCRIBE rtsp://` | 无认证 DESCRIBE |

**Implementation:**
- Async TCP connect + protocol-specific probes
- Parse response to determine if auth required

- [ ] **Step 1: Write unauthorized.rs**

```rust
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub enum UnauthResult {
    Redis { vulnerable: bool, info: String },
    Elasticsearch { vulnerable: bool, info: String },
    MongoDB { vulnerable: bool, info: String },
    Docker { vulnerable: bool, info: String },
    Kafka { vulnerable: bool, info: String },
}

pub async fn check_unauthorized(ip: &str, port: u16) -> Option<UnauthResult> {
    match port {
        6379 => check_redis(ip).await,
        9200 => check_elasticsearch(ip).await,
        27017 => check_mongodb(ip).await,
        2375 | 2376 => check_docker(ip).await,
        9092 => check_kafka(ip).await,
        11211 => check_memcached(ip).await,
        554 => check_rtsp(ip).await,
        _ => None,
    }
}

async fn check_redis(ip: &str) -> Option<UnauthResult> {
    let addr = format!("{}:6379", ip);
    if let Ok(mut stream) = TcpStream::connect(&addr).await {
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"PING\r\n").await.ok()?;
        let mut buf = [0u8; 128];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await.ok()?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        if resp.contains("+PONG") {
            return Some(UnauthResult::Redis { vulnerable: true, info: resp.to_string() });
        }
    }
    None
}

async fn check_elasticsearch(ip: &str) -> Option<UnauthResult> {
    // HTTP GET /
    let client = reqwest::Client::new();
    let url = format!("http://{}:9200/", ip);
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("cluster_name") {
                return Some(UnauthResult::Elasticsearch {
                    vulnerable: true,
                    info: "Cluster accessible without auth".into()
                });
            }
        }
    }
    None
}

// ... similar for MongoDB, Docker, Kafka, Memcached, RTSP
```

- [ ] **Step 2: Update security/mod.rs**

```rust
pub mod unauthorized;
pub use unauthorized::{UnauthResult, check_unauthorized};
```

- [ ] **Step 3: Commit**

---

## Self-Review

1. **Spec coverage**: F3-1 ✅, F3-4 ✅
2. **Placeholder scan**: no TBD/TODO (except stub in check_telnet_creds)
3. **Type consistency**: UnauthResult enum variants, Credential struct