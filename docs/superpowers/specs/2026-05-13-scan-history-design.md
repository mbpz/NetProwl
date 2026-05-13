# Scan History Design

> **版本**：v1.0
> **日期**：2026-05-13
> **状态**：待评审

---

## 1. 目标

PC 版扫描历史本地存储，支持结构化查询、自动清理、UI 展示。

---

## 2. 技术选型

- **SQLite**: rusqlite（纯 Rust，同步 API）
- **存储路径**: `~/.local/share/netprowl-pc/history.db`
- **配置**: `~/.config/netprowl-pc/config.toml`

---

## 3. 数据库结构

```sql
-- 扫描会话（一次扫描 = 一个 session）
CREATE TABLE scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at INTEGER NOT NULL,    -- unix timestamp
    finished_at INTEGER,
    result_count INTEGER DEFAULT 0,
    has_tls_audit INTEGER DEFAULT 0
);

-- 发现的设备
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    source TEXT,                    -- "masscan" / "nmap" / "mdns" / "ssdp"
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

-- 端口信息
CREATE TABLE ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    state TEXT,                    -- "open" / "closed"
    service TEXT,
    banner TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id),
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- 漏洞结果
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    port_id INTEGER,
    tool TEXT NOT NULL,            -- "nuclei" / "tls" / "testssl"
    vuln_id TEXT NOT NULL,         -- CVE-XXX or internal id
    name TEXT NOT NULL,
    severity TEXT NOT NULL,        -- "critical" / "high" / "medium" / "low"
    description TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id),
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- TLS 审计结果（独立存，字段多）
CREATE TABLE tls_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    port_id INTEGER NOT NULL,
    subject TEXT,
    issuer TEXT,
    not_before TEXT,
    not_after TEXT,
    san TEXT,                      -- JSON array as text
    fingerprint_sha256 TEXT,
    supports_tls10 INTEGER,
    supports_tls11 INTEGER,
    supports_tls12 INTEGER,
    supports_tls13 INTEGER,
    testssl_used INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id),
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- 索引
CREATE INDEX idx_devices_session ON devices(session_id);
CREATE INDEX idx_ports_session ON ports(session_id);
CREATE INDEX idx_vulns_session ON vulnerabilities(session_id);
CREATE INDEX idx_tls_session ON tls_audits(session_id);
```

---

## 4. 清理策略

| 策略 | 配置 | 默认值 |
|------|------|--------|
| 手动清理 | 用户在 UI 点删除 | — |
| 时间过期 | `history_max_days` | 30 天 |
| 空间限制 | `history_max_mb` | 500 MB |

```toml
[history]
max_days = 30
max_mb = 500
```

清理顺序：按 `finished_at` 从最旧开始删，删到满足条件为止。

---

## 5. Rust 层 API

```rust
pub struct ScanSession {
    pub id: i64,
    pub target: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub result_count: i32,
}

pub struct HistoryDb {
    conn: Connection,
}

impl HistoryDb {
    pub fn new(path: &Path) -> Result<Self>;
    pub fn start_session(&mut self, target: &str) -> Result<i64>;
    pub fn end_session(&mut self, id: i64, count: i32) -> Result<()>;
    pub fn insert_device(&mut self, session_id: i64, ip: &str, ...) -> Result<i64>;
    pub fn insert_port(&mut self, session_id: i64, device_id: i64, port: u16, ...) -> Result<i64>;
    pub fn insert_vulnerability(&mut self, session_id: i64, device_id: i64, ...) -> Result<()>;
    pub fn insert_tls_audit(&mut self, session_id: i64, device_id: i64, ...) -> Result<()>;
    pub fn get_sessions(&self, limit: usize, offset: usize) -> Result<Vec<ScanSession>>;
    pub fn get_session_detail(&self, session_id: i64) -> Result<SessionDetail>;
    pub fn delete_session(&mut self, session_id: i64) -> Result<()>;
    pub fn delete_all_sessions(&mut self) -> Result<()>;
    pub fn cleanup(&mut self) -> Result<usize>;  // returns deleted count
}
```

---

## 6. Tauri Commands

```rust
#[tauri::command]
fn start_scan_session(target: String) -> Result<i64, String>;

#[tauri::command]
fn end_scan_session(id: i64, count: i32) -> Result<(), String>;

#[tauri::command]
fn insert_scan_result(result: PipelineResult, session_id: i64) -> Result<(), String>;

#[tauri::command]
fn get_scan_history(limit: usize, offset: usize) -> Result<Vec<ScanSession>, String>;

#[tauri::command]
fn get_session_detail(session_id: i64) -> Result<SessionDetail, String>;

#[tauri::command]
fn delete_scan_session(session_id: i64) -> Result<(), String>;

#[tauri::command]
fn clear_scan_history() -> Result<(), String>;
```

---

## 7. 前端组件

| 组件 | 职责 |
|------|------|
| HistoryDrawer | 侧边 Drawer，宽 400px，显示历史列表 |
| HistoryListItem | 列表项：target + 时间 + 结果数量 + severity badge |
| HistoryDetail | 点击展开：设备树 / 端口 / 漏洞 / TLS 详情 |
| HistorySettings | 清理配置：max_days / max_mb 输入框 |

---

## 8. 验收标准

- [ ] 每次扫描结果存入 SQLite（devices / ports / vulnerabilities）
- [ ] HistoryDrawer 显示历史列表，最新在上
- [ ] 点击列表项展开详情
- [ ] 单条删除 + 清空全部功能
- [ ] 30天过期自动清理
- [ ] 500MB 空间超限自动清理最旧记录
- [ ] 配置项可修改（max_days / max_mb）

---

*规格书版本：v1.0 · NetProwl Scan History*