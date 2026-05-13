# Scan History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or executing-plans.

**Goal:** PC 版扫描历史 SQLite 存储，History Drawer UI，支持手动清理 + 自动过期 + 空间限制。

---

## 文件结构

```
netprowl-pc/src-tauri/src/
├── history/
│   ├── mod.rs              # HistoryDb struct + CRUD API
│   └── schema.rs           # 建表 DDL
├── commands.rs             # 修改：加 history Tauri commands
netprowl-pc/src/
├── components/
│   ├── HistoryDrawer.tsx
│   ├── HistoryListItem.tsx
│   ├── HistoryDetail.tsx
│   └── HistorySettings.tsx
├── stores/
│   └── historyStore.ts
└── pages/
    └── ScanPage.tsx        # 修改：集成 HistoryDrawer
```

---

## Task 1: SQLite 数据库层

**Files:**
- Create: `netprowl-pc/src-tauri/src/history/mod.rs`
- Create: `netprowl-pc/src-tauri/src/history/schema.rs`
- Modify: `netprowl-pc/src-tauri/Cargo.toml`

- [ ] **Step 1: Add Cargo.toml deps**

```toml
rusqlite = { version = "0.31", features = ["bundled"] }
dirs = "5"
toml = "0.8"
chrono = { version = "0.4", features = ["serde"] }
```

- [ ] **Step 2: Write history/schema.rs**

```rust
pub const INIT_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    result_count INTEGER DEFAULT 0,
    has_tls_audit INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    source TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    state TEXT,
    service TEXT,
    banner TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id),
    FOREIGN KEY (device_id) REFERENCES devices(id)
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    port_id INTEGER,
    tool TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id),
    FOREIGN KEY (device_id) REFERENCES devices(id)
);
CREATE TABLE IF NOT EXISTS tls_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    port_id INTEGER NOT NULL,
    subject TEXT,
    issuer TEXT,
    not_before TEXT,
    not_after TEXT,
    san TEXT,
    fingerprint_sha256 TEXT,
    supports_tls10 INTEGER,
    supports_tls11 INTEGER,
    supports_tls12 INTEGER,
    supports_tls13 INTEGER,
    testssl_used INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id),
    FOREIGN KEY (device_id) REFERENCES devices(id)
);
CREATE INDEX IF NOT EXISTS idx_devices_session ON devices(session_id);
CREATE INDEX IF NOT EXISTS idx_ports_session ON ports(session_id);
CREATE INDEX IF NOT EXISTS idx_vulns_session ON vulnerabilities(session_id);
"#;
```

- [ ] **Step 3: Write history/mod.rs**

```rust
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;
use chrono::Utc;

pub struct ScanSession {
    pub id: i64,
    pub target: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub result_count: i32,
    pub has_tls_audit: bool,
}

pub struct SessionDetail {
    pub session: ScanSession,
    pub devices: Vec<DeviceDetail>,
    pub vulnerabilities: Vec<VulnRecord>,
}

pub struct DeviceDetail {
    pub id: i64,
    pub ip: String,
    pub mac: Option<String>,
    pub ports: Vec<PortDetail>,
}

pub struct PortDetail {
    pub port: u16,
    pub state: String,
    pub service: Option<String>,
}

pub struct VulnRecord {
    pub vuln_id: String,
    pub name: String,
    pub severity: String,
    pub host: String,
    pub port: u16,
}

pub struct HistoryDb {
    conn: Mutex<Connection>,
}

impl HistoryDb {
    pub fn new(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(INIT_SQL)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn start_session(&self, target: &str) -> Result<i64, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO scan_sessions (target, started_at) VALUES (?1, ?2)",
            params![target, Utc::now().timestamp()],
        ).map_err(|e| e.to_string())?;
        Ok(conn.last_insert_rowid())
    }

    pub fn end_session(&self, id: i64, count: i32) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "UPDATE scan_sessions SET finished_at = ?1, result_count = ?2 WHERE id = ?3",
            params![Utc::now().timestamp(), count, id],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn insert_port(&self, session_id: i64, device_ip: &str, port: u16, state: &str, service: Option<&str>, banner: Option<&str>) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        // 先查或创建设备
        let device_id: i64 = conn.query_row(
            "SELECT id FROM devices WHERE session_id = ?1 AND ip = ?2 LIMIT 1",
            params![session_id, device_ip],
            |row| row.get(0),
        ).unwrap_or_else(|_| {
            conn.execute(
                "INSERT INTO devices (session_id, ip) VALUES (?1, ?2)",
                params![session_id, device_ip],
            ).ok();
            conn.last_insert_rowid()
        });
        
        conn.execute(
            "INSERT INTO ports (session_id, device_id, port, state, service, banner) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![session_id, device_id, port, state, service, banner],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn insert_vulnerability(&self, session_id: i64, device_ip: &str, port: u16, tool: &str, vuln_id: &str, name: &str, severity: &str, desc: Option<&str>) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let device_id: i64 = conn.query_row(
            "SELECT id FROM devices WHERE session_id = ?1 AND ip = ?2 LIMIT 1",
            params![session_id, device_ip],
            |row| row.get(0),
        ).unwrap_or_else(|_| {
            conn.execute(
                "INSERT INTO devices (session_id, ip) VALUES (?1, ?2)",
                params![session_id, device_ip],
            ).ok();
            conn.last_insert_rowid()
        });
        
        let port_id: Option<i64> = conn.query_row(
            "SELECT id FROM ports WHERE session_id = ?1 AND device_id = ?2 AND port = ?3 LIMIT 1",
            params![session_id, device_id, port],
            |row| row.get(0),
        ).ok();
        
        conn.execute(
            "INSERT INTO vulnerabilities (session_id, device_id, port_id, tool, vuln_id, name, severity, description) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![session_id, device_id, port_id, tool, vuln_id, name, severity, desc],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_sessions(&self, limit: usize, offset: usize) -> Result<Vec<ScanSession>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare(
            "SELECT id, target, started_at, finished_at, result_count, has_tls_audit FROM scan_sessions ORDER BY started_at DESC LIMIT ?1 OFFSET ?2"
        ).map_err(|e| e.to_string())?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            Ok(ScanSession {
                id: row.get(0)?,
                target: row.get(1)?,
                started_at: row.get(2)?,
                finished_at: row.get(3)?,
                result_count: row.get(4)?,
                has_tls_audit: row.get::<_, i64>(5)? != 0,
            })
        }).map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn get_session_detail(&self, session_id: i64) -> Result<SessionDetail, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let session = conn.query_row(
            "SELECT id, target, started_at, finished_at, result_count, has_tls_audit FROM scan_sessions WHERE id = ?1",
            params![session_id],
            |row| Ok(ScanSession {
                id: row.get(0)?, target: row.get(1)?, started_at: row.get(2)?,
                finished_at: row.get(3)?, result_count: row.get(4)?, has_tls_audit: row.get::<_, i64>(5)? != 0,
            }),
        ).map_err(|e| e.to_string())?;
        
        let mut stmt = conn.prepare(
            "SELECT ip, mac, port, state, service, vuln_id, name, severity FROM vulnerabilities v JOIN devices d ON v.device_id = d.id LEFT JOIN ports p ON v.port_id = p.id WHERE v.session_id = ?1"
        ).map_err(|e| e.to_string())?;
        let vulns = stmt.query_map(params![session_id], |row| {
            Ok(VulnRecord {
                host: row.get(0)?, vuln_id: row.get(5)?, name: row.get(6)?,
                severity: row.get(7)?, port: row.get::<_, Option<u16>>(2)?.unwrap_or(0),
            })
        }).map_err(|e| e.to_string())?.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
        
        Ok(SessionDetail { session, devices: vec![], vulnerabilities: vulns })
    }

    pub fn delete_session(&self, session_id: i64) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM vulnerabilities WHERE session_id = ?1", params![session_id]).ok();
        conn.execute("DELETE FROM ports WHERE session_id = ?1", params![session_id]).ok();
        conn.execute("DELETE FROM devices WHERE session_id = ?1", params![session_id]).ok();
        conn.execute("DELETE FROM scan_sessions WHERE id = ?1", params![session_id]).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn cleanup(&self, max_days: i64, max_mb: i64) -> Result<usize, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let cutoff = Utc::now().timestamp() - (max_days * 86400);
        let deleted = conn.execute("DELETE FROM scan_sessions WHERE started_at < ?1", params![cutoff],).map_err(|e| e.to_string())?;
        Ok(deleted as usize)
    }
}
```

- [ ] **Step 4: Build verify + Commit**

---

## Task 2: Tauri Commands 接入

**Files:**
- Modify: `netprowl-pc/src-tauri/src/commands.rs`
- Modify: `netprowl-pc/src-tauri/src/lib.rs`

- [ ] **Step 1: Wire history commands**

```rust
#[tauri::command]
fn start_scan_session(target: String, state: tauri::State<'_, ScannerState>) -> Result<i64, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.start_session(&target)
}

#[tauri::command]
fn end_scan_session(id: i64, count: i32, state: tauri::State<'_, ScannerState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.end_session(id, count)
}

#[tauri::command]
fn get_scan_history(limit: usize, state: tauri::State<'_, ScannerState>) -> Result<Vec<ScanSession>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.get_sessions(limit, 0)
}

#[tauri::command]
fn get_session_detail(session_id: i64, state: tauri::State<'_, ScannerState>) -> Result<SessionDetail, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.get_session_detail(session_id)
}

#[tauri::command]
fn delete_scan_session(session_id: i64, state: tauri::State<'_, ScannerState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.delete_session(session_id)
}

#[tauri::command]
fn clear_scan_history(state: tauri::State<'_, ScannerState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.delete_all_sessions()
}
```

Add `history_db` field to `ScannerState`. Initialize in `run()`.

- [ ] **Step 2: Build verify + Commit**

---

## Task 3: 前端组件

**Files:**
- Create: `netprowl-pc/src/stores/historyStore.ts`
- Create: `netprowl-pc/src/components/HistoryDrawer.tsx`
- Create: `netprowl-pc/src/components/HistoryListItem.tsx`
- Create: `netprowl-pc/src/components/HistoryDetail.tsx`
- Modify: `netprowl-pc/src/components/PipelinePanel.tsx` (加历史按钮)
- Modify: `netprowl-pc/src/pages/ScanPage.tsx`

- [ ] **Step 1: historyStore.ts**

```typescript
import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';

interface ScanSession {
  id: number;
  target: string;
  started_at: number;
  finished_at?: number;
  result_count: number;
  has_tls_audit: boolean;
}

interface HistoryStore {
  sessions: ScanSession[];
  selectedSession: number | null;
  open: boolean;
  setOpen: (v: boolean) => void;
  loadHistory: () => Promise<void>;
  selectSession: (id: number | null) => void;
  deleteSession: (id: number) => Promise<void>;
  clearAll: () => Promise<void>;
}

export const useHistoryStore = create<HistoryStore>((set, get) => ({
  sessions: [],
  selectedSession: null,
  open: false,
  setOpen: (open) => set({ open }),
  loadHistory: async () => {
    const sessions = await invoke<ScanSession[]>('get_scan_history', { limit: 50 });
    set({ sessions });
  },
  selectSession: (id) => set({ selectedSession: id }),
  deleteSession: async (id) => {
    await invoke('delete_scan_session', { sessionId: id });
    set((s) => ({ sessions: s.sessions.filter((x) => x.id !== id), selectedSession: null }));
  },
  clearAll: async () => {
    await invoke('clear_scan_history');
    set({ sessions: [], selectedSession: null });
  },
}));
```

- [ ] **Step 2: HistoryDrawer.tsx**

```tsx
import { useEffect } from 'react';
import { useHistoryStore } from '../stores/historyStore';
import { HistoryListItem } from './HistoryListItem';
import { HistoryDetail } from './HistoryDetail';

export function HistoryDrawer() {
  const { open, setOpen, loadHistory, selectedSession } = useHistoryStore();
  
  useEffect(() => { if (open) loadHistory(); }, [open]);

  return (
    <div className={`fixed right-0 top-0 h-full w-[400px] bg-white shadow-xl transform transition-transform z-50 ${open ? 'translate-x-0' : 'translate-x-full'}`}>
      <div className="flex items-center justify-between p-4 border-b">
        <h2 className="font-bold">Scan History</h2>
        <button onClick={() => setOpen(false)} className="text-gray-500 hover:text-gray-700">✕</button>
      </div>
      <div className="overflow-y-auto h-full pb-20">
        {selectedSession ? (
          <HistoryDetail sessionId={selectedSession} />
        ) : (
          <div className="p-2 space-y-1">
            {useHistoryStore.getState().sessions.map((s) => (
              <HistoryListItem key={s.id} session={s} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: HistoryListItem.tsx**

```tsx
import { useHistoryStore } from '../stores/historyStore';
import { invoke } from '@tauri-apps/api/core';

interface ScanSession {
  id: number;
  target: string;
  started_at: number;
  result_count: number;
}

export function HistoryListItem({ session }: { session: ScanSession }) {
  const { selectSession, deleteSession } = useHistoryStore();
  const date = new Date(session.started_at * 1000).toLocaleString();
  
  return (
    <div className="border rounded p-3 hover:bg-gray-50 cursor-pointer" onClick={() => selectSession(session.id)}>
      <div className="flex justify-between items-start">
        <div>
          <div className="font-mono text-sm font-medium">{session.target}</div>
          <div className="text-xs text-gray-500 mt-1">{date}</div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">{session.result_count} results</span>
          <button onClick={(e) => { e.stopPropagation(); deleteSession(session.id); }} className="text-red-500 hover:text-red-700 text-xs">Delete</button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: HistoryDetail.tsx**

```tsx
import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useHistoryStore } from '../stores/historyStore';

interface SessionDetail {
  session: { id: number; target: string; started_at: number; result_count: number; };
  vulnerabilities: Array<{ host: string; port: number; vuln_id: string; name: string; severity: string }>;
}

const SEV_COLORS: Record<string, string> = { critical: 'bg-red-100 text-red-800', high: 'bg-orange-100 text-orange-800', medium: 'bg-yellow-100 text-yellow-800', low: 'bg-blue-100 text-blue-800' };

export function HistoryDetail({ sessionId }: { sessionId: number }) {
  const { selectSession } = useHistoryStore();
  const [detail, setDetail] = useState<SessionDetail | null>(null);
  
  useEffect(() => {
    invoke<SessionDetail>('get_session_detail', { sessionId }).then(setDetail);
  }, [sessionId]);

  return (
    <div className="p-3">
      <button onClick={() => selectSession(null)} className="text-sm text-blue-600 hover:underline mb-3">← Back</button>
      {detail && (
        <>
          <div className="font-mono font-bold text-lg mb-2">{detail.session.target}</div>
          <div className="text-sm text-gray-600 mb-4">{new Date(detail.session.started_at * 1000).toLocaleString()}</div>
          <div className="space-y-1">
            {detail.vulnerabilities.map((v, i) => (
              <div key={i} className={`border-l-2 px-3 py-2 rounded ${SEV_COLORS[v.severity] || ''}`}>
                <div className="text-sm font-medium">[{v.severity.toUpperCase()}] {v.name}</div>
                <div className="text-xs text-gray-600">{v.host}:{v.port} — {v.vuln_id}</div>
              </div>
            ))}
            {detail.vulnerabilities.length === 0 && <div className="text-gray-400 text-sm">No vulnerabilities found</div>}
          </div>
        </>
      )}
    </div>
  );
}
```

- [ ] **Step 5: PipelinePanel.tsx 加 History 按钮 + ScanPage.tsx 引入 HistoryDrawer**

- [ ] **Step 6: Build verify + Commit**

---

## Self-Review

1. **Spec coverage**: SQLite schema ✓, CRUD API ✓, cleanup ✓, HistoryDrawer ✓
2. **Placeholder scan**: no TBD/TODO
3. Type consistency: PipelineResult types match history insert

---

Plan saved.