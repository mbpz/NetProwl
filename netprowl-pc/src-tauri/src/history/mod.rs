use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;
use chrono::Utc;

mod schema;
pub use schema::INIT_SQL;

pub struct ScanSession {
    pub id: i64,
    pub target: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub result_count: i32,
    pub has_tls_audit: bool,
}

pub struct VulnRecord {
    pub host: String,
    pub port: u16,
    pub vuln_id: String,
    pub name: String,
    pub severity: String,
}

#[derive(Debug, serde::Serialize)]
pub struct SessionDetail {
    pub session: ScanSession,
    pub vulnerabilities: Vec<VulnRecord>,
}

pub struct HistoryDb {
    conn: Mutex<Connection>,
}

impl HistoryDb {
    pub fn new(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(INIT_SQL).map_err(|e| e.to_string())?;
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

    pub fn insert_vulnerability(&self, session_id: i64, device_ip: &str, port: u16, tool: &str, vuln_id: &str, name: &str, severity: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let device_id: i64 = conn.query_row(
            "SELECT id FROM devices WHERE session_id = ?1 AND ip = ?2 LIMIT 1",
            params![session_id, device_ip],
            |row| row.get(0),
        ).unwrap_or_else(|_| {
            conn.execute("INSERT INTO devices (session_id, ip) VALUES (?1, ?2)", params![session_id, device_ip]).ok();
            conn.last_insert_rowid()
        });
        let port_id: Option<i64> = conn.query_row(
            "SELECT id FROM ports WHERE session_id = ?1 AND device_id = ?2 AND port = ?3 LIMIT 1",
            params![session_id, device_id, port],
            |row| row.get(0),
        ).ok();
        conn.execute(
            "INSERT INTO vulnerabilities (session_id, device_id, port_id, tool, vuln_id, name, severity) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![session_id, device_id, port_id, tool, vuln_id, name, severity],
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
                id: row.get(0)?, target: row.get(1)?, started_at: row.get(2)?,
                finished_at: row.get(3)?, result_count: row.get(4)?,
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
                finished_at: row.get(3)?, result_count: row.get(4)?,
                has_tls_audit: row.get::<_, i64>(5)? != 0,
            }),
        ).map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare(
            "SELECT d.ip, p.port, v.vuln_id, v.name, v.severity FROM vulnerabilities v JOIN devices d ON v.device_id = d.id LEFT JOIN ports p ON v.port_id = p.id WHERE v.session_id = ?1"
        ).map_err(|e| e.to_string())?;
        let vulns = stmt.query_map(params![session_id], |row| {
            Ok(VulnRecord {
                host: row.get(0)?, port: row.get::<_, Option<u16>>(1)?.unwrap_or(0),
                vuln_id: row.get(2)?, name: row.get(3)?, severity: row.get(4)?,
            })
        }).map_err(|e| e.to_string())?.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
        Ok(SessionDetail { session, vulnerabilities: vulns })
    }

    pub fn delete_session(&self, session_id: i64) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM vulnerabilities WHERE session_id = ?1", params![session_id]).ok();
        conn.execute("DELETE FROM ports WHERE session_id = ?1", params![session_id]).ok();
        conn.execute("DELETE FROM devices WHERE session_id = ?1", params![session_id]).ok();
        conn.execute("DELETE FROM scan_sessions WHERE id = ?1", params![session_id]).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn delete_all_sessions(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM vulnerabilities", []).ok();
        conn.execute("DELETE FROM ports", []).ok();
        conn.execute("DELETE FROM devices", []).ok();
        conn.execute("DELETE FROM scan_sessions", []).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn cleanup(&self, max_days: i64) -> Result<usize, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let cutoff = Utc::now().timestamp() - (max_days * 86400);
        let deleted = conn.execute("DELETE FROM scan_sessions WHERE started_at < ?1", params![cutoff],).map_err(|e| e.to_string())?;
        Ok(deleted as usize)
    }

    pub fn save_device(&self, session_id: i64, ip: &str, mac: Option<&str>, vendor: Option<&str>, source: &str) -> Result<i64, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO devices (session_id, ip, mac, vendor, source) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![session_id, ip, mac, vendor, source],
        ).map_err(|e| e.to_string())?;
        Ok(conn.last_insert_rowid())
    }

    pub fn save_port(&self, session_id: i64, device_id: i64, port: i32, state: &str, service: Option<&str>, banner: Option<&str>) -> Result<i64, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO ports (session_id, device_id, port, state, service, banner) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![session_id, device_id, port, state, service, banner],
        ).map_err(|e| e.to_string())?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_devices_for_session(&self, session_id: i64) -> Result<Vec<(String, Option<String>, Option<String>)>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare("SELECT ip, mac, vendor FROM devices WHERE session_id = ?1").map_err(|e| e.to_string())?;
        let rows = stmt.query_map(params![session_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        }).map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }
}