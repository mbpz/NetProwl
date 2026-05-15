//! SQLite banner cache — avoid re-parsing identical banners.

use rusqlite::{Connection, params};

pub struct BannerCache {
    conn: Connection,
}

#[derive(Debug)]
pub struct CachedBanner {
    pub raw: String,
    pub software: String,
    pub version: String,
    pub os: String,
    pub confidence: f64,
}

impl BannerCache {
    pub fn new(db_path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS banner_cache (
                banner_hash TEXT PRIMARY KEY,
                raw_banner TEXT,
                software TEXT,
                version TEXT,
                os TEXT,
                confidence REAL,
                cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        Ok(Self { conn })
    }

    pub fn in_memory() -> Self {
        Self::new(":memory:").expect("in-memory SQLite should always work")
    }

    pub fn load(&self, hash: &str) -> Option<CachedBanner> {
        let mut stmt = self.conn.prepare(
            "SELECT raw_banner, software, version, os, confidence FROM banner_cache WHERE banner_hash = ?"
        ).ok()?;
        let mut rows = stmt.query(params![hash]).ok()?;
        if let Ok(Some(row)) = rows.next() {
            Some(CachedBanner {
                raw: row.get(0).ok()?,
                software: row.get(1).ok()?,
                version: row.get(2).ok()?,
                os: row.get(3).ok()?,
                confidence: row.get(4).ok()?,
            })
        } else {
            None
        }
    }

    pub fn save(&self, hash: &str, raw: &str, software: &str, version: &str, os: &str, confidence: f64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO banner_cache (banner_hash, raw_banner, software, version, os, confidence) VALUES (?, ?, ?, ?, ?, ?)",
            params![hash, raw, software, version, os, confidence],
        )?;
        Ok(())
    }

    pub fn save_parsed(&self, hash: &str, raw: &str, result: &serde_json::Value) -> rusqlite::Result<()> {
        let software = result.get("software").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let version = result.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let os = result.get("os").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let confidence = result.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
        self.save(hash, raw, &software, &version, &os, confidence)
    }
}
