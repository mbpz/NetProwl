use crate::cve::types::{CveResult, CveRule};
use rusqlite::{params, Connection, Result};
use std::path::PathBuf;

const DB_FILE: &str = "cve.db";

fn get_db_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".netprowl").join(DB_FILE)
}

/// Ensure the parent directory exists
fn ensure_parent_dir() -> std::io::Result<()> {
    let path = get_db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Initialize the SQLite database (create table + index if not exists)
pub fn init_db() -> Result<Connection> {
    ensure_parent_dir().map_err(|_e| rusqlite::Error::InvalidPath(get_db_path()))?;
    let path = get_db_path();
    let conn = Connection::open(path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS cve_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            software TEXT NOT NULL,
            version_min TEXT NOT NULL,
            version_max TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            cvss REAL NOT NULL,
            description TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_software_version
         ON cve_rules(software, version_min, version_max)",
        [],
    )?;

    Ok(conn)
}

/// Batch insert CVE rules into the database
pub fn insert_cves(conn: &Connection, cves: &[CveRule]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO cve_rules (software, version_min, version_max, cve_id, cvss, description)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for cve in cves {
            stmt.execute(params![
                cve.software,
                cve.version_min,
                cve.version_max,
                cve.cve_id,
                cve.cvss,
                cve.description,
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Simple version comparison: check if version falls within [version_min, version_max]
/// Supports major.minor as floats (e.g. "1.2.3" -> 1.2, "2.0" -> 2.0, "10.0.1" -> 10.0).
/// String fallback for non-numeric versions.
fn version_in_range(version: &str, version_min: &str, version_max: &str) -> bool {
    // Try float extraction: split on dots, compare major.minor as floats
    if let (Some(v), Some(min), Some(max)) = (
        parse_version(version),
        parse_version(version_min),
        parse_version(version_max),
    ) {
        return v >= min && v <= max;
    }

    // Fallback: string prefix match (for versions like "1.2", "1.2.3")
    let v_prefix = version.trim_start_matches('v');
    v_prefix >= version_min.trim_start_matches('v') && v_prefix <= version_max.trim_start_matches('v')
}

/// Parse version to major.minor as f64.
/// "1.2.3" -> 1.2, "2.0" -> 2.0, "10.0.1" -> 10.0, "abc" -> None (uses string fallback)
fn parse_version(v: &str) -> Option<f64> {
    let s = v.trim_start_matches('v');
    let parts: Vec<&str> = s.split('.').collect();
    if parts.is_empty() {
        return None;
    }
    let major: u32 = parts[0].parse().ok()?;
    let minor: u32 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
    // Build major.minor as float: 1.2 -> 1.2, 10.0 -> 10.0
    // minor < 10 -> divide by 10; minor >= 10 -> divide by 100 to get 1.10 not 1.1
    let minor_frac = if minor < 10 {
        minor as f64 / 10.0
    } else {
        minor as f64 / 100.0
    };
    Some(major as f64 + minor_frac)
}

/// Query CVEs for a given software and version
pub fn query(conn: &Connection, software: &str, version: &str) -> Result<Vec<CveResult>> {
    let mut stmt = conn.prepare(
        "SELECT cve_id, cvss, description FROM cve_rules
         WHERE software = ?1 AND ?2 >= version_min AND ?2 <= version_max",
    )?;

    let rows = stmt.query_map(params![software, version], |row| {
        Ok(CveResult {
            cve_id: row.get(0)?,
            cvss: row.get(1)?,
            description: row.get(2)?,
        })
    })?;

    let mut results = Vec::new();
    for row in rows {
        if let Ok(cve) = row {
            results.push(cve);
        }
    }
    Ok(results)
}

/// Hot-update: download new CVE rules from URL (stub implementation)
pub async fn hot_update(_url: &str) -> Result<(), String> {
    // TODO: Implement actual HTTP download and parse
    // Stub: just return OK to indicate placeholder is in place
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_in_range() {
        assert!(version_in_range("1.2.3", "1.2.0", "1.3.0"));
        assert!(version_in_range("1.2.0", "1.2.0", "1.3.0"));
        assert!(version_in_range("1.3.0", "1.2.0", "1.3.0"));
        assert!(!version_in_range("1.1.9", "1.2.0", "1.3.0"));
        assert!(!version_in_range("1.4.0", "1.2.0", "1.3.0"));
        // Edge cases: "2.0" -> 2.0
        assert!(version_in_range("2.0", "2.0", "3.0"));
        // "10.0.1" -> 10.0
        assert!(version_in_range("10.0.1", "10.0", "11.0"));
        // Non-numeric falls back to string
        assert!(version_in_range("abc", "abc", "abc"));
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.2.3"), Some(1.2));
        assert_eq!(parse_version("v2.0.0"), Some(2.0));
        assert_eq!(parse_version("1.2"), Some(1.2));
        assert_eq!(parse_version("2.0"), Some(2.0));
        assert_eq!(parse_version("10.0.1"), Some(10.0));
        assert_eq!(parse_version("invalid"), None);
    }
}