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
CREATE INDEX IF NOT EXISTS idx_devices_session ON devices(session_id);
CREATE INDEX IF NOT EXISTS idx_ports_session ON ports(session_id);
CREATE INDEX IF NOT EXISTS idx_vulns_session ON vulnerabilities(session_id);
"#;