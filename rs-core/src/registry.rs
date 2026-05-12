//! Service fingerprint registry

/// Match service by port + optional banner
/// Returns (service_name, device_type)
pub fn match_service(port: u16, banner: Option<&str>) -> (&'static str, &'static str) {
    let rules: &[(u16, Option<&str>, &str, &str)] = &[
        (80,   None,          "HTTP",             "unknown"),
        (443,  None,          "HTTPS",            "unknown"),
        (22,   Some("SSH"),   "SSH",              "unknown"),
        (21,   Some("FTP"),   "FTP",              "unknown"),
        (554,  Some("RTSP"),  "RTSP Stream",      "camera"),
        (554,  Some("Hikvision"), "Hikvision Camera", "camera"),
        (5000, Some("Synology"), "Synology NAS",   "nas"),
        (8080, None,          "HTTP Proxy",       "unknown"),
        (5000, None,          "UPnP",             "unknown"),
        (9000, None,          "CSListener",        "unknown"),
        (3389, None,          "RDP",              "pc"),
        (445,  None,          "SMB",              "unknown"),
        (3306, None,          "MySQL",            "unknown"),
        (5432, None,          "PostgreSQL",        "unknown"),
        (6379, None,          "Redis",             "unknown"),
        (9200, None,          "Elasticsearch",      "unknown"),
        (27017, None,         "MongoDB",           "unknown"),
    ];

    for &(p, needle, svc, dtype) in rules {
        if p != port { continue; }
        match needle {
            Some(n) => {
                if let Some(b) = banner {
                    if b.contains(n) { return (svc, dtype); }
                }
            }
            None => return (svc, dtype),
        }
    }
    ("unknown", "unknown")
}
