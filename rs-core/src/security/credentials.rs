//! F3-1: Default credentials detection
//! Detects devices with known default credentials for cameras, NAS, routers, etc.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use crate::security::report::RiskLevel;

/// Risk level for weak credentials
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialRiskLevel {
    High,
    Medium,
    Low,
}

/// Weak credential finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakCredential {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub brand: Option<String>,
    pub default_user: String,
    pub default_pass: String,
    pub risk_level: RiskLevel,
}

/// Brand credentials tuple: (brand_name, service_type, &[credentials])
type BrandCredsEntry = (&'static str, &'static str, &'static [(&'static str, &'static str)]);

const HIKVISION_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", ""),
    ("root", "admin"),
    ("user", "user"),
];

const DAHUA_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", ""),
    ("root", "root"),
    ("user", "user"),
];

const AXIS_CREDS: &[(&str, &str)] = &[
    ("root", "pass"),
    ("admin", "admin"),
    ("admin", "12345"),
    ("root", "admin"),
];

const SYNOLOGY_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "12345"),
    ("root", "synology"),
    ("admin", ""),
    ("guest", "guest"),
];

const QNAP_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "12345"),
    ("root", "admin"),
    ("admin", ""),
    ("guest", "guest"),
];

const NETGEAR_CREDS: &[(&str, &str)] = &[
    ("admin", "password"),
    ("admin", "12345"),
    ("admin", "admin"),
    ("root", "password"),
];

const TPLINK_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", ""),
    ("root", "admin"),
];

const UBIQUITI_CREDS: &[(&str, &str)] = &[
    ("ubnt", "ubnt"),
    ("admin", "admin"),
    ("root", "ubnt"),
];

const GENERIC_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "admin"),
    ("user", "user"),
    ("guest", "guest"),
    ("test", "test"),
    ("administrator", "administrator"),
    ("supervisor", "supervisor"),
    ("666666", "666666"),
    ("888888", "888888"),
];

const BRAND_CREDENTIALS: &[BrandCredsEntry] = &[
    ("Hikvision", "Camera", HIKVISION_CREDS),
    ("Dahua", "Camera", DAHUA_CREDS),
    ("Axis", "Camera", AXIS_CREDS),
    ("Synology", "NAS", SYNOLOGY_CREDS),
    ("QNAP", "NAS", QNAP_CREDS),
    ("Netgear", "Router", NETGEAR_CREDS),
    ("TP-Link", "Router", TPLINK_CREDS),
    ("Ubiquiti", "Network", UBIQUITI_CREDS),
    ("Generic", "Unknown", GENERIC_CREDS),
];

/// Common HTTP Basic Auth credential pairs (Top 20)
pub const COMMON_WEAK_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "admin"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
    ("test", "test"),
    ("administrator", "administrator"),
    ("supervisor", "supervisor"),
    ("666666", "666666"),
    ("888888", "888888"),
    ("root", "password"),
    ("admin", "pass"),
    ("admin", "pwd"),
];

/// Detect device brand from banner
pub fn detect_brand(brand: &str) -> Option<&'static [(&'static str, &'static str)]> {
    for entry in BRAND_CREDENTIALS {
        if entry.0 == brand {
            return Some(entry.2);
        }
    }
    None
}

/// Detect device brand from banner
pub fn detect_brand_from_banner(banner: &str, port: u16) -> Option<&'static BrandCredsEntry> {
    let banner_lower = banner.to_lowercase();

    // Port-based initial detection
    let port_brand = match port {
        554 | 8000 => {
            if banner_lower.contains("hikvision") {
                Some("Hikvision")
            } else if banner_lower.contains("dahua") {
                Some("Dahua")
            } else if banner_lower.contains("axis") {
                Some("Axis")
            } else if banner_lower.contains("rtsp") || banner_lower.contains("stream") {
                Some("Generic")
            } else {
                None
            }
        }
        5000 | 5001 => {
            if banner_lower.contains("synology") {
                Some("Synology")
            } else if banner_lower.contains("qnap") {
                Some("QNAP")
            } else {
                Some("Generic")
            }
        }
        80 | 443 | 8080 | 8443 => {
            if banner_lower.contains("hikvision") {
                Some("Hikvision")
            } else if banner_lower.contains("dahua") {
                Some("Dahua")
            } else if banner_lower.contains("synology") {
                Some("Synology")
            } else if banner_lower.contains("qnap") {
                Some("QNAP")
            } else if banner_lower.contains("netgear") {
                Some("Netgear")
            } else if banner_lower.contains("tp-link") || banner_lower.contains("tplink") {
                Some("TP-Link")
            } else if banner_lower.contains("ubiquiti") || banner_lower.contains("unifi") {
                Some("Ubiquiti")
            } else {
                Some("Generic")
            }
        }
        _ => Some("Generic"),
    };

    if let Some(brand_name) = port_brand {
        for entry in BRAND_CREDENTIALS {
            if entry.0 == brand_name {
                return Some(entry);
            }
        }
    }

    None
}

/// Get credentials for a specific brand
pub fn get_brand_credentials(brand: &str) -> Option<&'static [(&'static str, &'static str)]> {
    detect_brand(brand)
}

/// Get all default credentials for a given service type
pub fn get_credentials_for_service(service: &str, port: u16) -> Vec<WeakCredential> {
    let mut results = Vec::new();

    // Find brand by scanning all brands for matching service type
    for entry in BRAND_CREDENTIALS {
        if entry.1 == service || entry.1 == "Unknown" {
            for (user, pass) in entry.2 {
                let risk_level = match (*user, *pass) {
                    ("admin", "") => RiskLevel::High,  // Empty password is critical
                    ("admin", "12345") => RiskLevel::High,
                    ("root", "root") => RiskLevel::High,
                    ("root", "toor") => RiskLevel::High,
                    ("admin", "admin") => RiskLevel::Medium,
                    ("admin", "password") => RiskLevel::Medium,
                    ("admin", "123456") => RiskLevel::Medium,
                    _ => RiskLevel::Low,
                };

                results.push(WeakCredential {
                    ip: String::new(), // To be filled by caller
                    port,
                    service: service.to_string(),
                    brand: Some(entry.0.to_string()),
                    default_user: user.to_string(),
                    default_pass: pass.to_string(),
                    risk_level,
                });
            }
        }
    }

    results
}

/// Test if a credential combination works for HTTP Basic Auth
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_http_basic_auth(
    ip: &str,
    port: u16,
    user: &str,
    pass: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};
    use base64::Engine;

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await??;

    let auth_header = base64::engine::general_purpose::STANDARD.encode(&format!("{}:{}", user, pass));
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
        ip, port, auth_header
    );

    conn.write_all(request.as_bytes()).await?;

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await?;

    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();

    // If we get 200 OK, auth worked
    // If we get 401, auth failed
    Ok(response.contains("http/1.1 200") || response.contains("http/1.0 200"))
}

/// Build default credentials map for quick lookup
pub fn build_credential_map() -> HashMap<String, &'static [(&'static str, &'static str)]> {
    let mut map = HashMap::new();

    for entry in BRAND_CREDENTIALS {
        map.insert(entry.0.to_string(), entry.2);
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_brand_hikvision() {
        let banner = "Hikvision DS-2CD2043G2";
        let brand = detect_brand_from_banner(banner, 80);
        assert!(brand.is_some());
        assert_eq!(brand.unwrap().0, "Hikvision");
    }

    #[test]
    fn test_detect_brand_synology() {
        let banner = "Synology NAS DSM 7.1";
        let brand = detect_brand_from_banner(banner, 5000);
        assert!(brand.is_some());
        assert_eq!(brand.unwrap().0, "Synology");
    }

    #[test]
    fn test_detect_brand_generic() {
        let banner = "Unknown device";
        let brand = detect_brand_from_banner(banner, 8080);
        assert!(brand.is_some());
        assert_eq!(brand.unwrap().0, "Generic");
    }

    #[test]
    fn test_get_credentials_for_service() {
        let creds = get_credentials_for_service("Camera", 554);
        assert!(!creds.is_empty());
    }

    #[test]
    fn test_build_credential_map() {
        let map = build_credential_map();
        assert!(!map.is_empty());
        assert!(map.contains_key("Hikvision"));
        assert!(map.contains_key("Synology"));
        assert!(map.contains_key("Generic"));
    }

    #[test]
    fn test_risk_level_assignment() {
        let creds = get_credentials_for_service("Camera", 554);
        // Empty password should be high risk
        let empty_pass = creds.iter().find(|c| c.default_pass.is_empty());
        assert!(empty_pass.is_some());
        assert_eq!(empty_pass.unwrap().risk_level, RiskLevel::High);
    }
}
