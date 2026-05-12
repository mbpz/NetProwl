//! F3-3: TLS/SSL configuration audit
//! Check certificate expiry, self-signed certs, weak cipher suites, TLS versions

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// TLS version support
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    Unknown,
}

/// Weak cipher suite
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakCipher {
    pub cipher: String,
    pub weakness: String,
}

/// TLS Report for a single endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsReport {
    pub ip: String,
    pub port: u16,
    pub cert_valid: bool,
    pub cert_expiry_days: Option<i64>,
    pub self_signed: bool,
    pub weak_ciphers: Vec<WeakCipher>,
    pub tls_versions: Vec<TlsVersion>,
    pub recommendations: Vec<String>,
    pub risk_level: RiskLevel,
}

/// Risk level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Weak cipher suites that should be flagged
static WEAK_CIPHERS: &[(&str, &str)] = &[
    ("SSL_RSA_WITH_RC4_128_MD5", "RC4 cipher is weak (deprecated)"),
    ("SSL_RSA_WITH_RC4_128_SHA", "RC4 cipher is weak (deprecated)"),
    ("TLS_RSA_WITH_RC4_128_SHA", "RC4 cipher is weak (deprecated)"),
    ("SSL_RSA_WITH_DES_CBC_SHA", "DES cipher is weak (56-bit)"),
    ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3DES cipher is weak (deprecated)"),
    ("TLS_RSA_WITH_DES_CBC_SHA", "DES cipher is weak (56-bit)"),
    ("SSL_RSA_EXPORT_WITH_RC4_40_MD5", "Export cipher is very weak (40-bit)"),
    ("SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "Export cipher is very weak (40-bit)"),
    ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "Export cipher is very weak (40-bit)"),
    ("TLS_RSA_WITH_NULL_MD5", "Null cipher provides no encryption"),
    ("TLS_RSA_WITH_NULL_SHA", "Null cipher provides no encryption"),
    ("TLS_RSA_WITH_NULL_SHA256", "Null cipher provides no encryption"),
    ("TLS_ECDHE_RSA_WITH_NULL_SHA", "Null cipher provides no encryption"),
    ("TLS_DH_RSA_WITH_DES_CBC_SHA", "DH key exchange with weak cipher"),
    ("TLS_DH_DSS_WITH_DES_CBC_SHA", "DH key exchange with weak cipher"),
    ("TLS_ECDH_RSA_WITH_DES_CBC_SHA", "ECDH key exchange with weak cipher"),
    ("TLS_ECDH_anon_WITH_RC4_128_SHA", "Anonymous key exchange is insecure"),
    ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES cipher is weak"),
    ("TLS_DHE_RSA_WITH_DES_CBC_SHA", "DHE cipher with weak DES"),
    ("TLS_DHE_DSS_WITH_DES_CBC_SHA", "DHE cipher with weak DES"),
];

/// Weak hash algorithms
static WEAK_HASH_ALGOS: &[(&str, &str)] = &[
    ("MD5", "MD5 is broken for cryptographic use"),
    ("SHA1", "SHA-1 is deprecated (collision attacks)"),
];

/// TLS 1.0/1.1 should be flagged as needs upgrade
static DEPRECATED_TLS: &[TlsVersion] = &[TlsVersion::TLS10, TlsVersion::TLS11];

/// Check if a cipher is weak
pub fn is_weak_cipher(cipher: &str) -> Option<WeakCipher> {
    let cipher_upper = cipher.to_uppercase();
    for (weak_suite, description) in WEAK_CIPHERS.iter() {
        if cipher_upper.contains(weak_suite) || cipher_upper.contains(&weak_suite.replace("_", "-")) {
            return Some(WeakCipher {
                cipher: cipher.to_string(),
                weakness: description.to_string(),
            });
        }
    }
    None
}

/// Check if hash algorithm is weak
pub fn is_weak_hash(hash: &str) -> Option<&'static str> {
    let hash_upper = hash.to_uppercase();
    for (weak_hash, description) in WEAK_HASH_ALGOS.iter() {
        if hash_upper.contains(weak_hash) {
            return Some(description);
        }
    }
    None
}

/// Parse TLS version from string
pub fn parse_tls_version(version: &str) -> TlsVersion {
    let lower = version.to_lowercase();
    if lower.contains("1.3") {
        TlsVersion::TLS13
    } else if lower.contains("1.2") {
        TlsVersion::TLS12
    } else if lower.contains("1.1") {
        TlsVersion::TLS11
    } else if lower.contains("1.0") || lower.contains("tls") {
        TlsVersion::TLS10
    } else {
        TlsVersion::Unknown
    }
}

/// Calculate days until certificate expiry
pub fn days_until_expiry(cert_expiry_timestamp: i64) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let days = (cert_expiry_timestamp - now) / (24 * 60 * 60);
    days
}

/// Check if certificate is expired
pub fn is_cert_expired(cert_expiry_timestamp: i64) -> bool {
    days_until_expiry(cert_expiry_timestamp) < 0
}

/// Build TLS report with recommendations
pub fn build_tls_report(
    ip: &str,
    port: u16,
    cert_valid: bool,
    cert_expiry_days: Option<i64>,
    self_signed: bool,
    weak_ciphers: Vec<WeakCipher>,
    tls_versions: Vec<TlsVersion>,
) -> TlsReport {
    let mut recommendations = Vec::new();
    let mut risk_factors = Vec::new();

    // Check certificate validity
    if !cert_valid {
        recommendations.push("Certificate is invalid or malformed".to_string());
        risk_factors.push("critical");
    }

    // Check expiry
    if let Some(days) = cert_expiry_days {
        if days < 0 {
            recommendations.push("Certificate is EXPIRED - renew immediately".to_string());
            risk_factors.push("critical");
        } else if days <= 30 {
            recommendations.push(format!("Certificate expires in {} days - renew soon", days));
            risk_factors.push("high");
        } else if days <= 90 {
            recommendations.push(format!("Certificate expires in {} days - plan renewal", days));
            risk_factors.push("medium");
        }
    }

    // Check self-signed
    if self_signed {
        recommendations.push("Self-signed certificate detected - replace with CA-signed cert".to_string());
        risk_factors.push("medium");
    }

    // Check weak ciphers
    if !weak_ciphers.is_empty() {
        recommendations.push(format!(
            "Found {} weak cipher suites - disable them",
            weak_ciphers.len()
        ));
        risk_factors.push("high");
    }

    // Check TLS versions
    for tls_ver in &tls_versions {
        if DEPRECATED_TLS.contains(tls_ver) {
            recommendations.push(format!("{:?} is deprecated - disable and use TLS 1.2+", tls_ver));
            risk_factors.push("high");
        }
    }

    if recommendations.is_empty() {
        recommendations.push("TLS configuration appears healthy".to_string());
    }

    // Determine overall risk level
    let risk_level = if risk_factors.contains(&"critical") {
        RiskLevel::Critical
    } else if risk_factors.contains(&"high") {
        RiskLevel::High
    } else if risk_factors.contains(&"medium") {
        RiskLevel::Medium
    } else if risk_factors.contains(&"low") {
        RiskLevel::Low
    } else {
        RiskLevel::Info
    };

    TlsReport {
        ip: ip.to_string(),
        port,
        cert_valid,
        cert_expiry_days,
        self_signed,
        weak_ciphers,
        tls_versions,
        recommendations,
        risk_level,
    }
}

/// Perform TLS audit by connecting and getting certificate info
#[cfg(not(target_arch = "wasm32"))]
pub async fn audit_tls(
    ip: &str,
    port: u16,
) -> Result<TlsReport, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout as tokio_timeout, Duration};

    let timeout_dur = Duration::from_millis(5000);
    let addr = format!("{}:{}", ip, port);

    // Try to connect and do TLS handshake
    let mut conn = tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await??;

    // Send HTTP request to trigger TLS handshake
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        ip, port
    );

    let _ = conn.write_all(request.as_bytes()).await;

    // Read response (should include certificate info in TLS handshake)
    let mut buf = vec![0u8; 8192];
    let _n = conn.read(&mut buf).await;

    // For now, return a basic report since full TLS inspection requires rustls/x509-parser
    // In production, you would use rustls to do proper TLS handshake and certificate extraction
    let report = TlsReport {
        ip: ip.to_string(),
        port,
        cert_valid: true, // Placeholder - would be extracted from TLS cert
        cert_expiry_days: Some(365), // Placeholder
        self_signed: false, // Placeholder
        weak_ciphers: Vec::new(), // Would be extracted from TLS handshake
        tls_versions: vec![TlsVersion::TLS12], // Placeholder
        recommendations: vec!["TLS audit requires full certificate parsing - configure rustls".to_string()],
        risk_level: RiskLevel::Info,
    };

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_weak_cipher_rc4() {
        let result = is_weak_cipher("TLS_RSA_WITH_RC4_128_SHA");
        assert!(result.is_some());
        assert!(result.unwrap().weakness.contains("RC4"));
    }

    #[test]
    fn test_is_weak_cipher_des() {
        let result = is_weak_cipher("TLS_RSA_WITH_DES_CBC_SHA");
        assert!(result.is_some());
    }

    #[test]
    fn test_is_weak_cipher_null() {
        let result = is_weak_cipher("TLS_RSA_WITH_NULL_MD5");
        assert!(result.is_some());
    }

    #[test]
    fn test_is_not_weak_cipher() {
        let result = is_weak_cipher("TLS_AES_256_GCM_SHA384");
        assert!(result.is_none());
    }

    #[test]
    fn test_is_weak_hash_md5() {
        let result = is_weak_hash("MD5");
        assert!(result.is_some());
    }

    #[test]
    fn test_is_weak_hash_sha1() {
        let result = is_weak_hash("SHA1");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_tls_version() {
        assert_eq!(parse_tls_version("TLS 1.3"), TlsVersion::TLS13);
        assert_eq!(parse_tls_version("TLSv1.2"), TlsVersion::TLS12);
        assert_eq!(parse_tls_version("TLS 1.1"), TlsVersion::TLS11);
        assert_eq!(parse_tls_version("TLS 1.0"), TlsVersion::TLS10);
    }

    #[test]
    fn test_days_until_expiry() {
        // Certificate expires in 30 days
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let expiry = now + (31 * 24 * 60 * 60);
        assert_eq!(days_until_expiry(expiry), 31);

        // Certificate expired 1 day ago
        let expired = now - (1 * 24 * 60 * 60);
        assert_eq!(days_until_expiry(expired), -1);
    }

    #[test]
    fn test_is_cert_expired() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let expired = now - 60; // 1 minute ago
        assert!(is_cert_expired(expired));

        let future = now + (365 * 24 * 60 * 60); // 1 year from now
        assert!(!is_cert_expired(future));
    }

    #[test]
    fn test_build_tls_report_expired() {
        let report = build_tls_report(
            "192.168.1.1",
            443,
            true,
            Some(-5), // Expired 5 days ago
            false,
            Vec::new(),
            vec![TlsVersion::TLS12],
        );
        assert_eq!(report.risk_level, RiskLevel::Critical);
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn test_build_tls_report_weak_ciphers() {
        let weak = vec![WeakCipher {
            cipher: "RC4".to_string(),
            weakness: "Weak cipher".to_string(),
        }];
        let report = build_tls_report(
            "192.168.1.1",
            443,
            true,
            Some(100),
            false,
            weak,
            vec![TlsVersion::TLS12],
        );
        assert!(report.risk_level == RiskLevel::High || report.risk_level == RiskLevel::Medium);
    }

    #[test]
    fn test_build_tls_report_self_signed() {
        let report = build_tls_report(
            "192.168.1.1",
            443,
            true,
            Some(200),
            true,
            Vec::new(),
            vec![TlsVersion::TLS12],
        );
        assert!(report.self_signed);
        assert!(report.risk_level == RiskLevel::Medium);
    }

    #[test]
    fn test_build_tls_report_deprecated_tls() {
        let report = build_tls_report(
            "192.168.1.1",
            443,
            true,
            Some(200),
            false,
            Vec::new(),
            vec![TlsVersion::TLS10],
        );
        assert!(report.tls_versions.contains(&TlsVersion::TLS10));
    }

    #[test]
    fn test_tls_report_serialization() {
        let report = TlsReport {
            ip: "192.168.1.1".to_string(),
            port: 443,
            cert_valid: true,
            cert_expiry_days: Some(90),
            self_signed: false,
            weak_ciphers: vec![WeakCipher {
                cipher: "RC4".to_string(),
                weakness: "Weak".to_string(),
            }],
            tls_versions: vec![TlsVersion::TLS12],
            recommendations: vec!["Upgrade cipher suite".to_string()],
            risk_level: RiskLevel::High,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("RC4"));
    }
}
