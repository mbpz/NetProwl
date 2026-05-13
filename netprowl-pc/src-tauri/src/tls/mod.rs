pub mod cert;
pub mod config;
pub mod headers;
pub mod rules;
pub mod testssl;

pub use cert::fetch_cert_info;
pub use config::check_tls_config;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TLSCertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub san: Vec<String>,
    pub fingerprint_sha256: String,
    pub key_algorithm: String,
    pub key_size: u32,
    pub has_ocsp_stapling: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TLSConfigInfo {
    pub supports_tls10: bool,
    pub supports_tls11: bool,
    pub supports_tls12: bool,
    pub supports_tls13: bool,
    pub supported_cipher_suites: Vec<String>,
    pub fallback_scsv: bool,
    pub renegotiation: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TLSVulnerability {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TLSAuditResult {
    pub host: String,
    pub port: u16,
    pub cert: TLSCertInfo,
    pub config: TLSConfigInfo,
    pub vulnerabilities: Vec<TLSVulnerability>,
    pub testssl_used: bool,
}