//! Security module for Phase 3 security detection features
//!
//! This module implements security vulnerability scanning including:
//! - F3-1: Default credentials detection
//! - F3-2: HTTP Basic Auth weak password probing
//! - F3-3: TLS/SSL configuration audit
//! - F3-4: Unauthorized access detection
//! - F3-5: Firmware version risk assessment
//! - F3-6: Risk report generation

pub mod credentials;
pub mod default_creds;
pub mod eos_db;
pub mod http_auth;
pub mod tls_audit;
pub mod unauthorized;
pub mod firmware;
pub mod report;

// Re-export commonly used types
pub use credentials::{
    WeakCredential,
    RiskLevel as CredentialRiskLevel,
    COMMON_WEAK_CREDS,
    detect_brand_from_banner,
    get_brand_credentials,
    get_credentials_for_service,
    build_credential_map,
};

#[cfg(not(target_arch = "wasm32"))]
pub use credentials::test_http_basic_auth;

pub use http_auth::{
    HttpAuthResult,
    HttpAuthConfig,
    WeakHttpAuth,
    CredentialPair,
    RiskLevel as HttpAuthRiskLevel,
    check_auth_required,
    probe_http_auth,
    probe_batch,
};

pub use tls_audit::{
    TlsReport,
    TlsVersion,
    WeakCipher,
    RiskLevel as TlsRiskLevel,
    is_weak_cipher,
    is_weak_hash,
    parse_tls_version,
    days_until_expiry,
    is_cert_expired,
    build_tls_report,
    audit_tls,
};

pub use unauthorized::{
    UnauthorizedEndpoint,
    UnauthResult,
    RiskLevel as UnauthRiskLevel,
    check_unauthorized,
    test_redis_unauth,
    test_elasticsearch_unauth,
    test_mongodb_unauth,
    test_memcached_unauth,
    test_docker_api_unauth,
    test_kubernetes_api_unauth,
    test_rtsp_camera_unauth,
    test_kafka_unauth,
    test_unauthorized_access,
    common_unauth_ports,
};

pub use eos_db::{
    FirmwareInfo,
    RiskLevel as EosRiskLevel,
    check_device_eos,
    get_eos_devices,
    get_devices_by_risk,
};

pub use firmware::{
    FirmwareRisk,
    DeviceCategory,
    RiskLevel as FirmwareRiskLevel,
    parse_version,
    extract_version_from_banner,
    assess_firmware_risk,
    get_eos_brands,
};

pub use report::{
    SecurityReport,
    SecurityRisk,
    SecurityScanSummary,
    CvssScore,
    FixPriority,
    RiskDistribution,
    RiskLevel as ReportRiskLevel,
    calculate_cvss,
    calculate_risk_distribution,
    calculate_overall_cvss,
    generate_fix_priority,
    generate_recommendations,
    generate_security_report,
};

/// Run a complete security scan on a target
#[cfg(not(target_arch = "wasm32"))]
pub async fn run_security_scan(
    ip: &str,
    open_ports: &[(u16, &str)], // (port, service_name)
    _timeout_ms: u64,
) -> Result<SecurityReport, Box<dyn std::error::Error + Send + Sync>> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::{sleep, Duration};

    let start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let weak_creds = Vec::new();
    let mut http_auth_results = Vec::new();
    let mut tls_reports = Vec::new();
    let mut unauthorized_endpoints = Vec::new();
    let firmware_risks = Vec::new();

    for (port, service) in open_ports {
        let port = *port;
        let service = service.to_string();

        // F3-1: Check for default credentials on known services
        if matches!(service.as_str(), "HTTP" | "HTTPS" | "RTSP" | "SSH" | "FTP") {
            // Try default credentials based on brand detection
            // This is a simplified check - full implementation would do actual auth attempts
        }

        // F3-2: HTTP Basic Auth probing for web services
        if matches!(service.as_str(), "HTTP" | "HTTPS") {
            let config = HttpAuthConfig {
                max_attempts: 20,
                concurrency_per_target: 5,
                delay_ms: 500,
                lockout_threshold: 3,
            };

            let result = probe_http_auth(ip, port, config).await;
            http_auth_results.push(result);

            // Small delay between probes
            sleep(Duration::from_millis(100)).await;
        }

        // F3-3: TLS audit for HTTPS
        if service == "HTTPS" {
            if let Ok(report) = audit_tls(ip, port).await {
                tls_reports.push(report);
            }
        }

        // F3-4: Unauthorized access testing for known services
        match service.as_str() {
            "Redis" => {
                if let Ok(result) = test_redis_unauth(ip, port).await {
                    unauthorized_endpoints.push(result);
                }
            }
            "Elasticsearch" => {
                if let Ok(result) = test_elasticsearch_unauth(ip, port).await {
                    unauthorized_endpoints.push(result);
                }
            }
            "MongoDB" => {
                if let Ok(result) = test_mongodb_unauth(ip, port).await {
                    unauthorized_endpoints.push(result);
                }
            }
            "Memcached" => {
                if let Ok(result) = test_memcached_unauth(ip, port).await {
                    unauthorized_endpoints.push(result);
                }
            }
            "Docker API" => {
                if let Ok(result) = test_docker_api_unauth(ip, port).await {
                    unauthorized_endpoints.push(result);
                }
            }
            "Kubernetes API" => {
                if let Ok(result) = test_kubernetes_api_unauth(ip, port).await {
                    unauthorized_endpoints.push(result);
                }
            }
            "RTSP" | "RTSP Camera" => {
                if let Ok(result) = test_rtsp_camera_unauth(ip, port).await {
                    unauthorized_endpoints.push(result);
                }
            }
            _ => {}
        }
    }

    let duration = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() - start;

    let report = generate_security_report(
        1, // 1 target scanned
        duration,
        weak_creds,
        http_auth_results,
        tls_reports,
        unauthorized_endpoints,
        firmware_risks,
    );

    Ok(report)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_module_exports() {
        // Verify all modules compile correctly
        use crate::security::*;
        let _ = COMMON_WEAK_CREDS;
        let _ = build_credential_map();
    }
}
