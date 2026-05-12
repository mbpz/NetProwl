//! F3-2: HTTP Basic Auth weak password probing
//! For HTTP services with 401 response, try Top 20 weak passwords

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

use super::credentials::COMMON_WEAK_CREDS;

/// Maximum concurrent probes per target
const MAX_CONCURRENT_PER_TARGET: usize = 5;

/// Delay between attempts (ms)
const ATTEMPT_DELAY_MS: u64 = 500;

/// Lockout detection: stop after N consecutive 401s
const LOCKOUT_THRESHOLD: usize = 3;

/// Weak HTTP auth finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakHttpAuth {
    pub ip: String,
    pub port: u16,
    pub valid_credential: CredentialPair,
    pub attempts_made: usize,
    pub risk_level: RiskLevel,
}

/// Credential pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPair {
    pub username: String,
    pub password: String,
}

/// Risk level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    High,
    Medium,
    Low,
}

/// HTTP Auth probe result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAuthResult {
    pub ip: String,
    pub port: u16,
    pub is_vulnerable: bool,
    pub valid_credential: Option<CredentialPair>,
    pub attempts_made: usize,
    pub locked_out: bool,
    pub risk_level: Option<RiskLevel>,
}

/// Configuration for HTTP auth probing
#[derive(Debug, Clone)]
pub struct HttpAuthConfig {
    pub max_attempts: usize,
    pub concurrency_per_target: usize,
    pub delay_ms: u64,
    pub lockout_threshold: usize,
}

impl Default for HttpAuthConfig {
    fn default() -> Self {
        Self {
            max_attempts: COMMON_WEAK_CREDS.len(),
            concurrency_per_target: MAX_CONCURRENT_PER_TARGET,
            delay_ms: ATTEMPT_DELAY_MS,
            lockout_threshold: LOCKOUT_THRESHOLD,
        }
    }
}

/// Check if response indicates authentication is required (401)
#[cfg(not(target_arch = "wasm32"))]
pub async fn check_auth_required(
    ip: &str,
    port: u16,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await??;

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        ip, port
    );

    conn.write_all(request.as_bytes()).await?;

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await?;

    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();
    Ok(response.contains("401") || response.contains("www-authenticate"))
}

/// Test a single credential pair against HTTP Basic Auth
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_credential(
    ip: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};
    use base64::Engine;

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await??;

    let auth_header = base64::engine::general_purpose::STANDARD.encode(&format!("{}:{}", username, password));
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
        ip, port, auth_header
    );

    conn.write_all(request.as_bytes()).await?;

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await?;

    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();

    // Check if we got 200 OK (auth succeeded) or 401 (auth failed)
    Ok(response.contains("http/1.1 200") || response.contains("http/1.0 200"))
}

/// Probe HTTP Basic Auth with weak passwords
#[cfg(not(target_arch = "wasm32"))]
pub async fn probe_http_auth(
    ip: &str,
    port: u16,
    config: HttpAuthConfig,
) -> HttpAuthResult {
    let semaphore = Arc::new(Semaphore::new(config.concurrency_per_target));
    let mut consecutive_401s = 0;
    let mut attempts_made = 0;
    let mut valid_credential: Option<CredentialPair> = None;
    let mut locked_out = false;

    for (creds, _idx) in COMMON_WEAK_CREDS.iter().zip(0..) {
        if attempts_made >= config.max_attempts {
            break;
        }

        // Check for lockout
        if consecutive_401s >= config.lockout_threshold {
            locked_out = true;
            break;
        }

        // Acquire permit for concurrency control
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        let (username, password) = *creds;
        let ip_owned = ip.to_string();
        let port_owned = port;

        let result = tokio::spawn(async move {
            test_credential(&ip_owned, port_owned, username, password).await
        });

        // Delay between attempts
        sleep(Duration::from_millis(config.delay_ms)).await;

        match result.await {
            Ok(Ok(success)) => {
                attempts_made += 1;
                drop(permit);

                if success {
                    valid_credential = Some(CredentialPair {
                        username: username.to_string(),
                        password: password.to_string(),
                    });
                    break;
                } else {
                    consecutive_401s += 1;
                }
            }
            Ok(Err(_)) | Err(_) => {
                attempts_made += 1;
                drop(permit);
                consecutive_401s += 1;
            }
        }
    }

    let is_vulnerable = valid_credential.is_some();

    let risk_level = valid_credential.as_ref().map(|cred| {
        match (cred.username.as_str(), cred.password.as_str()) {
            ("admin", "") | ("root", "") => RiskLevel::High,
            ("admin", "12345") | ("admin", "password") | ("root", "root") => RiskLevel::High,
            ("admin", "admin") | ("admin", "123456") => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    });

    HttpAuthResult {
        ip: ip.to_string(),
        port,
        is_vulnerable,
        valid_credential,
        attempts_made,
        locked_out,
        risk_level,
    }
}

/// Batch probe multiple targets
#[cfg(not(target_arch = "wasm32"))]
pub async fn probe_batch(
    targets: &[(String, u16)],
    config: HttpAuthConfig,
) -> Vec<HttpAuthResult> {
    let mut results = Vec::new();

    for (ip, port) in targets {
        let result = probe_http_auth(ip, *port, config.clone()).await;
        results.push(result);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_pair_serialization() {
        let cred = CredentialPair {
            username: "admin".to_string(),
            password: "12345".to_string(),
        };
        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("admin"));
        assert!(json.contains("12345"));
    }

    #[test]
    fn test_http_auth_result_serialization() {
        let result = HttpAuthResult {
            ip: "192.168.1.1".to_string(),
            port: 80,
            is_vulnerable: true,
            valid_credential: Some(CredentialPair {
                username: "admin".to_string(),
                password: "admin".to_string(),
            }),
            attempts_made: 5,
            locked_out: false,
            risk_level: Some(RiskLevel::Medium),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("vulnerable"));
    }

    #[test]
    fn test_http_auth_config_default() {
        let config = HttpAuthConfig::default();
        assert_eq!(config.concurrency_per_target, 5);
        assert_eq!(config.delay_ms, 500);
        assert_eq!(config.lockout_threshold, 3);
    }

    #[test]
    fn test_risk_level_serialization() {
        let high = RiskLevel::High;
        let medium = RiskLevel::Medium;
        let low = RiskLevel::Low;

        assert_eq!(serde_json::to_string(&high).unwrap(), "\"high\"");
        assert_eq!(serde_json::to_string(&medium).unwrap(), "\"medium\"");
        assert_eq!(serde_json::to_string(&low).unwrap(), "\"low\"");
    }
}
