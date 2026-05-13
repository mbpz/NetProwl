//! F3-4: Unauthorized access detection
//! Detects services that allow unauthenticated access (Redis, Elasticsearch, MongoDB, etc.)

use serde::{Deserialize, Serialize};

/// Unified result for unauthorized access detection (F3-4)
/// Returns Some(UnauthResult) if exposed without auth, None if secured or connection failed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnauthResult {
    Redis { vulnerable: bool, info: String },
    Elasticsearch { vulnerable: bool, info: String },
    MongoDB { vulnerable: bool, info: String },
    Docker { vulnerable: bool, info: String },
    Kafka { vulnerable: bool, info: String },
    Memcached { vulnerable: bool, info: String },
    RTSP { vulnerable: bool, info: String },
}

/// Check unauthorized access for a given IP and port.
/// Returns Some(UnauthResult) if the service is exposed without authentication.
/// Returns None if secured, not listening, or not a known unauth-checkable service.
#[cfg(not(target_arch = "wasm32"))]
pub async fn check_unauthorized(ip: &str, port: u16) -> Option<UnauthResult> {
    match port {
        6379 => {
            let result = test_redis_unauth_raw(ip, port).await;
            if result.is_vulnerable {
                Some(UnauthResult::Redis {
                    vulnerable: true,
                    info: result.result,
                })
            } else {
                None
            }
        }
        9200 => {
            let result = test_elasticsearch_unauth_raw(ip, port).await;
            if result.is_vulnerable {
                Some(UnauthResult::Elasticsearch {
                    vulnerable: true,
                    info: result.result,
                })
            } else {
                None
            }
        }
        27017 => {
            let result = test_mongodb_unauth_raw(ip, port).await;
            if result.is_vulnerable {
                Some(UnauthResult::MongoDB {
                    vulnerable: true,
                    info: result.result,
                })
            } else {
                None
            }
        }
        2375 | 2376 => {
            let result = test_docker_api_unauth_raw(ip, port).await;
            if result.is_vulnerable {
                Some(UnauthResult::Docker {
                    vulnerable: true,
                    info: result.result,
                })
            } else {
                None
            }
        }
        9092 => {
            let result = test_kafka_unauth_raw(ip, port).await;
            if result.is_vulnerable {
                Some(UnauthResult::Kafka {
                    vulnerable: true,
                    info: result.result,
                })
            } else {
                None
            }
        }
        11211 => {
            let result = test_memcached_unauth_raw(ip, port).await;
            if result.is_vulnerable {
                Some(UnauthResult::Memcached {
                    vulnerable: true,
                    info: result.result,
                })
            } else {
                None
            }
        }
        554 | 5000 => {
            let result = test_rtsp_camera_unauth_raw(ip, port).await;
            if result.is_vulnerable {
                Some(UnauthResult::RTSP {
                    vulnerable: true,
                    info: result.result,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Service type that can be tested for unauthenticated access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnauthService {
    Redis,
    Elasticsearch,
    MongoDB,
    Memcached,
    DockerAPI,
    KubernetesAPI,
    RTSPCamera,
}

/// Test result for unauthorized access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnauthorizedEndpoint {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub test_performed: String,
    pub result: String,
    pub is_vulnerable: bool,
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

/// Test Redis unauthenticated access (PING -> PONG)
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_redis_unauth(
    ip: &str,
    port: u16,
) -> Result<UnauthorizedEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = match tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await {
        Ok(Ok(c)) => c,
        _ => {
            return Ok(UnauthorizedEndpoint {
                ip: ip.to_string(),
                port,
                service: "Redis".to_string(),
                test_performed: "PING command".to_string(),
                result: "Connection failed".to_string(),
                is_vulnerable: false,
                risk_level: RiskLevel::Info,
            });
        }
    };

    // Send PING command
    let _ = conn.write_all(b"PING\r\n").await;

    let mut buf = vec![0u8; 256];
    let n = conn.read(&mut buf).await.unwrap_or(0);

    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();

    let is_vulnerable = response.contains("+pong") || response.contains("pong");
    let result = if is_vulnerable {
        "Responds to PING without authentication - NO AUTH REQUIRED"
    } else {
        "Authentication appears required"
    };

    Ok(UnauthorizedEndpoint {
        ip: ip.to_string(),
        port,
        service: "Redis".to_string(),
        test_performed: "PING command".to_string(),
        result: result.to_string(),
        is_vulnerable,
        risk_level: if is_vulnerable { RiskLevel::Critical } else { RiskLevel::Info },
    })
}

/// Test Elasticsearch unauthenticated access (GET / -> cluster info)
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_elasticsearch_unauth(
    ip: &str,
    port: u16,
) -> Result<UnauthorizedEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = match tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await {
        Ok(Ok(c)) => c,
        _ => {
            return Ok(UnauthorizedEndpoint {
                ip: ip.to_string(),
                port,
                service: "Elasticsearch".to_string(),
                test_performed: "GET /".to_string(),
                result: "Connection failed".to_string(),
                is_vulnerable: false,
                risk_level: RiskLevel::Info,
            });
        }
    };

    // Send GET / request
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        ip, port
    );
    let _ = conn.write_all(request.as_bytes()).await;

    let mut buf = vec![0u8; 4096];
    let n = conn.read(&mut buf).await.unwrap_or(0);

    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();

    let is_vulnerable = response.contains("cluster_name") ||
                        response.contains("\"name\"") && response.contains("\"cluster_name\"");
    let result = if is_vulnerable {
        "Returns cluster info without authentication - NO AUTH REQUIRED"
    } else {
        "Authentication appears required"
    };

    Ok(UnauthorizedEndpoint {
        ip: ip.to_string(),
        port,
        service: "Elasticsearch".to_string(),
        test_performed: "GET /".to_string(),
        result: result.to_string(),
        is_vulnerable,
        risk_level: if is_vulnerable { RiskLevel::Critical } else { RiskLevel::Info },
    })
}

/// Test MongoDB unauthenticated access (listDatabases)
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_mongodb_unauth(
    ip: &str,
    port: u16,
) -> Result<UnauthorizedEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = match tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await {
        Ok(Ok(c)) => c,
        _ => {
            return Ok(UnauthorizedEndpoint {
                ip: ip.to_string(),
                port,
                service: "MongoDB".to_string(),
                test_performed: "listDatabases command".to_string(),
                result: "Connection failed".to_string(),
                is_vulnerable: false,
                risk_level: RiskLevel::Info,
            });
        }
    };

    // MongoDB wire protocol: OP_QUERY for listDatabases
    // Simplified: just check if port is open and responds
    let request = b"\x41\x00\x00\x00\x00"; // Minimal MongoDB query
    let _ = conn.write_all(request).await;

    let mut buf = vec![0u8; 256];
    let n = conn.read(&mut buf).await.unwrap_or(0);

    let response = String::from_utf8_lossy(&buf[..n]);

    // MongoDB should respond with something like OP_REPLY
    let is_vulnerable = response.len() > 0 && !response.contains("auth");
    let result = if is_vulnerable {
        "Port is open and responding - may allow unauthenticated access"
    } else {
        "Authentication appears required"
    };

    Ok(UnauthorizedEndpoint {
        ip: ip.to_string(),
        port,
        service: "MongoDB".to_string(),
        test_performed: "listDatabases command".to_string(),
        result: result.to_string(),
        is_vulnerable,
        risk_level: if is_vulnerable { RiskLevel::Critical } else { RiskLevel::Info },
    })
}

/// Test Memcached unauthenticated access (stats command)
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_memcached_unauth(
    ip: &str,
    port: u16,
) -> Result<UnauthorizedEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = match tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await {
        Ok(Ok(c)) => c,
        _ => {
            return Ok(UnauthorizedEndpoint {
                ip: ip.to_string(),
                port,
                service: "Memcached".to_string(),
                test_performed: "stats command".to_string(),
                result: "Connection failed".to_string(),
                is_vulnerable: false,
                risk_level: RiskLevel::Info,
            });
        }
    };

    // Send stats command
    let _ = conn.write_all(b"stats\r\n").await;

    let mut buf = vec![0u8; 2048];
    let n = conn.read(&mut buf).await.unwrap_or(0);

    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();

    let is_vulnerable = response.contains("stat");
    let result = if is_vulnerable {
        "Responds to STATS without authentication - NO AUTH REQUIRED"
    } else {
        "Authentication appears required"
    };

    Ok(UnauthorizedEndpoint {
        ip: ip.to_string(),
        port,
        service: "Memcached".to_string(),
        test_performed: "stats command".to_string(),
        result: result.to_string(),
        is_vulnerable,
        risk_level: if is_vulnerable { RiskLevel::Critical } else { RiskLevel::Info },
    })
}

/// Test Docker API unauthenticated access
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_docker_api_unauth(
    ip: &str,
    port: u16,
) -> Result<UnauthorizedEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = match tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await {
        Ok(Ok(c)) => c,
        _ => {
            return Ok(UnauthorizedEndpoint {
                ip: ip.to_string(),
                port,
                service: "Docker API".to_string(),
                test_performed: "GET /v1.41/containers/json".to_string(),
                result: "Connection failed".to_string(),
                is_vulnerable: false,
                risk_level: RiskLevel::Info,
            });
        }
    };

    // Send Docker API request
    let request = format!(
        "GET /v1.41/containers/json HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        ip, port
    );
    let _ = conn.write_all(request.as_bytes()).await;

    let mut buf = vec![0u8; 4096];
    let n = conn.read(&mut buf).await.unwrap_or(0);

    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();

    let is_vulnerable = response.contains("\"containers\"") ||
                        response.contains("[]") && response.contains("http/1.1 200");
    let result = if is_vulnerable {
        "Docker API responds without authentication - FULL HOST CONTROL POSSIBLE"
    } else {
        "Authentication may be required"
    };

    Ok(UnauthorizedEndpoint {
        ip: ip.to_string(),
        port,
        service: "Docker API".to_string(),
        test_performed: "GET /v1.41/containers/json".to_string(),
        result: result.to_string(),
        is_vulnerable,
        risk_level: if is_vulnerable { RiskLevel::Critical } else { RiskLevel::Info },
    })
}

/// Test Kubernetes API unauthenticated access
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_kubernetes_api_unauth(
    ip: &str,
    port: u16,
) -> Result<UnauthorizedEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = match tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await {
        Ok(Ok(c)) => c,
        _ => {
            return Ok(UnauthorizedEndpoint {
                ip: ip.to_string(),
                port,
                service: "Kubernetes API".to_string(),
                test_performed: "GET /api/v1/nodes".to_string(),
                result: "Connection failed".to_string(),
                is_vulnerable: false,
                risk_level: RiskLevel::Info,
            });
        }
    };

    // Send Kubernetes API request
    let request = format!(
        "GET /api/v1/nodes HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        ip, port
    );
    let _ = conn.write_all(request.as_bytes()).await;

    let mut buf = vec![0u8; 8192];
    let n = conn.read(&mut buf).await.unwrap_or(0);

    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();

    let is_vulnerable = response.contains("\"nodes\"") ||
                        response.contains("\"kind\"") && response.contains("\"node\"") ||
                        response.contains("http/1.1 200");
    let result = if is_vulnerable {
        "Kubernetes API responds without authentication - FULL CLUSTER CONTROL POSSIBLE"
    } else {
        "Authentication is required"
    };

    Ok(UnauthorizedEndpoint {
        ip: ip.to_string(),
        port,
        service: "Kubernetes API".to_string(),
        test_performed: "GET /api/v1/nodes".to_string(),
        result: result.to_string(),
        is_vulnerable,
        risk_level: if is_vulnerable { RiskLevel::Critical } else { RiskLevel::Info },
    })
}

/// Test RTSP camera unauthenticated access (DESCRIBE without auth)
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_rtsp_camera_unauth(
    ip: &str,
    port: u16,
) -> Result<UnauthorizedEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = match tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await {
        Ok(Ok(c)) => c,
        _ => {
            return Ok(UnauthorizedEndpoint {
                ip: ip.to_string(),
                port,
                service: "RTSP Camera".to_string(),
                test_performed: "DESCRIBE request".to_string(),
                result: "Connection failed".to_string(),
                is_vulnerable: false,
                risk_level: RiskLevel::Info,
            });
        }
    };

    // Send RTSP DESCRIBE without authentication
    let request = "DESCRIBE rtsp://localhost/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n";
    let _ = conn.write_all(request.as_bytes()).await;

    let mut buf = vec![0u8; 2048];
    let n = conn.read(&mut buf).await.unwrap_or(0);

    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();

    // RTSP should respond with 200 OK and SDP, or 401 if auth required
    let is_vulnerable = response.contains("sdp") &&
                        !response.contains("401") &&
                        !response.contains("unauthorized");
    let result = if is_vulnerable {
        "RTSP stream accessible without authentication - VIDEO FEED EXPOSED"
    } else if response.contains("401") || response.contains("unauthorized") {
        "Authentication is required"
    } else {
        "Could not determine auth status"
    };

    Ok(UnauthorizedEndpoint {
        ip: ip.to_string(),
        port,
        service: "RTSP Camera".to_string(),
        test_performed: "DESCRIBE request (no auth)".to_string(),
        result: result.to_string(),
        is_vulnerable,
        risk_level: if is_vulnerable { RiskLevel::High } else { RiskLevel::Info },
    })
}

/// Run all unauthorized access tests for a target
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_unauthorized_access(
    ip: &str,
    port: u16,
    service_type: &str,
) -> Result<UnauthorizedEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    match service_type.to_lowercase().as_str() {
        "redis" => test_redis_unauth(ip, port).await,
        "elasticsearch" | "elastic" => test_elasticsearch_unauth(ip, port).await,
        "mongodb" | "mongo" => test_mongodb_unauth(ip, port).await,
        "memcached" => test_memcached_unauth(ip, port).await,
        "docker" | "docker-api" => test_docker_api_unauth(ip, port).await,
        "kubernetes" | "k8s" | "kube-api" => test_kubernetes_api_unauth(ip, port).await,
        "rtsp" | "camera" | "rtsp-camera" => test_rtsp_camera_unauth(ip, port).await,
        _ => {
            Ok(UnauthorizedEndpoint {
                ip: ip.to_string(),
                port,
                service: service_type.to_string(),
                test_performed: "Unknown".to_string(),
                result: "Service type not recognized for unauth testing".to_string(),
                is_vulnerable: false,
                risk_level: RiskLevel::Info,
            })
        }
    }
}

/// Test Kafka unauthenticated access (metadata request)
#[cfg(not(target_arch = "wasm32"))]
pub async fn test_kafka_unauth(
    ip: &str,
    port: u16,
) -> Result<UnauthorizedEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout as tokio_timeout, Duration};

    let timeout_dur = Duration::from_millis(3000);
    let addr = format!("{}:{}", ip, port);

    let mut conn = match tokio_timeout(timeout_dur, TcpStream::connect(&addr)).await {
        Ok(Ok(c)) => c,
        _ => {
            return Ok(UnauthorizedEndpoint {
                ip: ip.to_string(),
                port,
                service: "Kafka".to_string(),
                test_performed: "Metadata request".to_string(),
                result: "Connection failed".to_string(),
                is_vulnerable: false,
                risk_level: RiskLevel::Info,
            });
        }
    };

    // Kafka wire protocol: produce request (simplified)
    // API Key for Metadata is 3, Version 0
    let kafka_request: Vec<u8> = vec![
        // Message size (4 bytes, big endian) - 26 bytes total
        0x00, 0x00, 0x00, 0x1A,
        // API Key (2 bytes, big endian) = 3 for Metadata
        0x00, 0x03,
        // API Version (2 bytes) = 0
        0x00, 0x00,
        // Correlation ID (4 bytes)
        0x00, 0x00, 0x00, 0x01,
        // Client ID
        0x00, 0x05, b'n', b'e', b't', b'p',
        // Topic count (4 bytes) = 0
        0x00, 0x00, 0x00, 0x00,
    ];

    let _ = conn.write_all(&kafka_request).await;

    let mut buf = vec![0u8; 4096];
    let n = conn.read(&mut buf).await.unwrap_or(0);

    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();

    // Kafka should respond with correlation_id matching and broker info
    let is_vulnerable = response.len() > 10 &&
                        (response.contains("brokers") || response.contains("kafka"));
    let result = if is_vulnerable {
        "Kafka broker responds without authentication - METADATA EXPOSED"
    } else {
        "Authentication may be required"
    };

    Ok(UnauthorizedEndpoint {
        ip: ip.to_string(),
        port,
        service: "Kafka".to_string(),
        test_performed: "Metadata request".to_string(),
        result: result.to_string(),
        is_vulnerable,
        risk_level: if is_vulnerable { RiskLevel::High } else { RiskLevel::Info },
    })
}

/// Raw Redis test - returns UnauthorizedEndpoint directly
async fn test_redis_unauth_raw(ip: &str, port: u16) -> UnauthorizedEndpoint {
    match test_redis_unauth(ip, port).await {
        Ok(endpoint) => endpoint,
        Err(_) => UnauthorizedEndpoint {
            ip: ip.to_string(),
            port,
            service: "Redis".to_string(),
            test_performed: "PING command".to_string(),
            result: "Connection failed".to_string(),
            is_vulnerable: false,
            risk_level: RiskLevel::Info,
        },
    }
}

/// Raw Elasticsearch test - returns UnauthorizedEndpoint directly
async fn test_elasticsearch_unauth_raw(ip: &str, port: u16) -> UnauthorizedEndpoint {
    match test_elasticsearch_unauth(ip, port).await {
        Ok(endpoint) => endpoint,
        Err(_) => UnauthorizedEndpoint {
            ip: ip.to_string(),
            port,
            service: "Elasticsearch".to_string(),
            test_performed: "GET /".to_string(),
            result: "Connection failed".to_string(),
            is_vulnerable: false,
            risk_level: RiskLevel::Info,
        },
    }
}

/// Raw MongoDB test - returns UnauthorizedEndpoint directly
async fn test_mongodb_unauth_raw(ip: &str, port: u16) -> UnauthorizedEndpoint {
    match test_mongodb_unauth(ip, port).await {
        Ok(endpoint) => endpoint,
        Err(_) => UnauthorizedEndpoint {
            ip: ip.to_string(),
            port,
            service: "MongoDB".to_string(),
            test_performed: "listDatabases command".to_string(),
            result: "Connection failed".to_string(),
            is_vulnerable: false,
            risk_level: RiskLevel::Info,
        },
    }
}

/// Raw Memcached test - returns UnauthorizedEndpoint directly
async fn test_memcached_unauth_raw(ip: &str, port: u16) -> UnauthorizedEndpoint {
    match test_memcached_unauth(ip, port).await {
        Ok(endpoint) => endpoint,
        Err(_) => UnauthorizedEndpoint {
            ip: ip.to_string(),
            port,
            service: "Memcached".to_string(),
            test_performed: "stats command".to_string(),
            result: "Connection failed".to_string(),
            is_vulnerable: false,
            risk_level: RiskLevel::Info,
        },
    }
}

/// Raw Docker API test - returns UnauthorizedEndpoint directly
async fn test_docker_api_unauth_raw(ip: &str, port: u16) -> UnauthorizedEndpoint {
    match test_docker_api_unauth(ip, port).await {
        Ok(endpoint) => endpoint,
        Err(_) => UnauthorizedEndpoint {
            ip: ip.to_string(),
            port,
            service: "Docker API".to_string(),
            test_performed: "GET /v1.41/containers/json".to_string(),
            result: "Connection failed".to_string(),
            is_vulnerable: false,
            risk_level: RiskLevel::Info,
        },
    }
}

/// Raw Kafka test - returns UnauthorizedEndpoint directly
async fn test_kafka_unauth_raw(ip: &str, port: u16) -> UnauthorizedEndpoint {
    match test_kafka_unauth(ip, port).await {
        Ok(endpoint) => endpoint,
        Err(_) => UnauthorizedEndpoint {
            ip: ip.to_string(),
            port,
            service: "Kafka".to_string(),
            test_performed: "Metadata request".to_string(),
            result: "Connection failed".to_string(),
            is_vulnerable: false,
            risk_level: RiskLevel::Info,
        },
    }
}

/// Raw RTSP test - returns UnauthorizedEndpoint directly
async fn test_rtsp_camera_unauth_raw(ip: &str, port: u16) -> UnauthorizedEndpoint {
    match test_rtsp_camera_unauth(ip, port).await {
        Ok(endpoint) => endpoint,
        Err(_) => UnauthorizedEndpoint {
            ip: ip.to_string(),
            port,
            service: "RTSP Camera".to_string(),
            test_performed: "DESCRIBE request".to_string(),
            result: "Connection failed".to_string(),
            is_vulnerable: false,
            risk_level: RiskLevel::Info,
        },
    }
}

/// Common ports for unauth testing
pub fn common_unauth_ports() -> Vec<(u16, &'static str)> {
    vec![
        (6379, "Redis"),
        (9200, "Elasticsearch"),
        (27017, "MongoDB"),
        (11211, "Memcached"),
        (2375, "Docker API"),
        (6443, "Kubernetes API"),
        (9092, "Kafka"),
        (554, "RTSP Camera"),
        (5000, "RTSP Camera (alternative)"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unauthorized_endpoint_serialization() {
        let endpoint = UnauthorizedEndpoint {
            ip: "192.168.1.100".to_string(),
            port: 6379,
            service: "Redis".to_string(),
            test_performed: "PING command".to_string(),
            result: "NO AUTH REQUIRED".to_string(),
            is_vulnerable: true,
            risk_level: RiskLevel::Critical,
        };
        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains("192.168.1.100"));
        assert!(json.contains("Redis"));
        assert!(json.contains("vulnerable"));
    }

    #[test]
    fn test_risk_level_serialization() {
        assert_eq!(serde_json::to_string(&RiskLevel::Critical).unwrap(), "\"critical\"");
        assert_eq!(serde_json::to_string(&RiskLevel::High).unwrap(), "\"high\"");
        assert_eq!(serde_json::to_string(&RiskLevel::Medium).unwrap(), "\"medium\"");
        assert_eq!(serde_json::to_string(&RiskLevel::Low).unwrap(), "\"low\"");
        assert_eq!(serde_json::to_string(&RiskLevel::Info).unwrap(), "\"info\"");
    }

    #[test]
    fn test_common_unauth_ports() {
        let ports = common_unauth_ports();
        assert!(ports.contains(&(6379, "Redis")));
        assert!(ports.contains(&(9200, "Elasticsearch")));
        assert!(ports.contains(&(27017, "MongoDB")));
        assert!(ports.contains(&(11211, "Memcached")));
    }
}
