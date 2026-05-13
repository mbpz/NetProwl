//! OS fingerprint inference from TTL and open ports

#[derive(Debug, Clone)]
pub struct OsFingerprint {
    pub os: OsType,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OsType {
    Linux,
    Windows,
    MacOS,
    Ios,
    Android,
    NetworkDevice,
    Unknown,
}

/// Detect OS type based on TTL value and open ports.
///
/// TTL ranges:
///   - 64: Linux, macOS, iOS, Android
///   - 128: Windows
///   - 255: Network device (router/switch)
pub fn detect_os(ttl: u8, open_ports: &[u16]) -> OsFingerprint {
    if ttl == 0 {
        return OsFingerprint {
            os: OsType::Unknown,
            confidence: 0.0,
        };
    }

    // Primary inference from TTL
    let (os, mut base_confidence) = if ttl <= 64 {
        (OsType::Linux, 0.7)
    } else if ttl <= 128 {
        (OsType::Windows, 0.7)
    } else {
        // TTL > 128, likely 255 (network device)
        (OsType::NetworkDevice, 0.8)
    };

    // Refine based on open ports
    let mut adjusted_confidence = base_confidence;

    for port in open_ports {
        match port {
            // Windows-specific ports
            5985 | 5986 => {
                // WinRM - strong Windows indicator
                if os == OsType::Windows {
                    adjusted_confidence = adjusted_confidence.max(0.95);
                } else {
                    return OsFingerprint {
                        os: OsType::Windows,
                        confidence: 0.85,
                    };
                }
            }
            3389 => {
                // RDP - Windows
                if os == OsType::Windows {
                    adjusted_confidence = adjusted_confidence.max(0.9);
                } else {
                    return OsFingerprint {
                        os: OsType::Windows,
                        confidence: 0.8,
                    };
                }
            }
            // Linux/Unix-specific ports
            9090 => {
                // Cockpit - Linux management interface
                return OsFingerprint {
                    os: OsType::Linux,
                    confidence: 0.9,
                };
            }
            // Cross-platform ports (refine, not override)
            22 => {
                // SSH - common on Linux, macOS, network devices
                adjusted_confidence = adjusted_confidence.max(0.75);
            }
            80 | 443 | 8080 | 8443 => {
                // Web servers - common on all OSes, slight Linux preference
                adjusted_confidence = adjusted_confidence.max(0.6);
            }
            _ => {}
        }
    }

    OsFingerprint {
        os,
        confidence: adjusted_confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_64_linux() {
        let result = detect_os(64, &[]);
        assert_eq!(result.os, OsType::Linux);
        assert!(result.confidence >= 0.7);
    }

    #[test]
    fn test_ttl_128_windows() {
        let result = detect_os(128, &[]);
        assert_eq!(result.os, OsType::Windows);
        assert!(result.confidence >= 0.7);
    }

    #[test]
    fn test_ttl_255_network_device() {
        let result = detect_os(255, &[]);
        assert_eq!(result.os, OsType::NetworkDevice);
        assert!(result.confidence >= 0.8);
    }

    #[test]
    fn test_ttl_0_unknown() {
        let result = detect_os(0, &[]);
        assert_eq!(result.os, OsType::Unknown);
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_winrm_port_windows() {
        let result = detect_os(64, &[5985]);
        assert_eq!(result.os, OsType::Windows);
        assert!(result.confidence >= 0.85);
    }

    #[test]
    fn test_rdp_port_windows() {
        let result = detect_os(128, &[3389]);
        assert_eq!(result.os, OsType::Windows);
        assert!(result.confidence >= 0.9);
    }

    #[test]
    fn test_cockpit_port_linux() {
        let result = detect_os(128, &[9090]);
        assert_eq!(result.os, OsType::Linux);
        assert!(result.confidence >= 0.9);
    }

    #[test]
    fn test_ssh_port_refines() {
        let result = detect_os(64, &[22]);
        assert_eq!(result.os, OsType::Linux);
        assert!(result.confidence >= 0.75);
    }

    #[test]
    fn test_multiple_ports() {
        let result = detect_os(64, &[22, 80, 443]);
        assert_eq!(result.os, OsType::Linux);
        assert!(result.confidence >= 0.75);
    }
}
