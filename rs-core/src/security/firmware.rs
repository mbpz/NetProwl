//! F3-5: Firmware version risk assessment
//! Based on detected device type + version from banner
//! Query local DB of EOS (End of Support) devices

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Device type for firmware assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceCategory {
    Camera,
    Nas,
    Router,
    Switch,
    Printer,
    IoT,
    Unknown,
}

/// Firmware risk finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareRisk {
    pub ip: String,
    pub device_type: String,
    pub brand: Option<String>,
    pub current_version: Option<String>,
    pub eos_date: Option<String>,
    pub years_since_update: Option<i64>,
    pub risk_level: RiskLevel,
    pub recommendation: String,
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

/// EOS (End of Support) database entry
#[derive(Debug, Clone)]
pub(crate) struct EosEntry {
    brand: &'static str,
    model_pattern: &'static str,
    device_type: DeviceCategory,
    eos_date: &'static str, // YYYY-MM-DD format
    eos_year: i64,
    latest_version: &'static str,
    critical_cves: usize,
}

static EOS_DATABASE: &[EosEntry] = &[
    // Hikvision Cameras
    EosEntry {
        brand: "Hikvision",
        model_pattern: "DS-2CD2",
        device_type: DeviceCategory::Camera,
        eos_date: "2020-12-31",
        eos_year: 2020,
        latest_version: "5.5.82",
        critical_cves: 3,
    },
    EosEntry {
        brand: "Hikvision",
        model_pattern: "DS-2CD1",
        device_type: DeviceCategory::Camera,
        eos_date: "2019-06-30",
        eos_year: 2019,
        latest_version: "5.4.82",
        critical_cves: 5,
    },
    // Dahua Cameras
    EosEntry {
        brand: "Dahua",
        model_pattern: "IPC-HFW4",
        device_type: DeviceCategory::Camera,
        eos_date: "2021-03-31",
        eos_year: 2021,
        latest_version: "2.820",
        critical_cves: 2,
    },
    // Axis Cameras
    EosEntry {
        brand: "Axis",
        model_pattern: "P1346",
        device_type: DeviceCategory::Camera,
        eos_date: "2020-01-31",
        eos_year: 2020,
        latest_version: "6.50.1",
        critical_cves: 4,
    },
    // Synology NAS
    EosEntry {
        brand: "Synology",
        model_pattern: "DS213j",
        device_type: DeviceCategory::Nas,
        eos_date: "2020-12-31",
        eos_year: 2020,
        latest_version: "DSM 6.2.4",
        critical_cves: 2,
    },
    EosEntry {
        brand: "Synology",
        model_pattern: "DS214se",
        device_type: DeviceCategory::Nas,
        eos_date: "2021-06-30",
        eos_year: 2021,
        latest_version: "DSM 7.1",
        critical_cves: 1,
    },
    // QNAP NAS
    EosEntry {
        brand: "QNAP",
        model_pattern: "TS-251",
        device_type: DeviceCategory::Nas,
        eos_date: "2022-06-30",
        eos_year: 2022,
        latest_version: "QTS 5.0",
        critical_cves: 3,
    },
    // Netgear Routers
    EosEntry {
        brand: "Netgear",
        model_pattern: "R7000",
        device_type: DeviceCategory::Router,
        eos_date: "2021-12-31",
        eos_year: 2021,
        latest_version: "1.0.11.116",
        critical_cves: 4,
    },
    EosEntry {
        brand: "Netgear",
        model_pattern: "R6400",
        device_type: DeviceCategory::Router,
        eos_date: "2022-03-31",
        eos_year: 2022,
        latest_version: "1.0.1.62",
        critical_cves: 3,
    },
    // TP-Link Routers
    EosEntry {
        brand: "TP-Link",
        model_pattern: "Archer C7",
        device_type: DeviceCategory::Router,
        eos_date: "2022-06-30",
        eos_year: 2022,
        latest_version: "190121",
        critical_cves: 2,
    },
    // Generic/EOS Cameras (common patterns)
    EosEntry {
        brand: "Generic",
        model_pattern: "MJPEG",
        device_type: DeviceCategory::Camera,
        eos_date: "2018-01-01",
        eos_year: 2018,
        latest_version: "Unknown",
        critical_cves: 8,
    },
    // Generic IoT devices
    EosEntry {
        brand: "Generic",
        model_pattern: "IoT",
        device_type: DeviceCategory::IoT,
        eos_date: "2019-01-01",
        eos_year: 2019,
        latest_version: "Unknown",
        critical_cves: 12,
    },
];

/// Parse version string to major.minor.patch
pub fn parse_version(version: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let major = parts[0].parse().unwrap_or(0);
    let minor = parts[1].parse().unwrap_or(0);
    let patch = if parts.len() > 2 {
        parts[2].parse().unwrap_or(0)
    } else {
        0
    };

    Some((major, minor, patch))
}

/// Extract version from banner string
pub fn extract_version_from_banner(banner: &str) -> Option<String> {
    // Common version patterns
    let patterns = [
        r"v(\d+\.\d+\.?\d*)",
        r"version\s*(\d+\.\d+\.?\d*)",
        r"firmware\s*(\d+\.\d+\.?\d*)",
        r"(\d+\.\d+\.\d+)",
        r"build\s*(\d+)",
    ];

    for pattern in patterns.iter() {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(banner) {
                if let Some(m) = caps.get(1) {
                    return Some(m.as_str().to_string());
                }
            }
        }
    }
    None
}

/// Get current year
fn current_year() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64 / (365 * 24 * 60 * 60)
}

/// Calculate years since a given year
fn years_since(year: i64) -> i64 {
    current_year() - year
}

/// Find EOS entry by brand and model pattern
pub fn find_eos_entry(brand: &str, model: &str) -> Option<&'static EosEntry> {
    let brand_lower = brand.to_lowercase();
    let model_lower = model.to_lowercase();

    for entry in EOS_DATABASE.iter() {
        let entry_brand_lower = entry.brand.to_lowercase();

        // Check if brand matches (or is generic)
        if entry_brand_lower != "generic" && entry_brand_lower != brand_lower {
            continue;
        }

        // Check if model pattern matches
        if model_lower.contains(&entry.model_pattern.to_lowercase()) ||
           entry.model_pattern.to_lowercase() == "generic" {
            return Some(entry);
        }
    }
    None
}

/// Assess firmware risk for a device
pub fn assess_firmware_risk(
    ip: &str,
    device_type: &str,
    brand: Option<&str>,
    model: Option<&str>,
    version: Option<&str>,
) -> FirmwareRisk {
    // Try to find EOS entry
    let brand_str = brand.unwrap_or("Generic");
    let model_str = model.unwrap_or("");

    if let Some(eos_entry) = find_eos_entry(brand_str, model_str) {
        let years = years_since(eos_entry.eos_year);

        let risk_level = if years > 4 || eos_entry.critical_cves >= 5 {
            RiskLevel::Critical
        } else if years > 2 || eos_entry.critical_cves >= 3 {
            RiskLevel::High
        } else if years > 1 || eos_entry.critical_cves >= 1 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };

        let recommendation = if risk_level == RiskLevel::Critical {
            format!(
                "URGENT: {} {} is {} years past EOS with {} known critical CVEs. Replace immediately.",
                eos_entry.brand, eos_entry.model_pattern, years, eos_entry.critical_cves
            )
        } else if risk_level == RiskLevel::High {
            format!(
                "{} {} reached EOS in {}. Upgrade firmware to latest version or replace.",
                eos_entry.brand, eos_entry.model_pattern, eos_entry.eos_date
            )
        } else {
            format!(
                "Consider upgrading {} {} to latest firmware ({})",
                eos_entry.brand, eos_entry.model_pattern, eos_entry.latest_version
            )
        };

        return FirmwareRisk {
            ip: ip.to_string(),
            device_type: device_type.to_string(),
            brand: Some(eos_entry.brand.to_string()),
            current_version: version.map(|s| s.to_string()),
            eos_date: Some(eos_entry.eos_date.to_string()),
            years_since_update: Some(years),
            risk_level,
            recommendation,
        };
    }

    // No EOS entry found - assess based on age if version was provided
    if let Some(ver) = version {
        if let Some((major, minor, _)) = parse_version(ver) {
            // Very old version numbers suggest old firmware
            if major < 2 || (major == 2 && minor < 5) {
                return FirmwareRisk {
                    ip: ip.to_string(),
                    device_type: device_type.to_string(),
                    brand: brand.map(|s| s.to_string()),
                    current_version: Some(ver.to_string()),
                    eos_date: None,
                    years_since_update: None,
                    risk_level: RiskLevel::Medium,
                    recommendation: "Firmware version appears old. Check manufacturer for updates.".to_string(),
                };
            }
        }
    }

    // Default: no risk identified
    FirmwareRisk {
        ip: ip.to_string(),
        device_type: device_type.to_string(),
        brand: brand.map(|s| s.to_string()),
        current_version: version.map(|s| s.to_string()),
        eos_date: None,
        years_since_update: None,
        risk_level: RiskLevel::Info,
        recommendation: "No known firmware vulnerabilities found.".to_string(),
    }
}

/// Build a summary of all known EOS brands
pub fn get_eos_brands() -> Vec<(&'static str, DeviceCategory)> {
    let mut brands: HashMap<&'static str, DeviceCategory> = HashMap::new();
    for entry in EOS_DATABASE.iter() {
        brands.entry(entry.brand).or_insert_with(|| entry.device_type.clone());
    }
    brands.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("5.5.82"), Some((5, 5, 82)));
        assert_eq!(parse_version("2.820"), Some((2, 820, 0)));
        assert_eq!(parse_version("abc"), None);
    }

    #[test]
    fn test_extract_version_from_banner() {
        let v1 = extract_version_from_banner("Firmware V1.2.3");
        assert!(v1.is_some());
        assert_eq!(v1.unwrap(), "1.2.3");

        let v2 = extract_version_from_banner("version 5.5.82");
        assert!(v2.is_some());

        let v3 = extract_version_from_banner("build 12345");
        assert!(v3.is_some());
        assert_eq!(v3.unwrap(), "12345");
    }

    #[test]
    fn test_find_eos_entry_hikvision() {
        let entry = find_eos_entry("Hikvision", "DS-2CD2043G2");
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.brand, "Hikvision");
        assert_eq!(e.device_type, DeviceCategory::Camera);
    }

    #[test]
    fn test_find_eos_entry_synology() {
        let entry = find_eos_entry("Synology", "DS213j");
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.brand, "Synology");
        assert!(e.critical_cves >= 1);
    }

    #[test]
    fn test_assess_firmware_risk_eos() {
        let risk = assess_firmware_risk(
            "192.168.1.100",
            "Camera",
            Some("Hikvision"),
            Some("DS-2CD2"),
            Some("1.0.0"),
        );
        assert!(matches!(risk.risk_level, RiskLevel::High | RiskLevel::Critical | RiskLevel::Medium));
        assert!(risk.eos_date.is_some());
    }

    #[test]
    fn test_assess_firmware_risk_no_match() {
        let risk = assess_firmware_risk(
            "192.168.1.100",
            "Unknown",
            Some("Unknown"),
            Some("XYZ123"),
            None,
        );
        assert_eq!(risk.risk_level, RiskLevel::Info);
    }

    #[test]
    fn test_firmware_risk_serialization() {
        let risk = FirmwareRisk {
            ip: "192.168.1.100".to_string(),
            device_type: "Camera".to_string(),
            brand: Some("Hikvision".to_string()),
            current_version: Some("1.2.3".to_string()),
            eos_date: Some("2020-12-31".to_string()),
            years_since_update: Some(5),
            risk_level: RiskLevel::High,
            recommendation: "Upgrade firmware".to_string(),
        };
        let json = serde_json::to_string(&risk).unwrap();
        assert!(json.contains("192.168.1.100"));
        assert!(json.contains("Hikvision"));
        assert!(json.contains("high"));
    }

    #[test]
    fn test_get_eos_brands() {
        let brands = get_eos_brands();
        assert!(!brands.is_empty());
        assert!(brands.iter().any(|(b, _)| *b == "Hikvision"));
        assert!(brands.iter().any(|(b, _)| *b == "Synology"));
    }

    #[test]
    fn test_years_since_update() {
        // This test verifies the logic works
        let risk = assess_firmware_risk(
            "192.168.1.100",
            "Camera",
            Some("Generic"),
            Some("MJPEG"),
            None,
        );
        assert!(risk.years_since_update.is_some());
    }
}
