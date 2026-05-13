//! Firmware EOS (End of Support) Database
//!
//! Provides device firmware end-of-support dates and risk assessment.

use chrono::{Local, NaiveDate};
use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Risk level for EOS devices
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    /// Still supported (no EOS date or future date)
    Low,
    /// EOS date < 1 year ago
    Medium,
    /// EOS date > 1 year ago
    High,
    /// EOS date > 2 years ago
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Firmware information for a device
#[derive(Debug, Clone)]
pub struct FirmwareInfo {
    /// Device vendor
    pub vendor: String,
    /// Device model
    pub model: String,
    /// End of support date (YYYY-MM-DD format), None if still supported
    pub eos_date: Option<String>,
    /// Latest available firmware version, None if unknown
    pub latest_version: Option<String>,
    /// Risk level based on EOS status
    pub risk_level: RiskLevel,
}

/// EOS database entry
struct EosEntry {
    vendor: &'static str,
    model_pattern: &'static str,
    eos_date: Option<NaiveDate>,
    latest_version: Option<&'static str>,
}

/// Global EOS database
static EOS_DATABASE: Lazy<HashMap<String, EosEntry>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Hikvision cameras
    m.insert("hikvision_ds-2cd2043".to_string(), EosEntry {
        vendor: "Hikvision",
        model_pattern: "DS-2CD2043",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 6, 1).unwrap()),
        latest_version: Some("v5.7.4"),
    });
    m.insert("hikvision_ds-2cd2x43".to_string(), EosEntry {
        vendor: "Hikvision",
        model_pattern: "DS-2CD2X43",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 6, 1).unwrap()),
        latest_version: Some("v5.7.4"),
    });
    m.insert("hikvision_ds-2cd3x43".to_string(), EosEntry {
        vendor: "Hikvision",
        model_pattern: "DS-2CD3X43",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 6, 1).unwrap()),
        latest_version: Some("v5.7.4"),
    });
    m.insert("hikvision_ds-2cd5x23".to_string(), EosEntry {
        vendor: "Hikvision",
        model_pattern: "DS-2CD5X23",
        eos_date: Some(NaiveDate::from_ymd_opt(2020, 12, 1).unwrap()),
        latest_version: Some("v5.6.1"),
    });

    // Dahua cameras
    m.insert("dahua_hc3x52".to_string(), EosEntry {
        vendor: "Dahua",
        model_pattern: "HC3X52",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 3, 1).unwrap()),
        latest_version: Some("v3.2.1"),
    });
    m.insert("dahua_h4x52".to_string(), EosEntry {
        vendor: "Dahua",
        model_pattern: "H4X52",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 3, 1).unwrap()),
        latest_version: Some("v3.2.1"),
    });
    m.insert("dahua_hdw4x22".to_string(), EosEntry {
        vendor: "Dahua",
        model_pattern: "HDW4X22",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 9, 1).unwrap()),
        latest_version: Some("v3.2.0"),
    });
    m.insert("dahua_k42x".to_string(), EosEntry {
        vendor: "Dahua",
        model_pattern: "K42X",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 9, 1).unwrap()),
        latest_version: Some("v3.2.0"),
    });

    // Axis cameras
    m.insert("axis_p13xx".to_string(), EosEntry {
        vendor: "Axis",
        model_pattern: "P13XX",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 12, 31).unwrap()),
        latest_version: Some("9.80.1"),
    });
    m.insert("axis_m10xx".to_string(), EosEntry {
        vendor: "Axis",
        model_pattern: "M10XX",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 6, 30).unwrap()),
        latest_version: Some("9.80.1"),
    });
    m.insert("axis_m30xx".to_string(), EosEntry {
        vendor: "Axis",
        model_pattern: "M30XX",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 6, 30).unwrap()),
        latest_version: Some("9.80.1"),
    });
    m.insert("axis_q17xx".to_string(), EosEntry {
        vendor: "Axis",
        model_pattern: "Q17XX",
        eos_date: Some(NaiveDate::from_ymd_opt(2020, 12, 31).unwrap()),
        latest_version: Some("9.40.1"),
    });

    // Bosch cameras
    m.insert("bosch_nbn-xx".to_string(), EosEntry {
        vendor: "Bosch",
        model_pattern: "NBN-XX",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 6, 30).unwrap()),
        latest_version: Some("6.30.012"),
    });
    m.insert("bosch_dinion_x".to_string(), EosEntry {
        vendor: "Bosch",
        model_pattern: "DINION-X",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 6, 30).unwrap()),
        latest_version: Some("6.30.012"),
    });
    m.insert("bosch_flexidome_x".to_string(), EosEntry {
        vendor: "Bosch",
        model_pattern: "FLEXIDOME-X",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 6, 30).unwrap()),
        latest_version: Some("6.30.012"),
    });

    // TP-Link routers
    m.insert("tplink_tl-wr84x".to_string(), EosEntry {
        vendor: "TP-Link",
        model_pattern: "TL-WR84X",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 12, 31).unwrap()),
        latest_version: Some("v2.0.5"),
    });
    m.insert("tplink_tl-wr94x".to_string(), EosEntry {
        vendor: "TP-Link",
        model_pattern: "TL-WR94X",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 12, 31).unwrap()),
        latest_version: Some("v2.0.5"),
    });
    m.insert("tplink_tl-wr7xx".to_string(), EosEntry {
        vendor: "TP-Link",
        model_pattern: "TL-WR7XX",
        eos_date: Some(NaiveDate::from_ymd_opt(2020, 6, 30).unwrap()),
        latest_version: Some("v1.2.3"),
    });
    m.insert("tplink_tl-wr8xx".to_string(), EosEntry {
        vendor: "TP-Link",
        model_pattern: "TL-WR8XX",
        eos_date: Some(NaiveDate::from_ymd_opt(2020, 6, 30).unwrap()),
        latest_version: Some("v1.2.3"),
    });

    // Netgear routers
    m.insert("netgear_wndr4xxx".to_string(), EosEntry {
        vendor: "Netgear",
        model_pattern: "WNDR4XXX",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 12, 31).unwrap()),
        latest_version: Some("v1.0.0.72"),
    });
    m.insert("netgear_r6xxx".to_string(), EosEntry {
        vendor: "Netgear",
        model_pattern: "R6XXX",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 9, 30).unwrap()),
        latest_version: Some("v1.0.0.120"),
    });
    m.insert("netgear_dgnd3xxx".to_string(), EosEntry {
        vendor: "Netgear",
        model_pattern: "DGND3XXX",
        eos_date: Some(NaiveDate::from_ymd_opt(2020, 12, 31).unwrap()),
        latest_version: Some("v1.0.0.62"),
    });

    // Linksys routers
    m.insert("linksys_ea4xxx".to_string(), EosEntry {
        vendor: "Linksys",
        model_pattern: "EA4XXX",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 3, 31).unwrap()),
        latest_version: Some("v1.1.12"),
    });
    m.insert("linksys_ea6xxx".to_string(), EosEntry {
        vendor: "Linksys",
        model_pattern: "EA6XXX",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 3, 31).unwrap()),
        latest_version: Some("v1.1.12"),
    });
    m.insert("linksys_wrt1200ac".to_string(), EosEntry {
        vendor: "Linksys",
        model_pattern: "WRT1200AC",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 6, 30).unwrap()),
        latest_version: Some("v1.0.2.200"),
    });

    // Synology NAS
    m.insert("synology_ds2xxxj".to_string(), EosEntry {
        vendor: "Synology",
        model_pattern: "DS2XXXJ",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 6, 30).unwrap()),
        latest_version: Some("DSM 7.2"),
    });
    m.insert("synology_ds4xxxj".to_string(), EosEntry {
        vendor: "Synology",
        model_pattern: "DS4XXXJ",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 12, 31).unwrap()),
        latest_version: Some("DSM 7.2"),
    });
    m.insert("synology_ds1xxj".to_string(), EosEntry {
        vendor: "Synology",
        model_pattern: "DS1XXJ",
        eos_date: Some(NaiveDate::from_ymd_opt(2020, 6, 30).unwrap()),
        latest_version: Some("DSM 6.2"),
    });

    // QNAP NAS
    m.insert("qnap_ts-x10x".to_string(), EosEntry {
        vendor: "QNAP",
        model_pattern: "TS-X10X",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 12, 31).unwrap()),
        latest_version: Some("QTS 5.1.0"),
    });
    m.insert("qnap_ts-x31x".to_string(), EosEntry {
        vendor: "QNAP",
        model_pattern: "TS-X31X",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 6, 30).unwrap()),
        latest_version: Some("QTS 5.1.0"),
    });
    m.insert("qnap_ts-4xxx".to_string(), EosEntry {
        vendor: "QNAP",
        model_pattern: "TS-4XXX",
        eos_date: Some(NaiveDate::from_ymd_opt(2020, 12, 31).unwrap()),
        latest_version: Some("QTS 4.3.6"),
    });

    // Cisco network gear
    m.insert("cisco_rv0xx".to_string(), EosEntry {
        vendor: "Cisco",
        model_pattern: "RV0XX",
        eos_date: Some(NaiveDate::from_ymd_opt(2021, 6, 30).unwrap()),
        latest_version: Some("v1.0.2.8"),
    });
    m.insert("cisco_waas".to_string(), EosEntry {
        vendor: "Cisco",
        model_pattern: "WAAS",
        eos_date: Some(NaiveDate::from_ymd_opt(2020, 12, 31).unwrap()),
        latest_version: Some("v5.5.1"),
    });
    m.insert("cisco_prime_ncs".to_string(), EosEntry {
        vendor: "Cisco",
        model_pattern: "Prime NCS",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 3, 31).unwrap()),
        latest_version: Some("v3.0"),
    });

    // Ubiquiti network gear
    m.insert("ubiquiti_unifi_switch".to_string(), EosEntry {
        vendor: "Ubiquiti",
        model_pattern: "UniFi Switch",
        eos_date: Some(NaiveDate::from_ymd_opt(2023, 6, 30).unwrap()),
        latest_version: Some("v4.0.0"),
    });
    m.insert("ubiquiti_airmax".to_string(), EosEntry {
        vendor: "Ubiquiti",
        model_pattern: "AirMAX",
        eos_date: Some(NaiveDate::from_ymd_opt(2022, 12, 31).unwrap()),
        latest_version: Some("v8.0.0"),
    });
    m.insert("ubiquiti_unifi_ap".to_string(), EosEntry {
        vendor: "Ubiquiti",
        model_pattern: "UniFi AP",
        eos_date: None, // Still supported via firmware updates
        latest_version: Some("v6.0.0"),
    });

    m
});

/// Calculate risk level based on days since EOS
fn calculate_risk(eos_date: Option<NaiveDate>) -> RiskLevel {
    match eos_date {
        None => RiskLevel::Low,
        Some(date) => {
            let today = Local::now().date_naive();
            let days_since_eos = (today - date).num_days();

            if days_since_eos > 730 { // > 2 years
                RiskLevel::Critical
            } else if days_since_eos > 365 { // > 1 year
                RiskLevel::High
            } else if days_since_eos > 0 { // > 0 but < 1 year
                RiskLevel::Medium
            } else {
                // Future date or today - still supported
                RiskLevel::Low
            }
        }
    }
}

/// Check device EOS status
///
/// # Arguments
/// * `vendor` - Device vendor name (case-insensitive substring match)
/// * `model` - Device model name (case-insensitive substring match)
/// * `firmware_version` - Optional firmware version for future matching
///
/// # Returns
/// `FirmwareInfo` with EOS status and risk level
pub fn check_device_eos(vendor: &str, model: &str, firmware_version: Option<&str>) -> FirmwareInfo {
    let vendor_lower = vendor.to_lowercase();
    let model_lower = model.to_lowercase();

    let mut best_match: Option<&EosEntry> = None;
    let mut best_score: usize = 0;

    for entry in EOS_DATABASE.values() {
        let vendor_match = vendor_lower.contains(&entry.vendor.to_lowercase())
            || entry.vendor.to_lowercase().contains(&vendor_lower);
        let model_match = model_lower.contains(&entry.model_pattern.to_lowercase())
            || entry.model_pattern.to_lowercase().contains(&model_lower);

        if vendor_match && model_match {
            let score = entry.vendor.len() + entry.model_pattern.len();
            if score > best_score {
                best_score = score;
                best_match = Some(entry);
            }
        }
    }

    match best_match {
        Some(entry) => {
            let eos_date = entry.eos_date.map(|d| d.format("%Y-%m-%d").to_string());
            let risk_level = calculate_risk(entry.eos_date);

            FirmwareInfo {
                vendor: entry.vendor.to_string(),
                model: entry.model_pattern.to_string(),
                eos_date,
                latest_version: entry.latest_version.map(|s| s.to_string()),
                risk_level,
            }
        }
        None => {
            // No match found - device may not be in database
            FirmwareInfo {
                vendor: vendor.to_string(),
                model: model.to_string(),
                eos_date: None,
                latest_version: firmware_version.map(|s| s.to_string()),
                risk_level: RiskLevel::Low,
            }
        }
    }
}

/// Get all EOS devices as a list of (vendor, model) tuples
pub fn get_eos_devices() -> Vec<(String, String)> {
    EOS_DATABASE
        .values()
        .map(|entry| (entry.vendor.to_string(), entry.model_pattern.to_string()))
        .collect()
}

/// Get devices by risk level
pub fn get_devices_by_risk(risk: RiskLevel) -> Vec<(String, String)> {
    EOS_DATABASE
        .values()
        .filter(|entry| calculate_risk(entry.eos_date) == risk)
        .map(|entry| (entry.vendor.to_string(), entry.model_pattern.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hikvision_eos() {
        let info = check_device_eos("Hikvision", "DS-2CD2043", None);
        assert_eq!(info.vendor, "Hikvision");
        assert_eq!(info.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_dahua_eos() {
        let info = check_device_eos("Dahua", "HC3X52", None);
        assert_eq!(info.vendor, "Dahua");
        assert_eq!(info.risk_level, RiskLevel::High);
    }

    #[test]
    fn test_unifi_ap_supported() {
        let info = check_device_eos("Ubiquiti", "UniFi AP AC", None);
        assert_eq!(info.vendor, "Ubiquiti");
        assert_eq!(info.risk_level, RiskLevel::Low); // Still supported
    }

    #[test]
    fn test_unknown_device() {
        let info = check_device_eos("Unknown Vendor", "XYZ123", None);
        assert_eq!(info.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_get_eos_devices() {
        let devices = get_eos_devices();
        assert!(devices.len() >= 20);
    }

    #[test]
    fn test_risk_level_order() {
        // Critical: > 2 years EOS
        let critical = calculate_risk(Some(NaiveDate::from_ymd_opt(2020, 1, 1).unwrap()));
        assert_eq!(critical, RiskLevel::Critical);

        // High: > 1 year EOS
        let high = calculate_risk(Some(NaiveDate::from_ymd_opt(2024, 1, 1).unwrap()));
        assert_eq!(high, RiskLevel::High);

        // Medium: < 1 year EOS
        let medium = calculate_risk(Some(NaiveDate::from_ymd_opt(2025, 6, 1).unwrap()));
        assert_eq!(medium, RiskLevel::Medium);

        // Low: None (still supported)
        let low = calculate_risk(None);
        assert_eq!(low, RiskLevel::Low);
    }
}