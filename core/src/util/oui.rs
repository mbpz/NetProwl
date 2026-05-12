use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    static ref OUI_MAP: HashMap<String, &'static str> = {
        let mut m = HashMap::new();
        m.insert("00:00:0C".to_string(), "Cisco");
        m.insert("00:1A:2B".to_string(), "Ayecue");
        m.insert("00:50:56".to_string(), "VMware");
        m.insert("00:0C:29".to_string(), "VMware");
        m.insert("B8:27:EB".to_string(), "Raspberry Pi");
        m.insert("DC:A6:32".to_string(), "Raspberry Pi");
        m.insert("E8:94:F6".to_string(), "Raspberry Pi");
        m.insert("00:1B:44".to_string(), "Canon");
        m.insert("00:18:E7".to_string(), "Cameo");
        m.insert("00:24:E4".to_string(), "Xiaomi");
        m.insert("AC:CF:85".to_string(), "ESP");
        m.insert("5C:CF:7F".to_string(), "ESP");
        m.insert("60:01:94".to_string(), "Espressif");
        m.insert("68:27:37".to_string(), "Espressif");
        m.insert("A4:CF:12".to_string(), "Espressif");
        m.insert("00:1E:C2".to_string(), "Apple");
        m.insert("3C:06:30".to_string(), "Apple");
        m.insert("70:56:81".to_string(), "Apple");
        m.insert("00:25:00".to_string(), "Apple");
        m.insert("00:17:88".to_string(), "Philips Hue");
        m.insert("EC:B5:FA".to_string(), "Philips Hue");
        m.insert("00:1A:22".to_string(), "Shelly");
        m.insert("24:62:AB".to_string(), "Shelly");
        m.insert("00:04:4B".to_string(), "Nvidia");
        m.insert("00:1A:A0".to_string(), "Seagate");
        m.insert("00:C0:EE".to_string(), "Intel");
        m
    };
}

/// Look up vendor name from MAC address prefix
pub fn lookup_vendor(mac: &str) -> Option<String> {
    let mac_normalized = mac.to_uppercase().replace('-', ":");

    // Try different prefix lengths
    let prefixes = [
        &mac_normalized[..8],  // Full OUI (XX:XX:XX)
        &mac_normalized[..6],  // Short OUI (XX:XX)
    ];

    for prefix in &prefixes {
        if let Some(vendor) = OUI_MAP.get(*prefix) {
            return Some(vendor.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_vendor() {
        assert_eq!(lookup_vendor("00:50:56:AB:CD:EF"), Some("VMware".to_string()));
        assert_eq!(lookup_vendor("b8:27:eb:12:34:56"), Some("Raspberry Pi".to_string()));
    }
}
