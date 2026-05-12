use std::collections::HashMap;

fn build_oui_map() -> HashMap<String, &'static str> {
    let mut m = HashMap::new();
    m.insert("00:50:56".to_string(), "VMware");
    m.insert("00:0c:29".to_string(), "VMware");
    m.insert("b8:27:eb".to_string(), "Raspberry Pi");
    m.insert("dc:a6:32".to_string(), "Raspberry Pi");
    m.insert("e4:5f:01".to_string(), "Raspberry Pi");
    m.insert("00:1e:68".to_string(), "Huawei/H3C");
    m.insert("00:25:9e".to_string(), "Cisco");
    m.insert("00:1a:2b".to_string(), "Cisco");
    m.insert("00:17:88".to_string(), "Philips Hue");
    m.insert("a8:66:7f".to_string(), "Apple");
    m.insert("f0:18:98".to_string(), "Apple");
    m.insert("3c:06:30".to_string(), "Apple");
    m.insert("00:e0:4c".to_string(), "Realtek");
    m.insert("00:23:cd".to_string(), "Intel");
    m.insert("00:1b:21".to_string(), "Intel");
    m.insert("00:0d:2b".to_string(), "Dell");
    m.insert("00:1c:23".to_string(), "Dell");
    m.insert("00:24:e8".to_string(), "Dell");
    m.insert("ac:de:48".to_string(), "Hikvision");
    m.insert("b4:15:13".to_string(), "Hikvision");
    m
}

static OUI_MAP: once_cell::sync::Lazy<HashMap<String, &'static str>> =
    once_cell::sync::Lazy::new(build_oui_map);

pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    if mac.len() < 8 {
        return None;
    }
    let prefix = mac[..8].to_lowercase().replace('-', ":");
    OUI_MAP.get(&prefix).copied()
}
