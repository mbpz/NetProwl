//! MAC OUI vendor lookup

use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    static ref OUI_MAP: HashMap<String, &'static str> = {
        let mut m = HashMap::new();
        m.insert("00:50:56".into(), "VMware");
        m.insert("00:0c:29".into(), "VMware");
        m.insert("b8:27:eb".into(), "Raspberry Pi");
        m.insert("dc:a6:32".into(), "Raspberry Pi");
        m.insert("e4:5f:01".into(), "Raspberry Pi");
        m.insert("00:1e:68".into(), "Huawei/H3C");
        m.insert("00:25:9e".into(), "Cisco");
        m.insert("00:1a:2b".into(), "Cisco");
        m.insert("00:17:88".into(), "Philips Hue");
        m.insert("a8:66:7f".into(), "Apple");
        m.insert("f0:18:98".into(), "Apple");
        m.insert("3c:06:30".into(), "Apple");
        m.insert("00:e0:4c".into(), "Realtek");
        m.insert("00:23:cd".into(), "Intel");
        m.insert("00:1b:21".into(), "Intel");
        m.insert("00:0d:2b".into(), "Dell");
        m.insert("00:1c:23".into(), "Dell");
        m.insert("00:24:e8".into(), "Dell");
        m.insert("ac:de:48".into(), "Hikvision");
        m.insert("b4:15:13".into(), "Hikvision");
        m.insert("00:03:93".into(), "Siemens");
        m.insert("00:1b:a2".into(), "Schneider Electric");
        m
    };
}

pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    if mac.len() < 8 {
        return None;
    }
    let prefix = mac[..8].to_lowercase().replace('-', ":");
    OUI_MAP.get(&prefix).copied()
}
