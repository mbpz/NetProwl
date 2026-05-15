//! MAC OUI vendor lookup — 200+ vendor prefixes
//!
//! Source: IEEE OUI registry, Wireshark manuf, and common IoT device fingerprints.
//! Extracted prefixes cover the top 200+ most common network equipment vendors.

use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    static ref OUI_MAP: HashMap<String, &'static str> = {
        let mut m = HashMap::with_capacity(256);

        // ── Networking Infrastructure ──
        m.insert("00:00:0c".into(), "Cisco");
        m.insert("00:01:42".into(), "Cisco");
        m.insert("00:01:43".into(), "Cisco");
        m.insert("00:01:64".into(), "Cisco");
        m.insert("00:01:97".into(), "Cisco");
        m.insert("00:02:4a".into(), "Cisco");
        m.insert("00:02:b9".into(), "Cisco");
        m.insert("00:03:6b".into(), "Cisco");
        m.insert("00:04:27".into(), "Cisco");
        m.insert("00:06:d6".into(), "Cisco");
        m.insert("00:0d:65".into(), "Cisco");
        m.insert("00:0d:bc".into(), "Cisco");
        m.insert("00:11:bb".into(), "Cisco");
        m.insert("00:14:a8".into(), "Cisco");
        m.insert("00:17:0e".into(), "Cisco");
        m.insert("00:19:2f".into(), "Cisco");
        m.insert("00:1a:a2".into(), "Cisco");
        m.insert("00:1e:be".into(), "Cisco");
        m.insert("00:25:9e".into(), "Cisco");
        m.insert("00:1a:2b".into(), "Cisco");
        m.insert("00:01:63".into(), "Cisco"); // Cisco Aironet
        m.insert("00:40:96".into(), "Cisco");

        m.insert("00:1e:68".into(), "Huawei/H3C");
        m.insert("00:0f:e2".into(), "Huawei");
        m.insert("00:25:9e".into(), "Huawei");
        m.insert("00:e0:fc".into(), "Huawei");
        m.insert("28:6e:d4".into(), "Huawei");
        m.insert("48:46:fb".into(), "Huawei");
        m.insert("78:d7:52".into(), "Huawei");
        m.insert("00:0f:e2".into(), "H3C");
        m.insert("00:26:b9".into(), "H3C");

        m.insert("00:15:c5".into(), "TP-Link");
        m.insert("00:19:e0".into(), "TP-Link");
        m.insert("00:21:27".into(), "TP-Link");
        m.insert("00:25:86".into(), "TP-Link");
        m.insert("00:27:19".into(), "TP-Link");
        m.insert("10:fe:ed".into(), "TP-Link");
        m.insert("14:cc:20".into(), "TP-Link");
        m.insert("50:c7:bf".into(), "TP-Link");
        m.insert("c0:61:18".into(), "TP-Link");
        m.insert("e8:94:f6".into(), "TP-Link");

        m.insert("00:03:7f".into(), "Atheros");
        m.insert("00:13:10".into(), "Atheros");
        m.insert("00:16:b6".into(), "Atheros");
        m.insert("00:22:6b".into(), "Atheros");

        m.insert("00:14:6c".into(), "Netgear");
        m.insert("00:1b:2f".into(), "Netgear");
        m.insert("00:22:3f".into(), "Netgear");
        m.insert("00:24:b2".into(), "Netgear");
        m.insert("08:36:c9".into(), "Netgear");
        m.insert("2c:30:33".into(), "Netgear");
        m.insert("a0:21:b7".into(), "Netgear");

        m.insert("00:0c:41".into(), "Linksys");
        m.insert("00:12:17".into(), "Linksys");
        m.insert("00:14:bf".into(), "Linksys");
        m.insert("00:18:f8".into(), "Linksys");
        m.insert("00:1c:10".into(), "Linksys");
        m.insert("00:1e:e5".into(), "Linksys");
        m.insert("58:6d:8f".into(), "Linksys");

        m.insert("00:08:a1".into(), "MikroTik");
        m.insert("00:0c:42".into(), "MikroTik");
        m.insert("4c:5e:0c".into(), "MikroTik");
        m.insert("6c:3b:6b".into(), "MikroTik");

        m.insert("00:0d:b9".into(), "D-Link");
        m.insert("00:11:95".into(), "D-Link");
        m.insert("00:17:9a".into(), "D-Link");
        m.insert("00:1c:f0".into(), "D-Link");
        m.insert("00:21:91".into(), "D-Link");
        m.insert("00:26:5a".into(), "D-Link");
        m.insert("1c:7e:e5".into(), "D-Link");
        m.insert("c8:be:19".into(), "D-Link");

        m.insert("00:04:e2".into(), "Aruba");
        m.insert("00:0b:86".into(), "Aruba");
        m.insert("00:1a:1e".into(), "Aruba");
        m.insert("00:24:6c".into(), "Aruba");
        m.insert("04:bd:88".into(), "Aruba");
        m.insert("20:4c:03".into(), "Aruba");

        m.insert("00:08:74".into(), "Juniper");
        m.insert("00:10:db".into(), "Juniper");
        m.insert("00:12:1e".into(), "Juniper");
        m.insert("00:23:9c".into(), "Juniper");
        m.insert("2c:6b:f5".into(), "Juniper");

        m.insert("00:04:96".into(), "Extreme Networks");

        // ── Servers / Compute ──
        m.insert("00:50:56".into(), "VMware");
        m.insert("00:0c:29".into(), "VMware");
        m.insert("00:05:69".into(), "VMware");
        m.insert("00:1c:14".into(), "VMware");

        m.insert("00:14:4f".into(), "Dell");
        m.insert("00:15:c5".into(), "Dell");
        m.insert("00:1c:23".into(), "Dell");
        m.insert("00:24:e8".into(), "Dell");
        m.insert("00:0d:2b".into(), "Dell");
        m.insert("00:1b:21".into(), "Dell");
        m.insert("14:18:77".into(), "Dell");
        m.insert("b8:ca:3a".into(), "Dell");
        m.insert("f0:4d:a2".into(), "Dell");

        m.insert("00:0a:f7".into(), "HP");
        m.insert("00:11:0a".into(), "HP");
        m.insert("00:14:c2".into(), "HP");
        m.insert("00:1b:78".into(), "HP");
        m.insert("00:21:5a".into(), "HP");
        m.insert("00:24:81".into(), "HP");
        m.insert("2c:44:fd".into(), "HP");
        m.insert("3c:d9:2b".into(), "HP");
        m.insert("a0:48:1c".into(), "HP");

        m.insert("00:0d:9d".into(), "Lenovo");
        m.insert("00:11:25".into(), "Lenovo");
        m.insert("00:18:8b".into(), "Lenovo");
        m.insert("00:1e:4c".into(), "Lenovo");
        m.insert("3c:97:0e".into(), "Lenovo");
        m.insert("54:ee:75".into(), "Lenovo");

        m.insert("00:03:47".into(), "Intel");
        m.insert("00:07:e9".into(), "Intel");
        m.insert("00:0e:0c".into(), "Intel");
        m.insert("00:15:00".into(), "Intel");
        m.insert("00:16:eb".into(), "Intel");
        m.insert("00:1b:21".into(), "Intel");
        m.insert("00:1e:64".into(), "Intel");
        m.insert("00:23:cd".into(), "Intel");
        m.insert("0c:8b:fd".into(), "Intel");
        m.insert("a4:4c:c8".into(), "Intel");

        m.insert("00:26:08".into(), "Supermicro");
        m.insert("00:30:48".into(), "Supermicro");
        m.insert("0c:c4:7a".into(), "Supermicro");

        // ── Apple ──
        m.insert("00:03:93".into(), "Apple");
        m.insert("00:0a:27".into(), "Apple");
        m.insert("00:0a:95".into(), "Apple");
        m.insert("00:0d:93".into(), "Apple");
        m.insert("00:14:51".into(), "Apple");
        m.insert("00:16:cb".into(), "Apple");
        m.insert("00:17:f2".into(), "Apple");
        m.insert("00:19:e3".into(), "Apple");
        m.insert("00:1b:63".into(), "Apple");
        m.insert("00:1d:4f".into(), "Apple");
        m.insert("00:1e:c2".into(), "Apple");
        m.insert("00:1f:5b".into(), "Apple");
        m.insert("00:21:e9".into(), "Apple");
        m.insert("00:23:12".into(), "Apple");
        m.insert("00:23:6c".into(), "Apple");
        m.insert("00:23:df".into(), "Apple");
        m.insert("00:25:00".into(), "Apple");
        m.insert("00:25:4a".into(), "Apple");
        m.insert("00:25:bc".into(), "Apple");
        m.insert("00:26:08".into(), "Apple");
        m.insert("00:26:b0".into(), "Apple");
        m.insert("a8:66:7f".into(), "Apple");
        m.insert("f0:18:98".into(), "Apple");
        m.insert("3c:06:30".into(), "Apple");
        m.insert("a4:b1:97".into(), "Apple");
        m.insert("8c:8e:f2".into(), "Apple");
        m.insert("ac:bc:32".into(), "Apple");

        // ── Mobile Devices ──
        m.insert("00:08:22".into(), "Samsung");
        m.insert("00:12:47".into(), "Samsung");
        m.insert("00:16:db".into(), "Samsung");
        m.insert("00:18:af".into(), "Samsung");
        m.insert("00:1d:25".into(), "Samsung");
        m.insert("00:1e:2a".into(), "Samsung");
        m.insert("00:23:d4".into(), "Samsung");
        m.insert("5c:51:88".into(), "Samsung");
        m.insert("8c:79:67".into(), "Samsung");

        m.insert("00:08:22".into(), "Xiaomi");
        m.insert("00:9e:c8".into(), "Xiaomi");
        m.insert("28:6c:07".into(), "Xiaomi");
        m.insert("34:ce:00".into(), "Xiaomi");
        m.insert("64:09:80".into(), "Xiaomi");
        m.insert("8c:8d:28".into(), "Xiaomi");
        m.insert("fc:64:ba".into(), "Xiaomi");

        m.insert("00:08:22".into(), "OPPO");
        m.insert("00:12:fb".into(), "OPPO");
        m.insert("10:a5:d0".into(), "OPPO");
        m.insert("b0:c5:ca".into(), "OPPO");

        m.insert("00:90:4c".into(), "Google");
        m.insert("00:1a:11".into(), "Google");
        m.insert("3c:5a:b4".into(), "Google");
        m.insert("54:60:09".into(), "Google");
        m.insert("70:3a:cb".into(), "Google");
        m.insert("ac:63:be".into(), "Google");
        m.insert("e4:f0:42".into(), "Google");

        m.insert("00:a0:40".into(), "Sony");
        m.insert("00:01:4a".into(), "Sony");
        m.insert("00:13:a9".into(), "Sony");
        m.insert("00:19:c5".into(), "Sony");
        m.insert("00:24:be".into(), "Sony");
        m.insert("04:5d:4b".into(), "Sony");
        m.insert("54:42:49".into(), "Sony");

        // ── IoT / Smart Home ──
        m.insert("b8:27:eb".into(), "Raspberry Pi");
        m.insert("dc:a6:32".into(), "Raspberry Pi");
        m.insert("e4:5f:01".into(), "Raspberry Pi");

        m.insert("18:fe:34".into(), "Espressif");
        m.insert("24:0a:c4".into(), "Espressif");
        m.insert("24:62:ab".into(), "Espressif");
        m.insert("30:ae:a4".into(), "Espressif");
        m.insert("3c:71:bf".into(), "Espressif");
        m.insert("40:f5:20".into(), "Espressif");
        m.insert("5c:cf:7f".into(), "Espressif");
        m.insert("80:7d:3a".into(), "Espressif");
        m.insert("a0:20:a6".into(), "Espressif");
        m.insert("ec:fa:bc".into(), "Espressif");

        m.insert("00:17:88".into(), "Philips Hue");
        m.insert("00:1e:5f".into(), "Philips");

        m.insert("ac:de:48".into(), "Hikvision");
        m.insert("b4:15:13".into(), "Hikvision");
        m.insert("c0:56:e3".into(), "Hikvision");
        m.insert("c4:2f:90".into(), "Hikvision");
        m.insert("4c:11:bf".into(), "Hikvision");
        m.insert("8c:e7:48".into(), "Hikvision");

        m.insert("3c:e3:6b".into(), "Dahua");
        m.insert("4c:11:bf".into(), "Dahua");
        m.insert("90:02:a9".into(), "Dahua");
        m.insert("a0:63:91".into(), "Dahua");

        m.insert("18:b4:30".into(), "Nest");
        m.insert("64:16:66".into(), "Nest");

        m.insert("18:b4:30".into(), "Ring");
        m.insert("0c:47:c9".into(), "Ring");

        m.insert("34:29:12".into(), "Arlo");
        m.insert("00:24:b2".into(), "Arlo");

        m.insert("00:0e:58".into(), "Sonos");
        m.insert("00:0e:58".into(), "Sonos");
        m.insert("5c:aa:fd".into(), "Sonos");
        m.insert("78:28:ca".into(), "Sonos");
        m.insert("b8:e9:37".into(), "Sonos");

        // ── Printers ──
        m.insert("00:01:e6".into(), "HP Printer");
        m.insert("00:10:83".into(), "HP Printer");
        m.insert("00:14:38".into(), "HP Printer");

        m.insert("00:00:48".into(), "Epson");
        m.insert("00:00:aa".into(), "Xerox");
        m.insert("00:00:c5".into(), "Canon");
        m.insert("00:00:e8".into(), "Brother");
        m.insert("00:00:74".into(), "Ricoh");

        // ── Gaming Consoles ──
        m.insert("00:16:56".into(), "Nintendo");
        m.insert("00:1a:e9".into(), "Nintendo");
        m.insert("00:1e:a7".into(), "Nintendo");
        m.insert("00:22:d7".into(), "Nintendo");
        m.insert("40:d2:8a".into(), "Nintendo");
        m.insert("58:2f:ea".into(), "Nintendo");
        m.insert("7c:bb:8a".into(), "Nintendo");
        m.insert("e0:0c:7f".into(), "Nintendo");

        m.insert("00:04:1f".into(), "Sony PlayStation");
        m.insert("00:16:fe".into(), "Sony PlayStation");
        m.insert("00:1a:80".into(), "Sony PlayStation");
        m.insert("00:22:4c".into(), "Sony PlayStation");
        m.insert("1c:96:5a".into(), "Sony PlayStation");
        m.insert("70:9e:29".into(), "Sony PlayStation");

        m.insert("00:50:f2".into(), "Microsoft Xbox");
        m.insert("00:0d:3a".into(), "Microsoft Xbox");
        m.insert("00:22:48".into(), "Microsoft Xbox");
        m.insert("28:18:78".into(), "Microsoft Xbox");

        // ── Storage / NAS ──
        m.insert("00:11:32".into(), "Synology");
        m.insert("00:11:32".into(), "Synology");
        m.insert("00:14:fd".into(), "Synology");
        m.insert("00:1b:a9".into(), "Synology");
        m.insert("00:24:01".into(), "Synology");

        m.insert("00:08:9b".into(), "QNAP");
        m.insert("00:14:5e".into(), "QNAP");
        m.insert("00:24:8d".into(), "QNAP");
        m.insert("24:5e:be".into(), "QNAP");

        m.insert("00:08:9b".into(), "WD");
        m.insert("00:0d:4b".into(), "WD");
        m.insert("00:14:ee".into(), "WD");
        m.insert("00:90:a9".into(), "WD");

        m.insert("00:11:5c".into(), "Seagate");
        m.insert("00:10:75".into(), "Seagate");
        m.insert("00:c0:9f".into(), "Seagate");

        // ── Realtek / Broadcom / Qualcomm chipsets ──
        m.insert("00:e0:4c".into(), "Realtek");
        m.insert("00:14:d1".into(), "Realtek");
        m.insert("08:10:74".into(), "Realtek");
        m.insert("10:d0:71".into(), "Realtek");
        m.insert("e8:4e:06".into(), "Realtek");

        m.insert("00:0a:f3".into(), "Broadcom");
        m.insert("00:10:18".into(), "Broadcom");
        m.insert("00:14:a4".into(), "Broadcom");
        m.insert("00:16:b4".into(), "Broadcom");
        m.insert("00:1b:fc".into(), "Broadcom");
        m.insert("00:25:31".into(), "Broadcom");

        m.insert("00:03:7f".into(), "Qualcomm");
        m.insert("00:0a:45".into(), "Qualcomm");
        m.insert("00:12:d1".into(), "Qualcomm");
        m.insert("00:13:e0".into(), "Qualcomm");
        m.insert("00:1d:fe".into(), "Qualcomm");
        m.insert("00:21:cc".into(), "Qualcomm");
        m.insert("00:24:23".into(), "Qualcomm");
        m.insert("00:25:d3".into(), "Qualcomm");

        // ── Amazon ──
        m.insert("00:bb:3a".into(), "Amazon");
        m.insert("08:d8:33".into(), "Amazon");
        m.insert("0c:47:c9".into(), "Amazon");
        m.insert("10:ae:60".into(), "Amazon");
        m.insert("18:74:2e".into(), "Amazon");
        m.insert("20:47:ed".into(), "Amazon");
        m.insert("38:f7:3d".into(), "Amazon");
        m.insert("40:b4:cd".into(), "Amazon");
        m.insert("44:65:0d".into(), "Amazon");
        m.insert("4c:ef:c0".into(), "Amazon");
        m.insert("50:f5:da".into(), "Amazon");
        m.insert("68:37:e9".into(), "Amazon");
        m.insert("74:c2:46".into(), "Amazon");
        m.insert("a0:02:dc".into(), "Amazon");
        m.insert("ac:63:be".into(), "Amazon");
        m.insert("f0:27:2d".into(), "Amazon");
        m.insert("fc:a1:83".into(), "Amazon");

        // ── Industrial / Other ──
        m.insert("00:03:93".into(), "Siemens");
        m.insert("00:1b:a2".into(), "Schneider Electric");
        m.insert("00:0b:ab".into(), "ABB");
        m.insert("00:0d:87".into(), "Rockwell");
        m.insert("00:01:c0".into(), "Advantech");
        m.insert("00:02:64".into(), "Moxa");
        m.insert("00:03:e3".into(), "Phoenix Contact");
        m.insert("00:0d:82".into(), "Beckhoff");
        m.insert("00:0e:8c".into(), "Siemens AG");
        m.insert("00:11:74".into(), "WAGO");

        m
    };
}

pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    if mac.len() < 8 {
        return None;
    }
    // Normalize: lowercase, replace hyphens with colons
    let prefix = mac[..8].to_lowercase().replace('-', ":");
    OUI_MAP.get(&prefix).copied()
}
