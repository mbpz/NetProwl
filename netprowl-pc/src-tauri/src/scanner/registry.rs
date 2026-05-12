//! 服务指纹规则库

use crate::scanner::DeviceType;

pub struct ServiceRule {
    pub port: u16,
    pub banner_contains: Option<&'static str>,
    pub service: &'static str,
    pub device_type: DeviceType,
}

pub const RULES: &[ServiceRule] = &[
    ServiceRule { port: 80,   banner_contains: None,                   service: "HTTP",             device_type: DeviceType::Unknown },
    ServiceRule { port: 443,  banner_contains: None,                   service: "HTTPS",            device_type: DeviceType::Unknown },
    ServiceRule { port: 22,   banner_contains: Some("SSH"),           service: "SSH",              device_type: DeviceType::Unknown },
    ServiceRule { port: 21,   banner_contains: Some("FTP"),            service: "FTP",              device_type: DeviceType::Unknown },
    ServiceRule { port: 554,  banner_contains: Some("RTSP"),          service: "RTSP Stream",      device_type: DeviceType::Camera },
    ServiceRule { port: 554,  banner_contains: Some("Hikvision"),      service: "Hikvision Camera", device_type: DeviceType::Camera },
    ServiceRule { port: 5000, banner_contains: Some("Synology"),      service: "Synology NAS",     device_type: DeviceType::Nas },
    ServiceRule { port: 8080, banner_contains: None,                  service: "HTTP Proxy",       device_type: DeviceType::Unknown },
    ServiceRule { port: 5000, banner_contains: None,                  service: "UPnP",             device_type: DeviceType::Unknown },
    ServiceRule { port: 9000, banner_contains: None,                  service: "CSListener",       device_type: DeviceType::Unknown },
    ServiceRule { port: 3389, banner_contains: None,                  service: "RDP",              device_type: DeviceType::Pc },
    ServiceRule { port: 445,   banner_contains: None,                  service: "SMB",              device_type: DeviceType::Unknown },
    ServiceRule { port: 3306,  banner_contains: None,                  service: "MySQL",            device_type: DeviceType::Unknown },
    ServiceRule { port: 5432,  banner_contains: None,                 service: "PostgreSQL",       device_type: DeviceType::Unknown },
    ServiceRule { port: 6379,  banner_contains: None,                 service: "Redis",            device_type: DeviceType::Unknown },
    ServiceRule { port: 9200,  banner_contains: None,                 service: "Elasticsearch",    device_type: DeviceType::Unknown },
    ServiceRule { port: 27017, banner_contains: None,                 service: "MongoDB",          device_type: DeviceType::Unknown },
];

/// 根据端口 + banner 匹配服务
pub fn match_service(port: u16, banner: Option<&str>) -> (&'static str, DeviceType) {
    for rule in RULES {
        if rule.port != port {
            continue;
        }
        match rule.banner_contains {
            Some(needle) => {
                if let Some(b) = banner {
                    if b.contains(needle) {
                        return (rule.service, rule.device_type);
                    }
                }
            }
            None => return (rule.service, rule.device_type),
        }
    }
    ("unknown", DeviceType::Unknown)
}
