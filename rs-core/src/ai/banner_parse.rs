use serde::{Deserialize, Serialize};
use regex::Regex;
use std::collections::HashMap;

/// Banner analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerAnalysis {
    pub software: Option<String>,
    pub version: Option<String>,
    pub os: Option<String>,
    pub known_cves: Vec<String>,
    pub confidence: f32,
}

/// Parse a banner and extract software information
pub fn parse_banner(banner: &str) -> BannerAnalysis {
    let banner_lower = banner.to_lowercase();

    // Try SSH banner first
    if banner_lower.contains("ssh") && (banner_lower.contains("openssh") || banner.contains("SSH")) {
        return parse_ssh_banner(banner);
    }

    // Try HTTP server header
    if banner_lower.contains("http") || banner_lower.contains("server") {
        return parse_http_banner(banner);
    }

    // Try FTP banner
    if banner_lower.contains("ftp") || banner_lower.contains("220") {
        return parse_ftp_banner(banner);
    }

    // Try SMTP banner
    if banner_lower.contains("smtp") || banner_lower.contains("mail") {
        return parse_smtp_banner(banner);
    }

    // Try MySQL/MariaDB banner
    if banner_lower.contains("mysql") || banner_lower.contains("mariadb") {
        return parse_mysql_banner(banner);
    }

    // Try Redis banner
    if banner_lower.contains("redis") {
        return parse_redis_banner(banner);
    }

    // Try MongoDB banner
    if banner_lower.contains("mongod") || banner_lower.contains("mongodb") {
        return parse_mongodb_banner(banner);
    }

    // Try Elasticsearch banner
    if banner_lower.contains("elasticsearch") {
        return parse_elasticsearch_banner(banner);
    }

    // Generic banner parsing
    parse_generic_banner(banner)
}

/// Parse SSH banner: "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"
fn parse_ssh_banner(banner: &str) -> BannerAnalysis {
    let mut software = Some("OpenSSH".to_string());
    let mut version = None;
    let mut os = None;
    let mut confidence = 0.9;

    // Extract version
    if let Some(version_match) = Regex::new(r"OpenSSH[_-]?(\d+\.\d+(?:\.\d+)?)").ok().and_then(|r| r.find(banner)) {
        let version_str = version_match.as_str();
        version = version_str.split('_').last().map(|v| v.to_string());
    }

    // Extract OS from Debian/Ubuntu patterns
    if banner.to_lowercase().contains("debian") {
        os = Some("Debian Linux".to_string());
    } else if banner.to_lowercase().contains("ubuntu") {
        os = Some("Ubuntu Linux".to_string());
    } else if banner.to_lowercase().contains("centos") {
        os = Some("CentOS Linux".to_string());
    } else if banner.to_lowercase().contains("fedora") {
        os = Some("Fedora Linux".to_string());
    }

    // Check for known vulnerable SSH versions
    let mut known_cves = Vec::new();
    if let Some(ref ver) = version {
        if ver.starts_with("7.") || ver.starts_with("6.") || ver.starts_with("5.") {
            known_cves.push("CVE-2016-6515".to_string()); // OpenSSH before 7.3
            known_cves.push("CVE-2015-5600".to_string()); // OpenSSH before 7.0
        }
    }

    BannerAnalysis {
        software,
        version,
        os,
        known_cves,
        confidence,
    }
}

/// Parse HTTP server banner
fn parse_http_banner(banner: &str) -> BannerAnalysis {
    let mut software = None;
    let mut version = None;
    let mut confidence = 0.7;

    // Try to extract server type from Server header
    if let Some(server_match) = Regex::new(r"Server: ([^\r\n]+)").ok().and_then(|r| r.find(banner)) {
        let server_str = server_match.as_str().to_lowercase();

        if server_str.contains("apache") {
            software = Some("Apache HTTP Server".to_string());
        } else if server_str.contains("nginx") {
            software = Some("nginx".to_string());
        } else if server_str.contains("iis") || server_str.contains("microsoft") {
            software = Some("Microsoft IIS".to_string());
        } else if server_str.contains("tengine") || server_str.contains("taobao") {
            software = Some("Tengine".to_string());
        } else if server_str.contains("lighttpd") {
            software = Some("lighttpd".to_string());
        }

        // Try to extract version
        if let Some(version_match) = Regex::new(r"(?:Apache|nginx|IIS|Tengine)[/ ](\d+(?:\.\d+)*)").ok().and_then(|r| r.find(&server_str)) {
            let parts: Vec<&str> = version_match.as_str().split('/').collect();
            if parts.len() > 1 {
                version = Some(parts[1].to_string());
            }
        }
    }

    // Check for OS in headers
    let mut os = None;
    if banner.to_lowercase().contains("x-powered-by") {
        if banner.to_lowercase().contains("php") {
            os = Some("PHP".to_string());
        } else if banner.to_lowercase().contains("asp.net") {
            os = Some("ASP.NET".to_string());
        }
    }

    BannerAnalysis {
        software,
        version,
        os,
        known_cves: Vec::new(),
        confidence,
    }
}

/// Parse FTP banner
fn parse_ftp_banner(banner: &str) -> BannerAnalysis {
    let mut software = None;
    let mut version = None;
    let mut confidence = 0.8;

    if banner.contains("220-") {
        // Common FTP servers
        if banner.to_lowercase().contains("vsftpd") {
            software = Some("vsftpd".to_string());
        } else if banner.to_lowercase().contains("proftpd") {
            software = Some("ProFTPD".to_string());
        } else if banner.to_lowercase().contains("filezilla") {
            software = Some("FileZilla".to_string());
        } else if banner.to_lowercase().contains("wu-2.6") || banner.to_lowercase().contains("wuftpd") {
            software = Some("WU-FTPD".to_string());
        }

        // Extract version
        if let Some(ver_match) = Regex::new(r"(\d+\.\d+(?:\.\d+)?)").ok().and_then(|r| r.find(banner)) {
            if version.is_none() {
                version = Some(ver_match.as_str().to_string());
            }
        }
    }

    BannerAnalysis {
        software,
        version,
        os: None,
        known_cves: Vec::new(),
        confidence,
    }
}

/// Parse SMTP banner
fn parse_smtp_banner(banner: &str) -> BannerAnalysis {
    let mut software = None;
    let mut version = None;
    let mut confidence = 0.8;

    if banner.to_lowercase().contains("postfix") {
        software = Some("Postfix".to_string());
    } else if banner.to_lowercase().contains("exim") {
        software = Some("Exim".to_string());
    } else if banner.to_lowercase().contains("sendmail") {
        software = Some("Sendmail".to_string());
    } else if banner.to_lowercase().contains("exchange") {
        software = Some("Microsoft Exchange".to_string());
    }

    // Extract version
    if let Some(ver_match) = Regex::new(r"(?:Postfix|Exim|Sendmail)[/ ](\d+(?:\.\d+)*)").ok().and_then(|r| r.find(banner)) {
        version = Some(ver_match.as_str().split_whitespace().last().unwrap_or("").to_string());
    }

    BannerAnalysis {
        software,
        version,
        os: None,
        known_cves: Vec::new(),
        confidence,
    }
}

/// Parse MySQL/MariaDB banner
fn parse_mysql_banner(banner: &str) -> BannerAnalysis {
    let mut software = Some("MySQL".to_string());
    let mut version = None;
    let mut confidence = 0.9;

    if banner.to_lowercase().contains("mariadb") {
        software = Some("MariaDB".to_string());
    }

    // Extract version
    let banner_lower = banner.to_lowercase();
    if let Some(ver_match) = Regex::new(r"(?:mysql|mariadb|mysqld)\s+(\d+\.\d+(?:\.\d+)*)").ok().and_then(|r| r.find(&banner_lower)) {
        version = Some(ver_match.as_str().split_whitespace().last().unwrap_or("").to_string());
    }

    // Check for known vulnerable versions
    let mut known_cves = Vec::new();
    if let Some(ref ver) = version {
        if ver.starts_with("5.5.") || ver.starts_with("5.6.") || ver.starts_with("5.7.") {
            known_cves.push("CVE-2012-2122".to_string()); // MySQL authentication bypass
        }
    }

    BannerAnalysis {
        software,
        version,
        os: None,
        known_cves,
        confidence,
    }
}

/// Parse Redis banner
fn parse_redis_banner(banner: &str) -> BannerAnalysis {
    let mut software = Some("Redis".to_string());
    let mut version = None;
    let mut confidence = 0.95;

    // Extract version from "Redis server v=X.X.X"
    let banner_lower = banner.to_lowercase();
    if let Some(ver_match) = Regex::new(r"redis\s+(?:server\s+)?v?(\d+\.\d+(?:\.\d+)*)").ok().and_then(|r| r.find(&banner_lower)) {
        version = Some(ver_match.as_str().split_whitespace().last().unwrap_or("").trim_start_matches('v').to_string());
    }

    // Check for unauthenticated Redis
    if banner.contains("NOAUTH") {
        confidence = 0.5; // Lower confidence when we see NOAUTH
    }

    BannerAnalysis {
        software,
        version,
        os: None,
        known_cves: Vec::new(),
        confidence,
    }
}

/// Parse MongoDB banner
fn parse_mongodb_banner(banner: &str) -> BannerAnalysis {
    let mut software = Some("MongoDB".to_string());
    let mut version = None;
    let mut confidence = 0.9;
    let banner_lower = banner.to_lowercase();

    if let Some(ver_match) = Regex::new(r"mongodb\s+(?:server\s+)?(\d+\.\d+(?:\.\d+)*)").ok().and_then(|r| r.find(&banner_lower)) {
        version = Some(ver_match.as_str().split_whitespace().last().unwrap_or("").to_string());
    }

    BannerAnalysis {
        software,
        version,
        os: None,
        known_cves: Vec::new(),
        confidence,
    }
}

/// Parse Elasticsearch banner
fn parse_elasticsearch_banner(banner: &str) -> BannerAnalysis {
    let mut software = Some("Elasticsearch".to_string());
    let mut version = None;
    let mut confidence = 0.9;
    let banner_lower = banner.to_lowercase();

    if let Some(ver_match) = Regex::new(r"elasticsearch\s+(\d+\.\d+(?:\.\d+)*)").ok().and_then(|r| r.find(&banner_lower)) {
        version = Some(ver_match.as_str().split_whitespace().last().unwrap_or("").to_string());
    }

    BannerAnalysis {
        software,
        version,
        os: None,
        known_cves: Vec::new(),
        confidence,
    }
}

/// Generic banner parsing fallback
fn parse_generic_banner(banner: &str) -> BannerAnalysis {
    // Try to extract any version-like pattern
    let version_re = Regex::new(r"v?(\d+\.\d+(?:\.\d+)*)").ok();
    let version = version_re.and_then(|r| r.find(banner)).map(|m| m.as_str().trim_start_matches('v').to_string());

    BannerAnalysis {
        software: None,
        version,
        os: None,
        known_cves: Vec::new(),
        confidence: 0.3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_banner_parsing() {
        let banner = "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7";
        let result = parse_banner(banner);
        assert_eq!(result.software, Some("OpenSSH".to_string()));
        assert!(result.version.is_some());
        assert_eq!(result.os, Some("Debian Linux".to_string()));
        assert!(result.confidence > 0.8);
    }

    #[test]
    fn test_nginx_banner_parsing() {
        let banner = "Server: nginx/1.14.2";
        let result = parse_banner(banner);
        assert_eq!(result.software, Some("nginx".to_string()));
        assert_eq!(result.version, Some("1.14.2".to_string()));
    }

    #[test]
    fn test_redis_banner_parsing() {
        let banner = "Redis server v=5.0.7";
        let result = parse_banner(banner);
        assert_eq!(result.software, Some("Redis".to_string()));
        assert_eq!(result.version, Some("5.0.7".to_string()));
    }

    #[test]
    fn test_mysql_banner_parsing() {
        let banner = "MySQL Community Server 5.7.42";
        let result = parse_banner(banner);
        assert_eq!(result.software, Some("MySQL".to_string()));
        assert_eq!(result.version, Some("5.7.42".to_string()));
    }

    #[test]
    fn test_generic_banner_confidence() {
        let banner = "Some unknown service v1.2.3";
        let result = parse_banner(banner);
        assert!(result.confidence < 0.5);
    }
}
