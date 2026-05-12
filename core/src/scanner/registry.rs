use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref SERVICE_RULES: Vec<(Regex, &'static str)> = vec![
        // HTTP Servers
        (Regex::new(r"(?i)apache.*httpd").unwrap(), "Apache HTTP Server"),
        (Regex::new(r"(?i)nginx").unwrap(), "Nginx"),
        (Regex::new(r"(?i)microsoft.*iis").unwrap(), "Microsoft IIS"),
        (Regex::new(r"(?i)caddy").unwrap(), "Caddy"),
        (Regex::new(r"(?i)lighttpd").unwrap(), "Lighttpd"),
        (Regex::new(r"(?i)httpd").unwrap(), "Apache HTTP Server"),

        // SSH
        (Regex::new(r"(?i)ssh-.*openssh").unwrap(), "OpenSSH"),
        (Regex::new(r"(?i)ssh-.*dropbear").unwrap(), "Dropbear"),
        (Regex::new(r"(?i)^ssh-2-").unwrap(), "SSH"),

        // FTP
        (Regex::new(r"(?i)220.*ftp").unwrap(), "FTP Server"),
        (Regex::new(r"(?i)220.*vsftpd").unwrap(), "vsftpd"),
        (Regex::new(r"(?i)220.*proftpd").unwrap(), "ProFTPD"),
        (Regex::new(r"(?i)220.*filezilla").unwrap(), "FileZilla"),

        // SMTP
        (Regex::new(r"(?i)220.*postfix").unwrap(), "Postfix"),
        (Regex::new(r"(?i)220.*exim").unwrap(), "Exim"),
        (Regex::new(r"(?i)220.*sendmail").unwrap(), "Sendmail"),
        (Regex::new(r"(?i)220.*qmail").unwrap(), "qmail"),

        // Database
        (Regex::new(r"(?i)mysql").unwrap(), "MySQL"),
        (Regex::new(r"(?i)postgresql").unwrap(), "PostgreSQL"),
        (Regex::new(r"(?i)redis").unwrap(), "Redis"),
        (Regex::new(r"(?i)mongodb").unwrap(), "MongoDB"),
        (Regex::new(r"(?i)elasticsearch").unwrap(), "Elasticsearch"),

        // Other services
        (Regex::new(r"(?i)telnet").unwrap(), "Telnet"),
        (Regex::new(r"(?i)rtsp").unwrap(), "RTSP"),
        (Regex::new(r"(?i)sip").unwrap(), "SIP"),
    ];
}

/// Match service name from banner
pub fn match_service(banner: &str) -> Option<String> {
    for (re, service_name) in SERVICE_RULES.iter() {
        if re.is_match(banner) {
            return Some(service_name.to_string());
        }
    }
    None
}

/// Guess service by port number
pub fn guess_service(port: u16) -> Option<String> {
    match port {
        21 => Some("FTP".to_string()),
        22 => Some("SSH".to_string()),
        23 => Some("Telnet".to_string()),
        25 => Some("SMTP".to_string()),
        53 => Some("DNS".to_string()),
        80 => Some("HTTP".to_string()),
        110 => Some("POP3".to_string()),
        143 => Some("IMAP".to_string()),
        443 => Some("HTTPS".to_string()),
        554 => Some("RTSP".to_string()),
        5000 => Some("UPnP".to_string()),
        3306 => Some("MySQL".to_string()),
        5432 => Some("PostgreSQL".to_string()),
        6379 => Some("Redis".to_string()),
        8080 => Some("HTTP Proxy".to_string()),
        8443 => Some("HTTPS Alt".to_string()),
        9200 => Some("Elasticsearch".to_string()),
        27017 => Some("MongoDB".to_string()),
        _ => None,
    }
}

/// Match device type from banner
pub fn match_device_type(banner: &str) -> String {
    let banner_lower = banner.to_lowercase();

    if banner_lower.contains("router") || banner_lower.contains("gateway") {
        "Router".to_string()
    } else if banner_lower.contains("camera") || banner_lower.contains("dvr") || banner_lower.contains("nvr") {
        "Camera".to_string()
    } else if banner_lower.contains("printer") || banner_lower.contains("laserjet") || banner_lower.contains("deskjet") {
        "Printer".to_string()
    } else if banner_lower.contains("nas") || banner_lower.contains("synology") || banner_lower.contains("qnap") || banner_lower.contains("readyNAS") {
        "NAS".to_string()
    } else if banner_lower.contains("phone") || banner_lower.contains("voip") || banner_lower.contains("sip") {
        "Phone".to_string()
    } else if banner_lower.contains("tv") || banner_lower.contains("chromecast") || banner_lower.contains("airplay") || banner_lower.contains("appletv") {
        "TV".to_string()
    } else if banner_lower.contains("windows") || banner_lower.contains("linux") || banner_lower.contains("ubuntu") || banner_lower.contains("debian") {
        "Computer".to_string()
    } else if banner_lower.contains("raspberry") || banner_lower.contains("raspbian") {
        "Computer".to_string()
    } else {
        "Unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_service() {
        assert_eq!(match_service("220 FTP Server"), Some("FTP Server".to_string()));
        assert_eq!(match_service("SSH-2.0-OpenSSH"), Some("OpenSSH".to_string()));
        assert_eq!(match_service("220 nginx"), Some("Nginx".to_string()));
    }

    #[test]
    fn test_guess_service() {
        assert_eq!(guess_service(22), Some("SSH".to_string()));
        assert_eq!(guess_service(80), Some("HTTP".to_string()));
    }

    #[test]
    fn test_match_device_type() {
        assert_eq!(match_device_type("Router Firmware"), "Router".to_string());
        assert_eq!(match_device_type("Camera DVR"), "Camera".to_string());
    }
}
