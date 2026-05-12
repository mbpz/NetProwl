/// Check if an IP address is in a private range
pub fn is_private_ip(ip: &str) -> bool {
    if ip.starts_with("10.") {
        return true;
    }

    if ip.starts_with("172.") {
        if let Ok(octet) = ip[4..].split('.').next().unwrap_or("0").parse::<u8>() {
            if (16..=31).contains(&octet) {
                return true;
            }
        }
    }

    if ip.starts_with("192.168.") {
        return true;
    }

    if ip.starts_with("127.") {
        return true;
    }

    if ip.starts_with("169.254.") {
        return true;
    }

    false
}

/// Infer /24 subnet from a local IP address
pub fn infer_subnet(local_ip: &str) -> String {
    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() >= 4 {
        format!("{}.{}.{}.0", parts[0], parts[1], parts[2])
    } else {
        format!("{}.0.0.0", parts[0])
    }
}

/// Expand a subnet string into all IPs in a /24 range
pub fn expand_subnet(subnet: &str) -> Vec<String> {
    let subnet = subnet.trim_end_matches("/24").trim_end_matches(".0");

    let parts: Vec<&str> = subnet.split('.').collect();
    if parts.len() < 3 {
        return Vec::new();
    }

    let base = format!("{}.{}.{}", parts[0], parts[1], parts[2]);

    (1..=254)
        .map(|i| format!("{}.{}", base, i))
        .collect()
}

/// Parse IP range string like "192.168.1.1-50" into base IP and list of last octets
pub fn parse_ip_range(input: &str) -> (String, Vec<u8>) {
    let input = input.trim();

    if let Some((base, range)) = input.split_once('-') {
        let base = base.trim();
        let base_parts: Vec<&str> = base.split('.').collect();
        let prefix = if base_parts.len() >= 4 {
            format!("{}.{}.{}", base_parts[0], base_parts[1], base_parts[2])
        } else if base_parts.len() == 4 {
            format!("{}.{}.{}.", base_parts[0], base_parts[1], base_parts[2])
        } else {
            base.to_string()
        };

        let range_start: u16 = range
            .split('-')
            .next()
            .unwrap_or(range)
            .trim()
            .parse()
            .unwrap_or(1);

        let range_end: u16 = if range.contains('-') {
            range
                .split('-')
                .nth(1)
                .unwrap_or(range)
                .trim()
                .parse()
                .unwrap_or(range_start)
        } else {
            range_start
        };

        let start_byte = range_start as u8;
        let end_byte = range_end as u8;
        let last_octets: Vec<u8> = (start_byte..=end_byte).collect();

        (prefix, last_octets)
    } else {
        // Single IP or CIDR - just return as-is
        let parts: Vec<&str> = input.split('.').collect();
        if parts.len() == 4 {
            let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
            if let Ok(last) = parts[3].parse::<u8>() {
                return (prefix, vec![last]);
            }
        }
        (input.to_string(), vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
    }

    #[test]
    fn test_infer_subnet() {
        assert_eq!(infer_subnet("192.168.1.100"), "192.168.1.0");
        assert_eq!(infer_subnet("10.0.0.50"), "10.0.0.0");
    }

    #[test]
    fn test_expand_subnet() {
        let ips = expand_subnet("192.168.1.0");
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0], "192.168.1.1");
        assert_eq!(ips[253], "192.168.1.254");
    }

    #[test]
    fn test_parse_ip_range() {
        let (base, octets) = parse_ip_range("192.168.1.1-50");
        assert_eq!(base, "192.168.1");
        assert!(octets.len() > 0);
    }
}
