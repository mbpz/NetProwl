//! IP / subnet utilities

/// Expand /24 subnet into IP list
pub fn expand_subnet(subnet: &str) -> Vec<String> {
    let (ip, mask) = match subnet.split_once('/') {
        Some((ip, mask)) => (ip, mask.parse::<u8>().unwrap_or(24)),
        None => (subnet, 24u8),
    };
    if mask != 24 {
        return vec![];
    }
    let parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() != 4 {
        return vec![];
    }
    (1u8..=254).map(|i| format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], i)).collect()
}

/// Check if IP is private (RFC 1918)
pub fn is_private(ip: &str) -> bool {
    let parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() != 4 { return false; }
    parts[0] == 10
        || (parts[0] == 172 && (16..=31).contains(&parts[1]))
        || (parts[0] == 192 && parts[1] == 168)
}

/// Alias for compat
pub fn is_private_ip(ip: &str) -> bool { is_private(ip) }

/// Infer /24 subnet from local IP
pub fn infer_subnet(local_ip: &str) -> Option<String> {
    let parts: Vec<u8> = local_ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() != 4 { return None; }
    Some(format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]))
}

/// Guess gateway IP (base + .1)
pub fn guess_gateway(local_ip: &str) -> String {
    let parts: Vec<u8> = local_ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() != 4 { return local_ip.to_string(); }
    format!("{}.{}.{}.1", parts[0], parts[1], parts[2])
}
