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
    let base =
        u32::from_be_bytes([0, 0, 0, 0])
        | (u32::from(parts[0]) << 24)
        | (u32::from(parts[1]) << 16)
        | (u32::from(parts[2]) << 8);

    (1u32..=254).map(|i| {
        let addr = std::net::Ipv4Addr::from(base | i);
        addr.to_string()
    }).collect()
}

/// Check if IP is private
pub fn is_private(ip: &str) -> bool {
    let parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() != 4 { return false; }
    parts[0] == 10
        || (parts[0] == 172 && (16..=31).contains(&parts[1]))
        || (parts[0] == 192 && parts[1] == 168)
}

/// Infer /24 subnet from local IP
pub fn infer_subnet(local_ip: &str) -> Option<String> {
    let parts: Vec<u8> = local_ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() != 4 { return None; }
    Some(format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]))
}
