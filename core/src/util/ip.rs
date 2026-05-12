pub fn infer_subnet(local_ip: &str) -> Option<String> {
    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    Some(format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]))
}

pub fn expand_subnet(subnet: &str) -> Vec<String> {
    let Some((ip, mask)) = subnet.split_once('/') else { return vec![] };
    let Ok(ip): Result<std::net::Ipv4Addr, _> = ip.parse() else { return vec![] };
    let Ok(prefix): Result<u8, _> = mask.parse() else { return vec![] };
    if prefix > 32 { return vec![]; }

    let mask_bits = u32::MAX << (32 - prefix);
    let network = u32::from(ip) & mask_bits;
    let broadcast = network | !mask_bits;

    let mut ips = Vec::new();
    for n in (network + 1)..broadcast {
        let a = std::net::Ipv4Addr::try_from(n).expect("valid u32 to Ipv4Addr");
        ips.push(a.to_string());
    }
    ips
}

pub fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse() {
        match addr {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
            std::net::IpAddr::V6(_) => false,
        }
    } else {
        false
    }
}

pub fn infer_os(ttl: u32) -> &'static str {
    match ttl {
        0..=64 => "linux",
        65..=128 => "windows",
        _ => "unknown",
    }
}
