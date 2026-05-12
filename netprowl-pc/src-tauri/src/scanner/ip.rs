//! IP / 子网工具

use std::net::{IpAddr, Ipv4Addr};

/// 将 CIDR 子网展开为 IP 列表（/24 最常用）
pub fn expand_subnet(subnet: &str) -> Vec<String> {
    let (ip, mask) = match subnet.split_once('/') {
        Some((ip, mask)) => (ip, mask.parse::<u8>().unwrap_or(24)),
        None => (subnet, 24u8),
    };

    if mask != 24 {
        return vec![]; // 仅支持 /24 简化实现
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

    (1u32..=254)
        .map(|i| {
            let addr = Ipv4Addr::from(base | i);
            addr.to_string()
        })
        .collect()
}

/// 判断是否为私有 IP
pub fn is_private(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_private(),
        _ => false,
    }
}

/// 从本机 IP 推断 /24 子网
pub fn infer_subnet(local_ip: &str) -> Option<String> {
    let parts: Vec<u8> = local_ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() != 4 {
        return None;
    }
    Some(format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]))
}
