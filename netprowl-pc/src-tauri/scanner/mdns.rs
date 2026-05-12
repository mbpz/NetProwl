//! mDNS (Bonjour) 发现模块
//!
//! 注意：完整实现需要 multicast UDP socket 或 trust-dns-resolver。

use crate::scanner::Device;

/// 发现 mDNS 服务（stub：简化实现）
///
/// 完整实现后续使用：
/// - `trust-dns-resolver` 进行 mDNS 查询
/// - 或自定义 multicast socket (224.0.0.251:5353)
pub async fn discover_mdns(_timeout_ms: u64) -> Vec<Device> {
    // TODO: 实现完整的 mDNS multicast + service browse
    // 使用 trust-dns-resolver 或自定义 multicast socket
    vec![]
}
