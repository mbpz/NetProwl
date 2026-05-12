//! mDNS discovery stub

use crate::scanner::Device;

pub async fn discover_mdns(_timeout_ms: u64) -> Vec<Device> {
    // TODO: implement with trust-dns-resolver or custom multicast socket
    vec![]
}
