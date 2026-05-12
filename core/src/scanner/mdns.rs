// TODO: implement mDNS discovery

use crate::types::Device;

pub async fn discover_mdns(timeout_ms: u64) -> Result<Vec<Device>, String> {
    let _ = timeout_ms;
    Err("mDNS not implemented".to_string())
}