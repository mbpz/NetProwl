// TODO: implement SSDP discovery

use crate::types::Device;

pub async fn discover_ssdp(timeout_ms: u64) -> Result<Vec<Device>, String> {
    let _ = timeout_ms;
    Err("SSDP not implemented".to_string())
}