//! Service fingerprint registry — thin wrapper delegating to rs-core

use crate::scanner::DeviceType;

pub use rs_core::scanner::registry::{guess_service, match_service as match_service_raw};

/// Match port + optional banner to service name and device type.
/// Thin wrapper: rs-core expects `&str`, PC passes `Option<&str>`.
pub fn match_service(port: u16, banner: Option<&str>) -> (&'static str, DeviceType) {
    match_service_raw(port, banner.unwrap_or(""))
}
