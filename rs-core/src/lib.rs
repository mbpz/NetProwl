mod types;
mod ip;
mod oui;
mod tcp;
mod banner;
mod registry;
mod mdns;
mod ssdp;
pub mod scanner;
pub mod util;
pub mod consts;

pub use types::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn lookup_vendor(mac: &str) -> Option<String> {
    oui::lookup_vendor(mac).map(|s| s.to_string())
}

#[wasm_bindgen]
pub fn infer_subnet(local_ip: &str) -> Option<String> {
    ip::infer_subnet(local_ip)
}

#[wasm_bindgen]
pub fn expand_subnet(subnet: &str) -> String {
    let ips = ip::expand_subnet(subnet);
    serde_json::to_string(&ips).unwrap_or_else(|_| "[]".to_string())
}

#[wasm_bindgen]
pub fn guess_gateway(local_ip: &str) -> String {
    ip::guess_gateway(local_ip)
}

#[wasm_bindgen]
pub fn is_private_ip(ip: &str) -> bool {
    ip::is_private_ip(ip)
}

// Scanner exports (sync wrappers around async impls)
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Runtime;

#[wasm_bindgen]
pub fn discover_ssdp(timeout_ms: u64) -> String {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let rt = Runtime::new().unwrap();
        let devices = rt.block_on(crate::scanner::ssdp::discover_ssdp_sync(timeout_ms));
        serde_json::to_string(&devices).unwrap_or_else(|_| "[]".to_string())
    }
    #[cfg(target_arch = "wasm32")]
    {
        "[]".to_string()
    }
}

#[wasm_bindgen]
pub fn discover_mdns(service_types: Vec<String>, timeout_ms: u64) -> String {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let cfg = crate::scanner::mdns::MDNSConfig {
            service_types,
            timeout: std::time::Duration::from_secs(timeout_ms / 1000),
        };
        let rt = Runtime::new().unwrap();
        let devices = rt.block_on(crate::scanner::mdns::discover_mdns_sync(cfg));
        serde_json::to_string(&devices).unwrap_or_else(|_| "[]".to_string())
    }
    #[cfg(target_arch = "wasm32")]
    {
        "[]".to_string()
    }
}

#[wasm_bindgen]
pub fn probe_tcp_ports(ip: &str, ports: Vec<u16>, timeout_ms: u64) -> String {
    let cfg = crate::scanner::tcp::TCPConfig {
        ports,
        concurrency: 100,
        timeout_ms,
    };
    let ports = crate::scanner::tcp::probe_tcp_ports_sync(ip, cfg);
    serde_json::to_string(&ports).unwrap_or_else(|_| "[]".to_string())
}

#[wasm_bindgen]
pub fn grab_banner(ip: &str, port: u16, timeout_ms: u64) -> String {
    let cfg = crate::scanner::banner::BannerConfig {
        timeout_ms,
        include_deep_scan: true,
        include_rtsp_sdp: true,
    };
    crate::scanner::banner::grab_banner_sync(ip, port, cfg)
}

#[wasm_bindgen]
pub fn guess_service(port: u16) -> String {
    crate::scanner::registry::guess_service(port)
}

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}
