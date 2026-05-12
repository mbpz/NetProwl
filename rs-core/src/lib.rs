mod types;
mod ip;
mod oui;
mod tcp;
mod banner;
mod registry;
mod mdns;
mod ssdp;

pub use types::*;

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
    serde_json::to_string(&ip::expand_subnet(subnet)).unwrap_or_else(|_| "[]".into())
}

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}
