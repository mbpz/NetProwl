use wasm_bindgen::prelude::*;
use crate::util::{ip, oui};

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
    serde_json::to_string(&ip::expand_subnet(subnet)).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
use crate::scanner::{discover_lan, DiscoveryOptions};

#[cfg(not(target_arch = "wasm32"))]
use crate::types::ScanResult;

#[cfg(not(target_arch = "wasm32"))]
#[wasm_bindgen]
pub async fn scan_network() -> Result<JsValue, JsValue> {
    let opts = DiscoveryOptions::default();
    let result = discover_lan(opts)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn set_timeout(_ms: u32) {
    // WASM environments have limited timeout support
}