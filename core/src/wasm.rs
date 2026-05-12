use wasm_bindgen::prelude::*;
use crate::scanner::{discover_lan, DiscoveryOptions};
use crate::types::ScanResult;

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
pub fn set_timeout(ms: u32) {
    // WASM environments have limited timeout support
}