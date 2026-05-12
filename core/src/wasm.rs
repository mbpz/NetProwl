use wasm_bindgen::prelude::*;
use crate::util::{ip, oui};
use crate::scanner::{mdns, ssdp, tcp, discover_lan, DiscoveryOptions};
use crate::types::ScanResult;

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

#[wasm_bindgen]
pub async fn discover_mdns(service_types_js: String, timeout_ms: u32) -> Result<String, JsValue> {
    let service_types: Vec<String> = serde_json::from_str(&service_types_js).unwrap_or_default();
    let cfg = mdns::MDNSConfig {
        service_types,
        timeout: std::time::Duration::from_millis(timeout_ms as u64),
    };
    let devices = mdns::discover_mdns(cfg)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&devices)
        .map_err(|e| JsValue::from_str(&e.to_string()))
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| e)
}

#[wasm_bindgen]
pub async fn discover_ssdp(timeout_ms: u32) -> Result<String, JsValue> {
    let cfg = ssdp::SSDPConfig {
        timeout: std::time::Duration::from_millis(timeout_ms as u64),
    };
    let devices = ssdp::discover_ssdp(cfg)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&devices)
        .map_err(|e| JsValue::from_str(&e.to_string()))
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| e)
}

#[wasm_bindgen]
pub async fn probe_tcp_ports(ip: &str, ports_js: String, timeout_ms: u32) -> Result<String, JsValue> {
    let ports: Vec<u16> = serde_json::from_str(&ports_js).unwrap_or_default();
    let cfg = tcp::TCPConfig {
        ports,
        concurrency: 50,
        timeout_ms: timeout_ms as u64,
    };
    let result = tcp::probe_tcp_ports(ip, cfg)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&e.to_string()))
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| e)
}

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
pub fn set_timeout(_ms: u32) {}