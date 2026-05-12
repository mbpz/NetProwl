#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            scan_tcp,
            scan_mdns,
            scan_ssdp,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn scan_tcp(ip_start: String, ip_end: String, ports: Vec<u16>) -> Result<String, String> {
    // 调用 Go core 编译的库或 WASM
    // 简化：返回空 JSON
    Ok(r#"{"devices":[],"summary":{"total":0}}"#)
}

#[tauri::command]
fn scan_mdns() -> Result<String, String> {
    Ok(r#"{"devices":[]}"#)
}

#[tauri::command]
fn scan_ssdp() -> Result<String, String> {
    Ok(r#"{"devices":[]}"#)
}