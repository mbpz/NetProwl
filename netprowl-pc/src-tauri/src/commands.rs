//! Tauri commands — history, pipeline, and tool management.

use tauri::State;
use crate::{ScannerState, history::HistoryDb, Device};

fn with_db<T, F>(state: &ScannerState, f: F) -> Result<T, String>
where
    F: FnOnce(&HistoryDb) -> Result<T, String>,
{
    let guard = state.db.lock().map_err(|e| e.to_string())?;
    f(&guard)
}

#[tauri::command]
pub async fn start_scan_session(target: String, state: tauri::State<'_, ScannerState>) -> Result<i64, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.start_session(&target)
}

#[tauri::command]
pub async fn end_scan_session(id: i64, count: i32, state: tauri::State<'_, ScannerState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.end_session(id, count)
}

#[tauri::command]
pub async fn insert_scan_vulnerability(
    session_id: i64, device_ip: String, port: u16, tool: String,
    vuln_id: String, name: String, severity: String, state: tauri::State<'_, ScannerState>,
) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.insert_vulnerability(session_id, &device_ip, port, &tool, &vuln_id, &name, &severity)
}

#[tauri::command]
pub async fn get_scan_history(limit: usize, offset: usize, state: tauri::State<'_, ScannerState>) -> Result<Vec<crate::history::ScanSession>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.get_sessions(limit, offset)
}

#[tauri::command]
pub async fn get_session_detail(session_id: i64, state: tauri::State<'_, ScannerState>) -> Result<crate::history::SessionDetail, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.get_session_detail(session_id)
}

#[tauri::command]
pub async fn delete_scan_session(session_id: i64, state: tauri::State<'_, ScannerState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.delete_session(session_id)
}

#[tauri::command]
pub async fn clear_scan_history(state: tauri::State<'_, ScannerState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.delete_all_sessions()
}

#[tauri::command]
pub async fn cleanup_scan_history(max_days: i64, state: tauri::State<'_, ScannerState>) -> Result<usize, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.cleanup(max_days)
}

#[tauri::command]
pub async fn save_scan(session_id: i64, devices: Vec<Device>, state: tauri::State<'_, ScannerState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    for device in devices {
        let device_id = db.save_device(session_id, &device.ip, device.mac.as_deref(), device.vendor.as_deref(), "tcp")?;
        for port in &device.ports {
            let state_str = match port.state {
                crate::scanner::PortState::Open => "open",
                crate::scanner::PortState::Closed => "closed",
                crate::scanner::PortState::Filtered => "filtered",
            };
            db.save_port(session_id, device_id, port.port as i32, state_str, port.service.as_deref(), port.banner.as_deref())?;
        }
    }
    Ok(())
}