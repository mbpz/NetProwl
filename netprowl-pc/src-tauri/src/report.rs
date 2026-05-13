//! Report generation for scan history.

use crate::history::HistoryDb;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub scan_id: i64,
    pub target: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub devices: Vec<DeviceReport>,
    pub summary: ReportSummary,
}

#[derive(Debug, Serialize)]
pub struct DeviceReport {
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub device_type: Option<String>,
    pub ports: Vec<PortReport>,
}

#[derive(Debug, Serialize)]
pub struct PortReport {
    pub port: i32,
    pub service: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub total_devices: usize,
    pub total_ports: usize,
    pub services: HashMap<String, usize>,
}

pub fn build_report(db: &HistoryDb, scan_id: i64) -> Result<ScanReport, String> {
    let conn = db.conn.lock().map_err(|e| e.to_string())?;

    let (target, started_at, finished_at): (String, i64, Option<i64>) = conn
        .query_row(
            "SELECT target, started_at, finished_at FROM scan_sessions WHERE id = ?1",
            [scan_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare("SELECT ip, mac, vendor FROM devices WHERE session_id = ?1")
        .map_err(|e| e.to_string())?;
    let devices: Vec<(String, Option<String>, Option<String>)> = stmt
        .query_map([scan_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    let mut port_stmt = conn
        .prepare("SELECT port, service, state FROM ports WHERE device_id = ?1")
        .map_err(|e| e.to_string())?;

    let mut device_reports = Vec::new();
    let mut total_ports = 0;
    let mut services: HashMap<String, usize> = HashMap::new();

    for (ip, mac, vendor) in devices {
        let ports: Vec<(i32, Option<String>, Option<String>)> = port_stmt
            .query_map([scan_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        total_ports += ports.len();

        let port_reports: Vec<PortReport> = ports
            .iter()
            .map(|(port, service, state)| {
                if let Some(ref svc) = service {
                    *services.entry(svc.clone()).or_insert(0) += 1;
                }
                PortReport {
                    port: *port,
                    service: service.clone(),
                    state: state.clone(),
                }
            })
            .collect();

        device_reports.push(DeviceReport {
            ip,
            mac,
            vendor,
            device_type: None,
            ports: port_reports,
        });
    }

    let summary = ReportSummary {
        total_devices: device_reports.len(),
        total_ports,
        services,
    };

    Ok(ScanReport {
        scan_id,
        target,
        started_at,
        finished_at,
        devices: device_reports,
        summary,
    })
}

pub fn export_json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_default()
}

pub fn export_html(report: &ScanReport) -> String {
    let mut html = r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NetProwl Scan Report</title>
<style>
body{font-family:system-ui;background:#0f172a;color:#f1f5f9;padding:24px}
h1{color:#7dd3fc;font-size:24px}
h2{color:#c4b5fd;font-size:16px;margin-top:24px}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{padding:8px 12px;border:1px solid #334155;text-align:left}
th{background:#1e293b;color:#7dd3fc}
tr:nth-child(even){background:#1e293b}
.port{font-family:monospace}
.mac{font-family:monospace;font-size:12px}
.summary{display:flex;gap:12px;margin-top:12px}
.metric{background:#1e293b;border-radius:8px;padding:12px;flex:1;text-align:center}
.metric-value{font-size:24px;font-weight:bold;color:#7dd3fc}
.metric-label{font-size:11px;color:#94a3b8;margin-top:4px}
</style></head><body>
<h1>🔍 NetProwl Scan Report</h1>
<div class="summary">
<div class="metric"><div class="metric-value">"#.to_string();
    html.push_str(&report.devices.len().to_string());
    html.push_str(r#"</div><div class="metric-label">Devices</div></div>"#);
    html.push_str(r#"<div class="metric"><div class="metric-value">"#);
    let total_ports: usize = report.devices.iter().map(|d| d.ports.len()).sum();
    html.push_str(&total_ports.to_string());
    html.push_str(r#"</div><div class="metric-label">Open Ports</div></div>"#);
    html.push_str(r#"</div><h2>Devices</h2><table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Type</th><th>Ports</th></tr>"#);
    for d in &report.devices {
        html.push_str(&format!(r#"<tr><td>{}</td><td class="mac">{}</td><td>{}</td><td>{}</td><td class="port">{}</td></tr>"#,
            d.ip,
            d.mac.as_deref().unwrap_or("-"),
            d.vendor.as_deref().unwrap_or("-"),
            d.device_type.as_deref().unwrap_or("-"),
            d.ports.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(", ")
        ));
    }
    html.push_str(r#"</table></body></html>"#);
    html
}

pub fn export_csv(report: &ScanReport) -> String {
    let mut csv = "IP,MAC,Vendor,DeviceType,Port,Service,State\n".to_string();
    for d in &report.devices {
        for p in &d.ports {
            csv.push_str(&format!("{},{},{},{},{},{},{}\n",
                d.ip,
                d.mac.as_deref().unwrap_or(""),
                d.vendor.as_deref().unwrap_or(""),
                d.device_type.as_deref().unwrap_or(""),
                p.port,
                p.service.as_deref().unwrap_or(""),
                p.state.as_deref().unwrap_or("")
            ));
        }
    }
    csv
}