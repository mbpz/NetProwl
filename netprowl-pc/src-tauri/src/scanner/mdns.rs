//! mDNS discovery through the shared Rust core.

use crate::scanner::{Device, Port};
use std::time::Duration;

pub async fn discover_mdns(timeout_ms: u64) -> Vec<Device> {
    let cfg = rs_core::scanner::MDNSConfig {
        timeout: Duration::from_millis(timeout_ms),
        ..Default::default()
    };

    match rs_core::scanner::mdns::discover_mdns(cfg).await {
        Ok(devices) => devices.into_iter().map(from_core_device).collect(),
        Err(err) => {
            eprintln!("mDNS discovery unavailable: {err}");
            Vec::new()
        }
    }
}

fn from_core_device(device: rs_core::Device) -> Device {
    Device {
        ip: device.ip,
        mac: device.mac,
        hostname: device.hostname,
        vendor: device.vendor,
        device_type: Some(device.device_type),
        ports: device.open_ports.into_iter().map(from_core_port).collect(),
        sources: vec!["mdns".into()],
    }
}

fn from_core_port(port: rs_core::Port) -> Port {
    Port {
        port: port.port,
        state: port.state,
        service: port.service,
        banner: port.banner,
    }
}
