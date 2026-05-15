//! mDNS service registration for agent auto-discovery.
//!
//! Broadcasts `_netprowl._tcp` so the mini-program can discover
//! the agent on the LAN without manual IP configuration.

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Register mDNS service. Returns a handle that unregisters on drop.
pub fn register(port: u16, hostname: &str) -> Result<MDnsHandle, String> {
    // Use a simple UDP broadcast approach for mDNS service announcement.
    // Full mDNS implementation would need the `mdns-sd` crate.
    // For now, we broadcast a simple presence packet that the mini-program
    // can listen for on port 9788.
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let h = hostname.to_string();
    std::thread::spawn(move || broadcast_loop(port, &h, &r));

    Ok(MDnsHandle { running })
}

pub struct MDnsHandle {
    running: Arc<AtomicBool>,
}

impl Drop for MDnsHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

fn broadcast_loop(port: u16, hostname: &str, running: &AtomicBool) {
    // Broadcast UDP packets on a well-known port so mini-program can discover us.
    // The mini-program listens on UDP and looks for agents.
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = sock.set_broadcast(true);

    let msg = format!("netprowl-agent:{}:{}\0", hostname, port);
    let broadcast_addr = format!("255.255.255.255:{}", port);

    while running.load(Ordering::Relaxed) {
        let _ = sock.send_to(msg.as_bytes(), &broadcast_addr);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
