pub mod mdns;
pub mod ssdp;
pub mod tcp;
pub mod banner;
pub mod registry;

pub use mdns::{discover_mdns_sync, MDNSConfig};
pub use ssdp::{discover_ssdp_sync, SSDPConfig};
pub use tcp::probe_tcp_ports_sync;
pub use banner::grab_banner_sync;
pub use registry::match_service;
pub use registry::guess_service;

#[cfg(not(target_arch = "wasm32"))]
pub use registry::init_cve_db;
#[cfg(not(target_arch = "wasm32"))]
pub use registry::lookup_cve;

#[cfg(not(target_arch = "wasm32"))]
pub use tcp::{probe_tcp_ports, TCPConfig};
#[cfg(not(target_arch = "wasm32"))]
pub use banner::{grab_banner, BannerConfig};
