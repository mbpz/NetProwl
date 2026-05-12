//! NetProwl Core Scanner Module
//! Re-exports scanner functions from netprowl-core (NOT types — types are defined locally in lib.rs)

pub use netprowl_core::scanner::{tcp, ssdp, mdns};
pub use netprowl_core::types::PortState;

pub const WHITE_PORTS: &[u16] = &[80, 443, 8080, 8443, 554, 5000, 9000, 49152];
pub const FULL_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 9200, 27017,
];
