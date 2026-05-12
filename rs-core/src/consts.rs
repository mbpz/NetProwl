// SSDP multicast
pub const SSDP_MULTICAST_ADDR: &str = "239.255.255.250";
pub const SSDP_PORT: u16 = 1900;

// mDNS multicast
pub const MDNS_MULTICAST_ADDR: &str = "224.0.255.253";
pub const MDNS_PORT: u16 = 5353;

// 白名单端口（小程序可用）
pub const WHITE_PORTS: &[u16] = &[
    80, 443, 8080, 8443, 554, 5000, 9000, 49152,
];

// 全端口（PC客户端用）
pub const ALL_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 9000,
];