use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crate::tls::TLSConfigInfo;

/// Check which TLS protocol versions and cipher suites are supported by a server.
pub fn check_tls_config(host: &str, port: u16) -> Result<TLSConfigInfo, String> {
    let versions: [&(dyn rustls::SupportedProtocolVersion + Sync); 4] = [
        &rustls::version::TLS13,
        &rustls::version::TLS12,
        &rustls::version::TLS11,
        &rustls::version::TLS10,
    ];

    let mut info = TLSConfigInfo {
        supports_tls10: false,
        supports_tls11: false,
        supports_tls12: false,
        supports_tls13: false,
        supported_cipher_suites: vec![],
        fallback_scsv: false,
        renegotiation: "not_tested".into(),
    };

    for version in versions {
        let config = match build_config_for_version(version) {
            Some(cfg) => cfg,
            None => continue,
        };

        let conn = match ClientConnection::new(
            Arc::new(config),
            host.try_into().map_err(|e| format!("{:?}", e))?,
        ) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut sock = match TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(5)));

        let mut stream = match StreamOwned::new(conn, sock) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Try to read/write to force handshake
        let mut buf = [0u8; 1];
        let _ = stream.read(&mut buf);

        // Check which version was negotiated
        let negotiated = stream.conn.protocol_version();

        if negotiated == Some(rustls::version::TLS13) {
            info.supports_tls13 = true;
        } else if negotiated == Some(rustls::version::TLS12) {
            info.supports_tls12 = true;
        } else if negotiated == Some(rustls::version::TLS11) {
            info.supports_tls11 = true;
        } else if negotiated == Some(rustls::version::TLS10) {
            info.supports_tls10 = true;
        }
    }

    // If TLS 1.2 is supported, enumerate cipher suites by negotiating and reading back
    if info.supports_tls12 {
        let config = match build_config_for_version(&rustls::version::TLS12) {
            Some(cfg) => cfg,
            None => return Ok(info),
        };

        let conn = match ClientConnection::new(
            Arc::new(config),
            host.try_into().map_err(|e| format!("{:?}", e))?,
        ) {
            Ok(c) => c,
            Err(_) => return Ok(info),
        };

        let mut sock = match TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(s) => s,
            Err(_) => return Ok(info),
        };
        let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(5)));

        let mut stream = match StreamOwned::new(conn, sock) {
            Ok(s) => s,
            Err(_) => return Ok(info),
        };

        let mut buf = [0u8; 1];
        let _ = stream.read(&mut buf);

        // Collect cipher suites from the negotiated connection
        if let Some(cs) = stream.conn.negotiated_cipher_suite() {
            info.supported_cipher_suites.push(format!("{:?}", cs));
        }
    }

    Ok(info)
}

fn build_config_for_version(
    version: &(dyn rustls::SupportedProtocolVersion + Sync),
) -> Option<ClientConfig> {
    let mut config = ClientConfig::builder()
        .dangerous_disable_certificate_verification()
        .ok()?;

    config.alpn_protocols.clear();
    config.max_protocol_version = Some(version.version);
    config.min_protocol_version = Some(version.version);

    config.build().ok()
}
