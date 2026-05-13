use rustls::{ClientConfig, ClientConnection, StreamOwned, ProtocolVersion};
use std::io::Read;
use std::net::TcpStream;
use std::sync::Arc;

use crate::tls::TLSConfigInfo;

#[derive(Debug)]
struct NoVerifier;
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Check which TLS protocol versions and cipher suites are supported by a server.
pub fn check_tls_config(host: &str, port: u16) -> Result<TLSConfigInfo, String> {
    let versions: [ProtocolVersion; 4] = [
        ProtocolVersion::TLSv1_3,
        ProtocolVersion::TLSv1_2,
        ProtocolVersion::TLSv1_1,
        ProtocolVersion::TLSv1_0,
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

        let host_owned = host.to_string();
        let conn = match ClientConnection::new(
            Arc::new(config),
            host_owned.try_into().map_err(|e| format!("{:?}", e))?,
        ) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut sock = match TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(5)));

        let mut stream = StreamOwned::new(conn, sock);

        let mut buf = [0u8; 1];
        let _ = stream.read(&mut buf);

        let negotiated = stream.conn.protocol_version();

        if negotiated == Some(ProtocolVersion::TLSv1_3) {
            info.supports_tls13 = true;
        } else if negotiated == Some(ProtocolVersion::TLSv1_2) {
            info.supports_tls12 = true;
        } else if negotiated == Some(ProtocolVersion::TLSv1_1) {
            info.supports_tls11 = true;
        } else if negotiated == Some(ProtocolVersion::TLSv1_0) {
            info.supports_tls10 = true;
        }
    }

    if info.supports_tls12 {
        let config = match build_config_for_version(ProtocolVersion::TLSv1_2) {
            Some(cfg) => cfg,
            None => return Ok(info),
        };

        let host_owned = host.to_string();
        let conn = match ClientConnection::new(
            Arc::new(config),
            host_owned.try_into().map_err(|e| format!("{:?}", e))?,
        ) {
            Ok(c) => c,
            Err(_) => return Ok(info),
        };

        let mut sock = match TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(s) => s,
            Err(_) => return Ok(info),
        };
        let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(5)));

        let mut stream = StreamOwned::new(conn, sock);

        let mut buf = [0u8; 1];
        let _ = stream.read(&mut buf);

        if let Some(cs) = stream.conn.negotiated_cipher_suite() {
            info.supported_cipher_suites.push(format!("{:?}", cs));
        }
    }

    Ok(info)
}

fn build_config_for_version(_version: ProtocolVersion) -> Option<ClientConfig> {
    let verifier = Arc::new(NoVerifier);
    Some(ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}
