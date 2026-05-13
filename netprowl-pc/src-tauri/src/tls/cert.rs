use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use x509_parser::prelude::*;

use crate::tls::TLSCertInfo;

pub fn fetch_cert_info(host: &str, port: u16) -> Result<TLSCertInfo, String> {
    // 1. Build TLS config that skips verification (we check cert ourselves)
    let config = ClientConfig::builder()
        .dangerous_disable_certificate_verification()
        .build();

    let conn = ClientConnection::new(Arc::new(config), host.try_into().map_err(|e| format!("{:?}", e))?)
        .map_err(|e| e.to_string())?;

    // 2. Establish TCP + TLS connection
    let mut sock = TcpStream::connect(format!("{}:{}", host, port))
        .map_err(|e| format!("tcp connect failed: {}", e))?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let mut tls_stream = StreamOwned::new(conn, sock);

    // 3. Read peer certificates
    let cert_der = tls_stream.conn.peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or("no certificate returned")?;

    // 4. Parse with x509-parser
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| format!("x509 parse failed: {:?}", e))?;

    // 5. Extract subject/issuer
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_before = cert.validity().not_before.to_rfc2822_str();
    let not_after = cert.validity().not_after.to_rfc2822_str();

    // 6. SAN (Subject Alternative Names)
    let san = cert.subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| san.value.general_names.iter().map(|n| format!("{:?}", n)).collect())
        .unwrap_or_default();

    // 7. Fingerprint (using sha2 crate as ring_compat alternative)
    use std::fmt::Write as FmtWrite;
    let digest = sha2::Sha256::digest(cert_der.as_ref());
    let mut fp = String::new();
    for b in digest.as_ref() {
        write!(&mut fp, "{:02X}:", b).unwrap();
    }
    let fingerprint_sha256 = fp.trim_end_matches(':').to_string();

    // 8. OCSP stapling check (from Extensions)
    let has_ocsp_stapling = cert.extensions().iter().any(|ext| ext.oid.as_bytes() == b"1.3.6.1.5.5.7.1.1");

    // 9. Key algorithm and size from public key
    let (key_algorithm, key_size) = match cert.public_key().algorithm.algorithm.kind() {
        x509_parser::oid_registry::OidRegistry::RSA_ENCRYPTION => ("RSA".to_string(), 2048u32),
        x509_parser::oid_registry::OidRegistry::EC_PUBLIC_KEY => ("EC".to_string(), 256),
        _ => ("unknown".to_string(), 0),
    };

    Ok(TLSCertInfo {
        subject,
        issuer,
        not_before,
        not_after,
        san,
        fingerprint_sha256,
        key_algorithm,
        key_size,
        has_ocsp_stapling,
    })
}