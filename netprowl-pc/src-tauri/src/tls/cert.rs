use rustls::{ClientConfig, ClientConnection, StreamOwned, DigitallySignedStruct, SignatureScheme};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use x509_parser::prelude::*;
use sha2::{Sha256, Digest};

use crate::tls::TLSCertInfo;

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
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

pub fn fetch_cert_info(host: &str, port: u16) -> Result<TLSCertInfo, String> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let conn = ClientConnection::new(Arc::new(config), host.try_into().map_err(|e| format!("{:?}", e))?)
        .map_err(|e| e.to_string())?;

    let mut sock = TcpStream::connect(format!("{}:{}", host, port))
        .map_err(|e| format!("tcp connect failed: {}", e))?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let mut tls_stream = StreamOwned::new(conn, sock);

    let cert_der = tls_stream.conn.peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or("no certificate returned")?;

    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| format!("x509 parse failed: {:?}", e))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_before = cert.validity().not_before.to_rfc2822();
    let not_after = cert.validity().not_after.to_rfc2822();

    let san = cert.subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| san.value.general_names.iter().map(|n| format!("{:?}", n)).collect())
        .unwrap_or_default();

    use std::fmt::Write as FmtWrite;
    let digest = Sha256::digest(cert_der.as_ref());
    let mut fp = String::new();
    for b in &digest {
        write!(&mut fp, "{:02X}:", b).unwrap();
    }
    let fingerprint_sha256 = fp.trim_end_matches(':').to_string();

    let has_ocsp_stapling = cert.extensions().iter().any(|ext| ext.oid.as_bytes() == b"1.3.6.1.5.5.7.1.1");

    let pk_algorithm = &cert.public_key().algorithm.algorithm;
    let key_algorithm = if pk_algorithm.oid == x509_parser::oid_registry::OID_RSA_ENCRYPTION {
        "RSA".to_string()
    } else if pk_algorithm.oid == x509_parser::oid_registry::OID_EC_PUBLIC_KEY {
        "EC".to_string()
    } else {
        "unknown".to_string()
    };
    let key_size = 0;

    Ok(TLSCertInfo {
        subject,
        issuer,
        not_before: not_before?,
        not_after: not_after?,
        san,
        fingerprint_sha256,
        key_algorithm,
        key_size,
        has_ocsp_stapling,
    })
}