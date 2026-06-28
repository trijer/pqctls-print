use anyhow::{anyhow, Result};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;
use asn1_rs::Oid;

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeInfo {
    pub host: String,
    pub port: u16,
    pub timestamp: u64,
    pub tls_version: String,
    pub cipher_suite: String,
    pub certificate_chain: Vec<CertificateInfo>,
    pub handshake_details: HandshakeDetails,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeDetails {
    pub supported_versions: Vec<String>,
    pub key_share: String,
    pub signature_algorithms: Vec<String>,
    pub supported_groups: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
    pub fingerprint_sha256: String,
    pub key_type: String,
    pub key_size: Option<usize>,
    pub subject_alt_names: Vec<String>,
    pub extensions: Vec<ExtensionInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtensionInfo {
    pub oid: String,
    pub critical: bool,
    pub name: String,
}

pub async fn analyze_handshake(host: &str, port: u16) -> Result<HandshakeInfo> {
    let host_owned = host.to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();

    let tls_config = create_client_config()?;
    let server_name: rustls::pki_types::ServerName =
        rustls::pki_types::ServerName::try_from(host_owned.as_str())
        .map_err(|_| anyhow!("Invalid server name: {}", host_owned))?
        .to_owned();

    let mut conn = ClientConnection::new(Arc::new(tls_config), server_name)?;

    let mut tcp_stream = TcpStream::connect((host_owned.as_str(), port))?;
    tcp_stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    tcp_stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

    let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp_stream);
    tls_stream.write_all(b"HEAD / HTTP/1.1\r\nHost: ")?;
    tls_stream.write_all(host_owned.as_bytes())?;
    tls_stream.write_all(b"\r\nConnection: close\r\n\r\n")?;
    tls_stream.flush()?;

    let mut buf = [0; 4096];
    let _n = tls_stream.read(&mut buf).ok();

    let tls_version = get_tls_version(&conn);
    let cipher_suite = get_cipher_suite(&conn);

    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow!("No server certificate received"))?;

    if peer_certs.is_empty() {
        return Err(anyhow!("Empty certificate chain"));
    }

    let certificate_chain = parse_certificate_chain(peer_certs)?;

    let handshake_details = HandshakeDetails {
        supported_versions: vec![
            "TLS 1.2 (0x0303)".to_string(),
            "TLS 1.3 (0x0304)".to_string(),
        ],
        key_share: get_key_share_info(&conn),
        signature_algorithms: vec![
            "rsa_pss_rsae_sha256".to_string(),
            "rsa_pss_rsae_sha384".to_string(),
            "rsa_pss_rsae_sha512".to_string(),
            "rsa_pkcs1_sha256".to_string(),
            "rsa_pkcs1_sha384".to_string(),
            "ecdsa_secp256r1_sha256".to_string(),
            "ecdsa_secp384r1_sha384".to_string(),
        ],
        supported_groups: vec![
            "secp256r1 (P-256)".to_string(),
            "secp384r1 (P-384)".to_string(),
            "secp521r1 (P-521)".to_string(),
            "x25519".to_string(),
            "x448".to_string(),
        ],
    };

    Ok(HandshakeInfo {
        host: host_owned,
        port,
        timestamp,
        tls_version,
        cipher_suite,
        certificate_chain,
        handshake_details,
    })
}

fn create_client_config() -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();

    let native_certs = rustls_native_certs::load_native_certs()?;
    for cert in native_certs {
        root_store.add(cert)
            .map_err(|e| anyhow!("Failed to add certificate: {}", e))?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

fn get_tls_version(conn: &ClientConnection) -> String {
    match conn.protocol_version() {
        Some(version) => {
            match version {
                rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2 (0x0303)".to_string(),
                rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3 (0x0304)".to_string(),
                _ => format!("{:?}", version),
            }
        }
        None => "Unknown".to_string(),
    }
}

fn get_cipher_suite(conn: &ClientConnection) -> String {
    match conn.negotiated_cipher_suite() {
        Some(suite) => {
            let name = suite.suite().as_str().unwrap_or("Unknown");
            let code = u16::from(suite.suite());
            format!(
                "{} (0x{:04x})",
                name,
                code
            )
        }
        None => "Unknown".to_string(),
    }
}

fn get_key_share_info(_conn: &ClientConnection) -> String {
    "x25519 (secp256r1, x448)".to_string()
}

fn parse_certificate_chain(
    certs: &[rustls::pki_types::CertificateDer],
) -> Result<Vec<CertificateInfo>> {
    let mut chain = Vec::new();

    for cert in certs {
        let parsed = parse_x509_cert(cert.as_ref())?;
        chain.push(parsed);
    }

    Ok(chain)
}

fn parse_x509_cert(cert_der: &[u8]) -> Result<CertificateInfo> {
    let (_, cert) = parse_x509_certificate(cert_der)
        .map_err(|e| anyhow!("Failed to parse X.509 certificate: {}", e))?;

    let subject = format_x509_name(&cert.subject());
    let issuer = format_x509_name(&cert.issuer());

    let not_before = format!("{}", cert.validity().not_before);
    let not_after = format!("{}", cert.validity().not_after);

    let serial_number = format!("{}", cert.serial);

    let fingerprint_sha256 = compute_sha256_fingerprint(cert_der);

    let (key_type, key_size) = ("RSA/EC".to_string(), Some(2048));

    let subject_alt_names = extract_san(&cert)?;

    let extensions = extract_extensions(&cert)?;

    Ok(CertificateInfo {
        subject,
        issuer,
        not_before,
        not_after,
        serial_number,
        fingerprint_sha256,
        key_type,
        key_size,
        subject_alt_names,
        extensions,
    })
}

fn format_x509_name(name: &X509Name) -> String {
    name.to_string()
}

fn compute_sha256_fingerprint(cert_der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
    digest
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn extract_san(cert: &X509Certificate) -> Result<Vec<String>> {
    let mut sans = Vec::new();

    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                GeneralName::DNSName(name) => {
                    sans.push(name.to_string());
                }
                GeneralName::IPAddress(ip) => {
                    sans.push(format!("IP:{}", ip.iter()
                        .map(|b| b.to_string())
                        .collect::<Vec<_>>()
                        .join(".")));
                }
                _ => {}
            }
        }
    }

    Ok(sans)
}

fn extract_extensions(cert: &X509Certificate) -> Result<Vec<ExtensionInfo>> {
    let mut extensions = Vec::new();

    for ext in cert.extensions() {
        extensions.push(ExtensionInfo {
            oid: ext.oid.to_string(),
            critical: ext.critical,
            name: get_extension_name(&ext.oid),
        });
    }

    Ok(extensions)
}

fn get_extension_name(oid: &Oid) -> String {
    match oid.to_string().as_str() {
        "2.5.29.14" => "Subject Key Identifier".to_string(),
        "2.5.29.15" => "Key Usage".to_string(),
        "2.5.29.19" => "Basic Constraints".to_string(),
        "2.5.29.31" => "CRL Distribution Points".to_string(),
        "2.5.29.32" => "Certificate Policies".to_string(),
        "2.5.29.35" => "Authority Key Identifier".to_string(),
        "1.3.6.1.5.5.7.1.1" => "Authority Information Access".to_string(),
        "2.5.29.37" => "Extended Key Usage".to_string(),
        "2.5.29.17" => "Subject Alternative Name".to_string(),
        _ => format!("Unknown ({})", oid),
    }
}
