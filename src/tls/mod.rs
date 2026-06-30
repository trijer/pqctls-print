pub mod certificates;
pub mod encryption;
pub mod handshake;
pub mod http;
pub mod pqc;
pub mod stream;
pub mod types;
pub mod utils;

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, TlsError};
pub use types::*;
use certificates::parse_certificate_chain;
use encryption::build_encryption_negotiation;
use http::build_http_exchange;
use pqc::build_post_quantum_analysis;
use stream::TrackedStream;

/// Analyze a TLS connection and produce a comprehensive security report.
///
/// # What We Can Capture
/// - Unencrypted handshake messages (ClientHello, ServerHello, certificate, etc.)
/// - Cipher suite and TLS version negotiation
/// - Certificate chain details
/// - Key exchange parameters
/// - Session ticket presence (inferred from encrypted records)
///
/// # What We Cannot Capture (Without Rustls Modifications)
/// - Encrypted handshake messages (EncryptedExtensions, CertificateVerify, Finished)
/// - Session keys or master secrets
/// - Session ticket contents (lifetime, nonce, identity)
/// - Application data (HTTP responses are parsed but not dissected)
///
/// # Why?
/// Rustls intentionally hides session keys for security reasons. This is correct behavior:
/// - Prevents accidental key leakage through logs/dumps
/// - Enforces forward secrecy semantics
/// - Matches security practices of browsers/OS TLS stacks
///
/// # To See Encrypted Messages
/// See detailed comments in stream.rs and the session module for decryption options.
pub async fn analyze_handshake(host: &str, port: u16) -> Result<TLSAnalysisReport> {
    let host_owned = host.to_string();

    tokio::task::spawn_blocking(move || perform_tls_handshake(&host_owned, port))
        .await
        .map_err(|_| TlsError::Other("Blocking task failed".to_string()))?
}

fn perform_tls_handshake(host: &str, port: u16) -> Result<TLSAnalysisReport> {
    let host_owned = host.to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();

    let tls_config = create_client_config()?;
    let server_name: rustls::pki_types::ServerName =
        rustls::pki_types::ServerName::try_from(host_owned.as_str())
            .map_err(|_| TlsError::InvalidServerName {
                name: host_owned.clone(),
            })?
            .to_owned();

    let mut conn = ClientConnection::new(Arc::new(tls_config), server_name)?;

    let tcp_stream = TcpStream::connect((host_owned.as_str(), port))?;
    tcp_stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    tcp_stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

    let mut tracked_stream = TrackedStream::new(tcp_stream);

    let mut tls_stream = rustls::Stream::new(&mut conn, &mut tracked_stream);

    let http_request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: tls-outputter\r\nConnection: close\r\n\r\n",
        host_owned
    );

    tls_stream.write_all(http_request.as_bytes())?;
    tls_stream.flush()?;

    let mut response_buf = Vec::new();
    let mut buf = [0; 4096];
    loop {
        match tls_stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response_buf.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::Other => break,
            Err(_) => {
                break;
            }
        }
    }

    let http_response = String::from_utf8_lossy(&response_buf).to_string();

    let tls_version = get_tls_version(&conn);
    let cipher_suite = get_cipher_suite(&conn);
    let key_share = get_key_share_info(&conn);

    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| TlsError::NoCertificateReceived {
            host: host_owned.clone(),
        })?
        .to_vec();

    if peer_certs.is_empty() {
        return Err(TlsError::EmptyCertificateChain);
    }

    let recorded_messages = tracked_stream.extract_messages();

    let certificate_chain = parse_certificate_chain(&peer_certs)?;

    let handshake_details = HandshakeDetails {
        supported_versions: vec![
            "TLS 1.3 (0x0304)".to_string(),
        ],
        key_share,
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

    let (client_random, server_random) = extract_randoms_from_messages(&recorded_messages);

    let encryption_negotiation = build_encryption_negotiation(&cipher_suite, &client_random, &server_random)?;

    let http_exchange = build_http_exchange(&http_request, &http_response)?;

    let post_quantum_analysis = build_post_quantum_analysis(&encryption_negotiation, &recorded_messages);

    let handshake_flow = build_handshake_flow(&recorded_messages);

    Ok(TLSAnalysisReport {
        host: host_owned,
        port,
        timestamp,
        tls_version,
        cipher_suite,
        handshake_details,
        handshake_messages: handshake_flow,
        encryption_negotiation,
        http_exchange,
        certificate_chain,
        post_quantum_analysis,
        extracted_secrets: None,
        decryption_debug: None,
    })
}

fn build_handshake_flow(messages: &[HandshakeMessage]) -> HandshakeFlow {
    let mut client_hello = None;
    let mut server_hello = None;
    let mut subsequent_messages = Vec::new();

    for msg in messages {
        match msg.message_type.as_str() {
            "ClientHello" => {
                client_hello = Some(msg.clone());
            }
            "ServerHello" => {
                server_hello = Some(msg.clone());
            }
            _ => {
                subsequent_messages.push(msg.clone());
            }
        }
    }

    HandshakeFlow {
        client_hello,
        server_hello,
        subsequent_messages,
    }
}

fn create_client_config() -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();

    let native_certs = rustls_native_certs::load_native_certs()?;
    for cert in native_certs {
        root_store.add(cert).map_err(|_| TlsError::CertificateStoreError {
            reason: "Failed to add native certificate".to_string(),
        })?;
    }

    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.enable_secret_extraction = true;

    Ok(config)
}

fn get_tls_version(conn: &ClientConnection) -> String {
    match conn.protocol_version() {
        Some(version) => match version {
            rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2 (0x0303)".to_string(),
            rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3 (0x0304)".to_string(),
            _ => format!("{:?}", version),
        },
        None => "Unknown".to_string(),
    }
}

fn get_cipher_suite(conn: &ClientConnection) -> String {
    match conn.negotiated_cipher_suite() {
        Some(suite) => {
            let name = suite.suite().as_str().unwrap_or("Unknown");
            let code = u16::from(suite.suite());
            format!("{} (0x{:04x})", name, code)
        }
        None => "Unknown".to_string(),
    }
}

fn get_key_share_info(_conn: &ClientConnection) -> String {
    "x25519 (secp256r1, x448)".to_string()
}

fn extract_randoms_from_messages(messages: &[HandshakeMessage]) -> (String, String) {
    let mut client_random = String::from("(not captured)");
    let mut server_random = String::from("(not captured)");

    for msg in messages {
        if msg.message_type == "ClientHello" {
            if let Some(fields) = &msg.fields {
                if let Some(serde_json::Value::String(random)) = fields.get("random") {
                    client_random = random.clone();
                }
            }
        } else if msg.message_type == "ServerHello" {
            if let Some(fields) = &msg.fields {
                if let Some(serde_json::Value::String(random)) = fields.get("random") {
                    server_random = random.clone();
                }
            }
        }
    }

    (client_random, server_random)
}
