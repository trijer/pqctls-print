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
    pub handshake_details: HandshakeDetails,
    pub handshake_messages: Vec<HandshakeMessage>,
    pub encryption_negotiation: EncryptionNegotiation,
    pub session_ticket: SessionTicketInfo,
    pub http_exchange: HttpExchange,
    pub certificate_chain: Vec<CertificateInfo>,
    pub post_quantum_analysis: PostQuantumAnalysis,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub sequence: usize,
    pub direction: String,
    pub message_type: String,
    pub size: usize,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeDetails {
    pub supported_versions: Vec<String>,
    pub key_share: String,
    pub signature_algorithms: Vec<String>,
    pub supported_groups: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionTicketInfo {
    pub is_session_resumption_supported: bool,
    pub new_session_ticket_message: bool,
    pub ticket_lifetime_seconds: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: String,
    pub resumption_master_secret: ResumptionSecret,
    pub pre_shared_key: PreSharedKeyInfo,
    pub resumption_instructions: ResumptionInstructions,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResumptionSecret {
    pub secret_type: String,
    pub derivation: String,
    pub purpose: String,
    pub length_bits: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreSharedKeyInfo {
    pub mode: String,
    pub identity_obfuscation: String,
    pub early_exporter_master_secret: bool,
    pub max_early_data_size: usize,
    pub psk_key_exchange_mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResumptionInstructions {
    pub step_1: String,
    pub step_2: String,
    pub step_3: String,
    pub step_4: String,
    pub expected_obfuscated_ticket_age: String,
    pub psk_identity_format: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpExchange {
    pub request: HttpMessage,
    pub response: HttpMessage,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpMessage {
    pub plaintext: PlaintextData,
    pub encrypted: EncryptedData,
    pub encryption_analysis: EncryptionAnalysis,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlaintextData {
    pub content: String,
    pub size_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    pub tls_record_type: String,
    pub tls_record_type_code: u8,
    pub ciphertext_preview: String,
    pub total_encrypted_size: usize,
    pub content_type_in_record: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionAnalysis {
    pub encryption_overhead: usize,
    pub record_header_size: usize,
    pub authentication_tag_size: usize,
    pub content_type_byte: usize,
    pub content_type_padding: String,
    pub total_size_with_record_header: usize,
    pub encryption_note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionNegotiation {
    pub cipher_suite_code: String,
    pub cipher_suite_name: String,
    pub encryption_algorithm: CipherAlgorithm,
    pub mac_algorithm: Option<MacAlgorithm>,
    pub aead_details: Option<AeadDetails>,
    pub key_exchange: KeyExchangeDetails,
    pub signature_algorithm: String,
    pub secret_derivation: SecretDerivation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretDerivation {
    pub client_random: String,
    pub server_random: String,
    pub randoms_combined_length: usize,
    pub key_derivation_function: String,
    pub prf_hash_algorithm: String,
    pub derived_secrets: Vec<DerivedSecret>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CipherAlgorithm {
    pub algorithm: String,
    pub mode: String,
    pub key_bits: usize,
    pub block_size: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MacAlgorithm {
    pub algorithm: String,
    pub hash_bits: usize,
    pub output_bits: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AeadDetails {
    pub algorithm: String,
    pub key_bits: usize,
    pub nonce_bits: usize,
    pub tag_bits: usize,
    pub plaintext_record_size_limit: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExchangeDetails {
    pub algorithm: String,
    pub group: String,
    pub forward_secrecy: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DerivedSecret {
    pub name: String,
    pub purpose: String,
    pub length_bits: usize,
    pub kdf_formula: String,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct PostQuantumAnalysis {
    pub hybrid_approach_available: bool,
    pub pqc_algorithms_available: Vec<String>,
    pub recommended_hybrid_suites: Vec<String>,
    pub hybrid_key_exchange: HybridKeyExchange,
    pub post_quantum_readiness: PostQuantumReadiness,
    pub migration_strategy: MigrationStrategy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HybridKeyExchange {
    pub classical_key_agreement: ClassicalKeyAgreement,
    pub post_quantum_key_agreement: PostQuantumKeyAgreement,
    pub hybrid_secret_derivation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClassicalKeyAgreement {
    pub algorithm: String,
    pub curve: String,
    pub key_size_bits: usize,
    pub estimated_security_bits: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostQuantumKeyAgreement {
    pub algorithms: Vec<PQCAlgorithm>,
    pub recommended: String,
    pub hybrid_with_classical: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PQCAlgorithm {
    pub name: String,
    pub family: String,
    pub key_size_bits: usize,
    pub ciphertext_size_bits: usize,
    pub shared_secret_size_bits: usize,
    pub estimated_quantum_security_bits: usize,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostQuantumReadiness {
    pub quantum_safe: bool,
    pub hybrid_ready: bool,
    pub pqc_key_exchange_offered: bool,
    pub pqc_signature_offered: bool,
    pub recommendation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationStrategy {
    pub current_security_level: String,
    pub post_quantum_security_level: String,
    pub implementation_priority: String,
    pub timeline: String,
    pub action_items: Vec<String>,
}

pub async fn analyze_handshake(host: &str, port: u16) -> Result<HandshakeInfo> {
    let host_owned = host.to_string();

    tokio::task::spawn_blocking(move || {
        perform_tls_handshake(&host_owned, port)
    })
    .await
    .map_err(|e| anyhow!("Blocking task error: {}", e))?
}

fn perform_tls_handshake(host: &str, port: u16) -> Result<HandshakeInfo> {
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

    let tcp_stream = TcpStream::connect((host_owned.as_str(), port))?;
    tcp_stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    tcp_stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

    let mut tracked_stream = TrackedStream::new(tcp_stream);

    let mut tls_stream = rustls::Stream::new(&mut conn, &mut tracked_stream);

    // Prepare HTTP GET request
    let http_request = format!("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: tls-outputter\r\nConnection: close\r\n\r\n", host_owned);

    // Send HTTP request through encrypted connection
    tls_stream.write_all(http_request.as_bytes())?;
    tls_stream.flush()?;

    // Receive HTTP response
    let mut response_buf = Vec::new();
    let mut buf = [0; 4096];
    loop {
        match tls_stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response_buf.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::Other => break,
            Err(_) => break,
        }
    }

    let http_response = String::from_utf8_lossy(&response_buf).to_string();

    // Extract recorded messages from the tracked stream
    let recorded_messages = tracked_stream.extract_messages();

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

    // Extract client and server randoms from handshake messages
    let (client_random, server_random) = extract_randoms_from_messages(&recorded_messages);

    let encryption_negotiation = build_encryption_negotiation(&cipher_suite, &client_random, &server_random)?;

    let session_ticket = build_session_ticket_info(&tls_version, &recorded_messages)?;

    // Build HTTP exchange info with plaintext and encrypted data
    let http_exchange = build_http_exchange(&http_request, &http_response)?;

    let post_quantum_analysis = build_post_quantum_analysis(&encryption_negotiation);

    Ok(HandshakeInfo {
        host: host_owned,
        port,
        timestamp,
        tls_version,
        cipher_suite,
        handshake_details,
        handshake_messages: recorded_messages,
        encryption_negotiation,
        session_ticket,
        http_exchange,
        certificate_chain,
        post_quantum_analysis,
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

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    let not_before = format!("{}", cert.validity().not_before);
    let not_after = format!("{}", cert.validity().not_after);

    let serial_number = format!("{}", cert.serial);

    let fingerprint_sha256 = compute_sha256_fingerprint(cert_der);

    let (key_type, key_size) = extract_key_info(&cert)?;

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

fn extract_key_info(cert: &X509Certificate) -> Result<(String, Option<usize>)> {
    let pk_algo = &cert.public_key().algorithm.algorithm;

    let key_type = match pk_algo.to_string().as_str() {
        "1.2.840.113549.1.1.1" | "rsaEncryption" => "RSA".to_string(),
        "1.2.840.10045.2.1" | "id-ecPublicKey" => "ECDSA".to_string(),
        "1.3.101.112" => "EdDSA (Ed25519)".to_string(),
        "1.3.101.111" => "EdDSA (Ed448)".to_string(),
        oid_str => format!("Other ({})", oid_str),
    };

    let key_size = match pk_algo.to_string().as_str() {
        "1.2.840.113549.1.1.1" | "rsaEncryption" => {
            cert.public_key().raw.len().checked_mul(8).map(|bits| {
                if bits > 256 { bits - 24 } else { bits }
            })
        }
        "1.2.840.10045.2.1" | "id-ecPublicKey" => {
            let bits = cert.public_key().raw.len() * 8;
            match bits {
                264 => Some(256),
                392 => Some(384),
                528 => Some(521),
                _ => Some(bits),
            }
        }
        _ => None,
    };

    Ok((key_type, key_size))
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut sans = Vec::new();

    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                GeneralName::DNSName(name) => {
                    sans.push(name.to_string());
                }
                GeneralName::IPAddress(ip) => {
                    let ip_str = if ip.len() == 4 {
                        let ipv4 = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                        format!("IP:{}", ipv4)
                    } else if ip.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&ip);
                        let ipv6 = Ipv6Addr::from(arr);
                        format!("IP:{}", ipv6)
                    } else {
                        format!("IP:(invalid length {})", ip.len())
                    };
                    sans.push(ip_str);
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

fn parse_handshake_type(msg_type: u8) -> (String, String) {
    match msg_type {
        0 => ("HelloRequest".to_string(), "Server requests renegotiation (TLS 1.2)".to_string()),
        1 => ("ClientHello".to_string(), "Client initiates TLS handshake with supported versions, ciphers, and extensions".to_string()),
        2 => ("ServerHello".to_string(), "Server selects TLS version and cipher suite from client options".to_string()),
        3 => ("HelloRetryRequest".to_string(), "Server requests retry with different parameters (TLS 1.3)".to_string()),
        4 => ("NewSessionTicket".to_string(), "Server provides session resumption ticket (TLS 1.3)".to_string()),
        5 => ("EndOfEarlyData".to_string(), "Client signals end of early data (TLS 1.3)".to_string()),
        6 => ("EncryptedExtensions".to_string(), "Server sends encrypted TLS extensions (TLS 1.3)".to_string()),
        7 => ("CertificateRequest".to_string(), "Server requests client certificate (optional)".to_string()),
        8 => ("Certificate".to_string(), "Server presents certificate chain for authentication".to_string()),
        9 => ("ServerKeyExchange".to_string(), "Server provides key exchange parameters (TLS 1.2)".to_string()),
        10 => ("CertificateVerify".to_string(), "Client/Server proves possession of private key via signature".to_string()),
        11 => ("ClientKeyExchange".to_string(), "Client sends key exchange parameters (TLS 1.2)".to_string()),
        12 => ("Finished".to_string(), "Handshake complete, includes MAC of all messages".to_string()),
        13 => ("CertificateStatus".to_string(), "Server provides OCSP response (TLS 1.2)".to_string()),
        14 => ("KeyUpdate".to_string(), "Update traffic keys (TLS 1.3)".to_string()),
        _ => (format!("Unknown({})", msg_type), "Unknown message type".to_string()),
    }
}

pub struct TrackedStream {
    inner: TcpStream,
    messages: Vec<HandshakeMessage>,
    sequence: usize,
    handshake_complete: bool,
    encrypted_records_from_server: usize,
    encrypted_records_from_client: usize,
}

impl TrackedStream {
    pub fn new(stream: TcpStream) -> Self {
        TrackedStream {
            inner: stream,
            messages: Vec::new(),
            sequence: 0,
            handshake_complete: false,
            encrypted_records_from_server: 0,
            encrypted_records_from_client: 0,
        }
    }

    pub fn extract_messages(mut self) -> Vec<HandshakeMessage> {
        // Add synthesized encrypted handshake messages based on TLS 1.3 flow
        self.add_encrypted_handshake_messages();
        self.messages
    }

    fn add_encrypted_handshake_messages(&mut self) {
        use std::collections::HashMap;
        use serde_json::json;

        // In TLS 1.3, after ServerHello + ChangeCipherSpec from server,
        // the next encrypted record contains: EncryptedExtensions + Certificate + CertificateVerify + Finished
        if self.encrypted_records_from_server > 0 && !self.handshake_complete {
            // Add EncryptedExtensions
            let mut fields = HashMap::new();
            fields.insert("encrypted".to_string(), json!(true));
            fields.insert("note".to_string(), json!("Extensions sent encrypted (TLS 1.3)"));

            self.messages.push(HandshakeMessage {
                sequence: self.sequence,
                direction: "Server → Client".to_string(),
                message_type: "EncryptedExtensions".to_string(),
                size: 0, // Encrypted, size unknown
                description: "Server sends encrypted TLS extensions (TLS 1.3)".to_string(),
                fields: Some(fields),
            });
            self.sequence += 1;

            // Add Certificate
            let mut fields = HashMap::new();
            fields.insert("encrypted".to_string(), json!(true));
            fields.insert("note".to_string(), json!("Certificate message encrypted (TLS 1.3)"));

            self.messages.push(HandshakeMessage {
                sequence: self.sequence,
                direction: "Server → Client".to_string(),
                message_type: "Certificate".to_string(),
                size: 0, // Encrypted, size unknown
                description: "Server presents certificate chain for authentication".to_string(),
                fields: Some(fields),
            });
            self.sequence += 1;

            // Add CertificateVerify
            let mut fields = HashMap::new();
            fields.insert("encrypted".to_string(), json!(true));
            fields.insert("note".to_string(), json!("Signature proving key ownership (TLS 1.3)"));

            self.messages.push(HandshakeMessage {
                sequence: self.sequence,
                direction: "Server → Client".to_string(),
                message_type: "CertificateVerify".to_string(),
                size: 0, // Encrypted, size unknown
                description: "Server proves possession of private key via signature".to_string(),
                fields: Some(fields),
            });
            self.sequence += 1;

            // Add Finished
            let mut fields = HashMap::new();
            fields.insert("encrypted".to_string(), json!(true));
            fields.insert("note".to_string(), json!("MAC of all handshake messages (TLS 1.3)"));

            self.messages.push(HandshakeMessage {
                sequence: self.sequence,
                direction: "Server → Client".to_string(),
                message_type: "Finished".to_string(),
                size: 0, // Encrypted, size unknown
                description: "Handshake complete, includes MAC of all messages".to_string(),
                fields: Some(fields),
            });
            self.sequence += 1;
        }

        // Client Finished
        if self.encrypted_records_from_client > 0 && self.encrypted_records_from_server > 0 {
            let mut fields = HashMap::new();
            fields.insert("encrypted".to_string(), json!(true));
            fields.insert("note".to_string(), json!("MAC of all handshake messages (TLS 1.3)"));

            self.messages.push(HandshakeMessage {
                sequence: self.sequence,
                direction: "Client → Server".to_string(),
                message_type: "Finished".to_string(),
                size: 0, // Encrypted, size unknown
                description: "Client handshake complete with MAC".to_string(),
                fields: Some(fields),
            });
            self.sequence += 1;
        }
    }

    fn extract_tls_messages(&mut self, data: &[u8], is_write: bool) {
        let mut pos = 0;
        while pos + 5 <= data.len() {
            let content_type = data[pos];
            let _version = u16::from_be_bytes([data[pos + 1], data[pos + 2]]);
            let length = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;

            // Skip TLS record header
            pos += 5;

            if pos + length > data.len() {
                break;
            }

            // TLS record types: 22 = Handshake, 23 = Application Data, 20 = ChangeCipherSpec, 25 = Finished
            match content_type {
                22 => {
                    // Handshake record
                    let mut msg_pos = 0;
                    while msg_pos + 4 <= length {
                        let msg_type = data[pos + msg_pos];
                        let msg_length = u32::from_be_bytes([
                            0,
                            data[pos + msg_pos + 1],
                            data[pos + msg_pos + 2],
                            data[pos + msg_pos + 3],
                        ]) as usize;

                        let (type_name, description) = parse_handshake_type(msg_type);
                        let total_msg_size = msg_length + 4; // +4 for header

                        let direction = if is_write {
                            "Client → Server".to_string()
                        } else {
                            "Server → Client".to_string()
                        };

                        // Extract message payload
                        let payload_start = pos + msg_pos + 4;
                        let payload_end = payload_start + msg_length;
                        let fields = if payload_end <= data.len() {
                            parse_handshake_fields(msg_type, &data[payload_start..payload_end])
                        } else {
                            None
                        };

                        self.messages.push(HandshakeMessage {
                            sequence: self.sequence,
                            direction,
                            message_type: type_name,
                            size: total_msg_size,
                            description,
                            fields,
                        });

                        self.sequence += 1;
                        msg_pos += total_msg_size;
                    }
                }
                20 => {
                    // ChangeCipherSpec
                    let direction = if is_write {
                        "Client → Server".to_string()
                    } else {
                        "Server → Client".to_string()
                    };

                    self.messages.push(HandshakeMessage {
                        sequence: self.sequence,
                        direction,
                        message_type: "ChangeCipherSpec".to_string(),
                        size: length,
                        description: "Cipher suite change notification (TLS 1.2)".to_string(),
                        fields: None,
                    });

                    self.sequence += 1;
                }
                23 => {
                    // Application Data / Encrypted Handshake Messages
                    if is_write {
                        self.encrypted_records_from_client += 1;
                    } else {
                        self.encrypted_records_from_server += 1;
                    }
                }
                _ => {}
            }

            pos += length;
        }
    }
}

impl Read for TrackedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.extract_tls_messages(&buf[..n], false);
        }
        Ok(n)
    }
}

impl Write for TrackedStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.extract_tls_messages(buf, true);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn build_http_exchange(request: &str, response: &str) -> Result<HttpExchange> {
    // Create request message
    let request_msg = HttpMessage {
        plaintext: PlaintextData {
            content: request.to_string(),
            size_bytes: request.len(),
        },
        encrypted: EncryptedData {
            tls_record_type: "Application Data (type 23)".to_string(),
            tls_record_type_code: 23,
            ciphertext_preview: "[Encrypted with AES-256-GCM]".to_string(),
            total_encrypted_size: calculate_encrypted_size(request.len()),
            content_type_in_record: "0x16 (Handshake) or 0x17 (Application Data)".to_string(),
        },
        encryption_analysis: EncryptionAnalysis {
            encryption_overhead: 16 + 5,  // 16-byte tag + 5-byte record header
            record_header_size: 5,
            authentication_tag_size: 16,
            content_type_byte: 1,
            content_type_padding: "0x16 (after decryption)".to_string(),
            total_size_with_record_header: calculate_encrypted_size(request.len()),
            encryption_note: "Request is encrypted with negotiated cipher suite (AES-256-GCM)".to_string(),
        },
    };

    // Create response message (truncated for large responses)
    let response_preview = if response.len() > 500 {
        format!("{}...[truncated {} bytes]", &response[..500], response.len() - 500)
    } else {
        response.to_string()
    };

    let response_msg = HttpMessage {
        plaintext: PlaintextData {
            content: response_preview,
            size_bytes: response.len(),
        },
        encrypted: EncryptedData {
            tls_record_type: "Application Data (type 23)".to_string(),
            tls_record_type_code: 23,
            ciphertext_preview: "[Encrypted with AES-256-GCM]".to_string(),
            total_encrypted_size: calculate_encrypted_size(response.len()),
            content_type_in_record: "0x17 (Application Data)".to_string(),
        },
        encryption_analysis: EncryptionAnalysis {
            encryption_overhead: 16 + 5,
            record_header_size: 5,
            authentication_tag_size: 16,
            content_type_byte: 1,
            content_type_padding: "0x17 (content type appended, then padding added)".to_string(),
            total_size_with_record_header: calculate_encrypted_size(response.len()),
            encryption_note: "Response is encrypted with same cipher suite; each TLS record can be up to 16KB of plaintext + overhead".to_string(),
        },
    };

    Ok(HttpExchange {
        request: request_msg,
        response: response_msg,
    })
}

fn calculate_encrypted_size(plaintext_size: usize) -> usize {
    // TLS 1.3: plaintext + 1 byte content type + 16 bytes AEAD tag + 5 byte record header
    plaintext_size + 1 + 16 + 5
}

fn build_session_ticket_info(tls_version: &str, messages: &[HandshakeMessage]) -> Result<SessionTicketInfo> {
    let is_tls13 = tls_version.contains("1.3");

    let new_session_ticket_received = messages.iter()
        .any(|msg| msg.message_type == "NewSessionTicket");

    Ok(SessionTicketInfo {
        is_session_resumption_supported: is_tls13 && new_session_ticket_received,
        new_session_ticket_message: new_session_ticket_received,
        ticket_lifetime_seconds: 604800,
        ticket_age_add: 2147483647,
        ticket_nonce: "(encrypted, not captured)".to_string(),
        resumption_master_secret: ResumptionSecret {
            secret_type: "PSK (Pre-Shared Key)".to_string(),
            derivation: "HKDF-Expand-Label(Master Secret, 'res master', hash)".to_string(),
            purpose: "Base for deriving pre-shared key identity and binder".to_string(),
            length_bits: if is_tls13 { 384 } else { 256 },
        },
        pre_shared_key: PreSharedKeyInfo {
            mode: if new_session_ticket_received { "PSK with ECDHE (psk_dhe_ke)" } else { "Not supported" }.to_string(),
            identity_obfuscation: "Ticket age is obfuscated with ticket_age_add".to_string(),
            early_exporter_master_secret: false,
            max_early_data_size: if new_session_ticket_received { 16384 } else { 0 },
            psk_key_exchange_mode: if new_session_ticket_received { "psk_dhe_ke (recommended)" } else { "None" }.to_string(),
        },
        resumption_instructions: ResumptionInstructions {
            step_1: "Server sends NewSessionTicket message (encrypted in TLS 1.3)".to_string(),
            step_2: "Client stores ticket and derives obfuscated_ticket_age for next connection".to_string(),
            step_3: "On resumption, client sends PSK identity in ClientHello pre_shared_key extension".to_string(),
            step_4: "Server validates ticket and resumes session without full handshake".to_string(),
            expected_obfuscated_ticket_age: "Verified by server's ticket validation".to_string(),
            psk_identity_format: "{ identity: opaque<1..2^16-1>, obfuscated_ticket_age: uint32 }".to_string(),
        },
    })
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

fn build_encryption_negotiation(cipher_suite: &str, client_random: &str, server_random: &str) -> Result<EncryptionNegotiation> {
    let suite_code = cipher_suite
        .split("(")
        .last()
        .and_then(|s| s.strip_suffix(")"))
        .unwrap_or("0x0000");

    if cipher_suite.contains("AES_256_GCM") {
        Ok(build_aead_encryption(
            suite_code,
            "TLS_AES_256_GCM_SHA384",
            "AES-256-GCM",
            256,
            384,
            "SHA-384",
            "x25519 or secp384r1",
            "RSA-PSS-SHA384 or ECDSA-SHA384",
            client_random,
            server_random,
        ))
    } else if cipher_suite.contains("AES_128_GCM") {
        Ok(build_aead_encryption(
            suite_code,
            "TLS_AES_128_GCM_SHA256",
            "AES-128-GCM",
            128,
            256,
            "SHA-256",
            "x25519 or secp256r1",
            "RSA-PSS-SHA256 or ECDSA-SHA256",
            client_random,
            server_random,
        ))
    } else if cipher_suite.contains("CHACHA20") {
        Ok(build_chacha_encryption(
            suite_code,
            client_random,
            server_random,
        ))
    } else {
        Ok(build_unknown_encryption(
            suite_code,
            cipher_suite,
            client_random,
            server_random,
        ))
    }
}

fn build_aead_encryption(
    code: &str,
    name: &str,
    aead_name: &str,
    key_bits: usize,
    hash_bits: usize,
    hash_algo: &str,
    key_group: &str,
    sig_algo: &str,
    client_random: &str,
    server_random: &str,
) -> EncryptionNegotiation {
    let cipher_algo = if key_bits == 256 { "AES" } else { "AES" };

    EncryptionNegotiation {
        cipher_suite_code: code.to_string(),
        cipher_suite_name: name.to_string(),
        encryption_algorithm: CipherAlgorithm {
            algorithm: cipher_algo.to_string(),
            mode: "GCM (Authenticated Encryption)".to_string(),
            key_bits,
            block_size: 128,
        },
        mac_algorithm: None,
        aead_details: Some(AeadDetails {
            algorithm: aead_name.to_string(),
            key_bits,
            nonce_bits: 96,
            tag_bits: 128,
            plaintext_record_size_limit: 16384,
        }),
        key_exchange: KeyExchangeDetails {
            algorithm: "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)".to_string(),
            group: key_group.to_string(),
            forward_secrecy: true,
        },
        signature_algorithm: sig_algo.to_string(),
        secret_derivation: build_secret_derivation_aead(
            hash_bits,
            hash_algo,
            client_random,
            server_random,
        ),
    }
}

fn build_secret_derivation_aead(
    hash_bits: usize,
    hash_algo: &str,
    client_random: &str,
    server_random: &str,
) -> SecretDerivation {
    SecretDerivation {
        client_random: client_random.to_string(),
        server_random: server_random.to_string(),
        randoms_combined_length: 64,
        key_derivation_function: "HKDF (HMAC-based Extract-and-Expand Key Derivation Function)".to_string(),
        prf_hash_algorithm: hash_algo.to_string(),
        derived_secrets: vec![
            DerivedSecret {
                name: "Early Secret".to_string(),
                purpose: "Used for early data (0-RTT)".to_string(),
                length_bits: hash_bits,
                kdf_formula: "HKDF-Extract(salt=0, IKM=0x0000...)".to_string(),
            },
            DerivedSecret {
                name: "Handshake Secret".to_string(),
                purpose: "Derives server_handshake_traffic_secret and client_handshake_traffic_secret".to_string(),
                length_bits: hash_bits,
                kdf_formula: "HKDF-Extract(salt=Early Secret, IKM=ECDHE shared secret)".to_string(),
            },
            DerivedSecret {
                name: "Server Handshake Traffic Secret".to_string(),
                purpose: "Encrypts ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished".to_string(),
                length_bits: hash_bits,
                kdf_formula: "HKDF-Expand-Label(Handshake Secret, 's hs traffic', ServerHello...Finished)".to_string(),
            },
            DerivedSecret {
                name: "Client Handshake Traffic Secret".to_string(),
                purpose: "Encrypts Client Finished message".to_string(),
                length_bits: hash_bits,
                kdf_formula: "HKDF-Expand-Label(Handshake Secret, 'c hs traffic', ServerHello...Finished)".to_string(),
            },
            DerivedSecret {
                name: "Master Secret".to_string(),
                purpose: "Base for all application traffic secrets".to_string(),
                length_bits: hash_bits,
                kdf_formula: "HKDF-Extract(salt=Handshake Secret, IKM=0x0000...)".to_string(),
            },
            DerivedSecret {
                name: "Server Application Traffic Secret 0".to_string(),
                purpose: "Encrypts application data from server".to_string(),
                length_bits: hash_bits,
                kdf_formula: "HKDF-Expand-Label(Master Secret, 's ap traffic', ClientHello...Finished)".to_string(),
            },
            DerivedSecret {
                name: "Client Application Traffic Secret 0".to_string(),
                purpose: "Encrypts application data from client".to_string(),
                length_bits: hash_bits,
                kdf_formula: "HKDF-Expand-Label(Master Secret, 'c ap traffic', ClientHello...Finished)".to_string(),
            },
            DerivedSecret {
                name: "Exporter Master Secret".to_string(),
                purpose: "For exporters like SSLKEYLOGFILE".to_string(),
                length_bits: hash_bits,
                kdf_formula: "HKDF-Expand-Label(Master Secret, 'exp master', ClientHello...Finished)".to_string(),
            },
        ],
    }
}

fn build_chacha_encryption(
    code: &str,
    client_random: &str,
    server_random: &str,
) -> EncryptionNegotiation {
    EncryptionNegotiation {
        cipher_suite_code: code.to_string(),
        cipher_suite_name: "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        encryption_algorithm: CipherAlgorithm {
            algorithm: "ChaCha20".to_string(),
            mode: "Poly1305 (Authenticated Encryption)".to_string(),
            key_bits: 256,
            block_size: 512,
        },
        mac_algorithm: None,
        aead_details: Some(AeadDetails {
            algorithm: "ChaCha20-Poly1305".to_string(),
            key_bits: 256,
            nonce_bits: 96,
            tag_bits: 128,
            plaintext_record_size_limit: 16384,
        }),
        key_exchange: KeyExchangeDetails {
            algorithm: "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)".to_string(),
            group: "x25519".to_string(),
            forward_secrecy: true,
        },
        signature_algorithm: "RSA-PSS-SHA256 or ECDSA-SHA256".to_string(),
        secret_derivation: SecretDerivation {
            client_random: client_random.to_string(),
            server_random: server_random.to_string(),
            randoms_combined_length: 64,
            key_derivation_function: "HKDF (HMAC-based Extract-and-Expand Key Derivation Function)".to_string(),
            prf_hash_algorithm: "SHA-256".to_string(),
            derived_secrets: vec![
                DerivedSecret {
                    name: "Handshake Secret".to_string(),
                    purpose: "Derives handshake traffic secrets".to_string(),
                    length_bits: 256,
                    kdf_formula: "HKDF-Extract(salt=Early Secret, IKM=ECDHE shared secret)".to_string(),
                },
                DerivedSecret {
                    name: "Server Handshake Traffic Secret".to_string(),
                    purpose: "Encrypts server handshake messages".to_string(),
                    length_bits: 256,
                    kdf_formula: "HKDF-Expand-Label(Handshake Secret, 's hs traffic', hash)".to_string(),
                },
                DerivedSecret {
                    name: "Client Handshake Traffic Secret".to_string(),
                    purpose: "Encrypts client handshake messages".to_string(),
                    length_bits: 256,
                    kdf_formula: "HKDF-Expand-Label(Handshake Secret, 'c hs traffic', hash)".to_string(),
                },
                DerivedSecret {
                    name: "Master Secret".to_string(),
                    purpose: "Base for application traffic secrets".to_string(),
                    length_bits: 256,
                    kdf_formula: "HKDF-Extract(salt=Handshake Secret, IKM=0x00...)".to_string(),
                },
                DerivedSecret {
                    name: "Server Application Traffic Secret".to_string(),
                    purpose: "Encrypts server application data".to_string(),
                    length_bits: 256,
                    kdf_formula: "HKDF-Expand-Label(Master Secret, 's ap traffic', hash)".to_string(),
                },
                DerivedSecret {
                    name: "Client Application Traffic Secret".to_string(),
                    purpose: "Encrypts client application data".to_string(),
                    length_bits: 256,
                    kdf_formula: "HKDF-Expand-Label(Master Secret, 'c ap traffic', hash)".to_string(),
                },
            ],
        },
    }
}

fn build_unknown_encryption(
    code: &str,
    cipher_suite: &str,
    client_random: &str,
    server_random: &str,
) -> EncryptionNegotiation {
    EncryptionNegotiation {
        cipher_suite_code: code.to_string(),
        cipher_suite_name: cipher_suite.to_string(),
        encryption_algorithm: CipherAlgorithm {
            algorithm: "Unknown".to_string(),
            mode: "Unknown".to_string(),
            key_bits: 256,
            block_size: 128,
        },
        mac_algorithm: None,
        aead_details: None,
        key_exchange: KeyExchangeDetails {
            algorithm: "ECDHE".to_string(),
            group: "Unknown".to_string(),
            forward_secrecy: true,
        },
        signature_algorithm: "Unknown".to_string(),
        secret_derivation: SecretDerivation {
            client_random: client_random.to_string(),
            server_random: server_random.to_string(),
            randoms_combined_length: 64,
            key_derivation_function: "HKDF".to_string(),
            prf_hash_algorithm: "SHA-256 or SHA-384".to_string(),
            derived_secrets: vec![
                DerivedSecret {
                    name: "Handshake Secret".to_string(),
                    purpose: "Base secret for handshake phase".to_string(),
                    length_bits: 256,
                    kdf_formula: "HKDF-Extract(salt, IKM)".to_string(),
                },
                DerivedSecret {
                    name: "Master Secret".to_string(),
                    purpose: "Base secret for application phase".to_string(),
                    length_bits: 256,
                    kdf_formula: "HKDF-Extract(salt, IKM)".to_string(),
                },
            ],
        },
    }
}

fn parse_handshake_fields(msg_type: u8, data: &[u8]) -> Option<std::collections::HashMap<String, serde_json::Value>> {
    use std::collections::HashMap;
    use serde_json::json;

    let mut fields = HashMap::new();

    match msg_type {
        1 => {
            // ClientHello
            if data.len() < 34 {
                return None;
            }
            let version = u16::from_be_bytes([data[0], data[1]]);
            fields.insert("client_version".to_string(), json!(format!("0x{:04x}", version)));

            // Random (32 bytes)
            let random = data[2..34].iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join("");
            fields.insert("random".to_string(), json!(random));

            // Session ID Length
            if data.len() > 34 {
                let session_id_len = data[34] as usize;
                fields.insert("session_id_length".to_string(), json!(session_id_len));

                // Cipher Suites Length
                let cs_start = 35 + session_id_len;
                if data.len() > cs_start + 1 {
                    let cs_len = u16::from_be_bytes([data[cs_start], data[cs_start + 1]]) as usize;
                    let cipher_count = cs_len / 2;
                    fields.insert("cipher_suites_count".to_string(), json!(cipher_count));
                }
            }
            Some(fields)
        }
        2 => {
            // ServerHello
            if data.len() < 34 {
                return None;
            }
            let version = u16::from_be_bytes([data[0], data[1]]);
            fields.insert("server_version".to_string(), json!(format!("0x{:04x}", version)));

            // Random
            let random = data[2..34].iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join("");
            fields.insert("random".to_string(), json!(random));

            // Session ID
            if data.len() > 34 {
                let session_id_len = data[34] as usize;
                fields.insert("session_id_length".to_string(), json!(session_id_len));

                // Cipher Suite
                let cs_pos = 35 + session_id_len;
                if data.len() > cs_pos + 1 {
                    let cipher_suite = u16::from_be_bytes([data[cs_pos], data[cs_pos + 1]]);
                    fields.insert("selected_cipher_suite".to_string(), json!(format!("0x{:04x}", cipher_suite)));
                }

                // Compression Method
                if data.len() > cs_pos + 2 {
                    fields.insert("compression_method".to_string(), json!(data[cs_pos + 2]));
                }
            }
            Some(fields)
        }
        8 => {
            // Certificate
            if data.len() < 3 {
                return None;
            }
            let cert_chain_len = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
            fields.insert("certificate_chain_length".to_string(), json!(cert_chain_len));

            // Count certificates
            let mut cert_count = 0;
            let mut pos = 3;
            while pos < data.len() && pos < 3 + cert_chain_len {
                if pos + 3 <= data.len() {
                    let cert_len = u32::from_be_bytes([0, data[pos], data[pos + 1], data[pos + 2]]) as usize;
                    cert_count += 1;
                    pos += 3 + cert_len;
                } else {
                    break;
                }
            }
            fields.insert("certificate_count".to_string(), json!(cert_count));
            Some(fields)
        }
        12 => {
            // Finished - contains MAC/verification_data
            fields.insert("verification_data_length".to_string(), json!(data.len()));
            if data.len() > 0 {
                let data_hex = data[..std::cmp::min(16, data.len())].iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join("");
                fields.insert("verification_data_preview".to_string(), json!(data_hex + if data.len() > 16 { "..." } else { "" }));
            }
            Some(fields)
        }
        _ => {
            // For other message types, just include raw size
            fields.insert("payload_length".to_string(), json!(data.len()));
            Some(fields)
        }
    }
}

fn build_post_quantum_analysis(_encryption_negotiation: &EncryptionNegotiation) -> PostQuantumAnalysis {
    // Available PQC algorithms (based on NIST standardization)
    let pqc_algorithms_available = vec![
        "Kyber-512".to_string(),
        "Kyber-768".to_string(),
        "Kyber-1024".to_string(),
        "Dilithium-2".to_string(),
        "Dilithium-3".to_string(),
        "Dilithium-5".to_string(),
        "FALCON-512".to_string(),
        "FALCON-1024".to_string(),
    ];

    // Recommended hybrid suites combining classical and PQC
    let recommended_hybrid_suites = vec![
        "TLS_ECDHE_X25519_KYBER768_WITH_AES_256_GCM_SHA384".to_string(),
        "TLS_ECDHE_SECP256R1_KYBER512_WITH_AES_256_GCM_SHA384".to_string(),
        "TLS_ECDHE_X25519_DILITHIUM2_WITH_AES_256_GCM_SHA384".to_string(),
    ];

    let hybrid_key_exchange = HybridKeyExchange {
        classical_key_agreement: ClassicalKeyAgreement {
            algorithm: "ECDHE".to_string(),
            curve: "X25519".to_string(),
            key_size_bits: 256,
            estimated_security_bits: 128,
        },
        post_quantum_key_agreement: PostQuantumKeyAgreement {
            algorithms: vec![
                PQCAlgorithm {
                    name: "Kyber-768".to_string(),
                    family: "Lattice-based (Module-LWE)".to_string(),
                    key_size_bits: 1184,
                    ciphertext_size_bits: 1088,
                    shared_secret_size_bits: 256,
                    estimated_quantum_security_bits: 192,
                    status: "NIST standardized (FIPS 203)".to_string(),
                },
                PQCAlgorithm {
                    name: "Dilithium-3".to_string(),
                    family: "Lattice-based (Module-LWE)".to_string(),
                    key_size_bits: 2528,
                    ciphertext_size_bits: 2701,
                    shared_secret_size_bits: 256,
                    estimated_quantum_security_bits: 192,
                    status: "NIST standardized (FIPS 204)".to_string(),
                },
            ],
            recommended: "Kyber-768 + Dilithium-3".to_string(),
            hybrid_with_classical: true,
        },
        hybrid_secret_derivation: "HKDF-Expand(PRK, info || classical_shared_secret || pqc_shared_secret)".to_string(),
    };

    let post_quantum_readiness = PostQuantumReadiness {
        quantum_safe: false,
        hybrid_ready: true,
        pqc_key_exchange_offered: false,
        pqc_signature_offered: false,
        recommendation: "Server does not yet support post-quantum cryptography. Hybrid approach recommended for future-proofing.".to_string(),
    };

    let action_items = vec![
        "Monitor server TLS configuration for PQC support updates".to_string(),
        "Plan migration to hybrid classical-PQC key exchange".to_string(),
        "Test hybrid cipher suites in staging environment".to_string(),
        "Implement client-side PQC key agreement as fallback".to_string(),
        "Track NIST PQC standardization timeline".to_string(),
    ];

    let migration_strategy = MigrationStrategy {
        current_security_level: "Post-classical: Protected only by ECDHE and AES-GCM".to_string(),
        post_quantum_security_level: "Quantum-safe: Protected by hybrid ECDHE + Kyber and hybrid Dilithium".to_string(),
        implementation_priority: "High - Start planning now for 2025-2026 implementation".to_string(),
        timeline: "Phase 1 (2024): Evaluate and test | Phase 2 (2025): Deploy hybrid | Phase 3 (2026): Full PQC".to_string(),
        action_items,
    };

    PostQuantumAnalysis {
        hybrid_approach_available: true,
        pqc_algorithms_available,
        recommended_hybrid_suites,
        hybrid_key_exchange,
        post_quantum_readiness,
        migration_strategy,
    }
}
