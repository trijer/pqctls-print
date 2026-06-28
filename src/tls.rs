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
    pub handshake_messages: Vec<HandshakeMessage>,
    pub encryption_negotiation: EncryptionNegotiation,
    pub certificate_chain: Vec<CertificateInfo>,
    pub handshake_details: HandshakeDetails,
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

    let mut tracked_stream = TrackedStream::new(tcp_stream);

    let mut tls_stream = rustls::Stream::new(&mut conn, &mut tracked_stream);
    tls_stream.write_all(b"HEAD / HTTP/1.1\r\nHost: ")?;
    tls_stream.write_all(host_owned.as_bytes())?;
    tls_stream.write_all(b"\r\nConnection: close\r\n\r\n")?;
    tls_stream.flush()?;

    let mut buf = [0; 4096];
    let _n = tls_stream.read(&mut buf).ok();

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

    Ok(HandshakeInfo {
        host: host_owned,
        port,
        timestamp,
        tls_version,
        cipher_suite,
        handshake_messages: recorded_messages,
        encryption_negotiation,
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

fn parse_handshake_type(msg_type: u8) -> (String, String) {
    match msg_type {
        0 => ("HelloRequest".to_string(), "Server requests renegotiation".to_string()),
        1 => ("ClientHello".to_string(), "Client initiates TLS handshake with supported versions, ciphers, and extensions".to_string()),
        2 => ("ServerHello".to_string(), "Server selects TLS version and cipher suite from client options".to_string()),
        3 => ("NewSessionTicket".to_string(), "Server provides session resumption ticket (TLS 1.3)".to_string()),
        4 => ("EncryptedExtensions".to_string(), "Server sends encrypted TLS extensions (TLS 1.3)".to_string()),
        5 => ("Certificate".to_string(), "Server presents certificate chain for authentication".to_string()),
        6 => ("ServerKeyExchange".to_string(), "Server provides key exchange parameters (TLS 1.2)".to_string()),
        7 => ("CertificateRequest".to_string(), "Server requests client certificate (optional)".to_string()),
        8 => ("ServerHelloDone".to_string(), "Server signals end of handshake messages (TLS 1.2)".to_string()),
        9 => ("CertificateVerify".to_string(), "Client/Server proves possession of private key via signature".to_string()),
        10 => ("ClientKeyExchange".to_string(), "Client sends key exchange parameters (TLS 1.2)".to_string()),
        11 => ("Finished".to_string(), "Handshake complete, includes MAC of all messages".to_string()),
        12 => ("KeyUpdate".to_string(), "Update traffic keys (TLS 1.3)".to_string()),
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
    // Parse cipher suite to extract cryptographic details
    // Format: "SUITE_NAME (0xXXXX)"
    let suite_code = cipher_suite
        .split("(")
        .last()
        .and_then(|s| s.strip_suffix(")"))
        .unwrap_or("0x0000");

    // Determine cipher details based on suite name
    if cipher_suite.contains("AES_256_GCM") {
        Ok(EncryptionNegotiation {
            cipher_suite_code: suite_code.to_string(),
            cipher_suite_name: "TLS_AES_256_GCM_SHA384".to_string(),
            encryption_algorithm: CipherAlgorithm {
                algorithm: "AES".to_string(),
                mode: "GCM (Authenticated Encryption)".to_string(),
                key_bits: 256,
                block_size: 128,
            },
            mac_algorithm: Some(MacAlgorithm {
                algorithm: "SHA-384".to_string(),
                hash_bits: 384,
                output_bits: 384,
            }),
            aead_details: Some(AeadDetails {
                algorithm: "AES-256-GCM".to_string(),
                key_bits: 256,
                nonce_bits: 96,
                tag_bits: 128,
                plaintext_record_size_limit: 16384,
            }),
            key_exchange: KeyExchangeDetails {
                algorithm: "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)".to_string(),
                group: "x25519 or secp384r1".to_string(),
                forward_secrecy: true,
            },
            signature_algorithm: "RSA-PSS-SHA384 or ECDSA-SHA384".to_string(),
            secret_derivation: SecretDerivation {
                client_random: client_random.to_string(),
                server_random: server_random.to_string(),
                randoms_combined_length: 64,
                key_derivation_function: "HKDF (HMAC-based Extract-and-Expand Key Derivation Function)".to_string(),
                prf_hash_algorithm: "SHA-384".to_string(),
                derived_secrets: vec![
                    DerivedSecret {
                        name: "Early Secret".to_string(),
                        purpose: "Used for early data (0-RTT)".to_string(),
                        length_bits: 384,
                        kdf_formula: "HKDF-Extract(salt=0, IKM=0x0000...)".to_string(),
                    },
                    DerivedSecret {
                        name: "Handshake Secret".to_string(),
                        purpose: "Derives server_handshake_traffic_secret and client_handshake_traffic_secret".to_string(),
                        length_bits: 384,
                        kdf_formula: "HKDF-Extract(salt=Early Secret, IKM=ECDHE shared secret)".to_string(),
                    },
                    DerivedSecret {
                        name: "Server Handshake Traffic Secret".to_string(),
                        purpose: "Encrypts ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished".to_string(),
                        length_bits: 384,
                        kdf_formula: "HKDF-Expand-Label(Handshake Secret, 's hs traffic', ServerHello...Finished)".to_string(),
                    },
                    DerivedSecret {
                        name: "Client Handshake Traffic Secret".to_string(),
                        purpose: "Encrypts Client Finished message".to_string(),
                        length_bits: 384,
                        kdf_formula: "HKDF-Expand-Label(Handshake Secret, 'c hs traffic', ServerHello...Finished)".to_string(),
                    },
                    DerivedSecret {
                        name: "Master Secret".to_string(),
                        purpose: "Base for all application traffic secrets".to_string(),
                        length_bits: 384,
                        kdf_formula: "HKDF-Extract(salt=Handshake Secret, IKM=0x0000...)".to_string(),
                    },
                    DerivedSecret {
                        name: "Server Application Traffic Secret 0".to_string(),
                        purpose: "Encrypts application data from server".to_string(),
                        length_bits: 384,
                        kdf_formula: "HKDF-Expand-Label(Master Secret, 's ap traffic', ClientHello...Finished)".to_string(),
                    },
                    DerivedSecret {
                        name: "Client Application Traffic Secret 0".to_string(),
                        purpose: "Encrypts application data from client".to_string(),
                        length_bits: 384,
                        kdf_formula: "HKDF-Expand-Label(Master Secret, 'c ap traffic', ClientHello...Finished)".to_string(),
                    },
                    DerivedSecret {
                        name: "Exporter Master Secret".to_string(),
                        purpose: "For exporters like SSLKEYLOGFILE".to_string(),
                        length_bits: 384,
                        kdf_formula: "HKDF-Expand-Label(Master Secret, 'exp master', ClientHello...Finished)".to_string(),
                    },
                ],
            },
        })
    } else if cipher_suite.contains("AES_128_GCM") {
        Ok(EncryptionNegotiation {
            cipher_suite_code: suite_code.to_string(),
            cipher_suite_name: "TLS_AES_128_GCM_SHA256".to_string(),
            encryption_algorithm: CipherAlgorithm {
                algorithm: "AES".to_string(),
                mode: "GCM (Authenticated Encryption)".to_string(),
                key_bits: 128,
                block_size: 128,
            },
            mac_algorithm: Some(MacAlgorithm {
                algorithm: "SHA-256".to_string(),
                hash_bits: 256,
                output_bits: 256,
            }),
            aead_details: Some(AeadDetails {
                algorithm: "AES-128-GCM".to_string(),
                key_bits: 128,
                nonce_bits: 96,
                tag_bits: 128,
                plaintext_record_size_limit: 16384,
            }),
            key_exchange: KeyExchangeDetails {
                algorithm: "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)".to_string(),
                group: "x25519 or secp256r1".to_string(),
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
                        name: "Early Secret".to_string(),
                        purpose: "Used for early data (0-RTT)".to_string(),
                        length_bits: 256,
                        kdf_formula: "HKDF-Extract(salt=0, IKM=0x0000...)".to_string(),
                    },
                    DerivedSecret {
                        name: "Handshake Secret".to_string(),
                        purpose: "Derives server_handshake_traffic_secret and client_handshake_traffic_secret".to_string(),
                        length_bits: 256,
                        kdf_formula: "HKDF-Extract(salt=Early Secret, IKM=ECDHE shared secret)".to_string(),
                    },
                    DerivedSecret {
                        name: "Server Handshake Traffic Secret".to_string(),
                        purpose: "Encrypts ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished".to_string(),
                        length_bits: 256,
                        kdf_formula: "HKDF-Expand-Label(Handshake Secret, 's hs traffic', ServerHello...Finished)".to_string(),
                    },
                    DerivedSecret {
                        name: "Client Handshake Traffic Secret".to_string(),
                        purpose: "Encrypts Client Finished message".to_string(),
                        length_bits: 256,
                        kdf_formula: "HKDF-Expand-Label(Handshake Secret, 'c hs traffic', ServerHello...Finished)".to_string(),
                    },
                    DerivedSecret {
                        name: "Master Secret".to_string(),
                        purpose: "Base for all application traffic secrets".to_string(),
                        length_bits: 256,
                        kdf_formula: "HKDF-Extract(salt=Handshake Secret, IKM=0x0000...)".to_string(),
                    },
                    DerivedSecret {
                        name: "Server Application Traffic Secret 0".to_string(),
                        purpose: "Encrypts application data from server".to_string(),
                        length_bits: 256,
                        kdf_formula: "HKDF-Expand-Label(Master Secret, 's ap traffic', ClientHello...Finished)".to_string(),
                    },
                    DerivedSecret {
                        name: "Client Application Traffic Secret 0".to_string(),
                        purpose: "Encrypts application data from client".to_string(),
                        length_bits: 256,
                        kdf_formula: "HKDF-Expand-Label(Master Secret, 'c ap traffic', ClientHello...Finished)".to_string(),
                    },
                    DerivedSecret {
                        name: "Exporter Master Secret".to_string(),
                        purpose: "For exporters like SSLKEYLOGFILE".to_string(),
                        length_bits: 256,
                        kdf_formula: "HKDF-Expand-Label(Master Secret, 'exp master', ClientHello...Finished)".to_string(),
                    },
                ],
            },
        })
    } else if cipher_suite.contains("CHACHA20") {
        Ok(EncryptionNegotiation {
            cipher_suite_code: suite_code.to_string(),
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
        })
    } else {
        // Generic fallback
        Ok(EncryptionNegotiation {
            cipher_suite_code: suite_code.to_string(),
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
        })
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
            fields.insert("random".to_string(), json!(random[..16].to_string() + "..."));

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
            fields.insert("random".to_string(), json!(random[..16].to_string() + "..."));

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
        5 => {
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
        8 => {
            // ServerHelloDone - no fields
            fields.insert("message".to_string(), json!("No additional fields"));
            Some(fields)
        }
        11 => {
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
