use rustls::ConnectionTrafficSecrets;
use std::io::{Read, Write};
use std::net::TcpStream;

use crate::error::{Result, TlsError};
use super::types::{HandshakeMessage, DecryptionDebugInfo};
use super::handshake::{parse_handshake_type, parse_handshake_fields, parse_new_session_ticket};

#[derive(Clone)]
pub struct EncryptedRecord {
    pub data: Vec<u8>,
    pub direction_is_write: bool,
    pub sequence_number: u64,
}

pub struct TrackedStream {
    inner: TcpStream,
    messages: Vec<HandshakeMessage>,
    sequence: usize,
    handshake_complete: bool,
    encrypted_records_from_server: usize,
    encrypted_records_from_client: usize,
    encrypted_records: Vec<EncryptedRecord>,
    server_seq: u64,
    client_seq: u64,
    successfully_decrypted: std::cell::Cell<usize>,
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
            encrypted_records: Vec::new(),
            server_seq: 0,
            client_seq: 0,
            successfully_decrypted: std::cell::Cell::new(0),
        }
    }

    pub fn extract_messages_with_secrets(
        mut self,
        secrets: &rustls::ExtractedSecrets,
    ) -> Result<(Vec<HandshakeMessage>, DecryptionDebugInfo)> {
        let (_tx_initial_seq, _tx_secret) = &secrets.tx;
        let (rx_initial_seq, _rx_secret) = &secrets.rx;

        let records = self.encrypted_records.clone();
        for (_record_index, record) in records.iter().enumerate() {
            let is_applicable = if record.direction_is_write {
                true
            } else {
                record.sequence_number >= *rx_initial_seq as u64
            };

            if is_applicable {
                match self.decrypt_record(record, secrets) {
                    Ok(plaintext) => {
                        if !plaintext.is_empty() {
                            self.successfully_decrypted.set(self.successfully_decrypted.get() + 1);
                            self.parse_decrypted_record(&plaintext, record.direction_is_write);
                        }
                    }
                    Err(_) => {}
                }
            }
        }
        self.add_encrypted_handshake_messages();

        let debug_info = DecryptionDebugInfo {
            total_encrypted_records_captured: self.encrypted_records.len(),
            encrypted_from_server: self.encrypted_records_from_server,
            encrypted_from_client: self.encrypted_records_from_client,
            successfully_decrypted: self.successfully_decrypted.get(),
        };

        Ok((self.messages, debug_info))
    }

    fn decrypt_record(
        &self,
        record: &EncryptedRecord,
        secrets: &rustls::ExtractedSecrets,
    ) -> Result<Vec<u8>> {
        let traffic_secret = if record.direction_is_write {
            &secrets.tx.1
        } else {
            &secrets.rx.1
        };

        match traffic_secret {
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                self.decrypt_aes_gcm(&record.data, key, iv, record.sequence_number)
            }
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                self.decrypt_aes_gcm(&record.data, key, iv, record.sequence_number)
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                self.decrypt_chacha(&record.data, key, iv, record.sequence_number)
            }
            _ => Err(TlsError::SecretExtraction {
                reason: "Unknown traffic secret variant".to_string(),
            }),
        }
    }

    fn decrypt_aes_gcm(
        &self,
        ciphertext: &[u8],
        key: &rustls::crypto::cipher::AeadKey,
        iv: &rustls::crypto::cipher::Iv,
        seq_num: u64,
    ) -> Result<Vec<u8>> {
        decrypt_aead_record(ciphertext, key, iv, seq_num, true)
    }

    fn decrypt_chacha(
        &self,
        ciphertext: &[u8],
        key: &rustls::crypto::cipher::AeadKey,
        iv: &rustls::crypto::cipher::Iv,
        seq_num: u64,
    ) -> Result<Vec<u8>> {
        decrypt_aead_record(ciphertext, key, iv, seq_num, false)
    }

    fn parse_decrypted_record(&mut self, plaintext: &[u8], is_write: bool) {
        if plaintext.is_empty() {
            return;
        }

        let content = if plaintext.len() > 0 {
            &plaintext[..plaintext.len() - 1]
        } else {
            plaintext
        };
        let content_type = if plaintext.len() > 0 {
            plaintext[plaintext.len() - 1]
        } else {
            0
        };

        if content_type == 22 {
            self.parse_handshake_from_plaintext(content, is_write);
        } else if content_type == 23 && !is_write {
            self.parse_post_handshake_from_plaintext(content);
        }
    }

    fn parse_post_handshake_from_plaintext(&mut self, data: &[u8]) {
        if data.len() >= 4 {
            let msg_type = data[0];
            let (type_name, description) = parse_handshake_type(msg_type);

            if msg_type == 4 {
                self.messages.push(HandshakeMessage {
                    sequence: self.sequence,
                    direction: "Server → Client".to_string(),
                    message_type: type_name,
                    size: data.len(),
                    description,
                    fields: parse_new_session_ticket(data),
                    inferred: false,
                });
                self.sequence += 1;
            }
        }
    }

    fn parse_handshake_from_plaintext(&mut self, data: &[u8], is_write: bool) {
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let msg_type = data[pos];
            let msg_length = u32::from_be_bytes([0, data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize;

            let (type_name, description) = parse_handshake_type(msg_type);
            let total_msg_size = msg_length + 4;

            let direction = if is_write {
                "Client → Server".to_string()
            } else {
                "Server → Client".to_string()
            };

            let payload_start = pos + 4;
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
                inferred: false,
            });

            self.sequence += 1;
            pos += total_msg_size;
        }
    }

    pub fn post_handshake_encrypted_records(&self) -> usize {
        self.encrypted_records_from_server
    }

    fn add_encrypted_handshake_messages(&mut self) {
        use serde_json::json;
        use std::collections::HashMap;

        if self.encrypted_records_from_server > 0 && !self.handshake_complete {
            let messages_to_add = vec![
                ("EncryptedExtensions", "Server sends encrypted TLS extensions (TLS 1.3)"),
                ("Certificate", "Server presents certificate chain for authentication"),
                ("CertificateVerify", "Server proves possession of private key via signature"),
                ("Finished", "Handshake complete, includes MAC of all messages"),
            ];

            for (msg_type, description) in messages_to_add {
                let mut fields = HashMap::new();
                fields.insert("encrypted".to_string(), json!(true));
                fields.insert(
                    "note".to_string(),
                    json!(format!("{} sent encrypted (TLS 1.3)", msg_type)),
                );
                fields.insert("inferred_reason".to_string(), json!("Encrypted in TLS 1.3; actual message not captured from wire"));

                self.messages.push(HandshakeMessage {
                    sequence: self.sequence,
                    direction: "Server → Client".to_string(),
                    message_type: msg_type.to_string(),
                    size: 0,
                    description: description.to_string(),
                    fields: Some(fields),
                    inferred: true,
                });
                self.sequence += 1;
            }
        }

        if self.encrypted_records_from_client > 0 && self.encrypted_records_from_server > 0 {
            let mut fields = HashMap::new();
            fields.insert("encrypted".to_string(), json!(true));
            fields.insert("note".to_string(), json!("MAC of all handshake messages (TLS 1.3)"));
            fields.insert("inferred_reason".to_string(), json!("Encrypted in TLS 1.3; actual message not captured from wire"));

            self.messages.push(HandshakeMessage {
                sequence: self.sequence,
                direction: "Client → Server".to_string(),
                message_type: "Finished".to_string(),
                size: 0,
                description: "Client handshake complete with MAC".to_string(),
                fields: Some(fields),
                inferred: true,
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

            pos += 5;

            if pos + length > data.len() {
                break;
            }

            match content_type {
                22 => {
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
                        let total_msg_size = msg_length + 4;

                        let direction = if is_write {
                            "Client → Server".to_string()
                        } else {
                            "Server → Client".to_string()
                        };

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
                            inferred: false,
                        });

                        self.sequence += 1;
                        msg_pos += total_msg_size;
                    }
                }
                20 => {
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
                        inferred: false,
                    });

                    self.sequence += 1;
                }
                23 => {
                    if is_write {
                        self.encrypted_records_from_client += 1;
                        self.encrypted_records.push(EncryptedRecord {
                            data: data[pos..pos + length].to_vec(),
                            direction_is_write: true,
                            sequence_number: self.client_seq,
                        });
                        self.client_seq += 1;
                    } else {
                        self.encrypted_records_from_server += 1;
                        self.encrypted_records.push(EncryptedRecord {
                            data: data[pos..pos + length].to_vec(),
                            direction_is_write: false,
                            sequence_number: self.server_seq,
                        });
                        self.server_seq += 1;
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

pub fn decrypt_aead_record(
    ciphertext: &[u8],
    key: &rustls::crypto::cipher::AeadKey,
    iv: &rustls::crypto::cipher::Iv,
    seq_num: u64,
    is_aes: bool,
) -> Result<Vec<u8>> {
    use ring::aead::{self, UnboundKey};

    if ciphertext.len() < 16 {
        return Err(TlsError::Other("Ciphertext too short for AEAD".to_string()));
    }

    let mut nonce_bytes = [0u8; 12];
    for i in 0..12 {
        nonce_bytes[i] = iv.as_ref()[i];
    }
    let seq_bytes = seq_num.to_be_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= seq_bytes[i];
    }

    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = ciphertext.to_vec();

    let result = if is_aes {
        let key_bytes = key.as_ref();
        let aead_algo = match key_bytes.len() {
            16 => &aead::AES_128_GCM,
            32 => &aead::AES_256_GCM,
            _ => return Err(TlsError::Other(format!("Invalid AES key size: {}", key_bytes.len()))),
        };
        let unbound = UnboundKey::new(aead_algo, key_bytes)
            .map_err(|_| TlsError::Other("Failed to create AES-GCM key".to_string()))?;
        let key = aead::LessSafeKey::new(unbound);
        key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
    } else {
        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, key.as_ref())
            .map_err(|_| TlsError::Other("Failed to create ChaCha20-Poly1305 key".to_string()))?;
        let key = aead::LessSafeKey::new(unbound);
        key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
    };

    match result {
        Ok(plaintext) => Ok(plaintext.to_vec()),
        Err(_) => Err(TlsError::Other("AEAD decryption failed".to_string())),
    }
}
