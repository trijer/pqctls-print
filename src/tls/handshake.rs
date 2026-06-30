use serde_json::json;
use std::collections::HashMap;

pub fn parse_handshake_type(msg_type: u8) -> (String, String) {
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

pub fn parse_new_session_ticket(data: &[u8]) -> Option<HashMap<String, serde_json::Value>> {
    let mut fields = HashMap::new();

    if data.len() < 9 {
        return None;
    }

    let mut pos = 1;

    if pos + 4 > data.len() {
        return None;
    }
    let lifetime = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;
    fields.insert("lifetime_seconds".to_string(), json!(lifetime));

    if pos + 4 > data.len() {
        return None;
    }
    let age_add = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;
    fields.insert("age_add".to_string(), json!(age_add));

    if pos + 1 > data.len() {
        return None;
    }
    let nonce_len = data[pos] as usize;
    pos += 1;
    if pos + nonce_len > data.len() {
        return None;
    }
    let nonce_hex = data[pos..pos + nonce_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");
    pos += nonce_len;
    fields.insert("nonce_hex".to_string(), json!(nonce_hex));
    fields.insert("nonce_length".to_string(), json!(nonce_len));

    if pos + 2 > data.len() {
        return None;
    }
    let ticket_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + ticket_len > data.len() {
        return None;
    }
    let ticket_hex = data[pos..pos + ticket_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");
    pos += ticket_len;
    fields.insert("ticket_hex".to_string(), json!(ticket_hex));
    fields.insert("ticket_length".to_string(), json!(ticket_len));

    if pos + 2 <= data.len() {
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        fields.insert("extensions_length".to_string(), json!(ext_len));
    }

    Some(fields)
}

pub fn parse_handshake_fields(msg_type: u8, data: &[u8]) -> Option<HashMap<String, serde_json::Value>> {
    let mut fields = HashMap::new();

    match msg_type {
        1 => {
            if data.len() < 34 {
                return None;
            }
            let version = u16::from_be_bytes([data[0], data[1]]);
            fields.insert("client_version".to_string(), json!(format!("0x{:04x}", version)));

            let random = data[2..34]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join("");
            fields.insert("random".to_string(), json!(random));

            if data.len() > 34 {
                let session_id_len = data[34] as usize;
                fields.insert("session_id_length".to_string(), json!(session_id_len));

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
            if data.len() < 34 {
                return None;
            }
            let version = u16::from_be_bytes([data[0], data[1]]);
            fields.insert("server_version".to_string(), json!(format!("0x{:04x}", version)));

            let random = data[2..34]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join("");
            fields.insert("random".to_string(), json!(random));

            if data.len() > 34 {
                let session_id_len = data[34] as usize;
                fields.insert("session_id_length".to_string(), json!(session_id_len));

                let cs_pos = 35 + session_id_len;
                if data.len() > cs_pos + 1 {
                    let cipher_suite = u16::from_be_bytes([data[cs_pos], data[cs_pos + 1]]);
                    fields.insert("selected_cipher_suite".to_string(), json!(format!("0x{:04x}", cipher_suite)));
                }

                if data.len() > cs_pos + 2 {
                    fields.insert("compression_method".to_string(), json!(data[cs_pos + 2]));
                }
            }
            Some(fields)
        }
        8 => {
            if data.len() < 3 {
                return None;
            }
            let cert_chain_len = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
            fields.insert("certificate_chain_length".to_string(), json!(cert_chain_len));

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
            fields.insert("verification_data_length".to_string(), json!(data.len()));
            if data.len() > 0 {
                let data_hex = data[..std::cmp::min(16, data.len())]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join("");
                fields.insert(
                    "verification_data_preview".to_string(),
                    json!(data_hex + if data.len() > 16 { "..." } else { "" }),
                );
            }
            Some(fields)
        }
        _ => {
            fields.insert("payload_length".to_string(), json!(data.len()));
            Some(fields)
        }
    }
}
