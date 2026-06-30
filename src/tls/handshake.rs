use serde_json::json;
use std::collections::HashMap;

fn get_cipher_suite_name(code: u16) -> String {
    match code {
        0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        0x1304 => "TLS_AES_128_CCM_SHA256".to_string(),
        0x1305 => "TLS_AES_128_CCM_8_SHA256".to_string(),
        0xffc2 => "TLS_ECDHE_MLKEM768_AES_256_GCM_SHA384".to_string(),
        0xffc3 => "TLS_ECDHE_MLKEM512_AES_256_GCM_SHA384".to_string(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xcca8 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        _ => format!("CIPHER_0x{:04x}", code),
    }
}

fn get_named_group_name(code: u16) -> String {
    match code {
        0x0001 => "secp160r1".to_string(),
        0x0002 => "secp192r1".to_string(),
        0x0003 => "secp224r1".to_string(),
        0x0004 => "secp256r1 (P-256)".to_string(),
        0x0005 => "secp384r1 (P-384)".to_string(),
        0x0006 => "secp521r1 (P-521)".to_string(),
        0x0010 => "ffdhe2048".to_string(),
        0x0011 => "ffdhe3072".to_string(),
        0x0012 => "ffdhe4096".to_string(),
        0x0013 => "ffdhe6144".to_string(),
        0x0014 => "ffdhe8192".to_string(),
        0x001d => "x25519".to_string(),
        0x001e => "x448".to_string(),
        0xffc2 => "MLKEM768".to_string(),
        0xffc3 => "MLKEM512".to_string(),
        0x11ec => "X25519MLKEM768".to_string(),
        0x11eb => "secp256r1MLKEM768".to_string(),
        _ => format!("GROUP_0x{:04x}", code),
    }
}

fn extract_server_key_share(data: &[u8]) -> Option<serde_json::Value> {
    if data.len() < 35 {
        return None;
    }

    let session_id_len = data[34] as usize;
    let cs_pos = 35 + session_id_len;

    if cs_pos + 3 > data.len() {
        return None;
    }

    let comp_pos = cs_pos + 2;
    if comp_pos >= data.len() {
        return None;
    }

    let comp_len = data[comp_pos] as usize;
    let ext_start = comp_pos + 1 + comp_len;

    if ext_start + 2 > data.len() {
        return None;
    }

    let ext_total_len = u16::from_be_bytes([data[ext_start], data[ext_start + 1]]) as usize;
    let mut ext_pos = ext_start + 2;
    let ext_end = ext_pos + ext_total_len;

    while ext_pos + 4 <= ext_end && ext_pos < data.len() {
        let ext_type = u16::from_be_bytes([data[ext_pos], data[ext_pos + 1]]);
        let ext_len = u16::from_be_bytes([data[ext_pos + 2], data[ext_pos + 3]]) as usize;

        if ext_type == 0x0033 {
            return parse_server_key_share_extension(&data[ext_pos + 4..ext_pos + 4 + ext_len]);
        }

        ext_pos += 4 + ext_len;
    }

    None
}

fn parse_server_key_share_extension(data: &[u8]) -> Option<serde_json::Value> {
    if data.len() < 4 {
        return None;
    }

    let group = u16::from_be_bytes([data[0], data[1]]);
    let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;

    if 4 + key_len > data.len() {
        return None;
    }

    let key_hex = data[4..4 + key_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");

    Some(json!({
        "group": get_named_group_name(group),
        "group_code": format!("0x{:04x}", group),
        "key_exchange_length": key_len,
        "key_exchange": key_hex
    }))
}

fn extract_key_shares(data: &[u8]) -> Option<Vec<serde_json::Value>> {
    if data.len() < 35 {
        return None;
    }

    let session_id_len = data[34] as usize;
    let cs_start = 35 + session_id_len;

    if cs_start + 2 > data.len() {
        return None;
    }

    let cs_len = u16::from_be_bytes([data[cs_start], data[cs_start + 1]]) as usize;
    let comp_start = cs_start + 2 + cs_len;

    if comp_start >= data.len() {
        return None;
    }

    let comp_len = data[comp_start] as usize;
    let ext_start = comp_start + 1 + comp_len;

    if ext_start + 2 > data.len() {
        return None;
    }

    let ext_total_len = u16::from_be_bytes([data[ext_start], data[ext_start + 1]]) as usize;
    let mut ext_pos = ext_start + 2;
    let ext_end = ext_pos + ext_total_len;

    while ext_pos + 4 <= ext_end && ext_pos < data.len() {
        let ext_type = u16::from_be_bytes([data[ext_pos], data[ext_pos + 1]]);
        let ext_len = u16::from_be_bytes([data[ext_pos + 2], data[ext_pos + 3]]) as usize;

        if ext_type == 0x0033 {
            return parse_key_share_extension(&data[ext_pos + 4..ext_pos + 4 + ext_len]);
        }

        ext_pos += 4 + ext_len;
    }

    None
}

fn parse_key_share_extension(data: &[u8]) -> Option<Vec<serde_json::Value>> {
    if data.len() < 2 {
        return None;
    }

    let mut shares = Vec::new();
    let shares_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;

    while pos + 4 <= data.len() && pos < 2 + shares_len {
        let group = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let key_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        if pos + 4 + key_len > data.len() {
            break;
        }

        let key_hex = data[pos + 4..pos + 4 + key_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");

        shares.push(json!({
            "group": get_named_group_name(group),
            "group_code": format!("0x{:04x}", group),
            "key_exchange_length": key_len,
            "key_exchange": key_hex
        }));

        pos += 4 + key_len;
    }

    if shares.is_empty() {
        None
    } else {
        Some(shares)
    }
}

pub fn extract_cipher_suites(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 35 {
        return None;
    }

    let mut ciphers = Vec::new();
    let session_id_len = data[34] as usize;
    let cs_start = 35 + session_id_len;

    if cs_start + 2 > data.len() {
        return None;
    }

    let cs_len = u16::from_be_bytes([data[cs_start], data[cs_start + 1]]) as usize;
    let mut pos = cs_start + 2;

    while pos + 1 < data.len() && ciphers.len() * 2 < cs_len {
        if pos + 2 <= data.len() {
            let cipher_code = u16::from_be_bytes([data[pos], data[pos + 1]]);
            ciphers.push(get_cipher_suite_name(cipher_code));
            pos += 2;
        } else {
            break;
        }
    }

    Some(ciphers)
}

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

                    if let Some(ciphers) = extract_cipher_suites(data) {
                        fields.insert("cipher_suites".to_string(), json!(ciphers));
                    }
                }

                if let Some(shares) = extract_key_shares(data) {
                    fields.insert("key_shares".to_string(), json!(shares));
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

                if let Some(share) = extract_server_key_share(data) {
                    fields.insert("key_share".to_string(), share);
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
