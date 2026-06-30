use anyhow::Result;

use super::types::*;

pub fn build_http_exchange(request: &str, response: &str) -> Result<HttpExchange> {
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
            encryption_overhead: 16 + 5,
            record_header_size: 5,
            authentication_tag_size: 16,
            content_type_byte: 1,
            content_type_padding: "0x16 (after decryption)".to_string(),
            total_size_with_record_header: calculate_encrypted_size(request.len()),
            encryption_note: "Request is encrypted with negotiated cipher suite (AES-256-GCM)".to_string(),
        },
    };

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
    plaintext_size + 1 + 16 + 5
}
