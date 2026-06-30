use crate::error::Result;
use super::types::*;

pub fn build_session_ticket_info(
    tls_version: &str,
    messages: &[HandshakeMessage],
    has_post_handshake_data: bool,
) -> Result<SessionTicketInfo> {
    let is_tls13 = tls_version.contains("1.3");

    let new_session_ticket_received = messages
        .iter()
        .any(|msg| msg.message_type == "NewSessionTicket")
        || (is_tls13 && has_post_handshake_data);

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
            mode: if new_session_ticket_received {
                "PSK with ECDHE (psk_dhe_ke)"
            } else {
                "Not supported"
            }
            .to_string(),
            identity_obfuscation: "Ticket age is obfuscated with ticket_age_add".to_string(),
            early_exporter_master_secret: false,
            max_early_data_size: if new_session_ticket_received { 16384 } else { 0 },
            psk_key_exchange_mode: if new_session_ticket_received {
                "psk_dhe_ke (recommended)"
            } else {
                "None"
            }
            .to_string(),
        },
        resumption_instructions: ResumptionInstructions {
            step_1: "Server sends NewSessionTicket message (encrypted in TLS 1.3)".to_string(),
            step_2: "Client stores ticket and derives obfuscated_ticket_age for next connection"
                .to_string(),
            step_3: "On resumption, client sends PSK identity in ClientHello pre_shared_key extension"
                .to_string(),
            step_4: "Server validates ticket and resumes session without full handshake".to_string(),
            expected_obfuscated_ticket_age: "Verified by server's ticket validation".to_string(),
            psk_identity_format: "{ identity: opaque<1..2^16-1>, obfuscated_ticket_age: uint32 }"
                .to_string(),
        },
        decrypted_details: None,
    })
}
