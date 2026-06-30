/// Unit tests for individual TLS modules
/// These tests verify parsing and data structure construction without network access

#[cfg(test)]
mod handshake_parsing {
    use tls_outputter::tls::handshake::{parse_handshake_type, parse_handshake_fields};

    #[test]
    fn test_parse_client_hello_type() {
        let (name, desc) = parse_handshake_type(1);
        assert_eq!(name, "ClientHello");
        assert!(desc.contains("TLS handshake"));
    }

    #[test]
    fn test_parse_server_hello_type() {
        let (name, desc) = parse_handshake_type(2);
        assert_eq!(name, "ServerHello");
        assert!(desc.contains("Server selects"));
    }

    #[test]
    fn test_parse_certificate_type() {
        let (name, desc) = parse_handshake_type(8);
        assert_eq!(name, "Certificate");
        assert!(desc.contains("certificate chain"));
    }

    #[test]
    fn test_parse_finished_type() {
        let (name, desc) = parse_handshake_type(12);
        assert_eq!(name, "Finished");
        assert!(desc.contains("MAC"));
    }

    #[test]
    fn test_parse_new_session_ticket() {
        let (name, desc) = parse_handshake_type(4);
        assert_eq!(name, "NewSessionTicket");
        assert!(desc.contains("session resumption"));
    }

    #[test]
    fn test_parse_unknown_type() {
        let (name, desc) = parse_handshake_type(99);
        assert!(name.contains("Unknown"));
        assert!(desc.contains("Unknown message type"));
    }

    #[test]
    fn test_parse_client_hello_fields() {
        // Minimal ClientHello: version (2) + random (32) + session_id_len (1) = 35 bytes minimum
        let mut data = vec![0u8; 50];
        data[0] = 0x03; // version high
        data[1] = 0x03; // version low (TLS 1.2)

        // Random 32 bytes (indices 2-33)
        for i in 2..34 {
            data[i] = (i as u8).wrapping_mul(7);
        }

        data[34] = 0; // session_id_len
        data[35] = 0; // cipher_suites_len high
        data[36] = 4; // cipher_suites_len low (2 suites)

        let fields = parse_handshake_fields(1, &data);
        assert!(fields.is_some());

        let fields = fields.unwrap();
        assert!(fields.contains_key("client_version"));
        assert!(fields.contains_key("random"));
        assert!(fields.contains_key("session_id_length"));
    }

    #[test]
    fn test_parse_server_hello_fields() {
        let mut data = vec![0u8; 50];
        data[0] = 0x03; // version high
        data[1] = 0x03; // version low

        for i in 2..34 {
            data[i] = i as u8;
        }

        data[34] = 0; // session_id_len
        data[35] = 0x13; // cipher_suite high
        data[36] = 0x01; // cipher_suite low
        data[37] = 0; // compression_method

        let fields = parse_handshake_fields(2, &data);
        assert!(fields.is_some());

        let fields = fields.unwrap();
        assert!(fields.contains_key("server_version"));
        assert!(fields.contains_key("random"));
        assert!(fields.contains_key("selected_cipher_suite"));
    }

    #[test]
    fn test_parse_finished_fields() {
        let data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let fields = parse_handshake_fields(12, &data);
        assert!(fields.is_some());

        let fields = fields.unwrap();
        assert!(fields.contains_key("verification_data_length"));
        assert_eq!(fields["verification_data_length"].as_u64().unwrap(), 6);
    }

    #[test]
    fn test_parse_fields_too_short() {
        let data = vec![0x01, 0x02];
        let fields = parse_handshake_fields(1, &data);
        assert!(fields.is_none(), "should return None for too-short data");
    }
}

#[cfg(test)]
mod encryption_negotiation {
    use tls_outputter::tls::encryption::build_encryption_negotiation;

    #[test]
    fn test_aes_256_gcm_negotiation() {
        let result = build_encryption_negotiation(
            "TLS_AES_256_GCM_SHA384 (0x1301)",
            "abc123",
            "def456",
        );

        assert!(result.is_ok());
        let neg = result.unwrap();
        assert_eq!(neg.cipher_suite_name, "TLS_AES_256_GCM_SHA384");
        assert!(neg.aead_details.is_some());

        let aead = neg.aead_details.unwrap();
        assert_eq!(aead.key_bits, 256);
        assert_eq!(aead.algorithm, "AES-256-GCM");
    }

    #[test]
    fn test_aes_128_gcm_negotiation() {
        let result = build_encryption_negotiation(
            "TLS_AES_128_GCM_SHA256 (0x1301)",
            "abc123",
            "def456",
        );

        assert!(result.is_ok());
        let neg = result.unwrap();
        assert_eq!(neg.cipher_suite_name, "TLS_AES_128_GCM_SHA256");

        let aead = neg.aead_details.unwrap();
        assert_eq!(aead.key_bits, 128);
    }

    #[test]
    fn test_chacha_negotiation() {
        let result = build_encryption_negotiation(
            "TLS_CHACHA20_POLY1305_SHA256 (0x1303)",
            "abc123",
            "def456",
        );

        assert!(result.is_ok());
        let neg = result.unwrap();
        assert_eq!(neg.cipher_suite_name, "TLS_CHACHA20_POLY1305_SHA256");

        let aead = neg.aead_details.unwrap();
        assert_eq!(aead.algorithm, "ChaCha20-Poly1305");
    }

    #[test]
    fn test_unknown_cipher_suite() {
        let result = build_encryption_negotiation(
            "UNKNOWN_SUITE (0x9999)",
            "abc123",
            "def456",
        );

        assert!(result.is_ok());
        let neg = result.unwrap();
        assert!(neg.cipher_suite_name.contains("UNKNOWN"));
    }

    #[test]
    fn test_secret_derivation_present() {
        let result = build_encryption_negotiation(
            "TLS_AES_256_GCM_SHA384 (0x1301)",
            "client_random",
            "server_random",
        );

        let neg = result.unwrap();
        assert_eq!(neg.secret_derivation.client_random, "client_random");
        assert_eq!(neg.secret_derivation.server_random, "server_random");
        assert!(!neg.secret_derivation.derived_secrets.is_empty());
    }
}

#[cfg(test)]
mod pqc_analysis {
    use tls_outputter::tls::pqc::build_post_quantum_analysis;
    use tls_outputter::tls::types::*;

    fn create_dummy_encryption_negotiation(suite_name: &str) -> EncryptionNegotiation {
        EncryptionNegotiation {
            cipher_suite_code: "0x1301".to_string(),
            cipher_suite_name: suite_name.to_string(),
            encryption_algorithm: CipherAlgorithm {
                algorithm: "AES".to_string(),
                mode: "GCM".to_string(),
                key_bits: 256,
                block_size: 128,
            },
            mac_algorithm: None,
            aead_details: Some(AeadDetails {
                algorithm: "AES-256-GCM".to_string(),
                key_bits: 256,
                nonce_bits: 96,
                tag_bits: 128,
                plaintext_record_size_limit: 16384,
            }),
            key_exchange: KeyExchangeDetails {
                algorithm: "ECDHE".to_string(),
                group: "x25519".to_string(),
                forward_secrecy: true,
            },
            signature_algorithm: "RSA-PSS-SHA256".to_string(),
            secret_derivation: SecretDerivation {
                client_random: "abc".to_string(),
                server_random: "def".to_string(),
                randoms_combined_length: 64,
                key_derivation_function: "HKDF".to_string(),
                prf_hash_algorithm: "SHA-256".to_string(),
                derived_secrets: vec![],
            },
        }
    }

    #[test]
    fn test_classical_only_negotiation() {
        let enc = create_dummy_encryption_negotiation("TLS_AES_256_GCM_SHA384");
        let pqc = build_post_quantum_analysis(&enc);

        assert!(!pqc.post_quantum_readiness.quantum_safe, "classical-only should not be quantum-safe");
        assert!(!pqc.hybrid_ready, "classical-only should not be hybrid-ready");
        assert!(pqc.post_quantum_readiness.pqc_key_exchange_offered == false);
    }

    #[test]
    fn test_hybrid_key_exchange() {
        let enc = create_dummy_encryption_negotiation("TLS_KYBER768_WITH_AES_256_GCM");
        let pqc = build_post_quantum_analysis(&enc);

        assert!(pqc.post_quantum_readiness.pqc_key_exchange_offered);
        assert!(pqc.hybrid_ready);
    }

    #[test]
    fn test_pqc_algorithms_listed() {
        let enc = create_dummy_encryption_negotiation("TLS_AES_256_GCM_SHA384");
        let pqc = build_post_quantum_analysis(&enc);

        assert!(!pqc.pqc_algorithms_available.is_empty());
        assert!(pqc.pqc_algorithms_available.iter().any(|a| a.contains("Kyber")));
        assert!(pqc.pqc_algorithms_available.iter().any(|a| a.contains("Dilithium")));
    }

    #[test]
    fn test_migration_strategy_present() {
        let enc = create_dummy_encryption_negotiation("TLS_AES_256_GCM_SHA384");
        let pqc = build_post_quantum_analysis(&enc);

        assert!(!pqc.migration_strategy.current_security_level.is_empty());
        assert!(!pqc.migration_strategy.implementation_priority.is_empty());
        assert!(!pqc.migration_strategy.action_items.is_empty());
    }
}

#[cfg(test)]
mod http_exchange {
    use tls_outputter::tls::http::build_http_exchange;

    #[test]
    fn test_http_exchange_building() {
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";

        let result = build_http_exchange(request, response);
        assert!(result.is_ok());

        let exchange = result.unwrap();
        assert_eq!(exchange.request.plaintext.size_bytes, request.len());
        assert_eq!(exchange.response.plaintext.size_bytes, response.len());
    }

    #[test]
    fn test_large_response_truncation() {
        let request = "GET / HTTP/1.1\r\n\r\n";
        let response = "HTTP/1.1 200 OK\r\n".to_string() + &"x".repeat(1000);

        let exchange = build_http_exchange(request, &response).unwrap();
        assert_eq!(exchange.response.plaintext.size_bytes, response.len());
        // Content should be truncated at 500 characters
        assert!(exchange.response.plaintext.content.contains("[truncated"));
    }

    #[test]
    fn test_encryption_analysis() {
        let request = "GET / HTTP/1.1\r\n\r\n";
        let response = "HTTP/1.1 200 OK\r\n\r\nHello";

        let exchange = build_http_exchange(request, response).unwrap();

        let req_analysis = &exchange.request.encryption_analysis;
        assert_eq!(req_analysis.authentication_tag_size, 16);
        assert_eq!(req_analysis.record_header_size, 5);
        assert!(req_analysis.encryption_overhead > 0);

        let resp_analysis = &exchange.response.encryption_analysis;
        assert_eq!(resp_analysis.authentication_tag_size, 16);
    }
}

#[cfg(test)]
mod session_ticket {
    use tls_outputter::tls::session::build_session_ticket_info;
    use tls_outputter::tls::types::HandshakeMessage;

    #[test]
    fn test_tls13_no_session_ticket() {
        let messages = vec![];
        let result = build_session_ticket_info("TLS 1.3 (0x0304)", &messages, false);

        assert!(result.is_ok());
        let ticket = result.unwrap();
        assert!(!ticket.is_session_resumption_supported);
        assert!(!ticket.new_session_ticket_message);
    }

    #[test]
    fn test_tls13_with_session_ticket() {
        let messages = vec![HandshakeMessage {
            sequence: 0,
            direction: "Server → Client".to_string(),
            message_type: "NewSessionTicket".to_string(),
            size: 100,
            description: "Server provides session ticket".to_string(),
            fields: None,
            inferred: false,
        }];

        let result = build_session_ticket_info("TLS 1.3 (0x0304)", &messages, true);

        assert!(result.is_ok());
        let ticket = result.unwrap();
        assert!(ticket.is_session_resumption_supported);
        assert!(ticket.new_session_ticket_message);
    }

    #[test]
    fn test_tls12_no_session_ticket() {
        let messages = vec![];
        let result = build_session_ticket_info("TLS 1.2 (0x0303)", &messages, false);

        assert!(result.is_ok());
        let ticket = result.unwrap();
        assert!(!ticket.is_session_resumption_supported);
    }

    #[test]
    fn test_resumption_secret_details() {
        let messages = vec![];
        let result = build_session_ticket_info("TLS 1.3 (0x0304)", &messages, false).unwrap();

        let secret = &result.resumption_master_secret;
        assert_eq!(secret.secret_type, "PSK (Pre-Shared Key)");
        assert_eq!(secret.length_bits, 384);
    }
}
