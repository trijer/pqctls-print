use crate::error::Result;
use super::types::*;

pub fn build_encryption_negotiation(
    cipher_suite: &str,
    client_random: &str,
    server_random: &str,
) -> Result<EncryptionNegotiation> {
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
        Ok(build_chacha_encryption(suite_code, client_random, server_random))
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
