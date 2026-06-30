use super::types::*;

pub fn check_x25519_mlkem768_negotiated(messages: &[HandshakeMessage]) -> bool {
    for msg in messages {
        if msg.message_type == "ServerHello" {
            if let Some(fields) = &msg.fields {
                if let Some(share) = fields.get("key_share") {
                    if let serde_json::Value::Object(share_obj) = share {
                        if let Some(serde_json::Value::String(group)) = share_obj.get("group") {
                            if group == "X25519MLKEM768" {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

pub fn build_post_quantum_analysis(encryption_negotiation: &EncryptionNegotiation, messages: &[HandshakeMessage]) -> PostQuantumAnalysis {
    let cipher_name = &encryption_negotiation.cipher_suite_name;

    let x25519_mlkem768_negotiated = check_x25519_mlkem768_negotiated(messages);
    let pqc_key_exchange_offered = x25519_mlkem768_negotiated || cipher_name.contains("KYBER") || cipher_name.contains("MLKEM");
    let pqc_signature_offered =
        cipher_name.contains("DILITHIUM") || cipher_name.contains("MLDSA") || cipher_name.contains("FALCON");
    let quantum_safe = pqc_key_exchange_offered && pqc_signature_offered;
    let hybrid_ready = pqc_key_exchange_offered || pqc_signature_offered;

    let pqc_algorithms_available = vec![
        "Kyber-512 (MLKEM512)".to_string(),
        "Kyber-768 (MLKEM768)".to_string(),
        "Kyber-1024 (MLKEM1024)".to_string(),
        "Dilithium-2 (MLDSA44)".to_string(),
        "Dilithium-3 (MLDSA65)".to_string(),
        "Dilithium-5 (MLDSA87)".to_string(),
        "FALCON-512".to_string(),
        "FALCON-1024".to_string(),
    ];

    let recommended_hybrid_suites = if hybrid_ready {
        vec![cipher_name.clone()]
    } else {
        vec![
            "TLS_ECDHE_X25519_KYBER768_WITH_AES_256_GCM_SHA384".to_string(),
            "TLS_ECDHE_SECP256R1_KYBER512_WITH_AES_256_GCM_SHA384".to_string(),
        ]
    };

    let hybrid_key_exchange = HybridKeyExchange {
        classical_key_agreement: ClassicalKeyAgreement {
            algorithm: "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)".to_string(),
            curve: if encryption_negotiation.key_exchange.group.contains("25519") {
                "X25519 (Curve25519)".to_string()
            } else if encryption_negotiation.key_exchange.group.contains("384") {
                "secp384r1 (P-384)".to_string()
            } else {
                "secp256r1 (P-256)".to_string()
            },
            key_size_bits: 256,
            estimated_security_bits: 128,
        },
        post_quantum_key_agreement: PostQuantumKeyAgreement {
            algorithms: vec![
                PQCAlgorithm {
                    name: "Kyber-768 (MLKEM768)".to_string(),
                    family: "Lattice-based (Module-LWE)".to_string(),
                    key_size_bits: 1184,
                    ciphertext_size_bits: 1088,
                    shared_secret_size_bits: 256,
                    estimated_quantum_security_bits: 192,
                    status: "NIST standardized (FIPS 203)".to_string(),
                },
                PQCAlgorithm {
                    name: "Dilithium-3 (MLDSA65)".to_string(),
                    family: "Lattice-based (Module-LWE)".to_string(),
                    key_size_bits: 2528,
                    ciphertext_size_bits: 2701,
                    shared_secret_size_bits: 256,
                    estimated_quantum_security_bits: 192,
                    status: "NIST standardized (FIPS 204)".to_string(),
                },
            ],
            recommended: if quantum_safe {
                "Already deployed (using current cipher suite)".to_string()
            } else {
                "Kyber-768 + Dilithium-3".to_string()
            },
            hybrid_with_classical: !quantum_safe,
        },
        hybrid_secret_derivation: if hybrid_ready {
            "HKDF-Expand(PRK, info || pqc_shared_secret || classical_shared_secret)".to_string()
        } else {
            "HKDF-Expand(PRK, info || classical_shared_secret)".to_string()
        },
    };

    let recommendation = if quantum_safe {
        "✓ Server supports post-quantum cryptography. Quantum-safe connection established.".to_string()
    } else if hybrid_ready {
        "~ Server offers hybrid PQC key exchange. Partial quantum protection for key agreement."
            .to_string()
    } else {
        "✗ Server does not support post-quantum cryptography. At risk from future quantum computers."
            .to_string()
    };

    let post_quantum_readiness = PostQuantumReadiness {
        quantum_safe,
        hybrid_ready,
        pqc_key_exchange_offered,
        pqc_signature_offered,
        recommendation,
    };

    let (priority, timeline) = if quantum_safe {
        (
            "Complete - Already quantum-safe".to_string(),
            "No action needed; already protected against quantum threats.".to_string(),
        )
    } else if hybrid_ready {
        (
            "High - Deploy signature algorithm".to_string(),
            "Phase 1 (Now): Hybrid key exchange active | Phase 2 (2025): Add PQC signatures"
                .to_string(),
        )
    } else {
        (
            "Critical - Immediate migration required".to_string(),
            "Phase 1 (2024): Deploy hybrid suites | Phase 2 (2025): Full PQC | Phase 3 (2026): Retire classical-only".to_string(),
        )
    };

    let action_items = if quantum_safe {
        vec![
            "✓ No action required".to_string(),
            "Monitor for security updates and re-key periodically".to_string(),
            "Document PQC compliance status".to_string(),
        ]
    } else if hybrid_ready {
        vec![
            "Add post-quantum signature algorithm (Dilithium or FALCON)".to_string(),
            "Enable hybrid classical+PQC signatures".to_string(),
            "Test full PQC deployment path".to_string(),
        ]
    } else {
        vec![
            "Deploy hybrid ECDHE+Kyber key exchange immediately".to_string(),
            "Plan full PQC migration for Q1 2025".to_string(),
            "Test hybrid cipher suites in staging environment".to_string(),
            "Establish baseline for post-quantum readiness".to_string(),
        ]
    };

    let migration_strategy = MigrationStrategy {
        current_security_level: if quantum_safe {
            "Quantum-safe: Protected by PQC algorithms".to_string()
        } else if hybrid_ready {
            "Hybrid: Partial PQC protection for key agreement; classical signatures".to_string()
        } else {
            "Post-classical: ECDHE and AES-GCM only (vulnerable to quantum attacks)".to_string()
        },
        post_quantum_security_level: "Quantum-safe: Protected by hybrid/full PQC".to_string(),
        implementation_priority: priority,
        timeline,
        action_items,
    };

    PostQuantumAnalysis {
        hybrid_ready,
        hybrid_approach_available: !quantum_safe,
        pqc_algorithms_available,
        recommended_hybrid_suites,
        hybrid_key_exchange,
        post_quantum_readiness,
        migration_strategy,
    }
}
