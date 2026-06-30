mod common;

use tls_outputter::analyze_handshake;

#[tokio::test]
async fn test_analyze_example_com() {
    let result = analyze_handshake("example.com", 443).await;

    match result {
        Ok(report) => {
            common::verify_report_structure(&report);
            common::verify_certificate_chain(&report);
            common::verify_encryption_negotiation(&report);
            common::verify_handshake_messages(&report);
            common::verify_pqc_analysis(&report);

            println!(
                "✓ example.com analysis successful: TLS {}, {}",
                report.tls_version, report.cipher_suite
            );
        }
        Err(e) => {
            eprintln!("Warning: Could not connect to example.com (network may be unavailable): {}", e);
        }
    }
}

#[tokio::test]
async fn test_json_serialization() {
    match analyze_handshake("example.com", 443).await {
        Ok(report) => {
            common::verify_json_serialization(&report);

            let json_str = serde_json::to_string_pretty(&report)
                .expect("should serialize to pretty JSON");

            assert!(json_str.len() > 100, "JSON output should be substantial");
            assert!(
                json_str.contains("\"host\""),
                "JSON should contain host field"
            );
            assert!(
                json_str.contains("\"tls_version\""),
                "JSON should contain tls_version field"
            );

            println!("✓ JSON serialization test passed");
        }
        Err(e) => {
            eprintln!("Warning: Could not connect to example.com: {}", e);
        }
    }
}

#[tokio::test]
async fn test_certificate_chain_not_empty() {
    match analyze_handshake("example.com", 443).await {
        Ok(report) => {
            assert!(
                !report.certificate_chain.is_empty(),
                "Certificate chain should not be empty"
            );

            let leaf_cert = &report.certificate_chain[0];
            assert!(
                !leaf_cert.subject.is_empty(),
                "Leaf certificate should have subject"
            );
            assert!(
                !leaf_cert.subject_alt_names.is_empty(),
                "Leaf certificate should have SANs for example.com"
            );

            println!("✓ Certificate chain test passed: {} certificates", report.certificate_chain.len());
        }
        Err(e) => {
            eprintln!("Warning: Could not connect to example.com: {}", e);
        }
    }
}

#[tokio::test]
async fn test_tls_version_detection() {
    match analyze_handshake("example.com", 443).await {
        Ok(report) => {
            assert!(
                report.tls_version.contains("1.3") || report.tls_version.contains("1.2"),
                "Should detect TLS 1.2 or 1.3"
            );

            println!("✓ TLS version detected: {}", report.tls_version);
        }
        Err(e) => {
            eprintln!("Warning: Could not connect to example.com: {}", e);
        }
    }
}

#[tokio::test]
async fn test_cipher_suite_detection() {
    match analyze_handshake("example.com", 443).await {
        Ok(report) => {
            assert!(
                !report.cipher_suite.is_empty(),
                "Should detect cipher suite"
            );
            assert!(
                report.cipher_suite.contains("0x"),
                "Cipher suite should include hex code"
            );

            println!("✓ Cipher suite detected: {}", report.cipher_suite);
        }
        Err(e) => {
            eprintln!("Warning: Could not connect to example.com: {}", e);
        }
    }
}

#[tokio::test]
async fn test_handshake_details() {
    match analyze_handshake("example.com", 443).await {
        Ok(report) => {
            let details = &report.handshake_details;
            assert!(
                !details.supported_versions.is_empty(),
                "Should have supported versions"
            );
            assert!(
                !details.signature_algorithms.is_empty(),
                "Should have signature algorithms"
            );

            println!(
                "✓ Handshake details captured: {} supported versions, {} signature algorithms",
                details.supported_versions.len(),
                details.signature_algorithms.len()
            );
        }
        Err(e) => {
            eprintln!("Warning: Could not connect to example.com: {}", e);
        }
    }
}

#[tokio::test]
async fn test_post_quantum_analysis() {
    match analyze_handshake("example.com", 443).await {
        Ok(report) => {
            let pqc = &report.post_quantum_analysis;

            assert!(
                !pqc.pqc_algorithms_available.is_empty(),
                "Should list PQC algorithms"
            );
            assert!(
                pqc.pqc_algorithms_available.len() >= 4,
                "Should list multiple PQC algorithms"
            );

            let readiness = &pqc.post_quantum_readiness;
            assert!(
                !readiness.recommendation.is_empty(),
                "Should have PQC recommendation"
            );

            println!(
                "✓ PQC Analysis: quantum_safe={}, hybrid_ready={}",
                readiness.quantum_safe, readiness.hybrid_ready
            );
            println!("  Recommendation: {}", readiness.recommendation);
        }
        Err(e) => {
            eprintln!("Warning: Could not connect to example.com: {}", e);
        }
    }
}

#[tokio::test]
async fn test_extracted_secrets_present() {
    match analyze_handshake("example.com", 443).await {
        Ok(report) => {
            assert!(
                report.extracted_secrets.is_some(),
                "Should extract traffic secrets"
            );

            if let Some(secrets) = &report.extracted_secrets {
                assert!(
                    !secrets.tx_secrets.key_hex.is_empty(),
                    "Should have TX secret key"
                );
                assert!(
                    !secrets.rx_secrets.key_hex.is_empty(),
                    "Should have RX secret key"
                );
                assert!(
                    !secrets.decryption_capabilities.can_decrypt.is_empty(),
                    "Should list decryption capabilities"
                );

                println!("✓ Secrets extraction: TX algorithm={}, RX algorithm={}",
                    secrets.tx_secrets.algorithm, secrets.rx_secrets.algorithm);
            }
        }
        Err(e) => {
            eprintln!("Warning: Could not connect to example.com: {}", e);
        }
    }
}

#[tokio::test]
async fn test_http_exchange_captured() {
    match analyze_handshake("example.com", 443).await {
        Ok(report) => {
            let http = &report.http_exchange;
            assert!(
                http.request.plaintext.size_bytes > 0,
                "Should capture HTTP request size"
            );
            assert!(
                http.response.plaintext.size_bytes > 0,
                "Should capture HTTP response size"
            );

            println!(
                "✓ HTTP exchange captured: request={} bytes, response={} bytes",
                http.request.plaintext.size_bytes, http.response.plaintext.size_bytes
            );
        }
        Err(e) => {
            eprintln!("Warning: Could not connect to example.com: {}", e);
        }
    }
}

#[tokio::test]
async fn test_invalid_host_error_handling() {
    let result = analyze_handshake("invalid-host-that-does-not-exist-12345.com", 443).await;

    match result {
        Err(_) => {
            println!("✓ Invalid host correctly returned error");
        }
        Ok(_) => {
            panic!("Should have failed for invalid host");
        }
    }
}

#[tokio::test]
async fn test_invalid_port_error_handling() {
    let result = analyze_handshake("example.com", 1).await;

    match result {
        Err(_) => {
            println!("✓ Invalid port correctly returned error");
        }
        Ok(_) => {
            eprintln!("Warning: Unexpected success on invalid port (network may have allowed it)");
        }
    }
}
