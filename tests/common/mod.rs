use tls_outputter::types::TLSAnalysisReport;

/// Verify that the report has all required fields
pub fn verify_report_structure(report: &TLSAnalysisReport) {
    assert!(!report.host.is_empty(), "host should not be empty");
    assert!(report.port > 0, "port should be valid");
    assert!(report.timestamp > 0, "timestamp should be set");
    assert!(!report.tls_version.is_empty(), "tls_version should be set");
    assert!(!report.cipher_suite.is_empty(), "cipher_suite should be set");
    assert!(!report.certificate_chain.is_empty(), "certificate_chain should not be empty");
}

/// Verify certificate chain structure
pub fn verify_certificate_chain(report: &TLSAnalysisReport) {
    for (idx, cert) in report.certificate_chain.iter().enumerate() {
        assert!(
            !cert.subject.is_empty(),
            "certificate {} subject should not be empty",
            idx
        );
        assert!(
            !cert.issuer.is_empty(),
            "certificate {} issuer should not be empty",
            idx
        );
        assert!(
            !cert.fingerprint_sha256.is_empty(),
            "certificate {} fingerprint should not be empty",
            idx
        );
        assert!(
            !cert.key_type.is_empty(),
            "certificate {} key_type should be set",
            idx
        );
    }
}

/// Verify encryption negotiation is properly filled
pub fn verify_encryption_negotiation(report: &TLSAnalysisReport) {
    let enc = &report.encryption_negotiation;
    assert!(!enc.cipher_suite_code.is_empty(), "cipher_suite_code should be set");
    assert!(!enc.cipher_suite_name.is_empty(), "cipher_suite_name should be set");
    assert!(!enc.encryption_algorithm.algorithm.is_empty(), "algorithm should be set");
    assert!(!enc.key_exchange.algorithm.is_empty(), "key_exchange should be set");
    assert!(enc.secret_derivation.derived_secrets.len() > 0, "should have derived secrets");
}

/// Verify handshake messages are captured
pub fn verify_handshake_messages(report: &TLSAnalysisReport) {
    assert!(
        !report.handshake_messages.is_empty(),
        "should capture handshake messages"
    );

    let message_types: Vec<&str> = report
        .handshake_messages
        .iter()
        .map(|m| m.message_type.as_str())
        .collect();

    assert!(
        message_types.contains(&"ClientHello"),
        "should capture ClientHello"
    );
    assert!(
        message_types.contains(&"ServerHello"),
        "should capture ServerHello"
    );
    assert!(
        message_types.contains(&"Certificate"),
        "should capture Certificate"
    );
}

/// Verify post-quantum analysis is present
pub fn verify_pqc_analysis(report: &TLSAnalysisReport) {
    let pqc = &report.post_quantum_analysis;
    assert!(
        !pqc.pqc_algorithms_available.is_empty(),
        "should list PQC algorithms"
    );
    assert!(
        !pqc.post_quantum_readiness.recommendation.is_empty(),
        "should have PQC recommendation"
    );
}

/// Verify that JSON serialization works
pub fn verify_json_serialization(report: &TLSAnalysisReport) {
    let json_str = serde_json::to_string(report)
        .expect("should serialize to JSON");

    let json_obj: serde_json::Value =
        serde_json::from_str(&json_str).expect("should deserialize from JSON");

    assert!(json_obj["host"].is_string(), "host should be in JSON");
    assert!(json_obj["tls_version"].is_string(), "tls_version should be in JSON");
    assert!(json_obj["cipher_suite"].is_string(), "cipher_suite should be in JSON");
    assert!(json_obj["certificate_chain"].is_array(), "certificate_chain should be array in JSON");
}

/// Test host that should succeed (fast, reliable)
#[allow(dead_code)]
pub fn test_host() -> &'static str {
    "example.com"
}

/// Test port for HTTPS
#[allow(dead_code)]
pub fn test_port() -> u16 {
    443
}
