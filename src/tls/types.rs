use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TLSAnalysisReport {
    pub host: String,
    pub port: u16,
    pub timestamp: u64,
    pub tls_version: String,
    pub cipher_suite: String,
    pub handshake_details: HandshakeDetails,
    pub handshake_messages: HandshakeFlow,
    pub encryption_negotiation: EncryptionNegotiation,
    pub http_exchange: HttpExchange,
    pub certificate_chain: Vec<CertificateInfo>,
    pub post_quantum_analysis: PostQuantumAnalysis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_secrets: Option<ExtractedSecretsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decryption_debug: Option<DecryptionDebugInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HandshakeFlow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_hello: Option<HandshakeMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_hello: Option<HandshakeMessage>,
    pub subsequent_messages: Vec<HandshakeMessage>,
}

impl HandshakeFlow {
    #[allow(dead_code)]
    pub fn all_messages(&self) -> Vec<HandshakeMessage> {
        let mut messages = Vec::new();
        if let Some(ch) = &self.client_hello {
            messages.push(ch.clone());
        }
        if let Some(sh) = &self.server_hello {
            messages.push(sh.clone());
        }
        messages.extend(self.subsequent_messages.clone());
        messages
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptionDebugInfo {
    pub total_encrypted_records_captured: usize,
    pub encrypted_from_server: usize,
    pub encrypted_from_client: usize,
    pub successfully_decrypted: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractedSecretsInfo {
    pub note: String,
    pub tx_secrets: TrafficSecretsInfo,
    pub rx_secrets: TrafficSecretsInfo,
    pub decryption_capabilities: DecryptionCapabilities,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptionCapabilities {
    pub can_decrypt: Vec<String>,
    pub cannot_decrypt: Vec<String>,
    pub explanation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrafficSecretsInfo {
    pub sequence_number: u64,
    pub algorithm: String,
    pub key_hex: String,
    pub iv_hex: String,
    pub key_size_bits: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HandshakeMessage {
    pub sequence: usize,
    pub direction: String,
    pub message_type: String,
    pub size: usize,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<std::collections::HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub inferred: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeDetails {
    pub supported_versions: Vec<String>,
    pub key_share: String,
    pub signature_algorithms: Vec<String>,
    pub supported_groups: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpExchange {
    pub request: HttpMessage,
    pub response: HttpMessage,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpMessage {
    pub plaintext: PlaintextData,
    pub encrypted: EncryptedData,
    pub encryption_analysis: EncryptionAnalysis,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlaintextData {
    pub content: String,
    pub size_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    pub tls_record_type: String,
    pub tls_record_type_code: u8,
    pub ciphertext_preview: String,
    pub total_encrypted_size: usize,
    pub content_type_in_record: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionAnalysis {
    pub encryption_overhead: usize,
    pub record_header_size: usize,
    pub authentication_tag_size: usize,
    pub content_type_byte: usize,
    pub content_type_padding: String,
    pub total_size_with_record_header: usize,
    pub encryption_note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionNegotiation {
    pub cipher_suite_code: String,
    pub cipher_suite_name: String,
    pub encryption_algorithm: CipherAlgorithm,
    pub mac_algorithm: Option<MacAlgorithm>,
    pub aead_details: Option<AeadDetails>,
    pub key_exchange: KeyExchangeDetails,
    pub signature_algorithm: String,
    pub secret_derivation: SecretDerivation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretDerivation {
    pub client_random: String,
    pub server_random: String,
    pub randoms_combined_length: usize,
    pub key_derivation_function: String,
    pub prf_hash_algorithm: String,
    pub derived_secrets: Vec<DerivedSecret>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CipherAlgorithm {
    pub algorithm: String,
    pub mode: String,
    pub key_bits: usize,
    pub block_size: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MacAlgorithm {
    pub algorithm: String,
    pub hash_bits: usize,
    pub output_bits: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AeadDetails {
    pub algorithm: String,
    pub key_bits: usize,
    pub nonce_bits: usize,
    pub tag_bits: usize,
    pub plaintext_record_size_limit: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExchangeDetails {
    pub algorithm: String,
    pub group: String,
    pub forward_secrecy: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DerivedSecret {
    pub name: String,
    pub purpose: String,
    pub length_bits: usize,
    pub kdf_formula: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
    pub fingerprint_sha256: String,
    pub key_type: String,
    pub key_size: Option<usize>,
    pub subject_alt_names: Vec<String>,
    pub extensions: Vec<ExtensionInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtensionInfo {
    pub oid: String,
    pub critical: bool,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostQuantumAnalysis {
    pub hybrid_ready: bool,
    pub hybrid_approach_available: bool,
    pub pqc_algorithms_available: Vec<String>,
    pub recommended_hybrid_suites: Vec<String>,
    pub hybrid_key_exchange: HybridKeyExchange,
    pub post_quantum_readiness: PostQuantumReadiness,
    pub migration_strategy: MigrationStrategy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HybridKeyExchange {
    pub classical_key_agreement: ClassicalKeyAgreement,
    pub post_quantum_key_agreement: PostQuantumKeyAgreement,
    pub hybrid_secret_derivation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClassicalKeyAgreement {
    pub algorithm: String,
    pub curve: String,
    pub key_size_bits: usize,
    pub estimated_security_bits: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostQuantumKeyAgreement {
    pub algorithms: Vec<PQCAlgorithm>,
    pub recommended: String,
    pub hybrid_with_classical: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PQCAlgorithm {
    pub name: String,
    pub family: String,
    pub key_size_bits: usize,
    pub ciphertext_size_bits: usize,
    pub shared_secret_size_bits: usize,
    pub estimated_quantum_security_bits: usize,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostQuantumReadiness {
    pub quantum_safe: bool,
    pub hybrid_ready: bool,
    pub pqc_key_exchange_offered: bool,
    pub pqc_signature_offered: bool,
    pub recommendation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationStrategy {
    pub current_security_level: String,
    pub post_quantum_security_level: String,
    pub implementation_priority: String,
    pub timeline: String,
    pub action_items: Vec<String>,
}
