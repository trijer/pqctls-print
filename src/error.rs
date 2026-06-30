use std::io;
use thiserror::Error;

/// Custom error type for TLS analysis operations
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum TlsError {
    /// Network connection errors
    #[error("Failed to connect to {host}:{port}: {source}")]
    ConnectionFailed {
        host: String,
        port: u16,
        source: io::Error,
    },

    /// Connection timed out
    #[error("Connection to {host}:{port} timed out")]
    ConnectionTimeout { host: String, port: u16 },

    /// DNS resolution failed
    #[error("Failed to resolve hostname: {host}")]
    DnsResolution { host: String },

    /// Connection refused by server
    #[error("Connection refused by {host}:{port}")]
    ConnectionRefused { host: String, port: u16 },

    /// Invalid server name format
    #[error("Invalid server name format: {name}")]
    InvalidServerName { name: String },

    /// TLS handshake failed
    #[error("TLS handshake failed: {reason}")]
    HandshakeFailed { reason: String },

    /// No server certificate received
    #[error("No server certificate received from {host}")]
    NoCertificateReceived { host: String },

    /// Empty certificate chain
    #[error("Server returned an empty certificate chain")]
    EmptyCertificateChain,

    /// Certificate parsing failed
    #[error("Failed to parse X.509 certificate")]
    CertificateParsing(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),

    /// Failed to add certificate to trust store
    #[error("Failed to add certificate to trust store: {reason}")]
    CertificateStoreError { reason: String },

    /// Failed to extract secrets from TLS connection
    #[error("Failed to extract traffic secrets: {reason}")]
    SecretExtraction { reason: String },

    /// JSON serialization error
    #[error("Failed to serialize to JSON: {0}")]
    JsonSerialization(#[from] serde_json::Error),

    /// IO error (file operations, socket operations)
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// System time error
    #[error("System time error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),

    /// Crypto provider initialization failed
    #[error("Failed to initialize rustls crypto provider")]
    CryptoProviderInit,

    /// Generic TLS protocol error
    #[error("TLS protocol error: {0}")]
    TlsProtocol(String),

    /// URL parsing error
    #[error("Invalid URL: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Generic error from anyhow (fallback for unsupported errors)
    #[error("Internal error: {0}")]
    Other(String),
}

impl From<rustls::Error> for TlsError {
    fn from(err: rustls::Error) -> Self {
        TlsError::TlsProtocol(err.to_string())
    }
}

impl From<anyhow::Error> for TlsError {
    fn from(err: anyhow::Error) -> Self {
        TlsError::Other(err.to_string())
    }
}

/// Result type alias for TLS operations
pub type Result<T> = std::result::Result<T, TlsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_failed_error() {
        let err = TlsError::ConnectionFailed {
            host: "example.com".to_string(),
            port: 443,
            source: io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused"),
        };
        assert!(err.to_string().contains("example.com"));
        assert!(err.to_string().contains("443"));
    }

    #[test]
    fn test_invalid_server_name_error() {
        let err = TlsError::InvalidServerName {
            name: "invalid..name".to_string(),
        };
        assert!(err.to_string().contains("Invalid server name"));
    }

    #[test]
    fn test_no_certificate_error() {
        let err = TlsError::NoCertificateReceived {
            host: "example.com".to_string(),
        };
        assert!(err.to_string().contains("No server certificate"));
    }

    #[test]
    fn test_error_chain_display() {
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let err = TlsError::ConnectionFailed {
            host: "slow.example.com".to_string(),
            port: 443,
            source: io_err,
        };
        let msg = err.to_string();
        assert!(msg.contains("slow.example.com"));
        assert!(msg.contains("443"));
    }
}
