mod tls;

use anyhow::Result;
use std::env;
use std::fs;
use std::path::PathBuf;
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls crypto provider"))?;

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <url>", args[0]);
        eprintln!("Example: {} https://example.com", args[0]);
        std::process::exit(1);
    }

    let url_str = &args[1];
    let url = Url::parse(url_str).map_err(|e| {
        anyhow::anyhow!("Failed to parse URL '{}': {}", url_str, e)
    })?;

    let host = url.host_str().ok_or_else(|| {
        anyhow::anyhow!("URL must include a host")
    })?;

    let port = url.port().unwrap_or(443);

    eprintln!("Connecting to {}:{}", host, port);

    let handshake_info = tls::analyze_handshake(host, port).await?;

    // Generate filename: tls_hostname_timestamp.json
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("tls_{}_{}.json", host, timestamp);
    let filepath = PathBuf::from(&filename);

    // Write JSON to file
    let json = serde_json::to_string_pretty(&handshake_info)?;
    fs::write(&filepath, &json)?;

    // Output human-readable summary to stdout
    print_human_readable(&handshake_info);

    eprintln!("\n✓ JSON output saved to: {}", filepath.display());

    Ok(())
}

fn print_human_readable(info: &tls::HandshakeInfo) {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║                   TLS HANDSHAKE ANALYSIS                        ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // Connection Info
    println!("📡 Connection Info");
    println!("  Host: {}", info.host);
    println!("  Port: {}", info.port);
    println!("  TLS Version: {}", info.tls_version);
    println!("  Cipher Suite: {}", info.cipher_suite);

    // Negotiated Details
    println!("\n🤝 Handshake Details");
    println!("  Supported Versions:");
    for v in &info.handshake_details.supported_versions {
        println!("    • {}", v);
    }
    println!("  Key Share: {}", info.handshake_details.key_share);
    println!("  Supported Groups:");
    for g in &info.handshake_details.supported_groups {
        println!("    • {}", g);
    }

    // Encryption
    println!("\n🔐 Encryption");
    println!("  Algorithm: {}", info.encryption_negotiation.encryption_algorithm.algorithm);
    if let Some(aead) = &info.encryption_negotiation.aead_details {
        println!("  AEAD: {}", aead.algorithm);
        println!("  Key Size: {} bits", aead.key_bits);
        println!("  Nonce Size: {} bits", aead.nonce_bits);
        println!("  Tag Size: {} bits", aead.tag_bits);
    }

    // Handshake Flow
    println!("\n📨 Handshake Message Flow ({} messages)", info.handshake_messages.len());
    for msg in &info.handshake_messages {
        let dir_symbol = if msg.direction.contains("Client") { "→" } else { "←" };
        println!("  [{}] {} {} ({} bytes)",
            msg.sequence, dir_symbol, msg.message_type, msg.size);
    }

    // Session Ticket
    println!("\n🎫 Session Resumption");
    println!("  Supported: {}", if info.session_ticket.is_session_resumption_supported {
        "Yes (TLS 1.3)"
    } else {
        "No"
    });
    println!("  Ticket Lifetime: {} seconds ({} days)",
        info.session_ticket.ticket_lifetime_seconds,
        info.session_ticket.ticket_lifetime_seconds / 86400);

    // Certificate
    println!("\n📜 Certificate Chain ({} certificates)", info.certificate_chain.len());
    for (i, cert) in info.certificate_chain.iter().enumerate() {
        println!("  [{}] {}", i + 1, cert.subject);
        println!("      Issuer: {}", cert.issuer);
        println!("      Valid: {} → {}", cert.not_before, cert.not_after);
    }

    // HTTP Exchange
    println!("\n💬 HTTP Exchange");
    println!("  Request Size (plaintext): {} bytes", info.http_exchange.request.plaintext.size_bytes);
    println!("  Request Size (encrypted): {} bytes", info.http_exchange.request.encrypted.total_encrypted_size);
    println!("  Response Size (plaintext): {} bytes", info.http_exchange.response.plaintext.size_bytes);
    println!("  Response Size (encrypted): {} bytes", info.http_exchange.response.encrypted.total_encrypted_size);

    let total_overhead = (info.http_exchange.request.encrypted.total_encrypted_size - info.http_exchange.request.plaintext.size_bytes) +
                        (info.http_exchange.response.encrypted.total_encrypted_size - info.http_exchange.response.plaintext.size_bytes);
    println!("  Total Encryption Overhead: {} bytes", total_overhead);

    println!("\n╚════════════════════════════════════════════════════════════════╝\n");
}
