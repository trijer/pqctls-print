mod error;
mod tls;

use error::Result;
use std::env;
use std::fs;
use std::path::PathBuf;
use url::Url;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
     // Initialize the subscriber to log formatted traces to stdout
     tracing_subscriber::fmt::init();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install aws-lc-rs crypto provider"))?;

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [--output-dir DIR] [--json] <url> [url2] [url3] ...", args[0]);
        eprintln!("Example: {} https://example.com https://google.com", args[0]);
        eprintln!("Example: {} --json --output-dir ./results https://example.com", args[0]);
        std::process::exit(1);
    }

    let (output_dir, url_strings, output_json) = parse_args(&args[1..])?;

    if url_strings.is_empty() {
        eprintln!("Error: No URLs provided");
        eprintln!("Usage: {} [--output-dir DIR] [--json] <url> [url2] [url3] ...", args[0]);
        std::process::exit(1);
    }

    fs::create_dir_all(&output_dir)?;

    let mut reports = Vec::new();

    // Analyze each URL
    for url_str in &url_strings {
        eprintln!("\n🔍 Analyzing: {}", url_str);

        match analyze_url(url_str).await {
            Ok((host, info)) => {
                if output_json {
                    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
                    let filename = format!("tls_{}_{}.json", host, timestamp);
                    let filepath = output_dir.join(&filename);
                    let json = serde_json::to_string_pretty(&info)?;
                    fs::write(&filepath, &json)?;
                    eprintln!("   ✓ Saved: {}", filepath.display());
                }

                reports.push(info);
            }
            Err(e) => {
                eprintln!("   ✗ Error: {}", e);
            }
        }
    }

    if reports.is_empty() {
        eprintln!("No successful analyses");
        return Ok(());
    }

    // Display comparison table
    println!("\n");
    print_comparison_table(&reports);

    // Save comparison JSON if requested
    if output_json {
        let comparison_json = serde_json::to_string_pretty(&reports)?;
        let comparison_file = format!("tls_comparison_{}.json", chrono::Local::now().format("%Y%m%d_%H%M%S"));
        let comparison_path = output_dir.join(&comparison_file);
        fs::write(&comparison_path, comparison_json)?;
        eprintln!("\n✓ Comparison JSON saved to: {}", comparison_path.display());
    }

    Ok(())
}

fn parse_args(args: &[String]) -> Result<(PathBuf, Vec<String>, bool)> {
    let mut output_dir = PathBuf::from(".");
    let mut urls = Vec::new();
    let mut output_json = false;
    let mut i = 0;

    while i < args.len() {
        if args[i] == "--output-dir" {
            if i + 1 >= args.len() {
                return Err(error::TlsError::Other(
                    "--output-dir requires a directory path".to_string(),
                ));
            }
            output_dir = PathBuf::from(&args[i + 1]);
            i += 2;
        } else if args[i] == "--json" {
            output_json = true;
            i += 1;
        } else if args[i].starts_with("--") {
            return Err(error::TlsError::Other(format!(
                "Unknown option: {}",
                args[i]
            )));
        } else {
            urls.push(args[i].clone());
            i += 1;
        }
    }

    Ok((output_dir, urls, output_json))
}

async fn analyze_url(url_str: &str) -> Result<(String, tls::TLSAnalysisReport)> {
    let url = Url::parse(url_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse URL '{}': {}", url_str, e))?;

    let host = url.host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must include a host"))?
        .to_string();

    let port = url.port().unwrap_or(443);

    let handshake_info = tls::analyze_handshake(&host, port).await?;
    Ok((host, handshake_info))
}

fn generate_cert_summary(cert: &tls::CertificateInfo, is_self_signed: bool) -> String {
    let mut parts = Vec::new();

    // Self-signed indicator
    if is_self_signed {
        parts.push("Self-Signed".to_string());
    }

    // Key type and size
    if let Some(size) = cert.key_size {
        parts.push(format!("{}-bit {}", size, cert.key_type));
    } else {
        parts.push(cert.key_type.clone());
    }

    // Extract common name from subject
    if let Some(cn_start) = cert.subject.find("CN=") {
        if let Some(cn_end) = cert.subject[cn_start..].find(',') {
            let cn = &cert.subject[cn_start + 3..cn_start + cn_end];
            parts.push(format!("CN={}", truncate(cn, 30)));
        } else {
            let cn = &cert.subject[cn_start + 3..];
            parts.push(format!("CN={}", truncate(cn, 30)));
        }
    }

    // SAN count
    if !cert.subject_alt_names.is_empty() {
        parts.push(format!("+{} SANs", cert.subject_alt_names.len()));
    }

    parts.join(" • ")
}

fn print_comparison_table(results: &[tls::TLSAnalysisReport]) {
    println!("╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                                TLS CONFIGURATION COMPARISON                                                                ║");
    println!("╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n");

    // Print header
    println!("{:<20} {:<15} {:<15} {:<20} {:<25}",
        "Host", "TLS Version", "Key Bits", "Session Resume", "PQC Ready");
    println!("{}", "─".repeat(95));

    // Print each result
    for info in results {
        let host = &info.host;
        let tls_ver = &info.tls_version;
        let key_bits = info.encryption_negotiation.aead_details
            .as_ref()
            .map(|a| a.key_bits.to_string())
            .unwrap_or_else(|| "N/A".to_string());
        let resumption = if info.session_ticket.is_session_resumption_supported {
            let days = info.session_ticket.ticket_lifetime_seconds / 86400;
            format!("Yes ({} days)", days)
        } else {
            "No".to_string()
        };
        let pqc = &info.post_quantum_analysis;
        let has_x25519_mlkem768 = tls::pqc::check_x25519_mlkem768_negotiated(&info.handshake_messages);
        let pqc_status = if pqc.post_quantum_readiness.quantum_safe {
            "✓ Quantum-Safe".to_string()
        } else if has_x25519_mlkem768 {
            "✓ X25519MLKEM768".to_string()
        } else if pqc.hybrid_ready {
            "~ Hybrid (partial)".to_string()
        } else if pqc.hybrid_approach_available {
            "⚠ Needs Hybrid".to_string()
        } else {
            "✗ Not Ready".to_string()
        };

        println!("{:<20} {:<15} {:<15} {:<20} {:<25}",
            truncate(host, 19),
            truncate(tls_ver, 14),
            key_bits,
            resumption,
            pqc_status);
    }

    println!("\n{}", "─".repeat(130));

    println!("\n📄 Certificate Chain Summary\n");

    // Print certificate details for entire chain
    for (idx, info) in results.iter().enumerate() {
        println!("{}. {} ({} certificates in chain)", idx + 1, info.host, info.certificate_chain.len());

        for (cert_idx, cert) in info.certificate_chain.iter().enumerate() {
            let cert_type = match cert_idx {
                0 => "🍃 Leaf",
                n if n == info.certificate_chain.len() - 1 => "🔑 Root",
                _ => "🔗 Intermediate",
            };

            let is_self_signed = cert.subject == cert.issuer;
            let cert_summary = generate_cert_summary(cert, is_self_signed);

            println!();
            println!("   {} Certificate #{}: {}", cert_type, cert_idx + 1, cert_summary);
            println!("   ├─ Subject: {}", truncate(&cert.subject, 80));
            println!("   ├─ Issuer:  {}", truncate(&cert.issuer, 80));

            if !cert.subject_alt_names.is_empty() {
                print!("   └─ SANs:    ");
                for (i, san) in cert.subject_alt_names.iter().enumerate() {
                    if i > 0 { print!(", "); }
                    print!("{}", truncate(san, 35));
                }
                println!();
            }
        }

        println!();
    }

    println!("🔐 Encryption Details\n");

    // Print encryption details
    for (idx, info) in results.iter().enumerate() {
        println!("{}. {}", idx + 1, info.host);
        println!("   Algorithm: {}", info.encryption_negotiation.encryption_algorithm.algorithm);
        if let Some(aead) = &info.encryption_negotiation.aead_details {
            println!("   AEAD:     {}", aead.algorithm);
            println!("   Key:      {} bits", aead.key_bits);
            println!("   Nonce:    {} bits", aead.nonce_bits);
            println!("   Tag:      {} bits", aead.tag_bits);
        }
        println!();
    }

    println!("📨 Handshake Message Flow\n");

    // Print handshake stats
    for (idx, info) in results.iter().enumerate() {
        println!("{}. {} ({} messages)", idx + 1, info.host, info.handshake_messages.len());

        let mut client_msgs = 0;
        let mut server_msgs = 0;
        let mut total_size = 0;

        for msg in &info.handshake_messages {
            if msg.direction.starts_with("Client") {
                client_msgs += 1;
            } else {
                server_msgs += 1;
            }
            total_size += msg.size;
        }

        println!("   Client → Server: {} messages", client_msgs);
        println!("   Server → Client: {} messages", server_msgs);
        println!("   Total Size:      {} bytes", total_size);
        println!();
    }

    println!("\n🔐 Post-Quantum Cryptography Readiness\n");

    // Print PQC analysis
    for (idx, info) in results.iter().enumerate() {
        let pq = &info.post_quantum_analysis;
        println!("{}. {} (Quantum-Safe: {})",
            idx + 1,
            info.host,
            if pq.post_quantum_readiness.quantum_safe { "✓ Yes" } else { "✗ No" });

        println!("   Status: {}", pq.post_quantum_readiness.recommendation);
        println!("   Recommended: {}", &pq.hybrid_key_exchange.post_quantum_key_agreement.recommended);
        println!("   Timeline: {}", &pq.migration_strategy.timeline);
        println!();
    }

    println!("\n🔑 Extracted Session Secrets (dangerous_extract_secrets)\n");

    // Print extracted secrets
    for (idx, info) in results.iter().enumerate() {
        if let Some(secrets) = &info.extracted_secrets {
            println!("{}. {}", idx + 1, info.host);
            println!("   Note: {}", secrets.note);
            println!();
            println!("   TX (Transmit) Secrets:");
            println!("   ├─ Sequence #: {}", secrets.tx_secrets.sequence_number);
            println!("   ├─ Algorithm:  {}", secrets.tx_secrets.algorithm);
            println!("   ├─ Key ({}b):  {}", secrets.tx_secrets.key_size_bits, secrets.tx_secrets.key_hex);
            println!("   └─ IV (96b):   {}", secrets.tx_secrets.iv_hex);
            println!();
            println!("   RX (Receive) Secrets:");
            println!("   ├─ Sequence #: {}", secrets.rx_secrets.sequence_number);
            println!("   ├─ Algorithm:  {}", secrets.rx_secrets.algorithm);
            println!("   ├─ Key ({}b):  {}", secrets.rx_secrets.key_size_bits, secrets.rx_secrets.key_hex);
            println!("   └─ IV (96b):   {}", secrets.rx_secrets.iv_hex);
            println!();
            println!("   Decryption Capabilities:");
            println!("   ╔ Can Decrypt:");
            for capability in &secrets.decryption_capabilities.can_decrypt {
                println!("   ║  {}", capability);
            }
            println!("   ╠ Cannot Decrypt:");
            for limitation in &secrets.decryption_capabilities.cannot_decrypt {
                println!("   ║  {}", limitation);
            }
            println!("   ╚ Why: {}", secrets.decryption_capabilities.explanation);
            println!();
        }
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    if max_len < 3 {
        return s.to_string();
    }
    let target_len = max_len - 3;
    let mut truncated = String::new();
    for (idx, ch) in s.char_indices() {
        if idx >= target_len {
            break;
        }
        truncated.push(ch);
    }
    format!("{}...", truncated)
}
