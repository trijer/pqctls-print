mod tls;

use anyhow::Result;
use std::env;
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
    let json = serde_json::to_string_pretty(&handshake_info)?;
    println!("{}", json);

    Ok(())
}
