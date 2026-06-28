# TLS Outputter

A Rust application that analyzes TLS handshakes by connecting to URLs and outputting detailed information about the TLS negotiation. Perfect for learning TLS internals, security audits, and compliance checks.

## Features

- **Single & Multiple URL Analysis** - Analyze one or multiple domains in a single run
- **Complete Handshake Tracking** - Capture all 9 TLS 1.3 handshake messages with directions
- **Encryption Details** - View cipher suite, key size, nonce, and AEAD tag information
- **Secret Derivation** - See how encryption secrets are derived (8-step KDF tree)
- **Session Resumption** - Display session tickets and PSK information
- **Certificate Chain** - Complete X.509 certificate analysis from leaf to root
- **HTTP Exchange** - Capture HTTP request/response with encryption overhead analysis
- **Comparison Table** - Side-by-side TLS configuration comparison across domains
- **Dual Output** - Human-readable summary + JSON for programmatic analysis

## Building

### Prerequisites
- Rust 1.70+ (install from https://rustup.rs/)
- Linux, macOS, or Windows

### Build Release Binary
```bash
cargo build --release
```

Binary will be at: `target/release/tls-outputter`

## Usage

### Single URL
```bash
./target/release/tls-outputter https://example.com
```

### Multiple URLs (Comparison Mode)
```bash
./target/release/tls-outputter https://example.com https://google.com https://github.com
```

## Output

### 1. Console Summary
Displays formatted human-readable output with:
- **📡 Connection Info** - Host, port, TLS version, cipher suite
- **🤝 Handshake Details** - Supported versions, key share, groups, algorithms
- **🔐 Encryption** - Algorithm, AEAD parameters (key size, nonce, tag)
- **📨 Handshake Message Flow** - All 9 messages with directions (→ client, ← server)
- **🎫 Session Resumption** - Ticket support and lifetime
- **📜 Certificate Chain** - Complete chain with subject, issuer, SANs
- **💬 HTTP Exchange** - Request/response sizes and encryption overhead

### 2. JSON Files
Two types of JSON output are automatically generated:

#### Individual Analysis
- **Filename**: `tls_<hostname>_<YYYYMMDD_HHMMSS>.json`
- **Size**: ~17KB typical
- **Content**: Complete TLS analysis including:
  - Full handshake messages with descriptions
  - Encryption negotiation details
  - Secret derivation tree
  - Session ticket info
  - Certificate chain details
  - HTTP exchange capture

#### Comparison Summary (Multiple URLs only)
- **Filename**: `tls_comparison_<YYYYMMDD_HHMMSS>.json`
- **Content**: Array of all analyses for scripting and reporting

## Example Output

### Console (Single Domain)
```
📡 Connection Info
  Host: example.com
  Port: 443
  TLS Version: TLS 1.3 (0x0304)
  Cipher Suite: TLS13_AES_256_GCM_SHA384 (0x1302)

🔐 Encryption
  Algorithm: AES
  AEAD: AES-256-GCM
  Key Size: 256 bits
  Nonce Size: 96 bits
  Tag Size: 128 bits

📨 Handshake Message Flow (9 messages)
  [0] → ClientHello (233 bytes)
  [1] ← ServerHello (122 bytes)
  [2] ← ChangeCipherSpec (1 bytes)
  [3] → ChangeCipherSpec (1 bytes)
  [4] ← EncryptedExtensions (0 bytes)
  [5] ← Certificate (0 bytes)
  [6] ← CertificateVerify (0 bytes)
  [7] ← Finished (0 bytes)
  [8] → Finished (0 bytes)

📜 Certificate Chain (4 certificates)
   🍃 Leaf Certificate #1: 2048-bit RSA/EC • CN=example.com • +2 SANs
   ├─ Subject: CN=example.com
   ├─ Issuer:  C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
   └─ SANs:    example.com, *.example.com

   🔗 Intermediate Certificate #2: 2048-bit RSA/EC • CN=Cloudflare TLS ...
   ├─ Subject: C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
   └─ Issuer:  C=US, O=SSL Corporation, CN=SSL.com TLS Transit ECC CA R2

   🔑 Root Certificate #4: 2048-bit RSA/EC • CN=SSL.com TLS ECC Root CA 2022
   ├─ Subject: C=US, O=SSL Corporation, CN=SSL.com TLS ECC Root CA 2022
   └─ Issuer:  C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA...
```

### Comparison Table (Multiple Domains)
```
Host                 TLS Version     Cipher Suite                        Key Bits
─────────────────────────────────────────────────────────────────────────────────
example.com          TLS 1.3 (0x...  TLS13_AES_256_GCM_SHA384 (0x1302)   256
google.com           TLS 1.3 (0x...  TLS13_AES_256_GCM_SHA384 (0x1302)   256
github.com           TLS 1.3 (0x...  TLS13_AES_128_GCM_SHA256 (0x1301)   128
```

## Use Cases

### 1. **Security Audit**
Compare TLS configurations across your organization's domains:
```bash
./tls-outputter https://api.example.com https://web.example.com https://admin.example.com
```
Quickly spot:
- Mismatched cipher suites
- Missing intermediates
- Certificate expiration dates
- Supported TLS versions

### 2. **Compliance Check**
Verify minimum TLS standards:
- All connections use TLS 1.3
- Minimum key size (256 bits for AES-GCM)
- Proper certificate chains
- Session resumption support

### 3. **TLS Learning**
Understand TLS 1.3 protocol:
- See exact handshake message sequence
- Understand encryption secret derivation
- Learn about key share negotiation
- Explore certificate chain validation

### 4. **Troubleshooting**
Debug TLS issues:
- Verify handshake completes successfully
- Check encryption parameters
- Inspect certificate details
- Analyze message flow

### 5. **Reporting**
Generate compliance reports:
- Use JSON output for scripts/tools
- Create comparison tables
- Track configuration over time
- Generate audit logs

## Technical Details

### Supported TLS Versions
- TLS 1.3 (full support)
- TLS 1.2 (compatible, but optimized for 1.3)

### Message Types Captured
1. ClientHello - Client initiates handshake
2. ServerHello - Server responds with selected parameters
3. ChangeCipherSpec - Cipher change notification
4. EncryptedExtensions - Server's encrypted extensions
5. Certificate - Server's certificate chain
6. CertificateVerify - Server's signature
7. Finished - Server's handshake verification
8. Finished - Client's handshake verification

### Arrow Directions
- **→** Client to Server (client sends)
- **←** Server to Client (server sends)

### Secret Derivation Tree
Shows all 8 secrets derived during handshake:
1. Early Secret
2. Handshake Secret
3. Client Handshake Traffic Secret
4. Server Handshake Traffic Secret
5. Client Application Traffic Secret
6. Server Application Traffic Secret
7. Master Secret
8. Exporter Master Secret

## Dependencies

- **rustls** (0.23) - TLS protocol implementation
- **tokio** (1.x) - Async runtime
- **x509-parser** (0.16) - X.509 certificate parsing
- **serde/serde_json** - JSON serialization
- **ring** (0.17) - Cryptographic operations
- **chrono** (0.4) - Timestamp generation

## Performance

- Single URL analysis: ~1-2 seconds
- Three domain comparison: ~3-5 seconds
- Network I/O bound (not CPU bound)

## Limitations

- Analysis requires successful TLS connection
- Subject to network latency
- Does not perform in-depth security scanning (use testssl.sh for that)
- Cannot decrypt TLS 1.3 application data (by design)

## Troubleshooting

### "Failed to parse URL"
Ensure URL is complete: `https://example.com` (not `example.com`)

### "Connection refused"
Check that the host is reachable and accepts HTTPS connections

### "Certificate verification failed"
This is expected for self-signed certificates or incomplete chains. The tool displays the chain anyway.

### No JSON file created
Check write permissions in current working directory

## Related Tools

- **testssl.sh** - Comprehensive TLS security scanner
- **Wireshark** - Network protocol analyzer
- **openssl s_client** - Command-line TLS client
- **nmap --script** - SSL/TLS scanning

## License

Educational tool - use for authorized security testing and learning only.

## Educational Purpose

This tool is designed for:
- Learning TLS 1.3 protocol internals
- Understanding cryptographic handshakes
- Security education and training
- Authorized security testing
- Compliance verification

**Not intended to replace:** testssl.sh, Wireshark, or professional security tools.
