# Hybrid Post-Quantum Cryptography Guide

## Overview

This guide explains the post-quantum cryptography (PQC) readiness indicators shown by the TLS Outputter and what they mean for your infrastructure's quantum-safe migration strategy.

## Understanding the PQC Status Indicators

The TLS Outputter displays three PQC readiness levels:

### ✓ Quantum-Safe

**Status:** Server natively supports post-quantum cryptography in TLS handshake

**What it means:**
- Server implements RFC 9440 (Hybrid Post-Quantum TLS 1.3)
- Server actively participates in hybrid key exchange
- Both client and server use classical + PQC algorithms
- Full quantum-safe protection from both sides

**Server capabilities:**
- Sends PQC key shares (e.g., `kem_kyber768_ecdhe_x25519`)
- Negotiates hybrid cipher suites
- Derives hybrid shared secrets with client
- Validates PQC signatures

**Example flow:**
```
ClientHello:
  key_share: [X25519 pubkey, Kyber768 pubkey]

ServerHello:
  key_share: [X25519 pubkey, Kyber768 ciphertext]
  selected_group: kem_kyber768_ecdhe_x25519

Handshake secret derivation:
  HKDF-Expand(PRK, info || 
              X25519_shared_secret || 
              Kyber768_shared_secret)
```

**Timeline:**
- Expected: 2025-2026
- Depends on: NIST PQC standardization (FIPS 203/204)
- Implementations: OpenSSL, rustls, AWS TLS 1.3, others

**Action required:** Wait for server to upgrade

---

### ~ Hybrid Ready

**Status:** Server supports modern TLS but hasn't yet implemented native PQC

**What it means:**
- Server uses TLS 1.3 with strong classical key exchange (ECDHE)
- Client CAN implement hybrid protection independently
- Server doesn't need to know about or support PQC
- Protection is backward compatible

**Why it's "ready":**
- Modern ECDHE (X25519, P-256) provides strong classical foundation
- Client can perform PQC key agreement locally without server changes
- Hybrid secrets can be derived on client side
- Server continues to work normally—no changes needed

**Client-side hybrid approach:**
```
Step 1: Classical TLS 1.3 handshake
  Client ↔ Server (ECDHE-X25519)
  → classical_shared_secret (256-bit)

Step 2: Client generates PQC keypair locally
  Client generates Kyber768 keypair
  Client performs key encapsulation
  → pqc_shared_secret (256-bit)

Step 3: Hybrid secret derivation
  HKDF-Expand(PRK, info || 
              classical_shared_secret || 
              pqc_shared_secret)
  → hybrid_traffic_secret

Step 4: Use hybrid secret for symmetric encryption
  All record layer encryption uses hybrid secret
```

**Advantages:**
- ✓ Protects against future quantum threats
- ✓ Works with current servers (zero changes)
- ✓ No compatibility issues
- ✓ Can implement now, not 2025

**Limitations:**
- ~ Server doesn't validate PQC components
- ~ Full quantum-safe only if implementation is correct
- ~ Requires client-side PQC implementation

**Server requirements:**
- TLS 1.3
- ECDHE key exchange (or equivalent)
- Modern certificate (2048+ bit RSA or ECDSA)
- Likely: Almost ALL modern servers (2020+)

**Timeline:**
- Available: Now (client implementation needed)
- Can coexist: With quantum-safe servers later
- Migration path: From hybrid → full quantum-safe

**Action required:** Implement client-side PQC (Phase 1: 2024)

---

### ✗ Not Ready

**Status:** Server doesn't support modern key exchange suitable for hybrid protection

**What it means:**
- Server uses old/weak cryptography
- Cannot reliably add hybrid protection on client side
- Needs server upgrade before quantum-safe protection possible
- Vulnerable to both classical attacks AND quantum threats

**Examples of "Not Ready":**
- TLS 1.2 with RSA key exchange (no forward secrecy)
- Static Diffie-Hellman (no ephemeral secrets)
- Very small elliptic curves (< 224-bit)
- No perfect forward secrecy
- Pre-TLS 1.3 protocols

**Why it's problematic:**

| Issue | Impact |
|-------|--------|
| RSA key exchange | Key compromise reveals all past traffic |
| Static Diffie-Hellman | Long-term key used for every session |
| Weak curves | Vulnerable to classical attacks first |
| No forward secrecy | Quantum computer breaks all recorded sessions |
| Old protocols | Multiple attack vectors |

**Timeline for harvest-now-decrypt-later attacks:**
```
Year 2024: Attacker records encrypted traffic
Year 2035: Quantum computer breaks RSA/ECDH
Result: All 11 years of recorded data decrypted
```

**Server requirements to move to "Hybrid Ready":**
- Upgrade to TLS 1.3
- Enable ECDHE (X25519 or P-256)
- Use modern certificate authority
- Disable RSA-only key exchange
- No static Diffie-Hellman

**Action required:** Upgrade server immediately (high priority)

---

## Visual Comparison

### Status Indicators at a Glance

```
✓ Quantum-Safe          ~ Hybrid Ready          ✗ Not Ready
├─ Native PQC support   ├─ Modern ECDHE         ├─ Old protocols
├─ RFC 9440             ├─ Client-side hybrid   ├─ Weak ciphers
├─ Both sides ready     ├─ Works today          ├─ Vulnerable
├─ 2025+ servers        ├─ Current servers      ├─ Needs upgrade
└─ Full protection      └─ Interim protection   └─ No protection
```

### Security Timeline

```
Pre-2000                2010s                   2024              2026+
──────────────────────────────────────────────────────────────────────────
RSA/DH only      TLS 1.3 + ECDHE      Hybrid PQC ready   Native PQC
(vulnerable)     (classical safe)     (interim solution) (quantum-safe)
                                      ↑
                                  You are here
```

---

## Implementation Timeline

### Phase 1: NOW (2024) - Hybrid Ready

**Client-side hybrid implementation:**
1. Generate Kyber768 keypair locally
2. Perform ECDHE key agreement with server (classical)
3. Perform Kyber key encapsulation locally (PQC)
4. Combine both secrets: `HKDF-Expand(PRK, ... || classical || pqc)`
5. Use hybrid secret for all encryption

**Benefit:** Quantum-safe protection without server changes

**Implementation effort:** Medium (need PQC library)

```
Server TLS 1.3 + ECDHE
           ↓
Client hybrid layer
  ├─ Classical: ECDHE
  └─ Post-quantum: Kyber768
           ↓
Hybrid encryption
```

### Phase 2: 2025-2026 - Transition to Native PQC

**Wait for:**
- NIST finalization (FIPS 203/204)
- Server implementations (OpenSSL, rustls, etc.)
- RFC 9440 widespread adoption

**Action:**
- Deploy servers with PQC support
- Test hybrid cipher suites in staging
- Plan gradual rollout to production

**Example hybrid cipher suite:**
```
TLS_ECDHE_X25519_KYBER768_WITH_AES_256_GCM_SHA384
├─ ECDHE-X25519: Classical 128-bit security
├─ KYBER768: Post-quantum 192-bit security  
└─ AES-256-GCM: Symmetric encryption
```

### Phase 3: 2026+ - Full Quantum-Safe

**Target state:**
- All servers support native PQC
- Hybrid cipher suites standard
- Classical-only suites deprecated (but supported)
- Full quantum-safe by design

---

## Comparison Table: What Each Status Means

| Aspect | ✓ Quantum-Safe | ~ Hybrid Ready | ✗ Not Ready |
|--------|---|---|---|
| **Server Support** | RFC 9440 (2025+) | TLS 1.3 + ECDHE (now) | Old protocols (pre-2020) |
| **Key Exchange** | Hybrid (native) | Classical only | Weak or static |
| **PQC Algorithms** | Kyber + Dilithium | Client-generated locally | None |
| **Protection** | Full quantum-safe | Interim hybrid | None |
| **Compatibility** | With hybrid servers | All TLS 1.3 servers | Breaks some clients |
| **Implementation** | Server-side | Client-side | Server-side upgrade |
| **Timeline** | 2025-2026 | 2024 (NOW) | Immediate upgrade |
| **Action** | Wait/plan | Implement client PQC | Upgrade server ASAP |
| **Current Status** | ~0% of servers | ~95% of servers | ~5% of servers |

---

## Real-World Examples

### Example 1: Google (Hybrid Ready ~)

```json
{
  "host": "google.com",
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS13_AES_256_GCM_SHA384",
  "key_exchange": "ECDHE-X25519",
  "pqc_readiness": "~ Hybrid Ready",
  "recommendation": "Implement client-side Kyber768 now"
}
```

**Why Hybrid Ready:**
- ✓ TLS 1.3 with perfect forward secrecy
- ✓ Strong ECDHE-X25519 key exchange
- ✓ Modern encryption (AES-256-GCM)
- ✓ No server changes needed to add hybrid protection

**Action:** Client can add Kyber768 locally for quantum-safe protection

---

### Example 2: Legacy Server (Not Ready ✗)

```json
{
  "host": "oldserver.legacy",
  "tls_version": "TLS 1.2",
  "cipher_suite": "RSA_WITH_AES_256_CBC_SHA",
  "key_exchange": "RSA",
  "pqc_readiness": "✗ Not Ready",
  "recommendation": "Upgrade to TLS 1.3 ASAP"
}
```

**Why Not Ready:**
- ✗ TLS 1.2 (old protocol)
- ✗ RSA key exchange (no forward secrecy)
- ✗ Vulnerable to harvest-now-decrypt-later attacks
- ✗ Cannot safely add hybrid protection

**Action:** Upgrade server to TLS 1.3 immediately (security risk)

---

### Example 3: Future Server (Quantum-Safe ✓)

```json
{
  "host": "future.quantumsafe.com",
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS13_ECDHE_X25519_KYBER768_WITH_AES_256_GCM_SHA384",
  "key_exchange": "ECDHE-X25519 + KYBER768",
  "pqc_readiness": "✓ Quantum-Safe",
  "recommendation": "Native quantum-safe protection active"
}
```

**Why Quantum-Safe:**
- ✓ RFC 9440 hybrid TLS 1.3
- ✓ Both classical and PQC key exchange
- ✓ Server validates PQC components
- ✓ Full quantum-safe from both sides

**Action:** No changes needed—already protected

---

## Migration Checklist

### For "Hybrid Ready" Servers (Do Now - Phase 1)

- [ ] Audit current TLS configurations
- [ ] Identify servers showing "~ Hybrid Ready"
- [ ] Select PQC library (liboqs, OQS, etc.)
- [ ] Implement client-side Kyber768
- [ ] Test hybrid secret derivation
- [ ] Deploy in staging environment
- [ ] Monitor performance impact
- [ ] Roll out to production

### For "Not Ready" Servers (Do ASAP - High Priority)

- [ ] Create inventory of "✗ Not Ready" servers
- [ ] Prioritize by traffic volume
- [ ] Plan TLS 1.3 upgrade
- [ ] Test in staging first
- [ ] Update certificates
- [ ] Deploy with ECDHE enabled
- [ ] Remove RSA-only suites
- [ ] Verify all clients work
- [ ] Re-run TLS Outputter to confirm upgrade

### For Future "Quantum-Safe" (Monitor - Phase 2)

- [ ] Watch NIST PQC timeline
- [ ] Monitor OpenSSL/rustls releases
- [ ] Test RFC 9440 in labs (2025+)
- [ ] Plan server upgrade path
- [ ] Update certificates with PQC support
- [ ] Deploy to staging (2025-2026)
- [ ] Plan production rollout

---

## Key Takeaways

1. **Hybrid Ready (~)** = Safe NOW with client-side PQC implementation
2. **Quantum-Safe (✓)** = Safe FUTURE when servers support RFC 9440
3. **Not Ready (✗)** = Urgent server upgrade needed (security risk)

**The three-step journey:**
```
Now (2024)              Mid-term (2025-2026)    Future (2026+)
Hybrid Ready       →    Deploy Native PQC   →   All Quantum-Safe
(client-side)          (server + client)        (standard)
```

**Start here:** Check which servers are "~ Hybrid Ready" and implement Phase 1 client-side hybrid protection now!

---

## Resources

- **NIST PQC Standardization:** https://csrc.nist.gov/projects/post-quantum-cryptography/
- **RFC 9440:** Hybrid Post-Quantum TLS 1.3
- **Kyber:** ML-KEM (FIPS 203)
- **Dilithium:** ML-DSA (FIPS 204)
- **OQS (Open Quantum Safe):** https://openquantumsafe.org/
- **liboqs-rs:** Rust bindings for liboqs

---

## Questions?

For questions about your specific servers:
```bash
./target/release/tls-outputter https://example.com https://google.com
```

This will show you exactly where each server stands in the quantum-safe journey!
