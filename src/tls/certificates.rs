use rustls::pki_types::CertificateDer;
use x509_parser::prelude::*;
use asn1_rs::Oid;

use crate::error::Result;
use super::types::{CertificateInfo, ExtensionInfo};

pub fn parse_certificate_chain(certs: &[CertificateDer]) -> Result<Vec<CertificateInfo>> {
    let mut chain = Vec::new();

    for cert in certs {
        let parsed = parse_x509_cert(cert.as_ref())?;
        chain.push(parsed);
    }

    Ok(chain)
}

fn parse_x509_cert(cert_der: &[u8]) -> Result<CertificateInfo> {
    let (_, cert) = parse_x509_certificate(cert_der)?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    let not_before = format!("{}", cert.validity().not_before);
    let not_after = format!("{}", cert.validity().not_after);

    let serial_number = format!("{}", cert.serial);

    let fingerprint_sha256 = compute_sha256_fingerprint(cert_der);

    let (key_type, key_size) = extract_key_info(&cert)?;

    let subject_alt_names = extract_san(&cert)?;

    let extensions = extract_extensions(&cert)?;

    Ok(CertificateInfo {
        subject,
        issuer,
        not_before,
        not_after,
        serial_number,
        fingerprint_sha256,
        key_type,
        key_size,
        subject_alt_names,
        extensions,
    })
}

fn extract_key_info(cert: &X509Certificate) -> Result<(String, Option<usize>)> {
    let pk_algo = &cert.public_key().algorithm.algorithm;

    let key_type = match pk_algo.to_string().as_str() {
        "1.2.840.113549.1.1.1" | "rsaEncryption" => "RSA".to_string(),
        "1.2.840.10045.2.1" | "id-ecPublicKey" => "ECDSA".to_string(),
        "1.3.101.112" => "EdDSA (Ed25519)".to_string(),
        "1.3.101.111" => "EdDSA (Ed448)".to_string(),
        oid_str => format!("Other ({})", oid_str),
    };

    let key_size = match pk_algo.to_string().as_str() {
        "1.2.840.113549.1.1.1" | "rsaEncryption" => {
            let total_bytes = cert.public_key().raw.len();
            let der_overhead = 38;
            if total_bytes > der_overhead {
                Some((total_bytes - der_overhead) * 8)
            } else {
                Some(total_bytes * 8)
            }
        }
        "1.2.840.10045.2.1" | "id-ecPublicKey" => {
            let bits = cert.public_key().raw.len() * 8;
            match bits {
                264 => Some(256),
                392 => Some(384),
                528 => Some(521),
                _ => Some(bits),
            }
        }
        _ => None,
    };

    Ok((key_type, key_size))
}

fn compute_sha256_fingerprint(cert_der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
    digest
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn extract_san(cert: &X509Certificate) -> Result<Vec<String>> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut sans = Vec::new();

    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                GeneralName::DNSName(name) => {
                    sans.push(name.to_string());
                }
                GeneralName::IPAddress(ip) => {
                    let ip_str = if ip.len() == 4 {
                        let ipv4 = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                        format!("IP:{}", ipv4)
                    } else if ip.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&ip);
                        let ipv6 = Ipv6Addr::from(arr);
                        format!("IP:{}", ipv6)
                    } else {
                        format!("IP:(invalid length {})", ip.len())
                    };
                    sans.push(ip_str);
                }
                _ => {}
            }
        }
    }

    Ok(sans)
}

fn extract_extensions(cert: &X509Certificate) -> Result<Vec<ExtensionInfo>> {
    let mut extensions = Vec::new();

    for ext in cert.extensions() {
        extensions.push(ExtensionInfo {
            oid: ext.oid.to_string(),
            critical: ext.critical,
            name: get_extension_name(&ext.oid),
        });
    }

    Ok(extensions)
}

fn get_extension_name(oid: &Oid) -> String {
    match oid.to_string().as_str() {
        "2.5.29.14" => "Subject Key Identifier".to_string(),
        "2.5.29.15" => "Key Usage".to_string(),
        "2.5.29.19" => "Basic Constraints".to_string(),
        "2.5.29.31" => "CRL Distribution Points".to_string(),
        "2.5.29.32" => "Certificate Policies".to_string(),
        "2.5.29.35" => "Authority Key Identifier".to_string(),
        "1.3.6.1.5.5.7.1.1" => "Authority Information Access".to_string(),
        "2.5.29.37" => "Extended Key Usage".to_string(),
        "2.5.29.17" => "Subject Alternative Name".to_string(),
        _ => format!("Unknown ({})", oid),
    }
}
