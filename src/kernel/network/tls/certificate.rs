//! src/kernel/network/tls/certificate.rs
//!
//! Minimal X.509 v3 certificate parser (DER-encoded).
//!
//! Extracts the fields needed for TLS 1.3 server certificate validation:
//! subject CN, issuer CN, validity period, and public key algorithm.
//!
//! This is a hand-rolled ASN.1 DER parser — no external crates.  It handles
//! the subset of ASN.1 needed to decode typical web PKI certificates.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// OID for RSA encryption (1.2.840.113549.1.1.1).
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// OID for id-ecPublicKey (1.2.840.10045.2.1) — the SPKI algorithm for EC keys.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// OID for ECDSA with SHA-256 (1.2.840.10045.4.3.2).
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// OID for ECDSA with SHA-384 (1.2.840.10045.4.3.3).
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
// OID for SHA-256 with RSA; constructed in test certificates.
/// OID for SHA-256 with RSA (1.2.840.113549.1.1.11).
const OID_SHA256_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

// ── ASN.1 tag constants ────────────────────────────────────────────────────

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
// ASN.1 NULL tag; used in test certificates.
#[cfg_attr(not(test), allow(dead_code))]
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_PRINTABLE_STRING: u8 = 0x13;
const TAG_IA5_STRING: u8 = 0x16;
const TAG_UTC_TIME: u8 = 0x17;
// ASN.1 tag for GeneralizedTime; both UTCTime and GeneralizedTime are handled.
#[allow(dead_code)]
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;

// ── Public types ───────────────────────────────────────────────────────────

/// A parsed X.509 v3 certificate.
#[derive(Debug, Clone)]
pub struct X509Certificate {
    /// DER-encoded certificate bytes (for chain verification).
    pub der: Vec<u8>,
    /// DER-encoded TBSCertificate bytes, exactly as covered by `signature`.
    pub tbs: Vec<u8>,
    /// Version (0 = v1, 1 = v2, 2 = v3).
    pub version: u8,
    /// Serial number as raw bytes.
    pub serial: Vec<u8>,
    /// Signature algorithm OID (from the TBS `signature` field).
    pub signature_algorithm: Vec<u8>,
    /// Issuer distinguished name (raw DER).
    pub issuer: Vec<u8>,
    /// Subject distinguished name (raw DER).
    pub subject: Vec<u8>,
    /// Not-before time (ASN.1 UTCTime or GeneralizedTime, raw bytes).
    pub not_before: Vec<u8>,
    /// Not-after time (ASN.1 UTCTime or GeneralizedTime, raw bytes).
    pub not_after: Vec<u8>,
    /// Subject public key algorithm OID.
    pub public_key_algorithm: Vec<u8>,
    /// Subject public key (raw bit string bytes).
    pub public_key: Vec<u8>,
    /// Extensions (raw DER of the extensions SEQUENCE).
    pub extensions: Vec<u8>,
    /// Outer `signatureValue` (raw bytes, unused-bits byte stripped).
    ///
    /// This is the signature the issuer produced over `tbs`; chain
    /// verification checks it against the parent certificate's public key.
    pub signature: Vec<u8>,
}

/// Parsed X.509 name (issuer or subject).
#[derive(Debug, Clone, Default)]
pub struct X509Name {
    /// Common Name (CN = 2.5.4.3).
    pub common_name: Option<String>,
    /// Organization (O = 2.5.4.10).
    pub organization: Option<String>,
    /// Country (C = 2.5.4.6).
    pub country: Option<String>,
}

/// Public key algorithm extracted from a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    /// RSA public key.
    Rsa,
    /// ECDSA public key (on secp256r1 / P-256).
    Ecdsa,
    /// Unknown algorithm (OID stored).
    Unknown(Vec<u8>),
}

/// Validity status extracted from a certificate.
#[derive(Debug, Clone)]
pub struct Validity {
    /// Not-before as a human-readable string (YYMMDDHHMMSSZ or
    /// YYYYMMDDHHMMSSZ).
    pub not_before: String,
    /// Not-after as a human-readable string.
    pub not_after: String,
}

// ── DER reader ─────────────────────────────────────────────────────────────

/// Lightweight cursor for reading DER-encoded bytes.
struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn peek_tag(&self) -> Option<u8> {
        if self.pos < self.data.len() {
            Some(self.data[self.pos])
        } else {
            None
        }
    }

    fn read_tag(&mut self) -> Option<u8> {
        if self.pos < self.data.len() {
            let tag = self.data[self.pos];
            self.pos += 1;
            Some(tag)
        } else {
            None
        }
    }

    fn read_length(&mut self) -> Option<usize> {
        if self.pos >= self.data.len() {
            return None;
        }
        let first = self.data[self.pos];
        self.pos += 1;
        if first < 0x80 {
            // Short form: length fits in one byte.
            Some(first as usize)
        } else {
            // Long form: first byte indicates number of subsequent length bytes.
            let num_bytes = (first & 0x7F) as usize;
            if num_bytes == 0 || num_bytes > 4 || self.pos + num_bytes > self.data.len() {
                return None;
            }
            let mut len: usize = 0;
            for _ in 0..num_bytes {
                len = (len << 8) | (self.data[self.pos] as usize);
                self.pos += 1;
            }
            Some(len)
        }
    }

    /// Read a TLV and return `(tag, value_slice)`.
    fn read_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = self.read_tag()?;
        let len = self.read_length()?;
        if self.pos + len > self.data.len() {
            return None;
        }
        let value = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some((tag, value))
    }

    /// Read and expect a specific tag.
    fn read_tagged(&mut self, expected_tag: u8) -> Option<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag == expected_tag {
            Some(value)
        } else {
            None
        }
    }

    /// Skip the next TLV.
    fn skip_tlv(&mut self) -> bool {
        self.read_tlv().is_some()
    }

    /// Return the remaining unread bytes starting at current position.
    fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}

// ── OID matching ──────────────────────────────────────────────────────────

fn oid_eq(a: &[u8], b: &[u8]) -> bool {
    a == b
}

// ── Name parsing ───────────────────────────────────────────────────────────

/// Parse an X.500 Distinguished Name (SEQUENCE OF SET OF
/// AttributeTypeAndValue).
///
/// Extracts CN (2.5.4.3), O (2.5.4.10), and C (2.5.4.6).
fn parse_x509_name(der: &[u8]) -> X509Name {
    let mut name = X509Name::default();
    let reader = &mut DerReader::new(der);

    // Name ::= SEQUENCE OF RelativeDistinguishedName
    let seq_val = match reader.read_tagged(TAG_SEQUENCE) {
        Some(v) => v,
        None => return name,
    };

    let rdn_reader = &mut DerReader::new(seq_val);
    while rdn_reader.remaining() > 0 {
        // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        let set_val = match rdn_reader.read_tagged(TAG_SET) {
            Some(v) => v,
            None => break,
        };

        let attr_reader = &mut DerReader::new(set_val);
        while attr_reader.remaining() > 0 {
            // AttributeTypeAndValue ::= SEQUENCE { type OID, value }
            let attr_val = match attr_reader.read_tagged(TAG_SEQUENCE) {
                Some(v) => v,
                None => break,
            };

            let a = &mut DerReader::new(attr_val);
            let oid_val = match a.read_tagged(TAG_OID) {
                Some(v) => v,
                None => continue,
            };

            // Read the value (any string type).
            let str_val = match a.peek_tag() {
                Some(TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_IA5_STRING | TAG_UTC_TIME) => {
                    match a.read_tlv() {
                        Some((_, v)) => v,
                        None => continue,
                    }
                }
                _ => continue,
            };

            let value_str = String::from_utf8_lossy(str_val).into_owned();

            if oid_eq(oid_val, &[0x55, 0x04, 0x03]) {
                // 2.5.4.3 — Common Name
                name.common_name = Some(value_str);
            } else if oid_eq(oid_val, &[0x55, 0x04, 0x0A]) {
                // 2.5.4.10 — Organization
                name.organization = Some(value_str);
            } else if oid_eq(oid_val, &[0x55, 0x04, 0x06]) {
                // 2.5.4.6 — Country
                name.country = Some(value_str);
            }
        }
    }

    name
}

// ── Certificate parsing ────────────────────────────────────────────────────

/// Parse a DER-encoded X.509 v3 certificate.
///
/// Returns `None` if the data is not a valid DER certificate.
pub fn parse_x509_certificate(der: &[u8]) -> Option<X509Certificate> {
    let reader = &mut DerReader::new(der);

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue
    // }
    let cert_seq = reader.read_tagged(TAG_SEQUENCE)?;

    let c = &mut DerReader::new(cert_seq);

    // TBSCertificate ::= SEQUENCE
    let tbs_val = c.read_tagged(TAG_SEQUENCE)?;
    // The signature covers the *entire* TBS SEQUENCE (tag + length + content).
    // TBS is the first element of `cert_seq`; its SEQUENCE header sits between
    // `cert_seq_base` and `tbs_val`, so the full TBS spans both.
    let cert_seq_base = cert_seq.as_ptr() as usize - der.as_ptr() as usize;
    let tbs_header_len = tbs_val.as_ptr() as usize - cert_seq.as_ptr() as usize;
    let tbs = der[cert_seq_base..cert_seq_base + tbs_header_len + tbs_val.len()].to_vec();
    // Offset of the TBS content within `der` (used for issuer/subject slicing).
    let tbs_base = cert_seq_base + tbs_header_len;
    let tbs_reader = &mut DerReader::new(tbs_val);

    // The outer `signatureValue` BIT STRING follows the TBS; the first byte is
    // the count of unused bits, the remainder is the raw signature.
    c.read_tagged(TAG_SEQUENCE)?; // outer signatureAlgorithm (already parsed in TBS)
    let sig_bit_str = c.read_tagged(TAG_BIT_STRING)?;
    let signature = if sig_bit_str.is_empty() {
        Vec::new()
    } else {
        sig_bit_str[1..].to_vec()
    };

    // Version [0] EXPLICIT (default v1 = 0).
    let version = if tbs_reader.peek_tag() == Some(0xA0) {
        let (_, ver_val) = tbs_reader.read_tlv()?;
        // The version is an INTEGER inside the [0] wrapper.
        let vi = &mut DerReader::new(ver_val);
        let int_bytes = vi.read_tagged(TAG_INTEGER)?;
        if int_bytes.is_empty() {
            0
        } else {
            int_bytes.last().copied().unwrap_or(0)
        }
    } else {
        0 // Default: v1
    };

    // Serial number (INTEGER).
    let serial = tbs_reader.read_tagged(TAG_INTEGER)?.to_vec();

    // Signature algorithm (SEQUENCE { OID, ... }).
    let sig_alg_val = tbs_reader.read_tagged(TAG_SEQUENCE)?;
    let sig_alg_oid = {
        let sa = &mut DerReader::new(sig_alg_val);
        sa.read_tagged(TAG_OID)?.to_vec()
    };

    // Issuer (SEQUENCE OF SET OF ...).
    let issuer = {
        let start = tbs_base + tbs_reader.pos;
        tbs_reader.read_tagged(TAG_SEQUENCE)?;
        let end = tbs_base + tbs_reader.pos;
        der[start..end].to_vec()
    };

    // Validity ::= SEQUENCE { notBefore Time, notAfter Time }
    let validity_val = tbs_reader.read_tagged(TAG_SEQUENCE)?;
    let (not_before, not_after) = {
        let v = &mut DerReader::new(validity_val);
        let nb = v.read_tlv().map(|(_, val)| val.to_vec())?;
        let na = v.read_tlv().map(|(_, val)| val.to_vec())?;
        (nb, na)
    };

    // Subject (SEQUENCE OF SET OF ...).
    let subject = {
        let start = tbs_base + tbs_reader.pos;
        tbs_reader.read_tagged(TAG_SEQUENCE)?;
        let end = tbs_base + tbs_reader.pos;
        der[start..end].to_vec()
    };

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
    let spki_val = tbs_reader.read_tagged(TAG_SEQUENCE)?;
    let (pubkey_algo, pubkey) = {
        let sp = &mut DerReader::new(spki_val);
        // AlgorithmIdentifier ::= SEQUENCE { OID, ... }
        let algo_val = sp.read_tagged(TAG_SEQUENCE)?;
        let algo_oid = {
            let a = &mut DerReader::new(algo_val);
            a.read_tagged(TAG_OID)?.to_vec()
        };
        // Subject public key (BIT STRING).
        let bit_str = sp.read_tagged(TAG_BIT_STRING)?;
        // First byte of BIT STRING is the number of unused bits.
        let pk = if bit_str.is_empty() {
            Vec::new()
        } else {
            bit_str[1..].to_vec()
        };
        (algo_oid, pk)
    };

    // Extensions [3] EXPLICIT (optional).
    let extensions = if tbs_reader.peek_tag() == Some(0xA3) {
        let (_, ext_wrap) = tbs_reader.read_tlv()?;
        let ew = &mut DerReader::new(ext_wrap);
        let ext_seq = ew.read_tagged(TAG_SEQUENCE)?;
        ext_seq.to_vec()
    } else {
        Vec::new()
    };

    Some(X509Certificate {
        der: der.to_vec(),
        tbs,
        version,
        serial,
        signature_algorithm: sig_alg_oid,
        issuer,
        subject,
        not_before,
        not_after,
        public_key_algorithm: pubkey_algo,
        public_key: pubkey,
        extensions,
        signature,
    })
}

/// Parse a chain of certificates from a DER-encoded list.
///
/// Each certificate is a SEQUENCE; this function extracts each one in order.
pub fn parse_certificate_chain(der_list: &[u8]) -> Vec<X509Certificate> {
    let mut certs = Vec::new();
    let reader = &mut DerReader::new(der_list);

    while reader.remaining() > 0 {
        // Try to parse a certificate at this position.
        let start = reader.pos;
        if let Some(cert) = parse_x509_certificate(reader.rest()) {
            certs.push(cert);
            // Advance past the certificate we just parsed.
            // We need to find where it ended by re-reading the outer SEQUENCE.
            if let Some((_, val)) = DerReader::new(reader.rest()).read_tlv() {
                let consumed = val.as_ptr() as usize - reader.rest().as_ptr() as usize + val.len();
                reader.pos = start + consumed;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    certs
}

// ── Convenience accessors ──────────────────────────────────────────────────

impl X509Certificate {
    /// Parse and return the issuer name.
    pub fn issuer_name(&self) -> X509Name {
        parse_x509_name(&self.issuer)
    }

    /// Parse and return the subject name.
    pub fn subject_name(&self) -> X509Name {
        parse_x509_name(&self.subject)
    }

    /// Return the public key algorithm as a typed enum.
    pub fn public_key_algorithm_type(&self) -> PublicKeyAlgorithm {
        if oid_eq(&self.public_key_algorithm, OID_RSA_ENCRYPTION) {
            PublicKeyAlgorithm::Rsa
        } else if oid_eq(&self.public_key_algorithm, OID_EC_PUBLIC_KEY)
            || oid_eq(&self.public_key_algorithm, OID_ECDSA_SHA256)
            || oid_eq(&self.public_key_algorithm, OID_ECDSA_SHA384)
        {
            PublicKeyAlgorithm::Ecdsa
        } else {
            PublicKeyAlgorithm::Unknown(self.public_key_algorithm.clone())
        }
    }

    /// Return the validity period as strings.
    pub fn validity(&self) -> Validity {
        Validity {
            not_before: String::from_utf8_lossy(&self.not_before).into_owned(),
            not_after: String::from_utf8_lossy(&self.not_after).into_owned(),
        }
    }

    /// Check if this certificate is a CA certificate (has BasicConstraints
    /// CA:TRUE).
    pub fn is_ca(&self) -> bool {
        // BasicConstraints is OID 2.5.29.19 (0x55, 0x1D, 0x13).
        // We search the extensions for this OID and check if CA is TRUE.
        search_extension_bool(&self.extensions, &[0x55, 0x1D, 0x13])
    }

    /// Try to extract the subject CN from this certificate.
    pub fn common_name(&self) -> Option<String> {
        self.subject_name().common_name
    }

    /// Try to extract the issuer CN from this certificate.
    pub fn issuer_common_name(&self) -> Option<String> {
        self.issuer_name().common_name
    }

    /// Extract SAN DNS names from the Subject Alternative Name extension
    /// (2.5.29.17).
    pub fn subject_alt_names(&self) -> Vec<String> {
        // SAN = 2.5.29.17 = 0x55 0x1D 0x11
        search_extension_san(&self.extensions, &[0x55, 0x1D, 0x11])
    }
}

/// Parse an RSA public key from the SPKI BIT STRING payload.
///
/// The BIT STRING value (with the unused-bits byte already stripped) contains a
/// DER-encoded `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent
/// INTEGER }`.
///
/// Returns `(modulus, public_exponent)` as big-endian byte vectors.  Leading
/// zero bytes are stripped from the modulus for canonicalisation.  Keys larger
/// than 4096 bits are rejected.
pub(crate) fn parse_rsa_public_key(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut reader = DerReader::new(der);
    // Outer SEQUENCE.
    let seq = reader.read_tagged(TAG_SEQUENCE)?;
    let mut inner = DerReader::new(seq);

    // First INTEGER: modulus.
    let modulus_raw = inner.read_tagged(TAG_INTEGER)?;
    // Strip leading 0x00 bytes (ASN.1 sign byte, or DER canonicalization).
    let mut mod_start = 0usize;
    while mod_start < modulus_raw.len() && modulus_raw[mod_start] == 0 {
        mod_start += 1;
    }
    if mod_start >= modulus_raw.len() {
        return None;
    }
    let modulus = modulus_raw[mod_start..].to_vec();
    // Reject keys larger than 4096 bits.
    if modulus.len() > 512 {
        return None;
    }

    // Second INTEGER: publicExponent.
    let exp_raw = inner.read_tagged(TAG_INTEGER)?;
    let mut exp_start = 0usize;
    while exp_start < exp_raw.len() && exp_raw[exp_start] == 0 {
        exp_start += 1;
    }
    if exp_start >= exp_raw.len() {
        return None;
    }
    let exponent = exp_raw[exp_start..].to_vec();
    // Exponent should be at most 4 bytes for typical values (e=65537).
    if exponent.len() > 8 {
        return None;
    }

    Some((modulus, exponent))
}

/// Search an extensions SEQUENCE for a boolean extension value.
fn search_extension_bool(extensions: &[u8], oid: &[u8]) -> bool {
    let reader = &mut DerReader::new(extensions);
    while reader.remaining() > 0 {
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
        // extnValue OCTET STRING }
        let ext_val = match reader.read_tagged(TAG_SEQUENCE) {
            Some(v) => v,
            None => break,
        };
        let ext = &mut DerReader::new(ext_val);
        let ext_oid = match ext.read_tagged(TAG_OID) {
            Some(v) => v,
            None => continue,
        };
        if !oid_eq(ext_oid, oid) {
            continue;
        }
        // Skip optional critical BOOLEAN.
        if ext.peek_tag() == Some(TAG_BOOLEAN) {
            let _ = ext.read_tlv();
        }
        // extnValue is an OCTET STRING wrapping the actual value.
        let value_bytes = match ext.read_tagged(TAG_OCTET_STRING) {
            Some(v) => v,
            None => continue,
        };
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
        let bc = &mut DerReader::new(value_bytes);
        if let Some(seq_val) = bc.read_tagged(TAG_SEQUENCE) {
            let bcs = &mut DerReader::new(seq_val);
            if bcs.peek_tag() == Some(TAG_BOOLEAN) {
                if let Some(bool_val) = bcs.read_tagged(TAG_BOOLEAN) {
                    return !bool_val.is_empty() && bool_val[0] != 0;
                }
            }
        }
    }
    false
}

/// Search an extensions SEQUENCE for SAN DNS names.
fn search_extension_san(extensions: &[u8], oid: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let reader = &mut DerReader::new(extensions);
    while reader.remaining() > 0 {
        let ext_val = match reader.read_tagged(TAG_SEQUENCE) {
            Some(v) => v,
            None => break,
        };
        let ext = &mut DerReader::new(ext_val);
        let ext_oid = match ext.read_tagged(TAG_OID) {
            Some(v) => v,
            None => continue,
        };
        if !oid_eq(ext_oid, oid) {
            continue;
        }
        if ext.peek_tag() == Some(TAG_BOOLEAN) {
            let _ = ext.read_tlv();
        }
        let value_bytes = match ext.read_tagged(TAG_OCTET_STRING) {
            Some(v) => v,
            None => continue,
        };
        // SAN ::= SEQUENCE OF GeneralName
        // GeneralName (dNSName) = [2] IMPLICIT IA5String
        let san_seq = &mut DerReader::new(value_bytes);
        if let Some(seq_val) = san_seq.read_tagged(TAG_SEQUENCE) {
            let gn = &mut DerReader::new(seq_val);
            while gn.remaining() > 0 {
                // Look for context-specific tag [2] (dNSName).
                if gn.peek_tag() == Some(0x82) {
                    if let Some((_, dns_val)) = gn.read_tlv() {
                        if let Ok(s) = String::from_utf8(dns_val.to_vec()) {
                            names.push(s);
                        }
                    }
                } else {
                    if !gn.skip_tlv() {
                        break;
                    }
                }
            }
        }
    }
    names
}

// ── Certificate chain verification ─────────────────────────────────────────

/// Verification result for a certificate chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerifyStatus {
    /// Chain is trusted.
    Trusted,
    /// A certificate in the chain has expired or is not yet valid.
    Expired,
    /// None of the SANs or CNs match the expected hostname.
    HostnameMismatch,
    /// The chain could not be verified (missing intermediate, unknown issuer).
    Untrusted,
}

/// Build an ordered certificate chain from an unordered list.
///
/// The result is ordered from leaf (index 0) to root (last index).
/// Returns `None` if the chain cannot be built (missing links).
///
/// Algorithm: start with the certificate whose subject matches `hostname`
/// (or the first cert if none match), then repeatedly find the issuer
/// certificate whose subject matches the current cert's issuer, until
/// we reach a self-signed root or run out of certificates.
pub fn build_chain(certs: &[X509Certificate], hostname: &str) -> Option<Vec<X509Certificate>> {
    if certs.is_empty() {
        return None;
    }

    // Find the leaf: the certificate that matches the hostname.
    let leaf_idx = certs
        .iter()
        .position(|c| hostname_matches(c, hostname))
        .unwrap_or(0);

    let mut chain: Vec<X509Certificate> = vec![certs[leaf_idx].clone()];
    let mut used: Vec<bool> = vec![false; certs.len()];
    used[leaf_idx] = true;

    // Repeatedly find the issuer for the current top of chain.
    loop {
        let current = chain.last().unwrap();
        let issuer_cn = current.issuer_common_name();
        let subject_cn = current.common_name();

        // If the current cert is self-signed (issuer == subject), we've
        // reached the root.
        if issuer_cn.is_some() && issuer_cn == subject_cn {
            break;
        }

        // Find a certificate whose subject matches the current cert's issuer.
        let issuer_idx = certs.iter().enumerate().position(|(i, c)| {
            !used[i] && c.common_name().is_some() && c.common_name() == issuer_cn
        });

        match issuer_idx {
            Some(idx) => {
                used[idx] = true;
                chain.push(certs[idx].clone());
            }
            None => {
                // No issuer found — chain is incomplete.
                // For development, if we have at least the leaf, accept it.
                break;
            }
        }
    }

    if chain.is_empty() {
        None
    } else {
        Some(chain)
    }
}

/// Verify a certificate chain against a hostname.
///
/// Checks performed:
/// 1. At least one certificate is present.
/// 2. The leaf certificate's validity period is well-formed (and, when an RTC
///    is available, unexpired).
/// 3. The leaf certificate matches `hostname` (via SAN or CN).
/// 4. The chain is properly ordered and each certificate's issuer matches the
///    next certificate's subject.
/// 5. Chain-of-trust signature verification: every certificate's signature is
///    checked against its issuer's public key (`sha256WithRSAEncryption` via
///    RSASSA-PKCS1-v1_5, or `ecdsa-with-SHA256` via ECDSA P-256).
/// 6. The chain terminates at a trusted root from the built-in [`root_store`]
///    (servers normally omit the root, so the last presented certificate may be
///    issued *by* a trust anchor).
///
/// Returns `ChainVerifyStatus::Trusted` if all checks pass.
pub fn verify_chain(chain: &[X509Certificate], hostname: &str) -> ChainVerifyStatus {
    verify_chain_against_roots(chain, hostname, super::root_store::trusted_roots())
}

/// Verify a chain against an explicit set of trust anchors (raw DER root
/// certificates).  The public [`verify_chain`] wrapper uses the built-in
/// store; tests pass their own anchors.
fn verify_chain_against_roots(
    chain: &[X509Certificate],
    hostname: &str,
    roots: &[&[u8]],
) -> ChainVerifyStatus {
    if chain.is_empty() {
        return ChainVerifyStatus::Untrusted;
    }

    // Build an ordered chain and validate structure.
    let ordered = match build_chain(chain, hostname) {
        Some(c) => c,
        None => return ChainVerifyStatus::Untrusted,
    };

    let leaf = &ordered[0];

    // Check validity dates on every certificate in the chain.
    for cert in &ordered {
        if !check_certificate_validity(cert) {
            return ChainVerifyStatus::Expired;
        }
    }

    // Check hostname match against leaf.
    if !hostname_matches(leaf, hostname) {
        return ChainVerifyStatus::HostnameMismatch;
    }

    // Validate chain links: each cert's issuer CN should match the next
    // cert's subject CN.  The last certificate is validated against a trust
    // anchor below, so its issuer need not match any sent certificate.
    for i in 0..ordered.len().saturating_sub(1) {
        let issuer_cn = ordered[i].issuer_common_name();
        let next_subject_cn = ordered[i + 1].common_name();
        if issuer_cn.is_some() && issuer_cn != next_subject_cn {
            return ChainVerifyStatus::Untrusted;
        }
    }

    // Verify every link: the parent certificate's public key must have
    // produced the child's signature over the child's TBS bytes.
    for i in 0..ordered.len().saturating_sub(1) {
        if !verify_certificate_signature(&ordered[i], &ordered[i + 1]) {
            return ChainVerifyStatus::Untrusted;
        }
    }

    // The chain must terminate at a trusted root.  Two cases:
    //   1. `top` is itself a trust anchor (subject DN + public key match a store
    //      root) — its self-signature is a consistency check.
    //   2. `top` was issued by a trust anchor (its issuer DN matches a root's
    //      subject DN) — the common case, since servers omit the root.
    let top = ordered.last().unwrap();

    if let Some(root) = find_trusted_root(roots, &top.subject, &top.public_key) {
        if verify_certificate_signature(top, &root) {
            return ChainVerifyStatus::Trusted;
        }
        return ChainVerifyStatus::Untrusted;
    }

    if let Some(root) = find_issuer_trusted_root(roots, &top.issuer) {
        if verify_certificate_signature(top, &root) {
            return ChainVerifyStatus::Trusted;
        }
        return ChainVerifyStatus::Untrusted;
    }

    ChainVerifyStatus::Untrusted
}

/// Verify that `child`'s signature was produced by `parent`'s public key over
/// `child`'s TBS bytes.
///
/// Supports the two signature algorithms the kernel implements:
/// `sha256WithRSAEncryption` (RSASSA-PKCS1-v1_5 with SHA-256) and
/// `ecdsa-with-SHA256` (ECDSA P-256).  Anything else (PSS, SHA-1, SHA-384/512,
/// Ed25519, …) is rejected as untrusted.
fn verify_certificate_signature(child: &X509Certificate, parent: &X509Certificate) -> bool {
    if child.tbs.is_empty() || child.signature.is_empty() {
        return false;
    }
    match parent.public_key_algorithm_type() {
        PublicKeyAlgorithm::Rsa => {
            if !oid_eq(&child.signature_algorithm, OID_SHA256_RSA) {
                return false;
            }
            let (n, e) = match parse_rsa_public_key(&parent.public_key) {
                Some(pk) => pk,
                None => return false,
            };
            crate::kernel::crypto::rsa_pkcs1v15_verify(&n, &e, &child.tbs, &child.signature)
        }
        PublicKeyAlgorithm::Ecdsa => {
            if !oid_eq(&child.signature_algorithm, OID_ECDSA_SHA256) {
                return false;
            }
            let (r, s) = match crate::kernel::crypto::parse_ecdsa_der_signature(&child.signature) {
                Some(p) => p,
                None => return false,
            };
            let hash = crate::kernel::crypto::sha256(&child.tbs);
            crate::kernel::crypto::ecdsa_p256_verify(&parent.public_key, &hash, &r, &s)
        }
        PublicKeyAlgorithm::Unknown(_) => false,
    }
}

/// Find the parsed trust anchor whose subject DN and public key both match
/// `cert` (i.e. `cert` *is* the anchor).
fn find_trusted_root(
    roots: &[&[u8]],
    subject: &[u8],
    public_key: &[u8],
) -> Option<X509Certificate> {
    roots.iter().find_map(|der| {
        let root = parse_x509_certificate(der)?;
        if root.subject == subject && root.public_key == public_key {
            Some(root)
        } else {
            None
        }
    })
}

/// Find the parsed trust anchor whose subject DN matches `issuer` (i.e. the
/// anchor that issued `cert`).
fn find_issuer_trusted_root(roots: &[&[u8]], issuer: &[u8]) -> Option<X509Certificate> {
    roots.iter().find_map(|der| {
        let root = parse_x509_certificate(der)?;
        if root.subject == issuer {
            Some(root)
        } else {
            None
        }
    })
}

/// Parse an ASN.1 UTCTime or GeneralizedTime value into (year, month, day,
/// hour, min, sec).
///
/// UTCTime: "YYMMDDHHMMSSZ" (13 ASCII bytes).  Years 00–49 → 2000–2049,
/// years 50–99 → 1950–1999.
/// GeneralizedTime: "YYYYMMDDHHMMSSZ" (15 ASCII bytes).
///
/// Returns `None` if the time string is malformed or out of range.
fn parse_asn1_time(raw: &[u8]) -> Option<(i32, u8, u8, u8, u8, u8)> {
    let s = core::str::from_utf8(raw).ok()?;
    let (year, rest) = if s.len() == 13 && s.ends_with('Z') {
        let yy: i32 = s[0..2].parse().ok()?;
        let full_year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (full_year, &s[2..12])
    } else if s.len() == 15 && s.ends_with('Z') {
        let year: i32 = s[0..4].parse().ok()?;
        (year, &s[4..14])
    } else {
        return None;
    };

    let month: u8 = rest[0..2].parse().ok()?;
    let day: u8 = rest[2..4].parse().ok()?;
    let hour: u8 = rest[4..6].parse().ok()?;
    let min: u8 = rest[6..8].parse().ok()?;
    let sec: u8 = rest[8..10].parse().ok()?;

    // Sanity-check ranges.
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60
    // leap seconds
    {
        return None;
    }

    Some((year, month, day, hour, min, sec))
}

/// Convert a parsed ASN.1 time to a Unix timestamp (seconds since 1970-01-01
/// 00:00:00 UTC) using the proleptic Gregorian calendar.
///
/// Uses Howard Hinnant's civil-from-days algorithm so no external date library
/// is needed in the kernel (mirrors `rtc_to_unix_timestamp` in the RTC
/// drivers).
fn asn1_time_to_unix(t: (i32, u8, u8, u8, u8, u8)) -> u64 {
    let (year, month, day, hour, min, sec) = t;
    let y = i64::from(year);
    let m = i64::from(month);
    let d = i64::from(day);

    // Days from civil.
    let yy = if m <= 2 { y - 1 } else { y };
    let era = (if yy >= 0 { yy } else { yy - 399 }) / 400;
    let yoe = yy - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    (days * 86_400 + i64::from(hour) * 3_600 + i64::from(min) * 60 + i64::from(sec)) as u64
}

/// Whether a Unix timestamp falls inside `[not_before, not_after]`.
fn in_validity_window(not_before: u64, not_after: u64, now: u64) -> bool {
    now >= not_before && now <= not_after
}

/// Check that a certificate's validity period is well-formed and, when a
/// real-time clock is available, that the certificate is within its
/// [not_before, not_after] window.
///
/// On hosts without an RTC (`rtc_now_unix` returns `None`) only structural
/// validation of the time fields is performed.
fn check_certificate_validity(cert: &X509Certificate) -> bool {
    // Structural validation: both time fields must parse.
    let not_before = match parse_asn1_time(&cert.not_before) {
        Some(t) => t,
        None => return false,
    };
    let not_after = match parse_asn1_time(&cert.not_after) {
        Some(t) => t,
        None => return false,
    };

    // When a wall-clock source is available, enforce the validity window.
    if let Some(now) = crate::arch::timer::rtc_now_unix() {
        return in_validity_window(
            asn1_time_to_unix(not_before),
            asn1_time_to_unix(not_after),
            now,
        );
    }

    true
}

/// Check if a certificate matches a hostname.
///
/// First checks SAN DNS names, then falls back to CN.
fn hostname_matches(cert: &X509Certificate, hostname: &str) -> bool {
    let sans = cert.subject_alt_names();
    if !sans.is_empty() {
        return sans.iter().any(|san| name_matches_wildcard(san, hostname));
    }

    // Fallback: check CN.
    if let Some(ref cn) = cert.common_name() {
        return name_matches_wildcard(cn, hostname);
    }

    false
}

/// Match a hostname against a name that may contain a `*.` wildcard prefix.
fn name_matches_wildcard(pattern: &str, hostname: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("*.") {
        // Wildcard matches only the first label.
        // e.g., "*.example.com" matches "foo.example.com" but not
        // "foo.bar.example.com".
        if let Some(dot_pos) = hostname.find('.') {
            let host_rest = &hostname[dot_pos + 1..];
            // The wildcard part must also not contain additional dots.
            return host_rest.eq_ignore_ascii_case(rest) && !hostname[..dot_pos].contains('.');
        }
        return false;
    }
    // Exact match (case-insensitive for DNS names).
    pattern.eq_ignore_ascii_case(hostname)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::network::tls::test_fixtures;

    /// Build a minimal DER-encoded X.509 certificate for testing.
    ///
    /// This builds a valid ASN.1 DER structure by hand.
    fn build_test_cert_der(common_name: &str, is_ca: bool) -> Vec<u8> {
        let cn_bytes = common_name.as_bytes();
        // Subject: SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String CN } } }
        let subject_attr = build_name_attr(&[0x55, 0x04, 0x03], TAG_UTF8_STRING, cn_bytes);
        let subject_rdn = tlv(TAG_SET, &subject_attr);
        let subject = tlv(TAG_SEQUENCE, &subject_rdn);

        // Issuer: same as subject for self-signed test cert.
        let issuer = subject.clone();

        // Validity: notBefore=000101000000Z, notAfter=99991231235959Z
        let not_before = tlv(TAG_UTC_TIME, b"000101000000Z");
        let not_after = tlv(TAG_UTC_TIME, b"99991231235959Z");
        let validity = tlv(TAG_SEQUENCE, &[not_before, not_after].concat());

        // Public key algorithm: RSA OID + NULL
        let rsa_oid = tlv(TAG_OID, OID_RSA_ENCRYPTION);
        let rsa_null = tlv(TAG_NULL, &[]);
        let pubkey_algo = tlv(TAG_SEQUENCE, &[rsa_oid, rsa_null].concat());

        // Public key: BIT STRING (dummy 256-bit key)
        let pubkey_bits = vec![0x00u8; 32]; // 256 bits of zeros
        let mut pubkey_bitstring = vec![0x00u8]; // 0 unused bits
        pubkey_bitstring.extend_from_slice(&pubkey_bits);
        let pubkey = tlv(TAG_BIT_STRING, &pubkey_bitstring);

        let spki = tlv(TAG_SEQUENCE, &[pubkey_algo, pubkey].concat());

        // Serial number: 1
        let serial = tlv(TAG_INTEGER, &[0x01]);

        // Signature algorithm: SHA-256 with RSA
        let sig_oid_val = tlv(TAG_OID, OID_SHA256_RSA);
        let sig_null = tlv(TAG_NULL, &[]);
        let sig_algo = tlv(TAG_SEQUENCE, &[sig_oid_val, sig_null].concat());

        // Extensions: BasicConstraints (CA: true/false), SAN
        let mut ext_list = Vec::new();
        if is_ca {
            let bc_value = tlv(TAG_SEQUENCE, &tlv(TAG_BOOLEAN, &[0xFF]));
            let bc_octet = tlv(TAG_OCTET_STRING, &bc_value);
            let bc_oid = tlv(TAG_OID, &[0x55, 0x1D, 0x13]); // 2.5.29.19
            ext_list.extend_from_slice(&tlv(TAG_SEQUENCE, &[bc_oid, bc_octet].concat()));
        }

        // ext_list is Vec<u8>, already the concatenated extension TLVs.
        let extensions = if ext_list.is_empty() {
            Vec::new()
        } else {
            let ext_seq = tlv(TAG_SEQUENCE, &ext_list);
            // Wrap in [3] EXPLICIT
            let mut wrapped = vec![0xA3];
            write_der_length(&mut wrapped, ext_seq.len());
            wrapped.extend_from_slice(&ext_seq);
            wrapped
        };

        // TBSCertificate
        let mut tbs = Vec::new();
        // Version [0] EXPLICIT INTEGER 2 (v3)
        tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
        tbs.extend_from_slice(&serial);
        tbs.extend_from_slice(&sig_algo);
        tbs.extend_from_slice(&issuer);
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&subject);
        tbs.extend_from_slice(&spki);
        tbs.extend_from_slice(&extensions);
        let tbs_cert = tlv(TAG_SEQUENCE, &tbs);

        // Certificate: TBSCertificate + signatureAlgorithm + signatureValue
        let sig_value = tlv(TAG_BIT_STRING, &[0x00u8]); // dummy signature (0 unused bits, empty)
        let cert_content = [tbs_cert, sig_algo, sig_value].concat();
        tlv(TAG_SEQUENCE, &cert_content)
    }

    fn build_name_attr(oid: &[u8], str_tag: u8, value: &[u8]) -> Vec<u8> {
        let oid_tlv = tlv(TAG_OID, oid);
        let val_tlv = tlv(str_tag, value);
        tlv(TAG_SEQUENCE, &[oid_tlv, val_tlv].concat())
    }

    /// Build a TLV element with a tag and value.
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        write_der_length(&mut result, value.len());
        result.extend_from_slice(value);
        result
    }

    /// Write a DER length to a buffer.
    fn write_der_length(buf: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            buf.push(len as u8);
        } else if len < 0x100 {
            buf.push(0x81);
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
    }

    #[test]
    fn parse_test_cert() {
        let der = build_test_cert_der("example.com", false);
        let cert = parse_x509_certificate(&der).expect("parse test cert");
        assert_eq!(cert.version, 2); // v3
        assert_eq!(
            cert.subject_name().common_name.as_deref(),
            Some("example.com")
        );
        assert!(!cert.is_ca());
    }

    #[test]
    fn parse_ca_cert() {
        let der = build_test_cert_der("Test Root CA", true);
        let cert = parse_x509_certificate(&der).expect("parse CA cert");
        assert_eq!(
            cert.subject_name().common_name.as_deref(),
            Some("Test Root CA")
        );
        assert!(cert.is_ca());
    }

    #[test]
    fn hostname_match_exact() {
        let der = build_test_cert_der("example.com", false);
        let cert = parse_x509_certificate(&der).unwrap();
        assert!(hostname_matches(&cert, "example.com"));
        assert!(hostname_matches(&cert, "EXAMPLE.COM"));
        assert!(!hostname_matches(&cert, "other.com"));
    }

    #[test]
    fn hostname_match_wildcard() {
        // Wildcard CN
        let der = build_test_cert_der("*.example.com", false);
        let cert = parse_x509_certificate(&der).unwrap();
        assert!(hostname_matches(&cert, "foo.example.com"));
        assert!(hostname_matches(&cert, "bar.example.com"));
        assert!(!hostname_matches(&cert, "foo.bar.example.com"));
        assert!(!hostname_matches(&cert, "example.com"));
    }

    #[test]
    fn cert_with_san() {
        // Build a cert with a SAN extension containing "san.example.com"
        let cn_bytes = b"other.name";
        let subject_attr = build_name_attr(&[0x55, 0x04, 0x03], TAG_UTF8_STRING, cn_bytes);
        let subject_rdn = tlv(TAG_SET, &subject_attr);
        let subject = tlv(TAG_SEQUENCE, &subject_rdn);
        let issuer = subject.clone();
        let not_before = tlv(TAG_UTC_TIME, b"000101000000Z");
        let not_after = tlv(TAG_UTC_TIME, b"99991231235959Z");
        let validity = tlv(TAG_SEQUENCE, &[not_before, not_after].concat());
        let rsa_oid = tlv(TAG_OID, OID_RSA_ENCRYPTION);
        let rsa_null = tlv(TAG_NULL, &[]);
        let pubkey_algo = tlv(TAG_SEQUENCE, &[rsa_oid, rsa_null].concat());
        let pubkey = tlv(TAG_BIT_STRING, &[0x00u8, 0x00u8]);
        let spki = tlv(TAG_SEQUENCE, &[pubkey_algo, pubkey].concat());
        let serial = tlv(TAG_INTEGER, &[0x01]);
        let sig_oid_val = tlv(TAG_OID, OID_SHA256_RSA);
        let sig_null = tlv(TAG_NULL, &[]);
        let sig_algo = tlv(TAG_SEQUENCE, &[sig_oid_val, sig_null].concat());

        // Build SAN extension: dNSName = san.example.com
        // GeneralName dNSName = [2] IMPLICIT IA5String
        let dns_tlv = tlv(0x82, b"san.example.com");
        let san_seq = tlv(TAG_SEQUENCE, &dns_tlv);
        let san_octet = tlv(TAG_OCTET_STRING, &san_seq);
        let san_oid = tlv(TAG_OID, &[0x55, 0x1D, 0x11]); // 2.5.29.17
        let san_ext = tlv(TAG_SEQUENCE, &[san_oid, san_octet].concat());
        let ext_seq = tlv(TAG_SEQUENCE, &san_ext);
        let mut extensions = vec![0xA3];
        write_der_length(&mut extensions, ext_seq.len());
        extensions.extend_from_slice(&ext_seq);

        let mut tbs = Vec::new();
        tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
        tbs.extend_from_slice(&serial);
        tbs.extend_from_slice(&sig_algo);
        tbs.extend_from_slice(&issuer);
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&subject);
        tbs.extend_from_slice(&spki);
        tbs.extend_from_slice(&extensions);
        let tbs_cert = tlv(TAG_SEQUENCE, &tbs);
        let sig_value = tlv(TAG_BIT_STRING, &[0x00u8]);
        let cert_content = [tbs_cert, sig_algo, sig_value].concat();
        let der = tlv(TAG_SEQUENCE, &cert_content);

        let cert = parse_x509_certificate(&der).expect("parse SAN cert");
        let sans = cert.subject_alt_names();
        assert_eq!(sans, vec!["san.example.com"]);
        assert!(hostname_matches(&cert, "san.example.com"));
        // Should NOT match the CN "other.name" since SAN takes priority.
        assert!(!hostname_matches(&cert, "other.name"));
    }

    #[test]
    fn parse_empty_chain() {
        let result = verify_chain(&[], "example.com");
        assert_eq!(result, ChainVerifyStatus::Untrusted);
    }

    #[test]
    fn verify_chain_hostname_mismatch() {
        let der = build_test_cert_der("wrong.example.com", false);
        let cert = parse_x509_certificate(&der).unwrap();
        let result = verify_chain(&[cert], "expected.example.com");
        assert_eq!(result, ChainVerifyStatus::HostnameMismatch);
    }

    #[test]
    fn public_key_algorithm_rsa() {
        let der = build_test_cert_der("test.example.com", false);
        let cert = parse_x509_certificate(&der).unwrap();
        assert_eq!(cert.public_key_algorithm_type(), PublicKeyAlgorithm::Rsa);
    }

    #[test]
    fn validity_roundtrip() {
        let der = build_test_cert_der("test.example.com", false);
        let cert = parse_x509_certificate(&der).unwrap();
        let v = cert.validity();
        assert_eq!(v.not_before, "000101000000Z");
        assert_eq!(v.not_after, "99991231235959Z");
    }

    #[test]
    fn parse_certificate_chain_two_certs() {
        let der1 = build_test_cert_der("leaf.example.com", false);
        let der2 = build_test_cert_der("Root CA", true);
        let combined = [der1.clone(), der2.clone()].concat();
        let chain = parse_certificate_chain(&combined);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].common_name().as_deref(), Some("leaf.example.com"));
        assert_eq!(chain[1].common_name().as_deref(), Some("Root CA"));
    }

    #[test]
    fn garbage_data_returns_none() {
        assert!(parse_x509_certificate(b"not a certificate").is_none());
        assert!(parse_x509_certificate(&[]).is_none());
    }

    #[test]
    fn build_chain_single_self_signed() {
        let der = build_test_cert_der("leaf.example.com", false);
        let cert = parse_x509_certificate(&der).unwrap();
        let chain = build_chain(&[cert], "leaf.example.com").unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn build_chain_two_certs_leaf_and_ca() {
        // Create a leaf cert whose issuer CN matches the CA's subject CN.
        // The test cert builder creates self-signed certs, so we manually
        // verify that build_chain stops at the self-signed root.
        let leaf_der = build_test_cert_der("leaf.example.com", false);
        let ca_der = build_test_cert_der("Root CA", true);
        let leaf = parse_x509_certificate(&leaf_der).unwrap();
        let ca = parse_x509_certificate(&ca_der).unwrap();

        // Both are self-signed, so the chain builder will find the leaf
        // and stop since leaf is self-signed.
        let chain = build_chain(&[leaf.clone(), ca], "leaf.example.com").unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].common_name().as_deref(), Some("leaf.example.com"));
    }

    #[test]
    fn verify_chain_empty_is_untrusted() {
        assert_eq!(
            verify_chain(&[], "example.com"),
            ChainVerifyStatus::Untrusted
        );
    }

    // ── Chain verification with OpenSSL-generated signed fixtures ─────────

    #[test]
    fn verify_chain_signed_by_trusted_root() {
        // Leaf issued directly by the trust anchor; the server omits the root.
        let leaf = parse_x509_certificate(test_fixtures::DEMO_LEAF_DER).unwrap();
        let roots = [test_fixtures::DEMO_ROOT_DER];
        assert_eq!(
            verify_chain_against_roots(&[leaf], "demo.protofire.example", &roots),
            ChainVerifyStatus::Trusted
        );
    }

    #[test]
    fn verify_chain_public_uses_builtin_store() {
        // The public wrapper resolves the trust anchor from the built-in store.
        let leaf = parse_x509_certificate(test_fixtures::DEMO_LEAF_DER).unwrap();
        assert_eq!(
            verify_chain(&[leaf], "demo.protofire.example"),
            ChainVerifyStatus::Trusted
        );
    }

    #[test]
    fn verify_chain_full_rsa_path() {
        // leaf -> int -> test_root; the server sends leaf + intermediate.
        let leaf = parse_x509_certificate(test_fixtures::LEAF_DER).unwrap();
        let int = parse_x509_certificate(test_fixtures::INT_DER).unwrap();
        let roots = [test_fixtures::TEST_ROOT_DER];
        assert_eq!(
            verify_chain_against_roots(&[leaf, int], "test.example.com", &roots),
            ChainVerifyStatus::Trusted
        );
    }

    #[test]
    fn verify_chain_ec_leaf_signed_by_rsa_intermediate() {
        // ECDSA leaf issued by an RSA intermediate (cross-algorithm link).
        let ec = parse_x509_certificate(test_fixtures::EC_DER).unwrap();
        let int = parse_x509_certificate(test_fixtures::INT_DER).unwrap();
        let roots = [test_fixtures::TEST_ROOT_DER];
        assert_eq!(
            verify_chain_against_roots(&[ec, int], "test.example.com", &roots),
            ChainVerifyStatus::Trusted
        );
    }

    #[test]
    fn verify_chain_full_ecdsa_path() {
        // ec2 -> ec_int -> test_root: every link uses ECDSA P-256.
        let ec2 = parse_x509_certificate(test_fixtures::EC2_DER).unwrap();
        let ec_int = parse_x509_certificate(test_fixtures::EC_INT_DER).unwrap();
        let roots = [test_fixtures::TEST_ROOT_DER];
        assert_eq!(
            verify_chain_against_roots(&[ec2, ec_int], "test.example.com", &roots),
            ChainVerifyStatus::Trusted
        );
    }

    #[test]
    fn verify_chain_root_sent_explicitly() {
        // The server sends the full path including the self-signed root.
        let leaf = parse_x509_certificate(test_fixtures::LEAF_DER).unwrap();
        let int = parse_x509_certificate(test_fixtures::INT_DER).unwrap();
        let root = parse_x509_certificate(test_fixtures::TEST_ROOT_DER).unwrap();
        let roots = [test_fixtures::TEST_ROOT_DER];
        assert_eq!(
            verify_chain_against_roots(&[leaf, int, root], "test.example.com", &roots),
            ChainVerifyStatus::Trusted
        );
    }

    #[test]
    fn verify_chain_unknown_root_is_untrusted() {
        // A chain issued by a CA absent from the anchor set is rejected.
        let leaf = parse_x509_certificate(test_fixtures::LEAF_DER).unwrap();
        let int = parse_x509_certificate(test_fixtures::INT_DER).unwrap();
        let roots = [test_fixtures::DEMO_ROOT_DER]; // wrong anchor
        assert_eq!(
            verify_chain_against_roots(&[leaf, int], "test.example.com", &roots),
            ChainVerifyStatus::Untrusted
        );
    }

    #[test]
    fn verify_chain_rejects_tampered_leaf_signature() {
        // Flip a byte inside the leaf's TBS (its serial number): the stored
        // signature no longer covers the altered TBS, so verification fails.
        let mut der = test_fixtures::LEAF_DER.to_vec();
        der[30] ^= 0x01;
        let leaf = parse_x509_certificate(&der).unwrap();
        let int = parse_x509_certificate(test_fixtures::INT_DER).unwrap();
        let roots = [test_fixtures::TEST_ROOT_DER];
        assert_eq!(
            verify_chain_against_roots(&[leaf, int], "test.example.com", &roots),
            ChainVerifyStatus::Untrusted
        );
    }

    // ── Certificate validity dates ─────────────────────────────────────────

    #[test]
    fn asn1_time_to_unix_known_values() {
        // 2023-06-15 12:34:56 UTC.
        assert_eq!(asn1_time_to_unix((2023, 6, 15, 12, 34, 56)), 1_686_832_496);
        // Epoch.
        assert_eq!(asn1_time_to_unix((1970, 1, 1, 0, 0, 0)), 0);
        // A date in the 20th century (UTCTime year 50-99 → 1950-1999).
        assert_eq!(asn1_time_to_unix((1999, 12, 31, 23, 59, 59)), 946_684_799);
    }

    #[test]
    fn validity_window_boundaries() {
        assert!(in_validity_window(100, 200, 100));
        assert!(in_validity_window(100, 200, 200));
        assert!(!in_validity_window(100, 200, 99));
        assert!(!in_validity_window(100, 200, 201));
    }

    #[test]
    fn hostname_match_case_insensitive() {
        let der = build_test_cert_der("Example.COM", false);
        let cert = parse_x509_certificate(&der).unwrap();
        assert!(hostname_matches(&cert, "example.com"));
    }
}
