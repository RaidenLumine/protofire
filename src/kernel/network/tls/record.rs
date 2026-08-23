//! src/kernel/network/tls/record.rs
//! TLS 1.3 record layer (RFC 8446 §5).
//!
//! Encrypts and decrypts TLS records using AEAD ciphers (AES-128-GCM or
//! ChaCha20-Poly1305).  The record format is:
//!
//! ```text
//! ContentType (1) || legacy_record_version (2, 0x0303) || length (2) ||
//!   encrypted_record (length bytes)
//! ```
//!
//! The encrypted record consists of the ciphertext plus the AEAD
//! authentication tag appended at the end.

use alloc::vec::Vec;

use crate::kernel::crypto::{
    aes128_gcm_decrypt, aes128_gcm_encrypt, chacha20_poly1305_decrypt, chacha20_poly1305_encrypt,
};
use crate::{Error, Result};

// ── Record constants ──────────────────────────────────────────────────────

/// TLS 1.3 record content types.
pub const CONTENT_TYPE_INVALID: u8 = 0;
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CONTENT_TYPE_ALERT: u8 = 21;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

/// Legacy record version for TLS 1.3 (always 0x0303 on the wire).
const TLS_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];

/// Maximum plaintext fragment length (2^14 = 16 384 bytes, RFC 8446 §5.1).
pub const TLS_MAX_FRAGMENT_LEN: usize = 16384;

/// AEAD authentication tag length (16 bytes for both AES-128-GCM and
/// ChaCha20-Poly1305).
const AEAD_TAG_LEN: usize = 16;

// ── Cipher suite ──────────────────────────────────────────────────────────

/// Supported TLS 1.3 cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256 (0x1301).
    Aes128GcmSha256 = 0x1301,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303).
    ChaCha20Poly1305Sha256 = 0x1303,
}

impl CipherSuite {
    /// AEAD key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256 => 16,
            CipherSuite::ChaCha20Poly1305Sha256 => 32,
        }
    }

    /// AEAD nonce (IV) length in bytes.
    pub fn iv_len(self) -> usize {
        12
    }

    /// AEAD tag length in bytes.
    pub fn tag_len(self) -> usize {
        AEAD_TAG_LEN
    }
}

// ── Traffic keys ──────────────────────────────────────────────────────────

/// Per-direction traffic keys derived during the TLS 1.3 handshake.
pub struct TrafficKeys {
    /// AEAD write key (client→server for client keys).
    pub write_key: Vec<u8>,
    /// AEAD write IV (12 bytes).
    pub write_iv: [u8; 12],
    /// AEAD read key (server→client for client keys).
    pub read_key: Vec<u8>,
    /// AEAD read IV (12 bytes).
    pub read_iv: [u8; 12],
    /// Cipher suite.
    pub suite: CipherSuite,
    /// Write sequence number (monotonically increasing per record).
    write_seq: u64,
    /// Read sequence number.
    read_seq: u64,
}

impl TrafficKeys {
    /// Create new traffic keys for the given cipher suite.
    pub fn new(
        write_key: Vec<u8>,
        write_iv: [u8; 12],
        read_key: Vec<u8>,
        read_iv: [u8; 12],
        suite: CipherSuite,
    ) -> Self {
        Self {
            write_key,
            write_iv,
            read_key,
            read_iv,
            suite,
            write_seq: 0,
            read_seq: 0,
        }
    }
}

// ── Record protection ──────────────────────────────────────────────────────

/// Build the additional-data input for AEAD (RFC 8446 §5.2).
///
/// ```text
/// additional_data = TLSCiphertext.opaque_type     (1 byte)
///                 || TLSCiphertext.legacy_record_version (2 bytes, 0x0303)
///                 || TLSCiphertext.length          (2 bytes)
/// ```
fn build_aead_ad(content_type: u8, encrypted_len: usize) -> [u8; 5] {
    let mut ad = [0u8; 5];
    ad[0] = content_type;
    ad[1..3].copy_from_slice(&0x0303u16.to_be_bytes());
    ad[3..5].copy_from_slice(&(encrypted_len as u16).to_be_bytes());
    ad
}

/// Encrypt a plaintext TLS record, producing the wire-format ciphertext
/// (including the authentication tag appended at the end).
///
/// Returns the encrypted record content (ciphertext || tag).
fn encrypt_record_content(
    keys: &mut TrafficKeys,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let seq = keys.write_seq;
    keys.write_seq = keys.write_seq.wrapping_add(1);

    // Build the nonce by XOR'ing the sequence number into the last 8 bytes
    // of the IV (RFC 8446 §5.3).
    let mut nonce = keys.write_iv;
    let seq_be = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_be[i];
    }

    let encrypted_len = plaintext.len() + keys.suite.tag_len();
    let ad = build_aead_ad(content_type, encrypted_len);

    match keys.suite {
        CipherSuite::Aes128GcmSha256 => {
            let key: &[u8; 16] = keys
                .write_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::InternalError)?;
            let (ct, tag) = aes128_gcm_encrypt(key, &nonce, &ad, plaintext);
            let mut result = ct;
            result.extend_from_slice(&tag);
            Ok(result)
        }
        CipherSuite::ChaCha20Poly1305Sha256 => {
            let key: &[u8; 32] = keys
                .write_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::InternalError)?;
            let (ct, tag) = chacha20_poly1305_encrypt(key, &nonce, &ad, plaintext);
            let mut result = ct;
            result.extend_from_slice(&tag);
            Ok(result)
        }
    }
}

/// Decrypt and verify a received TLS record.
///
/// `encrypted` is the wire-format encrypted content (ciphertext || tag).
/// Returns the plaintext on success.
fn decrypt_record_content(
    keys: &mut TrafficKeys,
    content_type: u8,
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    if encrypted.len() < keys.suite.tag_len() {
        return Err(Error::InvalidArgument);
    }

    let seq = keys.read_seq;
    keys.read_seq = keys.read_seq.wrapping_add(1);

    let mut nonce = keys.read_iv;
    let seq_be = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_be[i];
    }

    let tag_offset = encrypted.len() - keys.suite.tag_len();
    let (ciphertext, tag_bytes) = encrypted.split_at(tag_offset);
    let tag: &[u8; AEAD_TAG_LEN] = tag_bytes.try_into().map_err(|_| Error::InvalidArgument)?;

    let encrypted_len = encrypted.len();
    let ad = build_aead_ad(content_type, encrypted_len);

    match keys.suite {
        CipherSuite::Aes128GcmSha256 => {
            let key: &[u8; 16] = keys
                .read_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::InternalError)?;
            aes128_gcm_decrypt(key, &nonce, &ad, ciphertext, tag)
        }
        CipherSuite::ChaCha20Poly1305Sha256 => {
            let key: &[u8; 32] = keys
                .read_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::InternalError)?;
            chacha20_poly1305_decrypt(key, &nonce, &ad, ciphertext, tag)
        }
    }
}

// ── Record framing ────────────────────────────────────────────────────────

/// Build a complete TLS record (header + encrypted content).
///
/// Wire format:
///   ContentType[1] || 0x0303[2] || length[2] || encrypted_content[length]
pub fn build_tls_record(
    keys: &mut TrafficKeys,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > TLS_MAX_FRAGMENT_LEN {
        return Err(Error::InvalidArgument);
    }

    let encrypted = encrypt_record_content(keys, content_type, plaintext)?;
    let total_len = encrypted.len();
    if total_len > 65535 {
        return Err(Error::InvalidArgument);
    }

    let mut record = Vec::with_capacity(5 + total_len);
    record.push(content_type);
    record.extend_from_slice(&TLS_LEGACY_VERSION);
    record.extend_from_slice(&(total_len as u16).to_be_bytes());
    record.extend_from_slice(&encrypted);

    Ok(record)
}

/// Parse and decrypt a TLS record from the wire.
///
/// Returns `(ContentType, plaintext)` on success.
pub fn parse_tls_record(keys: &mut TrafficKeys, record: &[u8]) -> Result<(u8, Vec<u8>)> {
    if record.len() < 5 {
        return Err(Error::InvalidArgument);
    }

    let content_type = record[0];
    let version = u16::from_be_bytes([record[1], record[2]]);
    let length = u16::from_be_bytes([record[3], record[4]]) as usize;

    // TLS 1.3 uses 0x0303 on the wire but may receive 0x0301.
    if version != 0x0303 && version != 0x0301 {
        return Err(Error::InvalidArgument);
    }

    if record.len() < 5 + length {
        return Err(Error::InvalidArgument);
    }

    let encrypted = &record[5..5 + length];
    let plaintext = decrypt_record_content(keys, content_type, encrypted)?;

    Ok((content_type, plaintext))
}

/// Build a TLS alert record.
pub fn build_alert(keys: &mut TrafficKeys, level: u8, description: u8) -> Result<Vec<u8>> {
    let alert = [level, description];
    build_tls_record(keys, CONTENT_TYPE_ALERT, &alert)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::crypto::sha256;

    /// Create a test key pair where client_keys.write == server_keys.read
    /// and client_keys.read == server_keys.write, so that a roundtrip
    /// build on one side and parse on the other side works.
    fn make_test_key_pair(suite: CipherSuite) -> (TrafficKeys, TrafficKeys) {
        let key_len = suite.key_len();
        let cwk = sha256(b"client-write-key-seed-32-bytes!")[..key_len].to_vec();
        let crk = sha256(b"client-read-key-seed-32-bytes!!")[..key_len].to_vec();
        let cwiv: [u8; 12] = sha256(b"client-write-iv-seed")[..12].try_into().unwrap();
        let criv: [u8; 12] = sha256(b"client-read-iv-seed")[..12].try_into().unwrap();

        // Client keys: write = cwk, read = crk
        // Server keys: write = crk (client reads), read = cwk (client writes)
        let client = TrafficKeys::new(cwk.clone(), cwiv, crk.clone(), criv, suite);
        let server = TrafficKeys::new(crk, criv, cwk, cwiv, suite);
        (client, server)
    }

    #[test]
    fn encrypt_decrypt_record_aes128gcm() {
        let (mut client, mut server) = make_test_key_pair(CipherSuite::Aes128GcmSha256);
        let plaintext = b"Hello, TLS 1.3 Record Layer!";

        let record =
            build_tls_record(&mut client, CONTENT_TYPE_HANDSHAKE, plaintext).expect("build record");
        // Server decrypts with client write = server read.
        let (ct, decrypted) = parse_tls_record(&mut server, &record).expect("parse record");

        assert_eq!(ct, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_record_chacha20() {
        let (mut client, mut server) = make_test_key_pair(CipherSuite::ChaCha20Poly1305Sha256);
        let plaintext = b"ChaCha20-Poly1305 TLS record test.";

        let record = build_tls_record(&mut client, CONTENT_TYPE_APPLICATION_DATA, plaintext)
            .expect("build record");
        let (ct, decrypted) = parse_tls_record(&mut server, &record).expect("parse record");

        assert_eq!(ct, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn record_rejects_truncated_input() {
        let (mut client, mut server) = make_test_key_pair(CipherSuite::Aes128GcmSha256);
        let record =
            build_tls_record(&mut client, CONTENT_TYPE_HANDSHAKE, b"test").expect("build record");
        // Truncate the record.
        let truncated = &record[..record.len() - 5];
        let result = parse_tls_record(&mut server, truncated);
        assert!(result.is_err());
    }

    #[test]
    fn record_rejects_wrong_keys() {
        let (mut client, _server) = make_test_key_pair(CipherSuite::Aes128GcmSha256);
        // Build a completely different key pair for the wrong server.
        let wrong_key: [u8; 16] = sha256(b"wrong-key-seed-32-bytes!!")[..16]
            .try_into()
            .unwrap();
        let wrong_iv: [u8; 12] = sha256(b"wrong-iv-seed")[..12].try_into().unwrap();
        let mut wrong_server = TrafficKeys::new(
            wrong_key.to_vec(),
            wrong_iv,
            wrong_key.to_vec(),
            wrong_iv,
            CipherSuite::Aes128GcmSha256,
        );
        let plaintext = b"sensitive";
        let record = build_tls_record(&mut client, CONTENT_TYPE_APPLICATION_DATA, plaintext)
            .expect("build record");
        let result = parse_tls_record(&mut wrong_server, &record);
        assert!(result.is_err());
    }

    #[test]
    fn alert_record_roundtrip() {
        let (mut client, mut server) = make_test_key_pair(CipherSuite::Aes128GcmSha256);
        let alert_record = build_alert(&mut client, 2, 80) // level=fatal, desc=internal_error
            .expect("build alert");
        let (ct, decrypted) = parse_tls_record(&mut server, &alert_record).expect("parse alert");
        assert_eq!(ct, CONTENT_TYPE_ALERT);
        assert_eq!(decrypted, &[2, 80]);
    }

    #[test]
    fn sequence_number_increments() {
        let (mut client, _) = make_test_key_pair(CipherSuite::Aes128GcmSha256);
        let r1 = build_tls_record(&mut client, CONTENT_TYPE_HANDSHAKE, b"msg1").unwrap();
        let r2 = build_tls_record(&mut client, CONTENT_TYPE_HANDSHAKE, b"msg2").unwrap();
        let r1b = build_tls_record(&mut client, CONTENT_TYPE_HANDSHAKE, b"msg1").unwrap();
        assert_ne!(r1, r2, "different plaintexts differ");
        assert_ne!(r1, r1b, "same plaintext with different seq differs");
    }
}
