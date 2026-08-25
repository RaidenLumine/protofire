//! src/kernel/network/tls/handshake.rs
//!
//! TLS 1.3 handshake state machine — server message parsing, key schedule,
//! and client Finished generation (RFC 8446 §4, §7).
//!
//! The handshake flow from the client's perspective:
//!
//! ```text
//! Client                                               Server
//! ClientHello          -------->
//!                                              ServerHello
//!                                      {EncryptedExtensions}
//!                                      {Certificate*}
//!                                        {CertificateVerify}
//!                      <--------               {Finished}
//! {Finished}           -------->
//! [Application Data]   <------->       [Application Data]
//! ```
//!
//! Messages in braces are encrypted with the handshake traffic keys.
//! The legacy `ChangeCipherSpec` (type 20, single byte 0x01) may appear
//! between ServerHello and the first encrypted record and is silently skipped.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::crypto::hkdf_sha256_expand;
use crate::kernel::crypto::hkdf_sha256_extract;
use crate::kernel::crypto::hmac_sha256;
use crate::kernel::crypto::sha256;
use crate::Error;
use crate::Result;

use super::certificate;
use super::record::CipherSuite;
use super::record::TrafficKeys;
use super::record::CONTENT_TYPE_HANDSHAKE;
use super::TranscriptHash;

// Re-export certificate types for convenience.
pub use super::certificate::parse_x509_certificate;
pub use super::certificate::verify_chain;
pub use super::certificate::ChainVerifyStatus;
pub use super::certificate::X509Certificate;

// ── Handshake message type constants ────────────────────────────────────────

const HS_SERVER_HELLO: u8 = 2;
const HS_CERTIFICATE: u8 = 11;
const HS_FINISHED: u8 = 20;

// ── HKDF-Expand-Label (RFC 8446 §7.1) ───────────────────────────────────────

/// HKDF-Expand-Label(Secret, Label, Context, Length) as defined in RFC 8446
/// §7.1.
///
/// Internally builds the `HkdfLabel` structure:
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
pub fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let label_str = format!("tls13 {label}");
    let mut hkdf_label = Vec::with_capacity(2 + label_str.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    hkdf_label.extend_from_slice(label_str.as_bytes());
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    // hkdf_sha256_expand expects a [u8; 32] PRK.
    let prk: &[u8; 32] = secret
        .try_into()
        .expect("HKDF-Expand-Label secret must be 32 bytes");
    hkdf_sha256_expand(prk, &hkdf_label, length)
}

/// Derive a 32-byte secret: `HKDF-Expand-Label(Secret, Label, Transcript-Hash,
/// 32)`.
fn derive_secret(secret: &[u8], label: &str, messages_hash: &[u8]) -> [u8; 32] {
    let expanded = hkdf_expand_label(secret, label, messages_hash, 32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&expanded);
    result
}

/// Derive AEAD key + IV from a traffic secret.
fn derive_key_iv(secret: &[u8; 32], suite: CipherSuite) -> (Vec<u8>, [u8; 12]) {
    let key = hkdf_expand_label(secret, "key", &[], suite.key_len());
    let iv = hkdf_expand_label(secret, "iv", &[], 12);
    let mut iv_arr = [0u8; 12];
    iv_arr.copy_from_slice(&iv);
    (key, iv_arr)
}

/// Derive a finished key: `HKDF-Expand-Label(BaseKey, "finished", "",
/// Hash.length)`.
fn derive_finished_key(base_key: &[u8; 32]) -> [u8; 32] {
    let expanded = hkdf_expand_label(base_key, "finished", &[], 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&expanded);
    key
}

// ── Key schedule (RFC 8446 §7.1) ────────────────────────────────────────────

/// Secrets produced at each stage of the TLS 1.3 key schedule.
pub struct HandshakeSecrets {
    /// Client handshake traffic secret (encrypts client Finished).
    pub client_handshake_secret: [u8; 32],
    /// Server handshake traffic secret (decrypts server handshake messages).
    pub server_handshake_secret: [u8; 32],
    /// The handshake_secret = HKDF-Extract(derived, shared_secret).
    /// Carried forward to derive the master secret.
    pub handshake_secret: [u8; 32],
}

impl HandshakeSecrets {
    /// Compute the handshake secrets from the ECDH shared secret and the
    /// current transcript hash (covering ClientHello...ServerHello).
    pub fn compute(shared_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> Self {
        let psk = [0u8; 32]; // No PSK mode.
        let early_secret = hkdf_sha256_extract(&[], &psk);

        // derived = HKDF-Expand-Label(EarlySecret, "derived", "", 32)
        let empty_hash = sha256(b"");
        let derived = derive_secret(&early_secret, "derived", &empty_hash);

        // handshake_secret = HKDF-Extract(derived, shared_secret)
        let handshake_secret = hkdf_sha256_extract(&derived, shared_secret);

        let client_handshake_secret =
            derive_secret(&handshake_secret, "c hs traffic", transcript_hash);
        let server_handshake_secret =
            derive_secret(&handshake_secret, "s hs traffic", transcript_hash);

        Self {
            client_handshake_secret,
            server_handshake_secret,
            handshake_secret,
        }
    }

    /// Derive the per-direction TrafficKeys for the handshake phase.
    ///
    /// Returns `(client_keys, server_keys)` where client_keys encrypts
    /// client→server and server_keys decrypts server→client.
    pub fn derive_handshake_keys(&self, suite: CipherSuite) -> (TrafficKeys, TrafficKeys) {
        let (c_write_key, c_write_iv) = derive_key_iv(&self.client_handshake_secret, suite);
        let (s_write_key, s_write_iv) = derive_key_iv(&self.server_handshake_secret, suite);

        // Client keys: write=client_secret, read=server_secret
        let client_keys = TrafficKeys::new(
            c_write_key.clone(),
            c_write_iv,
            s_write_key.clone(),
            s_write_iv,
            suite,
        );
        // Server keys: write=server_secret, read=client_secret
        let server_keys = TrafficKeys::new(
            s_write_key,
            s_write_iv,
            c_write_key, // client_secret key for read
            c_write_iv,  // client_secret iv for read
            suite,
        );
        (client_keys, server_keys)
    }

    /// Derive the server finished key.
    pub fn server_finished_key(&self) -> [u8; 32] {
        derive_finished_key(&self.server_handshake_secret)
    }

    /// Derive the client finished key.
    pub fn client_finished_key(&self) -> [u8; 32] {
        derive_finished_key(&self.client_handshake_secret)
    }
}

/// Application traffic secrets and keys.
pub struct ApplicationSecrets {
    pub client_application_secret: [u8; 32],
    pub server_application_secret: [u8; 32],
}

impl ApplicationSecrets {
    /// Compute the master secret and application traffic secrets from the
    /// handshake secret and the transcript hash covering ClientHello through
    /// server Finished.
    pub fn compute(handshake_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> Self {
        let empty_hash = sha256(b"");
        let derived = derive_secret(handshake_secret, "derived", &empty_hash);

        let zero_ikm = [0u8; 32];
        let master_secret = hkdf_sha256_extract(&derived, &zero_ikm);

        let client_application_secret =
            derive_secret(&master_secret, "c ap traffic", transcript_hash);
        let server_application_secret =
            derive_secret(&master_secret, "s ap traffic", transcript_hash);

        Self {
            client_application_secret,
            server_application_secret,
        }
    }

    /// Derive the per-direction TrafficKeys for the application-data phase.
    pub fn derive_application_keys(&self, suite: CipherSuite) -> (TrafficKeys, TrafficKeys) {
        let (c_key, c_iv) = derive_key_iv(&self.client_application_secret, suite);
        let (s_key, s_iv) = derive_key_iv(&self.server_application_secret, suite);

        let client_keys = TrafficKeys::new(c_key.clone(), c_iv, s_key.clone(), s_iv, suite);
        let server_keys = TrafficKeys::new(s_key, s_iv, c_key, c_iv, suite);
        (client_keys, server_keys)
    }
}

// ── ServerHello parsing ─────────────────────────────────────────────────────

/// A parsed TLS 1.3 ServerHello message.
pub struct ParsedServerHello {
    /// Server's 32-byte random value.
    pub server_random: [u8; 32],
    /// Cipher suite selected by the server.
    pub cipher_suite: CipherSuite,
    /// Legacy version from the ServerHello (0x0303 for TLS 1.2 compatibility).
    pub legacy_version: u16,
    /// Server's X25519 public key (from the key_share extension).
    pub server_public_key: [u8; 32],
    /// Raw bytes of the ServerHello handshake message (for transcript hash).
    pub raw_message: Vec<u8>,
}

fn u24_from_be(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
}

fn u16_from_be(bytes: &[u8]) -> u16 {
    ((bytes[0] as u16) << 8) | (bytes[1] as u16)
}

/// Validate and parse a ServerHello handshake message.
///
/// Extracts the server_random, negotiated cipher suite, and server's
/// X25519 key share.  Also validates that the server selected TLS 1.3
/// (via the `supported_versions` extension).
pub fn parse_server_hello(data: &[u8]) -> Result<ParsedServerHello> {
    // Handshake header: type (1), length (3).
    if data.len() < 4 {
        return Err(Error::InvalidArgument);
    }
    if data[0] != HS_SERVER_HELLO {
        return Err(Error::InvalidArgument);
    }
    let msg_len = u24_from_be(&data[1..4]) as usize;
    if data.len() < 4 + msg_len {
        return Err(Error::InvalidArgument);
    }
    let payload = &data[4..4 + msg_len];
    let offset = 0usize;

    // Legacy version (2 bytes).
    if payload.len() < offset + 2 {
        return Err(Error::InvalidArgument);
    }
    let legacy_version = u16_from_be(&payload[offset..offset + 2]);

    // Server random (32 bytes).
    if payload.len() < offset + 2 + 32 {
        return Err(Error::InvalidArgument);
    }
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&payload[offset + 2..offset + 2 + 32]);

    // Legacy session ID (length-prefixed, skip).
    let mut pos = offset + 2 + 32;
    if pos >= payload.len() {
        return Err(Error::InvalidArgument);
    }
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > payload.len() {
        return Err(Error::InvalidArgument);
    }

    // Cipher suite (2 bytes).
    let suite_id = u16_from_be(&payload[pos..pos + 2]);
    let cipher_suite = match suite_id {
        0x1301 => CipherSuite::Aes128GcmSha256,
        0x1303 => CipherSuite::ChaCha20Poly1305Sha256,
        _ => return Err(Error::DeviceError),
    };
    pos += 2;

    // Legacy compression method (1 byte, skip).
    if pos >= payload.len() {
        return Err(Error::InvalidArgument);
    }
    pos += 1;

    // Extensions.
    if pos + 2 > payload.len() {
        // No extensions: valid only for non-TLS 1.3 (shouldn't happen).
        return Err(Error::InvalidArgument);
    }
    let ext_len = u16_from_be(&payload[pos..pos + 2]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > payload.len() {
        return Err(Error::InvalidArgument);
    }

    let mut server_public_key = None;
    let mut tls13_confirmed = false;

    while pos + 4 <= ext_end {
        let ext_type = u16_from_be(&payload[pos..pos + 2]);
        let ext_data_len = u16_from_be(&payload[pos + 2..pos + 4]) as usize;
        pos += 4;
        if pos + ext_data_len > ext_end {
            return Err(Error::InvalidArgument);
        }
        let ext_data = &payload[pos..pos + ext_data_len];

        match ext_type {
            0x0033 => {
                // Key share extension: selected group (2B) + key_exchange.
                if ext_data.len() < 4 {
                    return Err(Error::InvalidArgument);
                }
                let group = u16_from_be(&ext_data[..2]);
                if group != 0x001D {
                    // Not X25519.
                    return Err(Error::DeviceError);
                }
                let key_len = u16_from_be(&ext_data[2..4]) as usize;
                if key_len != 32 || ext_data.len() < 4 + key_len {
                    return Err(Error::InvalidArgument);
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&ext_data[4..4 + 32]);
                server_public_key = Some(pk);
            }
            0x002B if ext_data.len() >= 2 => {
                // Supported versions: must confirm TLS 1.3 (0x0304).
                let sv = u16_from_be(&ext_data[..2]);
                if sv == 0x0304 {
                    tls13_confirmed = true;
                }
            }
            _ => {
                // Unknown extension — skip.
            }
        }
        pos += ext_data_len;
    }

    if !tls13_confirmed {
        return Err(Error::DeviceError);
    }

    let server_public_key = server_public_key.ok_or(Error::DeviceError)?;

    Ok(ParsedServerHello {
        server_random,
        cipher_suite,
        legacy_version,
        server_public_key,
        raw_message: data[..4 + msg_len].to_vec(),
    })
}

// ── Server handshake message parsing ─────────────────────────────────────────

/// Parsed server Finished message.
pub struct ParsedServerFinished {
    /// 32-byte verify_data.
    pub verify_data: [u8; 32],
}

/// Verify a server Finished message.
///
/// `data` is the raw Finished handshake message.
/// `finished_key` is `HKDF-Expand-Label(server_handshake_secret, "finished",
/// "", 32)`. `transcript_hash` covers all handshake messages up to (but not
/// including) the Finished message itself.
pub fn verify_server_finished(
    data: &[u8],
    finished_key: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<ParsedServerFinished> {
    if data.len() < 4 {
        return Err(Error::InvalidArgument);
    }
    if data[0] != HS_FINISHED {
        return Err(Error::InvalidArgument);
    }
    let msg_len = u24_from_be(&data[1..4]) as usize;
    if msg_len != 32 || data.len() < 4 + 32 {
        return Err(Error::InvalidArgument);
    }
    let mut verify_data = [0u8; 32];
    verify_data.copy_from_slice(&data[4..4 + 32]);

    // Compute expected verify_data = HMAC(finished_key, transcript_hash).
    let expected = hmac_sha256(finished_key, transcript_hash);
    if verify_data != expected {
        return Err(Error::DeviceError);
    }

    Ok(ParsedServerFinished { verify_data })
}

/// Build a client Finished handshake message.
///
/// `finished_key` is `HKDF-Expand-Label(client_handshake_secret, "finished",
/// "", 32)`. `transcript_hash` covers all handshake messages including server
/// Finished.
pub fn build_client_finished(finished_key: &[u8; 32], transcript_hash: &[u8; 32]) -> Vec<u8> {
    let verify_data = hmac_sha256(finished_key, transcript_hash);

    let mut finished = Vec::with_capacity(4 + 32);
    finished.push(HS_FINISHED);
    finished.extend_from_slice(&(32u32).to_be_bytes()[1..]); // 3-byte length
    finished.extend_from_slice(&verify_data);
    finished
}

// ── TLS 1.3 record I/O helpers ──────────────────────────────────────────────

/// Parse a plaintext (unencrypted) TLS record.
///
/// Returns `(content_type, payload)`.
/// Used for the initial ClientHello and ServerHello records.
pub fn parse_plaintext_tls_record(data: &[u8]) -> Result<(u8, Vec<u8>)> {
    if data.len() < 5 {
        return Err(Error::InvalidArgument);
    }
    let content_type = data[0];
    let version = u16_from_be(&data[1..3]);
    let length = u16_from_be(&data[3..5]) as usize;

    // Accept TLS 1.0–1.3 record versions.
    if !(0x0301..=0x0304).contains(&version) {
        return Err(Error::InvalidArgument);
    }
    if data.len() < 5 + length {
        return Err(Error::InvalidArgument);
    }

    Ok((content_type, data[5..5 + length].to_vec()))
}

/// Wrap a handshake message into a plaintext TLS record for sending.
pub fn build_plaintext_handshake_record(message: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + message.len());
    record.push(CONTENT_TYPE_HANDSHAKE);
    record.extend_from_slice(&0x0301u16.to_be_bytes()); // Legacy version for ClientHello
    record.extend_from_slice(&(message.len() as u16).to_be_bytes());
    record.extend_from_slice(message);
    record
}

/// Read a complete TLS record from a TCP connection into a reusable buffer.
///
/// Reads the 5-byte header first, then the payload.  Returns
/// `(content_type, payload_bytes)`.
///
/// In a full implementation this would use non-blocking I/O with proper
/// buffering; here we do a simple blocking read with a moderate timeout.
pub fn read_tls_record(
    connection: &crate::kernel::network::TcpConnection,
    buf: &mut Vec<u8>,
) -> Result<(u8, Vec<u8>)> {
    // Read the 5-byte record header.
    let mut header = [0u8; 5];
    let mut offset = 0usize;
    while offset < 5 {
        let n = connection.read(&mut header[offset..], 3000)?; // 30s timeout
        if n == 0 {
            return Err(Error::DeviceError);
        }
        offset += n;
    }

    let content_type = header[0];
    let length = u16_from_be(&header[3..5]) as usize;

    // Read the record payload.
    buf.resize(length, 0u8);
    let mut offset = 0usize;
    while offset < length {
        let n = connection.read(&mut buf[offset..], 3000)?;
        if n == 0 {
            return Err(Error::DeviceError);
        }
        offset += n;
    }

    Ok((content_type, buf.clone()))
}

// ── Handshake message accumulator ────────────────────────────────────────────

/// Accumulate decrypted handshake messages and feed them to the transcript.
///
/// Parses individual handshake messages from the concatenated stream,
/// updating the transcript and returning each message type + payload.
///
/// **Important:** Finished messages (type 20) are NOT fed to the transcript
/// by this function.  The caller must verify the Finished verify_data against
/// the current transcript hash *before* adding the Finished to the transcript,
/// per RFC 8446 §4.4.4.
pub fn parse_handshake_messages_from_stream(
    stream: &[u8],
    transcript: &mut TranscriptHash,
) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut messages = Vec::new();
    let mut pos = 0usize;

    while pos + 4 <= stream.len() {
        let msg_type = stream[pos];
        let msg_len = u24_from_be(&stream[pos + 1..pos + 4]) as usize;
        if pos + 4 + msg_len > stream.len() {
            break; // Partial message — stop.
        }
        let payload = stream[pos..pos + 4 + msg_len].to_vec();

        // Feed every message to the transcript *except* Finished.
        // Finished must be verified against the pre-Finished transcript hash.
        if msg_type != HS_FINISHED {
            transcript.update(&payload);
        }
        messages.push((msg_type, payload));

        pos += 4 + msg_len;
    }

    Ok(messages)
}

// ── Certificate types (minimal X.509) ────────────────────────────────────────

/// Verification status for a TLS server certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertVerifyStatus {
    /// Certificate is trusted (for development: all certs accepted).
    Trusted,
    /// Certificate has expired.
    Expired,
    /// Certificate subject does not match the expected server name.
    NameMismatch,
    /// Certificate is self-signed or from an untrusted CA.
    Untrusted,
}

/// Minimal X.509 certificate extracted from a TLS Certificate message.
pub struct ParsedCertificate {
    /// Common Name (CN) from the Subject field.
    pub common_name: Option<String>,
    /// DER-encoded certificate bytes.
    pub der: Vec<u8>,
}

/// Parse a TLS Certificate handshake message (type 11).
///
/// RFC 8446 §4.4.2: the Certificate message contains:
/// ```text
/// opaque certificate_request_context<0..2^8-1>;
/// CertificateEntry certificate_list<0..2^24-1>;
///
/// CertificateEntry:
///     opaque cert_data<1..2^24-1>;
///     Extension extensions<0..2^16-1>;
/// ```
///
/// Returns a list of DER-encoded certificates (leaf first).
pub fn parse_certificate_message(data: &[u8]) -> Result<Vec<ParsedCertificate>> {
    if data.len() < 4 || data[0] != HS_CERTIFICATE {
        return Err(Error::InvalidArgument);
    }
    let msg_len = u24_from_be(&data[1..4]) as usize;
    if data.len() < 4 + msg_len {
        return Err(Error::InvalidArgument);
    }
    let payload = &data[4..4 + msg_len];
    let mut pos = 0usize;

    // Certificate request context (1-byte length prefix).
    if pos >= payload.len() {
        return Err(Error::InvalidArgument);
    }
    let ctx_len = payload[pos] as usize;
    pos += 1 + ctx_len;
    if pos + 3 > payload.len() {
        return Err(Error::InvalidArgument);
    }

    // Certificate list (3-byte length prefix).
    let list_len = u24_from_be(&payload[pos..pos + 3]) as usize;
    pos += 3;
    let list_end = pos + list_len;
    if list_end > payload.len() {
        return Err(Error::InvalidArgument);
    }

    let mut certs = Vec::new();
    while pos + 3 <= list_end {
        let cert_len = u24_from_be(&payload[pos..pos + 3]) as usize;
        pos += 3;
        if pos + cert_len > list_end {
            return Err(Error::InvalidArgument);
        }
        let cert_der = payload[pos..pos + cert_len].to_vec();

        // Skip extensions (2-byte length prefix).
        pos += cert_len;
        if pos + 2 > list_end {
            return Err(Error::InvalidArgument);
        }
        let ext_len = u16_from_be(&payload[pos..pos + 2]) as usize;
        pos += 2 + ext_len;

        // Use the X.509 certificate parser to extract fields.
        let cn = certificate::parse_x509_certificate(&cert_der).and_then(|c| c.common_name());
        certs.push(ParsedCertificate {
            common_name: cn,
            der: cert_der,
        });
    }

    Ok(certs)
}

/// Certificate verification: delegates to the X.509 certificate parser.
///
/// Parses each certificate, then uses [`certificate::verify_chain`] to check
/// hostname match (SAN or CN) and chain structure.  Leaf certificate signature
/// verification is performed during the CertificateVerify handshake step using
/// ECDSA P-256 primitives.  Full path validation (intermediate CA and root
/// signatures) requires a root CA store which is not yet integrated.
pub fn verify_certificate_chain(
    certs: &[ParsedCertificate],
    server_name: &str,
) -> CertVerifyStatus {
    let parsed: Vec<X509Certificate> = certs
        .iter()
        .filter_map(|c| certificate::parse_x509_certificate(&c.der))
        .collect();
    match certificate::verify_chain(&parsed, server_name) {
        ChainVerifyStatus::Trusted => CertVerifyStatus::Trusted,
        ChainVerifyStatus::Expired => CertVerifyStatus::Expired,
        ChainVerifyStatus::HostnameMismatch => CertVerifyStatus::NameMismatch,
        ChainVerifyStatus::Untrusted => CertVerifyStatus::Untrusted,
    }
}

/// ECDSA P-256 with SHA-256 signature scheme identifier (TLS 1.3).
const SIG_SCHEME_ECDSA_P256_SHA256: u16 = 0x0403;
/// RSA-PSS with RSA encryption and SHA-256 (TLS 1.3).
const SIG_SCHEME_RSA_PSS_RSAE_SHA256: u16 = 0x0804;

/// Verify the CertificateVerify signature.
///
/// Parses the CertificateVerify handshake message body, extracts the
/// signature scheme and signature, computes the transcript hash, and
/// verifies the signature using the leaf certificate's public key.
///
/// Returns `true` if the signature is valid.
pub fn verify_certificate_verify_signature(
    msg_data: &[u8],
    peer_certificates: &[X509Certificate],
    transcript: &TranscriptHash,
) -> bool {
    // CertificateVerify format (TLS 1.3):
    //   SignatureScheme (2 bytes, big-endian)
    //   Signature length (2 bytes, big-endian)
    //   Signature (variable)
    if msg_data.len() < 4 {
        return false;
    }
    let sig_scheme = u16::from_be_bytes([msg_data[0], msg_data[1]]);
    let sig_len = u16::from_be_bytes([msg_data[2], msg_data[3]]) as usize;
    if msg_data.len() < 4 + sig_len {
        return false;
    }
    let sig = &msg_data[4..4 + sig_len];

    // Get the leaf certificate's public key.
    let leaf = match peer_certificates.first() {
        Some(c) => c,
        None => return false,
    };

    // RFC 8446 §4.4.3: the CertificateVerify signature covers the
    // *context-prefixed* transcript hash, not the raw digest:
    //   signed_content = "TLS 1.3, server CertificateVerify" || 0x00 ||
    //                    Transcript-Hash(Handshake Context, Certificate)
    // where the transcript at this point spans ClientHello .. Certificate.
    // Verifying against the bare digest would never match a real server.
    let transcript_hash = transcript.digest();
    let mut signed_content = Vec::with_capacity(35 + 1 + 32);
    signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed_content.push(0x00);
    signed_content.extend_from_slice(&transcript_hash);
    let hash = sha256(&signed_content);

    match leaf.public_key_algorithm_type() {
        certificate::PublicKeyAlgorithm::Ecdsa => {
            if sig_scheme != SIG_SCHEME_ECDSA_P256_SHA256 {
                return false;
            }
            // Parse the DER-encoded ECDSA signature.
            let (r, s) = match crate::kernel::crypto::parse_ecdsa_der_signature(sig) {
                Some(parts) => parts,
                None => return false,
            };
            crate::kernel::crypto::ecdsa_p256_verify(&leaf.public_key, &hash, &r, &s)
        }
        certificate::PublicKeyAlgorithm::Rsa => {
            if sig_scheme != SIG_SCHEME_RSA_PSS_RSAE_SHA256 {
                return false;
            }
            // Parse the RSA public key from the leaf certificate's SPKI.
            let (n, e) = match certificate::parse_rsa_public_key(&leaf.public_key) {
                Some(parts) => parts,
                None => return false,
            };
            crate::kernel::crypto::rsa_pss_verify(&n, &e, &hash, sig)
        }
        _ => false,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HKDF-Expand-Label test vector (RFC 8448 §3) ──────────────────────

    #[test]
    fn hkdf_expand_label_produces_known_output() {
        // Using the RFC 5869 test vector for HKDF-SHA256 as the PRK,
        // derive a labeled key.
        // Test vectors from RFC 8446 §7.1 (handshake traffic secrets
        // derivation is tested end-to-end in the key_schedule test).
        let secret = sha256(b"test-secret-32-bytes-xxxxxxxxx");
        let output = hkdf_expand_label(&secret, "key", &[], 16);
        assert_eq!(output.len(), 16);
        // Deterministic output: same input → same output.
        let output2 = hkdf_expand_label(&secret, "key", &[], 16);
        assert_eq!(output, output2);
        // Different label → different output.
        let output3 = hkdf_expand_label(&secret, "iv", &[], 12);
        assert_ne!(&output[..12], &output3);
    }

    // ── Key schedule end-to-end ─────────────────────────────────────────

    #[test]
    fn key_schedule_roundtrip() {
        // Simulate a complete key schedule:
        //   1. ECDH shared secret (simulated with random)
        //   2. Derive handshake secrets
        //   3. Derive application secrets
        let mut shared_secret = [0u8; 32];
        crate::kernel::random::fill_random(&mut shared_secret);
        shared_secret[0] &= 248; // Clamp.

        // Transcript after ClientHello...ServerHello.
        let ch_sh_hash = sha256(b"CH...SH transcript");

        let hs = HandshakeSecrets::compute(&shared_secret, &ch_sh_hash);
        // Verify secrets are non-zero and distinct.
        assert_ne!(hs.client_handshake_secret, [0u8; 32]);
        assert_ne!(hs.server_handshake_secret, [0u8; 32]);
        assert_ne!(hs.client_handshake_secret, hs.server_handshake_secret);

        // Derive handshake keys.
        let (client_hs_keys, server_hs_keys) =
            hs.derive_handshake_keys(CipherSuite::Aes128GcmSha256);
        assert_eq!(client_hs_keys.write_key.len(), 16);
        assert_eq!(server_hs_keys.write_key.len(), 16);
        assert_ne!(client_hs_keys.write_key, server_hs_keys.write_key);

        // Finished keys.
        let s_fin_key = hs.server_finished_key();
        let c_fin_key = hs.client_finished_key();
        assert_ne!(s_fin_key, c_fin_key);
        assert_ne!(s_fin_key, [0u8; 32]);

        // Application secrets.
        let sf_hash = sha256(b"CH...SF transcript");
        let app = ApplicationSecrets::compute(&hs.handshake_secret, &sf_hash);
        assert_ne!(app.client_application_secret, [0u8; 32]);
        assert_ne!(app.server_application_secret, [0u8; 32]);
        assert_ne!(app.client_application_secret, app.server_application_secret);
        // App secrets should differ from handshake secrets.
        assert_ne!(app.client_application_secret, hs.client_handshake_secret);
    }

    // ── ServerHello parsing ─────────────────────────────────────────────

    #[test]
    fn parse_server_hello_extracts_fields() {
        let mut sh = Vec::new();
        // Handshake type (ServerHello = 2).
        sh.push(0x02);
        // Length (3 bytes) — placeholder filled later.
        let len_pos = sh.len();
        sh.extend_from_slice(&[0x00, 0x00, 0x00]);

        // Legacy version (0x0303).
        sh.extend_from_slice(&0x0303u16.to_be_bytes());

        // Server random (32 bytes).
        let server_random = [0xA1u8; 32];
        sh.extend_from_slice(&server_random);

        // Legacy session ID (empty).
        sh.push(0x00);

        // Cipher suite: TLS_AES_128_GCM_SHA256 (0x1301).
        sh.extend_from_slice(&0x1301u16.to_be_bytes());

        // Legacy compression (null).
        sh.push(0x00);

        // Extensions.
        let ext_start = sh.len();
        sh.extend_from_slice(&[0x00, 0x00]); // extensions length placeholder

        // Key share extension (type 0x0033).
        let key_share_data = {
            let mut ksd = Vec::new();
            ksd.extend_from_slice(&0x001Du16.to_be_bytes()); // X25519
            ksd.extend_from_slice(&0x0020u16.to_be_bytes()); // key length = 32
            ksd.extend_from_slice(&[0xB2u8; 32]); // server public key
            ksd
        };
        sh.extend_from_slice(&0x0033u16.to_be_bytes());
        sh.extend_from_slice(&(key_share_data.len() as u16).to_be_bytes());
        sh.extend_from_slice(&key_share_data);

        // Supported versions extension (type 0x002B).
        sh.extend_from_slice(&0x002Bu16.to_be_bytes());
        sh.extend_from_slice(&0x0002u16.to_be_bytes()); // length
        sh.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3

        // Fix lengths.
        let ext_len = sh.len() - ext_start - 2;
        sh[ext_start] = (ext_len >> 8) as u8;
        sh[ext_start + 1] = ext_len as u8;
        let msg_len = sh.len() - len_pos - 3;
        sh[len_pos] = (msg_len >> 16) as u8;
        sh[len_pos + 1] = (msg_len >> 8) as u8;
        sh[len_pos + 2] = msg_len as u8;

        let parsed = parse_server_hello(&sh).expect("parse ServerHello");
        assert_eq!(parsed.server_random, server_random);
        assert_eq!(parsed.cipher_suite, CipherSuite::Aes128GcmSha256);
        assert_eq!(parsed.legacy_version, 0x0303);
        assert_eq!(parsed.server_public_key, [0xB2u8; 32]);
    }

    #[test]
    fn parse_server_hello_rejects_non_tls13() {
        let mut sh = Vec::new();
        sh.push(0x02);
        sh.extend_from_slice(&[0x00, 0x00, 0x1C]); // length
        sh.extend_from_slice(&0x0303u16.to_be_bytes());
        sh.extend_from_slice(&[0xC0u8; 32]); // server random
        sh.push(0x00); // empty session id
        sh.extend_from_slice(&0x1301u16.to_be_bytes());
        sh.push(0x00); // null compression
                       // Supported versions: TLS 1.2 (0x0303) — NOT TLS 1.3.
        sh.extend_from_slice(&0x002Bu16.to_be_bytes());
        sh.extend_from_slice(&0x0002u16.to_be_bytes());
        sh.extend_from_slice(&0x0303u16.to_be_bytes()); // 1.2, not 1.3
                                                        // Key share.
        sh.extend_from_slice(&0x0033u16.to_be_bytes());
        sh.extend_from_slice(&0x0024u16.to_be_bytes());
        sh.extend_from_slice(&0x001Du16.to_be_bytes());
        sh.extend_from_slice(&0x0020u16.to_be_bytes());
        sh.extend_from_slice(&[0xD0u8; 32]);

        assert!(parse_server_hello(&sh).is_err());
    }

    // ── Finished verification ───────────────────────────────────────────

    #[test]
    fn server_finished_verifies_and_rejects_bad_hmac() {
        let finished_key = sha256(b"server-finished-key-32-bytes!!");
        let transcript = sha256(b"transcript up to server finished");

        // Build a valid Finished.
        let verify_data = hmac_sha256(&finished_key, &transcript);
        let mut finished_msg = Vec::new();
        finished_msg.push(HS_FINISHED);
        finished_msg.extend_from_slice(&(32u32).to_be_bytes()[1..]);
        finished_msg.extend_from_slice(&verify_data);

        let parsed = verify_server_finished(&finished_msg, &finished_key, &transcript)
            .expect("valid Finished");
        assert_eq!(parsed.verify_data, verify_data);

        // Corrupt verify_data.
        let mut bad = finished_msg.clone();
        bad[5] ^= 1;
        assert!(verify_server_finished(&bad, &finished_key, &transcript).is_err());
    }

    #[test]
    fn client_finished_build_and_verify() {
        let finished_key = sha256(b"client-finished-key-32-bytes!!");
        let transcript = sha256(b"transcript including server finished");

        let client_finished = build_client_finished(&finished_key, &transcript);
        assert_eq!(client_finished[0], HS_FINISHED);
        let msg_len = u24_from_be(&client_finished[1..4]);
        assert_eq!(msg_len, 32);

        // Verify by recomputing HMAC.
        let expected = hmac_sha256(&finished_key, &transcript);
        assert_eq!(&client_finished[4..4 + 32], &expected);
    }

    // ── Plaintext record I/O ────────────────────────────────────────────

    #[test]
    fn parse_plaintext_tls_record_roundtrip() {
        let payload = b"test handshake message";
        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);

        let (ct, data) = parse_plaintext_tls_record(&record).expect("parse");
        assert_eq!(ct, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(data, payload);
    }

    // ── Handshake message stream parsing ───────────────────────────────

    #[test]
    fn parse_handshake_messages_from_stream_multiple() {
        let mut stream = Vec::new();
        // Message 1: type=8, len=2, payload=[0xAA, 0xBB]
        stream.push(8);
        stream.extend_from_slice(&[0x00, 0x00, 0x02]);
        stream.extend_from_slice(&[0xAA, 0xBB]);
        // Message 2: type=11, len=4, payload=[0x01, 0x02, 0x03, 0x04]
        stream.push(11);
        stream.extend_from_slice(&[0x00, 0x00, 0x04]);
        stream.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let mut transcript = TranscriptHash::new();
        let msgs =
            parse_handshake_messages_from_stream(&stream, &mut transcript).expect("parse stream");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].0, 8);
        assert_eq!(msgs[1].0, 11);

        // Transcript should now contain both messages.
        let digest = transcript.digest();
        // Sanity: non-zero digest.
        assert_ne!(digest, [0u8; 32]);
    }

    // ── Certificate message parsing ──────────────────────────────────────

    /// Build a minimal DER-encoded certificate for testing.
    fn build_minimal_der_cert(cn: &str) -> Vec<u8> {
        // Build a simple self-signed X.509 v3 cert with the given CN.
        // We reuse the approach from certificate.rs tests.
        let cn_bytes = cn.as_bytes();

        // Subject attribute: SEQUENCE { OID 2.5.4.3, UTF8String CN }
        let oid_cn = &[0x55, 0x04, 0x03];
        let mut attr = Vec::new();
        attr.push(0x06);
        attr.push(oid_cn.len() as u8);
        attr.extend_from_slice(oid_cn);
        attr.push(0x0C);
        attr.push(cn_bytes.len() as u8);
        attr.extend_from_slice(cn_bytes);
        let attr_seq = {
            let mut s = Vec::new();
            s.push(0x30);
            s.push(attr.len() as u8);
            s.extend_from_slice(&attr);
            s
        };

        // SET { attr_seq }
        let mut set = Vec::new();
        set.push(0x31);
        set.push(attr_seq.len() as u8);
        set.extend_from_slice(&attr_seq);

        // SEQUENCE { set } (subject)
        let mut subject = Vec::new();
        subject.push(0x30);
        subject.push(set.len() as u8);
        subject.extend_from_slice(&set);

        let issuer = subject.clone();

        // Validity
        let not_before = [
            0x17, 0x0D, b'0', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0',
            b'Z',
        ];
        let not_after = [
            0x17, 0x0D, b'9', b'9', b'9', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9',
            b'5', b'9', b'Z',
        ];
        let mut validity = Vec::new();
        validity.push(0x30);
        validity.push((not_before.len() + not_after.len()) as u8);
        validity.extend_from_slice(&not_before);
        validity.extend_from_slice(&not_after);

        // SPKI: RSA OID + NULL + BIT STRING
        let rsa_oid = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
        ];
        let null = [0x05, 0x00];
        let mut algo = Vec::new();
        algo.push(0x30);
        algo.push((rsa_oid.len() + null.len()) as u8);
        algo.extend_from_slice(&rsa_oid);
        algo.extend_from_slice(&null);
        let pubkey = [0x03, 0x02, 0x00, 0x00]; // BIT STRING with 0 unused bits + 1 byte

        let mut spki = Vec::new();
        spki.push(0x30);
        spki.push((algo.len() + pubkey.len()) as u8);
        spki.extend_from_slice(&algo);
        spki.extend_from_slice(&pubkey);

        // Version [0] INTEGER 2
        let ver = [0xA0, 0x03, 0x02, 0x01, 0x02];
        // Serial = 1
        let serial = [0x02, 0x01, 0x01];

        // Signature algorithm
        let sig_alg = algo.clone();

        // TBSCertificate
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&ver);
        tbs.extend_from_slice(&serial);
        tbs.extend_from_slice(&sig_alg);
        tbs.extend_from_slice(&issuer);
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&subject);
        tbs.extend_from_slice(&spki);

        let mut tbs_wrap = Vec::new();
        tbs_wrap.push(0x30);
        write_u16_length(&mut tbs_wrap, tbs.len());
        tbs_wrap.extend_from_slice(&tbs);

        // Certificate
        let sig_value = [0x03, 0x01, 0x00]; // empty signature
        let mut cert = Vec::new();
        cert.push(0x30);
        write_u16_length(&mut cert, tbs_wrap.len() + sig_alg.len() + sig_value.len());
        cert.extend_from_slice(&tbs_wrap);
        cert.extend_from_slice(&sig_alg);
        cert.extend_from_slice(&sig_value);
        cert
    }

    fn write_u16_length(buf: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
    }

    #[test]
    fn parse_certificate_message_extracts_cn() {
        let cert_der = build_minimal_der_cert("example.com");
        // Build a TLS Certificate handshake message containing this cert.
        let mut payload = Vec::new();
        payload.push(0x00); // certificate_request_context (empty)
                            // Certificate list length (3 bytes in big-endian).
        let cert_list = {
            let mut cl = Vec::new();
            // Each cert: 3-byte length + DER + 2-byte extensions (empty)
            cl.push((cert_der.len() >> 16) as u8);
            cl.push((cert_der.len() >> 8) as u8);
            cl.push(cert_der.len() as u8);
            cl.extend_from_slice(&cert_der);
            cl.extend_from_slice(&[0x00, 0x00]); // empty extensions
            cl
        };
        // 3-byte big-endian length.
        payload.extend_from_slice(&(cert_list.len() as u32).to_be_bytes()[1..]);
        payload.extend_from_slice(&cert_list);

        // Prepend handshake header.
        let mut msg = alloc::vec![HS_CERTIFICATE];
        msg.push((payload.len() >> 16) as u8);
        msg.push((payload.len() >> 8) as u8);
        msg.push(payload.len() as u8);
        msg.extend_from_slice(&payload);

        let certs = parse_certificate_message(&msg).expect("parse certificate message");
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].common_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_certificate_message_rejects_truncated() {
        let truncated = [HS_CERTIFICATE, 0x00, 0x00, 0x10, 0x00]; // claimed length 16, only 1 byte payload
        assert!(parse_certificate_message(&truncated).is_err());
    }
}
