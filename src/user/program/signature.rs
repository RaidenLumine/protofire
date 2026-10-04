//! src/user/program/signature.rs
//!
//! Detached signature parsing and verification helpers for launch metadata
//! integrity checks.
//!
//! Launch metadata (catalog manifests, installed program images) can carry an
//! optional `…_signature` field.  When present, the signature is verified
//! against a trusted Lamport-sha256 public key record under
//! [`TRUSTED_SIGNATURE_KEY_ROOT`]; when absent, verification is skipped.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::fs::FileSystem;
use crate::Error;
use crate::Result;

use super::catalog::path_parent_dir;
use super::catalog::read_text_file;
use super::integrity::sha256_digest;
use super::integrity::sha256_hex;
use super::metadata::parse_optional_string_field;
use super::metadata::parse_string_field;

/// Root directory containing trusted public-key records (`.toml`).
const TRUSTED_SIGNATURE_KEY_ROOT: &str = "/system/trusted-keys";

const LAMPORT_SIGNATURE_KIND: &str = "lamport-sha256";
pub(crate) const LAMPORT_MESSAGE_BITS: usize = 256;
pub(crate) const LAMPORT_ELEMENT_BYTES: usize = 32;
pub(crate) const LAMPORT_SIGNATURE_BYTES: usize = LAMPORT_MESSAGE_BITS * LAMPORT_ELEMENT_BYTES;
pub(crate) const LAMPORT_PUBLIC_KEY_BYTES: usize = LAMPORT_MESSAGE_BITS * 2 * LAMPORT_ELEMENT_BYTES;
const MAX_SIGNATURE_KEY_ID_BYTES: usize = 128;

pub(crate) struct ParsedDetachedSignature<'a> {
    pub(crate) key_id: &'a str,
    pub(crate) payload: Vec<u8>,
}

pub(crate) fn verify_optional_signature(
    fs: &FileSystem,
    bytes: &[u8],
    signature_text: Option<&str>,
) -> Result<()> {
    let Some(signature_text) = signature_text else {
        return Ok(());
    };

    let signature = parse_detached_signature(signature_text)?;
    let public_key = load_trusted_lamport_public_key(fs, signature.key_id)?;
    verify_lamport_signature(bytes, &signature.payload, &public_key)
}

#[cfg(not(target_os = "none"))]
/// The one place that knows what a detached signature looks like.
///
/// The signer and the verifier are on opposite sides of a trust boundary — one
/// runs on a build host, the other in the kernel — and the format is what they
/// have to agree on, so it is rendered here and parsed here.
pub(crate) fn render_detached_signature(key_id: &str, payload: &[u8]) -> String {
    format!("{LAMPORT_SIGNATURE_KIND}:{key_id}:{}", encode_hex(payload))
}

#[cfg(not(target_os = "none"))]
/// Validate a key id, for a caller that is about to make one up.
pub(crate) fn validate_key_id(key_id: &str) -> Result<()> {
    validate_signature_key_id(key_id)
}

#[cfg(not(target_os = "none"))]
/// Render the trusted-key record a verifier reads for `key_id`.
///
/// The reader is [`load_trusted_lamport_public_key`], and this is its other
/// half, so a key a host tool writes is one the kernel can check — including
/// the digest the record carries about itself, which the reader verifies when
/// it is present.
pub(crate) fn render_trusted_key_record(key_id: &str, public_key: &[u8]) -> String {
    format!(
        "kind = \"{LAMPORT_SIGNATURE_KIND}\"\n\
         key_id = \"{key_id}\"\n\
         public_key_hex = \"{}\"\n\
         public_key_sha256 = \"{}\"\n",
        encode_hex(public_key),
        sha256_hex(public_key),
    )
}

pub(crate) fn parse_detached_signature(value: &str) -> Result<ParsedDetachedSignature<'_>> {
    let Some(rest) = value.strip_prefix(LAMPORT_SIGNATURE_KIND) else {
        return Err(Error::Unsupported);
    };
    let Some(rest) = rest.strip_prefix(':') else {
        return Err(Error::InvalidArgument);
    };
    let Some((key_id, payload_hex)) = rest.split_once(':') else {
        return Err(Error::InvalidArgument);
    };
    validate_signature_key_id(key_id)?;

    Ok(ParsedDetachedSignature {
        key_id,
        payload: decode_hex_bytes(payload_hex, LAMPORT_SIGNATURE_BYTES)?,
    })
}

fn validate_signature_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty() || key_id.len() > MAX_SIGNATURE_KEY_ID_BYTES {
        return Err(Error::InvalidArgument);
    }
    if !key_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

/// Check `payload` against `public_key` for the digest of `bytes`.
///
/// The public key is passed in rather than looked up, so the same check serves
/// the kernel (whose key comes from `/system/trusted-keys`) and a host tool
/// (whose key comes from a file beside the artifact).
pub(crate) fn verify_lamport_signature(
    bytes: &[u8],
    payload: &[u8],
    public_key: &[u8],
) -> Result<()> {
    if payload.len() != LAMPORT_SIGNATURE_BYTES || public_key.len() != LAMPORT_PUBLIC_KEY_BYTES {
        return Err(Error::InvalidArgument);
    }

    let digest = sha256_digest(bytes);

    for bit_index in 0..LAMPORT_MESSAGE_BITS {
        let bit = digest_bit(&digest, bit_index) as usize;
        let signature_offset = bit_index * LAMPORT_ELEMENT_BYTES;
        let public_key_offset =
            bit_index * (LAMPORT_ELEMENT_BYTES * 2) + bit * LAMPORT_ELEMENT_BYTES;
        let hashed_signature_element =
            sha256_digest(&payload[signature_offset..signature_offset + LAMPORT_ELEMENT_BYTES]);
        if hashed_signature_element.as_slice()
            != &public_key[public_key_offset..public_key_offset + LAMPORT_ELEMENT_BYTES]
        {
            return Err(Error::PermissionDenied);
        }
    }

    Ok(())
}

fn load_trusted_lamport_public_key(fs: &FileSystem, key_id: &str) -> Result<Vec<u8>> {
    let path = trusted_signature_key_path(key_id)?;
    let text = match read_text_file(fs, path_parent_dir(&path), &path) {
        Ok(text) => text,
        Err(Error::NotFound) => return Err(Error::PermissionDenied),
        Err(error) => return Err(error),
    };

    parse_trusted_key_record(&text, key_id)
}

/// Read a trusted-key record's public key, checking what the record claims.
///
/// The kernel's key comes from `/system/trusted-keys` and a host tool's comes
/// from a file beside the artifact; both are this format, so both are read
/// here.  Keeping one reader is what stops a record the tool writes from being
/// one the kernel cannot check.
pub(crate) fn parse_trusted_key_record(text: &str, key_id: &str) -> Result<Vec<u8>> {
    if parse_string_field(text, "kind")? != LAMPORT_SIGNATURE_KIND {
        return Err(Error::Unsupported);
    }
    if let Some(record_key_id) = parse_optional_string_field(text, "key_id")? {
        if record_key_id != key_id {
            return Err(Error::InvalidArgument);
        }
    }

    let public_key_hex = parse_string_field(text, "public_key_hex")?;
    let public_key = decode_hex_bytes(&public_key_hex, LAMPORT_PUBLIC_KEY_BYTES)?;
    if let Some(public_key_sha256) = parse_optional_string_field(text, "public_key_sha256")? {
        if sha256_hex(&public_key) != public_key_sha256 {
            return Err(Error::PermissionDenied);
        }
    }

    Ok(public_key)
}

fn trusted_signature_key_path(key_id: &str) -> Result<String> {
    validate_signature_key_id(key_id)?;
    Ok(format!("{TRUSTED_SIGNATURE_KEY_ROOT}/{key_id}.toml"))
}

fn decode_hex_bytes(value: &str, expected_len: usize) -> Result<Vec<u8>> {
    if value.len() != expected_len * 2 {
        return Err(Error::InvalidArgument);
    }

    let bytes = value.as_bytes();
    let mut decoded = vec![0_u8; expected_len];
    for index in 0..expected_len {
        let upper = decode_hex_nibble(bytes[index * 2])?;
        let lower = decode_hex_nibble(bytes[index * 2 + 1])?;
        decoded[index] = (upper << 4) | lower;
    }

    Ok(decoded)
}

#[cfg(not(target_os = "none"))]
/// Render bytes as lower-case hex, the form the signature and key records use.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidArgument),
    }
}

fn digest_bit(digest: &[u8; 32], bit_index: usize) -> u8 {
    let byte = digest[bit_index / 8];
    (byte >> (7 - (bit_index % 8))) & 1
}
