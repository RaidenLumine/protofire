//! src/kernel/fs/luks2.rs
//!
//! LUKS2 on-disk format parser and keyslot unlock.
//!
//! Parses the LUKS2 binary header (at sector 0), locates the JSON
//! metadata area, extracts keyslot parameters via minimal string
//! scanning, recovers the master key via AF-merge + PBKDF2, verifies
//! the digest, and returns an [`EncryptedBlockDevice`].

use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::crypto::{pbkdf2_hmac_sha256, sha256};
use crate::kernel::fs::block::{BlockDevice, BLOCK_SIZE};
use crate::kernel::fs::crypt_device::EncryptedBlockDevice;
use crate::{Error, Result};

// ── LUKS2 magic constants ──────────────────────────────────────────────

/// LUKS2 magic: "LUKS\xBA\xBE"
const LUKS2_MAGIC: [u8; 6] = [0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE];
/// Expected LUKS2 version number (big-endian).
const LUKS2_VERSION: u16 = 2;

// ── Base64 decoder ─────────────────────────────────────────────────────

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode a base64 string (standard RFC 4648, padding optional).
fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() {
        return Some(Vec::new());
    }

    // Build reverse lookup table.
    let mut rev = [0xFFu8; 256];
    for (i, &c) in BASE64_CHARS.iter().enumerate() {
        rev[c as usize] = i as u8;
    }

    let mut output = Vec::with_capacity(input.len() / 4 * 3);

    let mut i = 0;
    while i < input.len() {
        // Skip whitespace/newlines
        if input[i] == b' ' || input[i] == b'\n' || input[i] == b'\r' || input[i] == b'\t' {
            i += 1;
            continue;
        }

        // Collect up to 4 valid base64 characters.
        let mut vals = [0u8; 4];
        let mut data_count = 0usize;
        let mut pad_count = 0usize;
        while data_count + pad_count < 4 && i < input.len() {
            if input[i] == b'=' {
                pad_count += 1;
                i += 1;
                continue;
            }
            let v = rev[input[i] as usize];
            if v == 0xFF {
                // Invalid character.
                return None;
            }
            vals[data_count] = v;
            data_count += 1;
            i += 1;
        }

        if data_count == 0 {
            break;
        }

        let b0 = vals[0];
        match data_count {
            2 => {
                // 2 data chars → 1 byte
                output.push((b0 << 2) | (vals[1] >> 4));
            }
            3 => {
                // 3 data chars → 2 bytes
                output.push((b0 << 2) | (vals[1] >> 4));
                output.push((vals[1] << 4) | (vals[2] >> 2));
            }
            4 => {
                // 4 data chars → 3 bytes
                output.push((b0 << 2) | (vals[1] >> 4));
                output.push((vals[1] << 4) | (vals[2] >> 2));
                output.push((vals[2] << 6) | vals[3]);
            }
            _ => {}
        }
    }

    Some(output)
}

// ── Minimal JSON string scanner ────────────────────────────────────────

/// Find the value of a quoted string key in a JSON-like text.
///
/// Searches for `"<key>":` and then extracts the next JSON value
/// (either a quoted string or a number).  Returns `None` if the key
/// is not found.
fn json_find_string<'a>(haystack: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let key_pattern: Vec<u8> = {
        let mut p = Vec::new();
        p.push(b'"');
        p.extend_from_slice(key.as_bytes());
        p.extend_from_slice(b"\":");
        p
    };

    let pos = haystack
        .windows(key_pattern.len())
        .position(|w| w == &key_pattern[..])?;
    let rest = &haystack[pos + key_pattern.len()..];
    // Skip whitespace.
    let start = rest
        .iter()
        .position(|&c| c != b' ' && c != b'\n' && c != b'\r' && c != b'\t')?;
    let rest = &rest[start..];

    if rest.is_empty() {
        return None;
    }

    if rest[0] == b'"' {
        // Quoted string.
        let end = rest[1..].iter().position(|&c| c == b'"')?;
        Some(&rest[1..1 + end])
    } else if rest[0] == b'-' || rest[0].is_ascii_digit() {
        // Number (treated as string).
        let end = rest[1..]
            .iter()
            .position(|&c| c != b'-' && c != b'.' && !c.is_ascii_digit())
            .map(|p| p + 1)
            .unwrap_or(rest.len());
        Some(&rest[..end])
    } else {
        None
    }
}

/// Find a JSON object by scanning for `"<key>":{`.
fn json_find_object<'a>(haystack: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let obj_pattern: Vec<u8> = {
        let mut p = Vec::new();
        p.push(b'"');
        p.extend_from_slice(key.as_bytes());
        p.extend_from_slice(b"\":{");
        p
    };

    let pos = haystack
        .windows(obj_pattern.len())
        .position(|w| w == &obj_pattern[..])?;
    let rest = &haystack[pos + obj_pattern.len() - 1..];
    // rest starts at '{'
    // Find matching closing brace.
    let mut depth = 1u32;
    for (i, &c) in rest[1..].iter().enumerate() {
        if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                // Include the closing brace.
                return Some(&rest[..=i + 1]);
            }
        }
    }
    None
}

/// Parse a decimal integer from a byte slice.
fn parse_decimal(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut val: u64 = 0;
    let mut neg = false;
    for (i, &c) in s.iter().enumerate() {
        if i == 0 && c == b'-' {
            neg = true;
            continue;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?;
        val = val.checked_add((c - b'0') as u64)?;
    }
    if neg {
        None // Negative values not expected.
    } else {
        Some(val)
    }
}

// ── LUKS2 header reading ───────────────────────────────────────────────

/// Parsed LUKS2 binary header.
struct Luks2Header {
    /// Offset to the JSON metadata area (in bytes from device start).
    json_offset: u64,
    /// Size of the JSON metadata area in bytes.
    json_size: u64,
    // NOTE: payload offset is NOT in the binary header (the field at bytes
    // 48-55 is padding/reserved).  Read it from JSON "segments"."0"."offset".
}

/// Parse the LUKS2 binary header from the first block of the device.
fn parse_luks2_header(device: &dyn BlockDevice) -> Result<Luks2Header> {
    let mut block = [0u8; BLOCK_SIZE];
    device.read_blocks(0, &mut block)?;

    // Check magic.
    if block[..6] != LUKS2_MAGIC {
        return Err(Error::InvalidArgument);
    }

    // Check version (big-endian u16 at offset 6).
    let version = u16::from_be_bytes([block[6], block[7]]);
    if version != LUKS2_VERSION {
        return Err(Error::Unsupported);
    }

    // Parse hdr_size (u64 big-endian at offset 8).
    let hdr_size = u64::from_be_bytes([
        block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
    ]);

    // Parse JSON area offset (u64 big-endian at offset 16).
    let json_offset = u64::from_be_bytes([
        block[16], block[17], block[18], block[19], block[20], block[21], block[22], block[23],
    ]);

    Ok(Luks2Header {
        json_offset,
        json_size: hdr_size, // JSON area size is typically hdr_size for primary header
    })
}

// Not all BE positions are standard — let's also read json_size from JSON.
fn get_json_size_from_json(json: &[u8]) -> Option<u64> {
    // Look for "config":{"json_size":"...",...}
    let config_obj = json_find_object(json, "config")?;
    let size_str = json_find_string(config_obj, "json_size")?;
    parse_decimal(size_str)
}

fn get_payload_offset_from_json(json: &[u8]) -> Option<u64> {
    // In LUKS2, the payload (encrypted data) offset is stored in the
    // "segments" section: segments -> "0" -> "offset" (in bytes).
    let segments_obj = json_find_object(json, "segments")?;
    let segment0_obj = json_find_object(segments_obj, "0")?;
    let offset_str = json_find_string(segment0_obj, "offset")?;
    parse_decimal(offset_str)
}

// ── Keyslot parameters ─────────────────────────────────────────────────

/// Parameters extracted from a LUKS2 keyslot.
struct KeyslotParams {
    /// Keyslot area offset on disk (in bytes).
    area_offset: u64,
    /// Keyslot area size on disk (in bytes).
    area_size: u64,
    /// KDF salt (base64-decoded).
    kdf_salt: Vec<u8>,
    /// PBKDF2 iteration count.
    kdf_iterations: u32,
    /// Key size in bytes (e.g., 32 for AES-256).
    key_size: usize,
    /// AF stripes count.
    af_stripes: u32,
    /// AF hash algorithm.
    af_hash: String,
}

/// Parse keyslot parameters from the JSON metadata.
///
/// Searches for the first keyslot that uses "luks2" type with "pbkdf2" KDF.
fn parse_keyslot(json: &[u8]) -> Option<KeyslotParams> {
    // Find the "keyslots" object.
    let keyslots_obj = json_find_object(json, "keyslots")?;

    // Scan for numbered keyslot entries.
    let mut slot_id = 0u32;
    loop {
        let slot_key = alloc::format!("{}", slot_id);
        let slot_obj = json_find_object(keyslots_obj, &slot_key)?;

        // Check type.
        let slot_type = json_find_string(slot_obj, "type")?;
        if slot_type != b"luks2" {
            slot_id += 1;
            continue;
        }

        // Parse key_size.
        let key_size_str = json_find_string(slot_obj, "key_size")?;
        let key_size = parse_decimal(key_size_str)? as usize;

        // Parse area section.
        let area_obj = json_find_object(slot_obj, "area")?;
        let area_offset_str = json_find_string(area_obj, "offset")?;
        let area_offset = parse_decimal(area_offset_str)?;
        let area_size_str = json_find_string(area_obj, "size")?;
        let area_size = parse_decimal(area_size_str)?;

        // Parse KDF section.
        let kdf_obj = json_find_object(slot_obj, "kdf")?;
        let kdf_type = json_find_string(kdf_obj, "type")?;
        if kdf_type != b"pbkdf2" {
            slot_id += 1;
            continue;
        }
        let salt_str = json_find_string(kdf_obj, "salt")?;
        let salt = base64_decode(salt_str)?;
        let iterations_str = json_find_string(kdf_obj, "iterations")?;
        let iterations = parse_decimal(iterations_str)? as u32;

        // Parse AF section.
        let af_obj = json_find_object(slot_obj, "af")?;
        let stripes_str = json_find_string(af_obj, "stripes")?;
        let stripes = parse_decimal(stripes_str)? as u32;
        let af_hash_str = json_find_string(af_obj, "hash")?;
        let af_hash = core::str::from_utf8(af_hash_str).ok()?.to_string();

        return Some(KeyslotParams {
            area_offset,
            area_size,
            kdf_salt: salt,
            kdf_iterations: iterations,
            key_size,
            af_stripes: stripes,
            af_hash,
        });
    }
}

// ── Digest verification ────────────────────────────────────────────────

/// Digest parameters for verifying the recovered master key.
struct DigestParams {
    /// Digest salt (base64-decoded).
    salt: Vec<u8>,
    /// Digest iterations.
    iterations: u32,
    /// Expected digest value (base64-decoded, typically 32 bytes for SHA-256).
    digest: Vec<u8>,
    /// Digest hash algorithm.
    hash: String,
}

/// Parse digest parameters from the JSON metadata.
///
/// Searches for the first digest that references a keyslot.
fn parse_digest(json: &[u8]) -> Option<DigestParams> {
    let digests_obj = json_find_object(json, "digests")?;

    // Try digests "0", "1", etc.
    let mut digest_id = 0u32;
    loop {
        let digest_key = alloc::format!("{}", digest_id);
        let digest_obj = json_find_object(digests_obj, &digest_key)?;

        let digest_type = json_find_string(digest_obj, "type")?;
        if digest_type != b"pbkdf2" {
            digest_id += 1;
            continue;
        }

        let salt_str = json_find_string(digest_obj, "salt")?;
        let salt = base64_decode(salt_str)?;
        let iterations_str = json_find_string(digest_obj, "iterations")?;
        let iterations = parse_decimal(iterations_str)? as u32;
        let digest_str = json_find_string(digest_obj, "digest")?;
        let digest = base64_decode(digest_str)?;
        let hash_str = json_find_string(digest_obj, "hash")?;
        let hash = core::str::from_utf8(hash_str).ok()?.to_string();

        return Some(DigestParams {
            salt,
            iterations,
            digest,
            hash,
        });
    }
}

// ── AF merge (anti-forensic split merge) ───────────────────────────────

/// Merge AF stripes to recover the wrapped master key.
///
/// Uses SHA-256 as the hash function for the AF chain.
/// The AF data is `stripes * key_size` bytes on disk.
/// After the merge, the first `key_size` bytes contain the wrapped key.
fn af_merge(af_data: &[u8], _stripes: u32, key_size: usize) -> Vec<u8> {
    let stripes = _stripes as usize;
    if af_data.len() < stripes * key_size {
        return Vec::new();
    }

    let mut result = af_data.to_vec();

    // Process stripes in forward order: for each stripe i >= 1,
    // XOR the hash of the previous stripe into the current stripe.
    for i in 1..stripes {
        let prev_start = (i - 1) * key_size;
        let cur_start = i * key_size;

        let prev_stripe = &result[prev_start..prev_start + key_size];
        let hash_val = sha256(prev_stripe);

        // XOR hash into current stripe (repeat hash if key_size > 32).
        for j in 0..key_size {
            result[cur_start + j] ^= hash_val[j % 32];
        }
    }

    // The first key_size bytes now contain the wrapped key.
    result[..key_size].to_vec()
}

// ── Main LUKS2 open function ──────────────────────────────────────────

/// Open a LUKS2-encrypted block device using a passphrase.
///
/// Reads the LUKS2 header, locates a viable keyslot, derives the master
/// key using PBKDF2-HMAC-SHA256 and AF merge, verifies the digest, and
/// returns an `EncryptedBlockDevice` that transparently encrypts/decrypts
/// the payload area.
///
/// The returned `EncryptedBlockDevice` wraps a block-device *slice* that
/// starts after the LUKS2 header/payload offset, so data-unit indices
/// are relative to the payload.
pub fn luks2_open(device: Arc<dyn BlockDevice>, passphrase: &[u8]) -> Result<EncryptedBlockDevice> {
    // 1. Parse the binary header.
    let header = parse_luks2_header(device.as_ref())?;

    // 2. Read the JSON metadata area.
    let json_size = header.json_size as usize;
    let mut json_raw = Vec::new();

    // Read the JSON area (may span multiple blocks).
    let json_start_byte = header.json_offset;
    let json_start_sector = json_start_byte / BLOCK_SIZE as u64;
    let json_byte_offset_in_sector = (json_start_byte % BLOCK_SIZE as u64) as usize;

    let total_json_bytes = json_size;
    let mut remaining = total_json_bytes as usize;
    let mut current_sector = json_start_sector;

    // Pre-fill with the offset within the first sector.
    if json_byte_offset_in_sector > 0 {
        // Read the first sector and grab the relevant portion.
        let mut sector_buf = alloc::vec![0u8; BLOCK_SIZE];
        device.read_blocks(current_sector, &mut sector_buf)?;
        let available = BLOCK_SIZE - json_byte_offset_in_sector;
        let take = remaining.min(available);
        json_raw.extend_from_slice(
            &sector_buf[json_byte_offset_in_sector..json_byte_offset_in_sector + take],
        );
        remaining -= take;
        current_sector += 1;
    }

    while remaining > 0 {
        let mut sector_buf = alloc::vec![0u8; BLOCK_SIZE];
        device.read_blocks(current_sector, &mut sector_buf)?;
        let take = remaining.min(BLOCK_SIZE);
        json_raw.extend_from_slice(&sector_buf[..take]);
        remaining -= take;
        current_sector += 1;
    }

    // Also try to get json_size from the JSON itself if the header value was
    // unreliable.
    if let Some(js) = get_json_size_from_json(&json_raw) {
        let target_len = (js as usize).max(json_raw.len());
        while json_raw.len() < target_len {
            let mut sector_buf = alloc::vec![0u8; BLOCK_SIZE];
            device.read_blocks(current_sector, &mut sector_buf)?;
            let take = (target_len - json_raw.len()).min(BLOCK_SIZE);
            json_raw.extend_from_slice(&sector_buf[..take]);
            current_sector += 1;
        }
    }

    // 3. Find a valid keyslot.
    let keyslot = parse_keyslot(&json_raw).ok_or(Error::NotFound)?;

    // The AF merge below implements SHA-256; reject keyslots that request
    // any other AF hash algorithm.
    if keyslot.af_hash != "sha256" {
        return Err(Error::Unsupported);
    }

    // 4. Derive key from passphrase.
    let derived_key = pbkdf2_hmac_sha256(
        passphrase,
        &keyslot.kdf_salt,
        keyslot.kdf_iterations,
        keyslot.key_size,
    );

    // 5. Read AF data from the keyslot area on disk.
    let af_total_size = keyslot.af_stripes as usize * keyslot.key_size;
    // The AF chain must fit entirely within the keyslot's declared area.
    if af_total_size > keyslot.area_size as usize {
        return Err(Error::InvalidArgument);
    }
    let af_start_byte = keyslot.area_offset;
    let af_start_sector = af_start_byte / BLOCK_SIZE as u64;
    let af_byte_offset = (af_start_byte % BLOCK_SIZE as u64) as usize;

    let mut af_data = alloc::vec![0u8; af_total_size];
    device.read_blocks(af_start_sector, &mut af_data)?;

    if af_byte_offset > 0 {
        // If AF data doesn't start at a sector boundary, read more.
        let mut extended = alloc::vec![0u8; af_total_size + BLOCK_SIZE];
        device.read_blocks(af_start_sector, &mut extended)?;
        af_data.copy_from_slice(&extended[af_byte_offset..af_byte_offset + af_total_size]);
    }

    // 6. AF merge to recover the wrapped key.
    let wrapped_key = af_merge(&af_data, keyslot.af_stripes, keyslot.key_size);

    if wrapped_key.len() != keyslot.key_size {
        return Err(Error::InvalidCredential);
    }

    // 7. XOR with derived key to get the candidate master key.
    //    For AES-256-XTS, key_size is 64 bytes (two 32-byte keys).
    //    For AES-128-XTS, key_size is 32 bytes.
    let xts_key_size = keyslot.key_size;
    let mut xts_key = alloc::vec![0u8; xts_key_size.max(64)];

    for j in 0..xts_key_size {
        xts_key[j] = wrapped_key[j] ^ derived_key[j];
    }

    // If key is only 32 bytes (AES-128-XTS), derive Key2 = SHA256(Key1).
    if xts_key_size == 32 {
        let key1 = &xts_key[..32];
        let key2 = sha256(key1);
        xts_key[32..64].copy_from_slice(&key2);
    }

    // 8. Verify the digest.
    let digest = parse_digest(&json_raw).ok_or(Error::NotFound)?;

    // The digest check below uses PBKDF2-HMAC-SHA256; reject digests that
    // request any other hash algorithm.
    if digest.hash != "sha256" {
        return Err(Error::Unsupported);
    }

    // Compute expected digest: PBKDF2(master_key, digest.salt, digest.iterations)
    let check = pbkdf2_hmac_sha256(
        &xts_key[..xts_key_size.min(32)],
        &digest.salt,
        digest.iterations,
        digest.digest.len(),
    );

    // Constant-time comparison.
    let mut diff: u8 = 0;
    for (a, b) in check.iter().zip(digest.digest.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(Error::InvalidCredential);
    }

    // 9. Determine the payload offset from JSON.
    let payload_offset_sectors = get_payload_offset_from_json(&json_raw).unwrap_or(0);

    // 10. Build the payload slice and wrap in EncryptedBlockDevice.
    let payload_block_count = device
        .block_count()
        .saturating_sub(payload_offset_sectors / (BLOCK_SIZE as u64));

    let payload_slice = crate::kernel::fs::block::BlockSliceDevice::new(
        "luks2-payload",
        device,
        payload_offset_sectors / (BLOCK_SIZE as u64),
        payload_block_count,
        false,
    );

    let mut final_key = [0u8; 64];
    final_key.copy_from_slice(&xts_key[..64]);

    Ok(EncryptedBlockDevice::new(
        payload_slice,
        final_key,
        "luks2-crypt",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_roundtrip() {
        let input = b"SGVsbG8gV29ybGQ=";
        let decoded = base64_decode(input).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn base64_decode_empty() {
        assert_eq!(base64_decode(b"").unwrap(), b"");
    }

    #[test]
    fn base64_decode_no_padding() {
        let input = b"SGVsbG8gV29ybGQ"; // without padding
        let decoded = base64_decode(input).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn base64_decode_binary() {
        let input = b"////"; // 0xFF 0xFF 0xFF
        let decoded = base64_decode(input).unwrap();
        assert_eq!(decoded, &[0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn json_find_string_works() {
        let json = br#"{"foo":"bar","baz":42}"#;
        assert_eq!(json_find_string(json, "foo"), Some(&b"bar"[..]));
    }

    #[test]
    fn json_find_string_number() {
        let json = br#"{"count": 1234}"#;
        assert_eq!(json_find_string(json, "count"), Some(&b"1234"[..]));
    }

    #[test]
    fn json_find_object_works() {
        let json = br#"{"outer":{"inner":"value"}}"#;
        let obj = json_find_object(json, "outer").unwrap();
        assert_eq!(obj, br#"{"inner":"value"}"#);
    }

    #[test]
    fn parse_decimal_works() {
        assert_eq!(parse_decimal(b"12345"), Some(12345));
        assert_eq!(parse_decimal(b"0"), Some(0));
        assert_eq!(parse_decimal(b"9999999999999999"), Some(9999999999999999));
    }
}
