//! src/fs/luks2.rs
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

use crate::fs::block::BlockDevice;
use crate::fs::block::BLOCK_SIZE;
use crate::fs::crypt_device::EncryptedBlockDevice;
use crate::kernel::crypto::aes_xts_decrypt;
use crate::kernel::crypto::pbkdf2_hmac_sha256;
use crate::kernel::crypto::sha256;
use crate::Error;
use crate::Result;

// ── LUKS2 magic constants ──────────────────────────────────────────────

/// LUKS2 magic: "LUKS\xBA\xBE"
const LUKS2_MAGIC: [u8; 6] = [0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE];
/// Expected LUKS2 version number (big-endian).
const LUKS2_VERSION: u16 = 2;

// ── Base64 decoder ─────────────────────────────────────────────────────

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode a base64 string (standard RFC 4648, padding optional).
///
/// Exposed as `pub` so the in-tree parser fuzz harness can feed it arbitrary
/// bytes directly.
pub fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
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
pub fn json_find_string<'a>(haystack: &'a [u8], key: &str) -> Option<&'a [u8]> {
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
pub fn json_find_object<'a>(haystack: &'a [u8], key: &str) -> Option<&'a [u8]> {
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
pub fn parse_decimal(s: &[u8]) -> Option<u64> {
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

/// Decrypt a keyslot area with AES-256-XTS and the derived key.
///
/// The area is `aes-xts-plain64` with a 512-byte data unit, and the tweak's
/// unit index counts from **0** within the area — see the call site for how
/// that was established.  `derived_key` is used whole: its first half is the
/// data key and its second half the tweak key, which is what a 64-byte
/// `key_size` means here.
///
/// A key that is not a whole number of 64-byte XTS keys cannot be one, so an
/// area under that is returned unchanged rather than half-decrypted; the merge
/// after it then fails the digest, which is the honest outcome for a volume
/// this function does not understand.
fn decrypt_keyslot_area(area: &[u8], derived_key: &[u8]) -> Vec<u8> {
    /// The XTS data unit the format uses for a keyslot area.
    const KEYS_AREA_UNIT: usize = 512;

    if derived_key.len() < 64 {
        return area.to_vec();
    }
    let key: &[u8; 64] = match derived_key[..64].try_into() {
        Ok(key) => key,
        Err(_) => return area.to_vec(),
    };

    let mut plain = area.to_vec();
    for (unit_index, unit) in plain.chunks_mut(KEYS_AREA_UNIT).enumerate() {
        // The last chunk may be short; XTS decrypts a whole number of blocks,
        // so it is decrypted up to its own length and the tail left as is.
        aes_xts_decrypt(key, unit_index as u64, unit);
    }
    plain
}

/// Diffuse one block with SHA-256, the block index as a big-endian IV.
///
/// This is `diffuse` via `hash_buf` in cryptsetup's `lib/luks1/af.c`: the
/// buffer is hashed in digest-sized pieces, and each piece is preceded by its
/// own index as a `uint32_t` in big-endian order.  A trailing piece shorter
/// than a digest is hashed (and written) at its own length, which is why the
/// last piece is handled separately rather than zero-padded.
fn af_diffuse_into(src: &[u8], dst: &mut [u8]) {
    const DIGEST_SIZE: usize = 32; // SHA-256
    let blocks = src.len() / DIGEST_SIZE;
    let padding = src.len() % DIGEST_SIZE;

    for i in 0..blocks {
        let start = i * DIGEST_SIZE;
        let mut input = Vec::with_capacity(4 + DIGEST_SIZE);
        input.extend_from_slice(&(i as u32).to_be_bytes());
        input.extend_from_slice(&src[start..start + DIGEST_SIZE]);
        let digest = sha256(&input);
        dst[start..start + DIGEST_SIZE].copy_from_slice(&digest[..DIGEST_SIZE]);
    }
    if padding > 0 {
        let start = blocks * DIGEST_SIZE;
        let mut input = Vec::with_capacity(4 + padding);
        input.extend_from_slice(&(blocks as u32).to_be_bytes());
        input.extend_from_slice(&src[start..start + padding]);
        let digest = sha256(&input);
        dst[start..start + padding].copy_from_slice(&digest[..padding]);
    }
}

/// Recover the master key from the AF stripes a keyslot's area holds.
///
/// This is `AF_merge` in cryptsetup's `lib/luks1/af.c`, and it is not what
/// this function used to do.  The old version XORed the hash of the *previous
/// stripe* into the current one and returned the first stripe, which recovers
/// nothing from a volume `AF_split` actually wrote.  The real algorithm folds
/// each stripe into a running buffer, diffusing after every fold, and the last
/// stripe is the one that unwraps it:
///
/// ```text
/// buffer = 0
/// for i in 0 .. stripes-1:
///     buffer ^= stripe[i]
///     buffer  = diffuse(buffer)
/// key = stripe[stripes-1] ^ buffer
/// ```
///
/// The asymmetry with `AF_split` is the format's point: splitting XORs the
/// running buffer *into* each freshly drawn random stripe, so merging walks
/// the same chain forward, and the last stripe is computed rather than drawn.
///
/// `af_data` is the whole area, `stripes * key_size` bytes, where `key_size`
/// is the volume key length.  An area too short for that returns an empty
/// vector, which the caller already refuses on.
fn af_merge(af_data: &[u8], stripes: u32, key_size: usize) -> Vec<u8> {
    let stripes = stripes as usize;
    if stripes == 0 || key_size == 0 || af_data.len() < stripes * key_size {
        return Vec::new();
    }

    let mut buffer = alloc::vec![0u8; key_size];

    for i in 0..stripes - 1 {
        let start = i * key_size;
        for j in 0..key_size {
            buffer[j] ^= af_data[start + j];
        }
        // `diffuse` reads and writes one block in cryptsetup; a separate
        // destination keeps that aliasing out of the borrow checker's way.
        let mut diffused = alloc::vec![0u8; key_size];
        af_diffuse_into(&buffer, &mut diffused);
        buffer = diffused;
    }

    let last = (stripes - 1) * key_size;
    let mut key = alloc::vec![0u8; key_size];
    for j in 0..key_size {
        key[j] = af_data[last + j] ^ buffer[j];
    }
    key
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
    let (master_key, payload_offset_sectors) = unwrap(device.as_ref(), passphrase)?;

    let payload_block_count = device
        .block_count()
        .saturating_sub(payload_offset_sectors / (BLOCK_SIZE as u64));

    let payload_slice = crate::fs::block::BlockSliceDevice::new(
        "luks2-payload",
        device,
        payload_offset_sectors / (BLOCK_SIZE as u64),
        payload_block_count,
        false,
    );

    let mut final_key = [0u8; 64];
    final_key.copy_from_slice(&master_key[..64]);

    Ok(EncryptedBlockDevice::new(
        payload_slice,
        final_key,
        "luks2-crypt",
    ))
}

/// Recover the volume key from a whole LUKS2 image held in memory.
///
/// The same unwrap `luks2_open` performs, split out so a test can compare the
/// key itself against what `cryptsetup luksDump --dump-master-key` printed
/// rather than only whether it satisfied the digest.  Those are different
/// claims: a key that reproduces the digest is *a* key the volume would
/// accept, and the assertion worth making is that it is *the* key.
pub fn recover_master_key(image: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    let device = crate::kernel::block::MemoryBlockDevice::new(
        "luks2-recover",
        alloc::vec::Vec::from(image),
        true,
    );
    let (key, _payload_offset) = unwrap(device.as_ref(), passphrase)?;
    Ok(key)
}

/// The unwrap's core: header, JSON, keyslot, decrypt, merge, digest.
///
/// Returns the volume key and the payload offset in sectors.
fn unwrap(device: &dyn BlockDevice, passphrase: &[u8]) -> Result<(Vec<u8>, u64)> {
    // 1. Parse the binary header.
    let header = parse_luks2_header(device)?;

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

    // 6. Decrypt the keyslot area, then AF-merge it.
    //
    // The area is itself encrypted — `"encryption": "aes-xts-plain64"` names
    // the cipher and the derived key *is* the XTS key — so the stripes only
    // become stripes after this.  This step did not exist, and a volume
    // `cryptsetup` wrote shows it immediately: merging the raw area recovers
    // nothing.
    //
    // The tweak's data-unit index starts at **0**, not at the area's offset.
    // That is the one parameter no amount of reading the source settles by
    // inspection — `luks2_decrypt_from_storage` passes `area_offset /
    // SECTOR_SIZE`, which reads like a starting index — and it was measured
    // against a real volume: with the index at 0 the merge reproduces the
    // master key `luksDump --dump-master-key` reports, and with it at
    // `area_offset / 512` it does not.  `crypt_storage_init` is given the
    // area's own offset as the *device* offset and counts from zero within it.
    let area_plain = decrypt_keyslot_area(&af_data, &derived_key);

    // 7. AF merge recovers the master key.
    let master_key = af_merge(&area_plain, keyslot.af_stripes, keyslot.key_size);

    if master_key.len() != keyslot.key_size {
        return Err(Error::InvalidCredential);
    }

    // There is no XOR with the derived key here, and no XTS key expansion from
    // a single half.  LUKS1 wraps the master key by XORing it with the KDF
    // output; LUKS2 does not — the derived key's job is to decrypt the area,
    // and what comes out of the merge *is* the volume key, already
    // `key_size` bytes with an XTS pair inside it when the cipher needs one.
    // Adding the XOR back would recover the right answer only for a volume
    // whose key happened to be the XOR of two things.
    let xts_key_size = keyslot.key_size;

    // 8. Verify the digest.
    let digest = parse_digest(&json_raw).ok_or(Error::NotFound)?;

    // The digest check below uses PBKDF2-HMAC-SHA256; reject digests that
    // request any other hash algorithm.
    if digest.hash != "sha256" {
        return Err(Error::Unsupported);
    }

    // Compute expected digest: PBKDF2(master_key, digest.salt, digest.iterations)
    //
    // The whole master key, not its first half.  This used to take
    // `xts_key[..min(32)]`, which is the *data* key of a 512-bit XTS pair and
    // half of a 256-bit one; the digest is taken over the key the volume
    // stores, and a volume `cryptsetup` wrote shows the difference at once:
    // `PBKDF2(full key, salt)` reproduces the digest and `PBKDF2(first 32)`
    // does not.  Measured against a volume made with
    // `cryptsetup luksFormat --pbkdf pbkdf2 --key-size 512`.
    if !digest_matches_key(&master_key[..xts_key_size], &digest) {
        return Err(Error::InvalidCredential);
    }

    // 9. Determine the payload offset from JSON.
    let payload_offset_sectors = get_payload_offset_from_json(&json_raw).unwrap_or(0);

    Ok((master_key, payload_offset_sectors))
}

/// Whether `key` is the master key a digest was taken over.
///
/// A named function so the model can be tested without a volume: the digest
/// is PBKDF2 over the **whole** key the volume stores, and the comparison is
/// constant-time because a caller controls the passphrase and a timing
/// difference here is an oracle.
fn digest_matches_key(key: &[u8], digest: &DigestParams) -> bool {
    let check = pbkdf2_hmac_sha256(key, &digest.salt, digest.iterations, digest.digest.len());
    let mut diff: u8 = 0;
    for (a, b) in check.iter().zip(digest.digest.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A LUKS2 digest is taken over the whole master key.
    ///
    /// This is the one stage of an unwrap whose answer can be checked
    /// without a volume to hand: `cryptsetup luksDump --dump-master-key`
    /// prints the key, and the digest in the metadata is that key put
    /// through PBKDF2.  The parameters here are from a volume made with
    /// `cryptsetup luksFormat --pbkdf pbkdf2 --pbkdf-force-iterations 1000
    /// --key-size 512`, and the assertion that matters is the second one:
    /// the first 32 bytes of the key do *not* reproduce the digest, which
    /// is what the code used to take.
    ///
    /// What this does not cover: the caller's choice of slice.  `luks2_open`
    /// decides how much of `xts_key` to pass, and a mutation that passes half
    /// of it from there still leaves this test green — the assertion below is
    /// about the model, not about the call.  Pinning the call needs a volume,
    /// which is what `check-luks2-image` is for.
    #[test]
    fn a_digest_is_over_the_whole_master_key_not_its_first_half() {
        let master: [u8; 64] = [
            0x55, 0xd8, 0xe9, 0x53, 0x4d, 0x9d, 0x75, 0x32, 0xfd, 0x82, 0x4b, 0xab, 0xcc, 0xf4,
            0x33, 0x44, 0x6d, 0x72, 0x54, 0x00, 0x76, 0x1f, 0x13, 0x15, 0x1f, 0x1a, 0x55, 0xb8,
            0x86, 0x4b, 0x7b, 0x4a, 0x6f, 0x26, 0x95, 0xbd, 0x18, 0xf8, 0x99, 0x97, 0xd6, 0x1d,
            0x2d, 0x0b, 0x6a, 0xc8, 0x47, 0xa1, 0xe5, 0xa4, 0xeb, 0xa3, 0xf4, 0x60, 0xd7, 0xe1,
            0x95, 0x3c, 0x71, 0xce, 0x0d, 0x6b, 0xdb, 0x50,
        ];
        let salt = base64_decode(b"WZquuQNQ9EZdtLv/H2w1Jb7vGb48BiaB0FQ4ZaVFGno=").expect("salt");
        let expected =
            base64_decode(b"qmQQjGXZlCpnQtBqOlpEuyaNOYn6hJbCynu+acbxx7Y=").expect("digest");

        let digest = DigestParams {
            salt,
            iterations: 1000,
            digest: expected.clone(),
            hash: alloc::string::String::from("sha256"),
        };

        assert!(
            super::digest_matches_key(&master, &digest),
            "the whole master key reproduces the digest the volume carries"
        );
        assert!(
            !super::digest_matches_key(&master[..32], &digest),
            "and its first half does not — which is what the old code used"
        );
    }

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
