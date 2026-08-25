//! src/user/program/integrity.rs
//!
//! Minimal integrity helpers for launch metadata, including SHA-256 digests and
//! bounded signature metadata fields.

use alloc::string::String;

use crate::{Error, Result};

const SHA256_WORDS: usize = 8;
const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_HEX_BYTES: usize = 64;
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&sha256_digest(bytes))
}

pub(crate) fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    sha256_bytes(bytes)
}

pub(crate) fn verify_optional_sha256(bytes: &[u8], expected: Option<&str>) -> Result<String> {
    let digest = sha256_digest(bytes);
    if let Some(expected) = expected {
        if decode_sha256_hex(expected)? != digest {
            return Err(Error::PermissionDenied);
        }
    }

    Ok(encode_hex(&digest))
}

pub(crate) fn validate_optional_sha256_hex(value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        let _ = decode_sha256_hex(value)?;
    }

    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (bytes.len() as u64).wrapping_mul(8);

    let mut chunk = [0_u8; SHA256_BLOCK_BYTES];
    let full_chunk_count = bytes.len() / SHA256_BLOCK_BYTES;
    for chunk_index in 0..full_chunk_count {
        let start = chunk_index * SHA256_BLOCK_BYTES;
        chunk.copy_from_slice(&bytes[start..start + SHA256_BLOCK_BYTES]);
        sha256_compress(&mut state, &chunk);
    }

    let remainder = &bytes[full_chunk_count * SHA256_BLOCK_BYTES..];
    chunk.fill(0);
    chunk[..remainder.len()].copy_from_slice(remainder);
    chunk[remainder.len()] = 0x80;

    if remainder.len() >= 56 {
        sha256_compress(&mut state, &chunk);
        chunk.fill(0);
    }

    chunk[56..].copy_from_slice(&bit_len.to_be_bytes());
    sha256_compress(&mut state, &chunk);

    let mut digest = [0_u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn sha256_compress(state: &mut [u32; SHA256_WORDS], chunk: &[u8; SHA256_BLOCK_BYTES]) {
    let mut schedule = [0_u32; 64];
    for (index, word) in schedule.iter_mut().take(16).enumerate() {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            chunk[offset],
            chunk[offset + 1],
            chunk[offset + 2],
            chunk[offset + 3],
        ]);
    }
    for index in 16..64 {
        schedule[index] = small_sigma1(schedule[index - 2])
            .wrapping_add(schedule[index - 7])
            .wrapping_add(small_sigma0(schedule[index - 15]))
            .wrapping_add(schedule[index - 16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for index in 0..64 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(choice(e, f, g))
            .wrapping_add(SHA256_K[index])
            .wrapping_add(schedule[index]);
        let t2 = big_sigma0(a).wrapping_add(majority(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn decode_sha256_hex(value: &str) -> Result<[u8; 32]> {
    if value.len() != SHA256_HEX_BYTES {
        return Err(Error::InvalidArgument);
    }

    let bytes = value.as_bytes();
    let mut decoded = [0_u8; 32];
    for index in 0..decoded.len() {
        let upper = decode_hex_nibble(bytes[index * 2])?;
        let lower = decode_hex_nibble(bytes[index * 2 + 1])?;
        decoded[index] = (upper << 4) | lower;
    }

    Ok(decoded)
}

fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidArgument),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut rendered = String::new();
    for byte in bytes {
        rendered.push(hex_digit(byte >> 4));
        rendered.push(hex_digit(byte & 0x0f));
    }
    rendered
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => '?',
    }
}

#[inline]
fn choice(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

#[inline]
fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn big_sigma0(value: u32) -> u32 {
    value.rotate_right(2) ^ value.rotate_right(13) ^ value.rotate_right(22)
}

#[inline]
fn big_sigma1(value: u32) -> u32 {
    value.rotate_right(6) ^ value.rotate_right(11) ^ value.rotate_right(25)
}

#[inline]
fn small_sigma0(value: u32) -> u32 {
    value.rotate_right(7) ^ value.rotate_right(18) ^ (value >> 3)
}

#[inline]
fn small_sigma1(value: u32) -> u32 {
    value.rotate_right(17) ^ value.rotate_right(19) ^ (value >> 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_optional_sha256_rejects_mismatched_digest() {
        assert_eq!(
            verify_optional_sha256(
                b"abc",
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ),
            Err(Error::PermissionDenied)
        );
    }
}
