//! src/kernel/crypto.rs
//!
//! Minimal cryptographic primitives for the adAstra kernel.
//!
//! Provides SHA-256 hashing per NIST FIPS 180-4, plus a deterministic salt
//! generator for password hashing.

use crate::Error;
use crate::Result;
use alloc::string::String;
use alloc::vec::Vec;

// ── SHA-256 ────────────────────────────────────────────────────────────────

/// Initial hash values (FIPS 180-4 Section 5.3.3).
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants (FIPS 180-4 Section 4.2.2).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// FIPS 180-4 Section 4.1.2 — logical functions.
#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn cap_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn cap_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Process one 512-bit message block (FIPS 180-4 Section 6.2.2).
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];

    // Prepare message schedule W[0..15].
    for (t, chunk) in block.as_chunks::<4>().0.iter().take(16).enumerate() {
        w[t] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    // Extend to W[16..63].
    for t in 16..64 {
        w[t] = sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }

    // Initialize working variables.
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // Compression rounds.
    for t in 0..64 {
        let t1 = h
            .wrapping_add(cap_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = cap_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    // Update state.
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Compute the SHA-256 hash of `data` and return the 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = H_INIT;
    let bit_len: u64 = (data.len() as u64).wrapping_mul(8);
    let mut remaining = data;

    // Process full 512-bit (64-byte) blocks.
    while remaining.len() >= 64 {
        let block: &[u8; 64] = remaining[..64].try_into().unwrap();
        compress(&mut state, block);
        remaining = &remaining[64..];
    }

    // Padding.
    let pad_len = if remaining.len() < 56 {
        64 - remaining.len()
    } else {
        128 - remaining.len()
    };

    let mut padded = Vec::with_capacity(remaining.len() + pad_len);
    padded.extend_from_slice(remaining);
    padded.push(0x80u8); // append '1' bit followed by zeros

    // Zero-pad to 8 bytes before the end of the block(s).
    let total_padded = if remaining.len() < 56 { 64 } else { 128 };
    while padded.len() < total_padded - 8 {
        padded.push(0u8);
    }

    // Append 64-bit big-endian message length.
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process the final block(s).
    for block in padded.as_chunks::<64>().0 {
        compress(&mut state, block);
    }

    // Produce final digest as a flat byte array.
    let mut digest = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_be_bytes();
        digest[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    digest
}

/// Return the SHA-256 digest of `data` as a 64-character lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    let mut out = String::with_capacity(64);
    for byte in &digest {
        out.push(HEX_CHARS[(byte >> 4) as usize]);
        out.push(HEX_CHARS[(byte & 0x0f) as usize]);
    }
    out
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

// ── CRC32C (Castagnoli) ───────────────────────────────────────────────────

/// CRC32C (Castagnoli) lookup table — polynomial 0x1EDC6F41 (reflected).
const CRC32C_TABLE: [u32; 256] = [
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A, 0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A, 0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687, 0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859, 0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
    0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043, 0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
    0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C, 0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
    0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D, 0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
    0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D, 0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
    0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530, 0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
    0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF, 0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
    0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
    0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE, 0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
    0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
    0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E, 0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
];

/// Compute the CRC32C (Castagnoli) checksum of `data`.
///
/// Uses the Castagnoli polynomial 0x1EDC6F41, as specified for iSCSI,
/// SCTP, Btrfs, and XFS v5 metadata checksums.  Table-driven software
/// implementation; a hardware-accelerated path (SSE4.2 / ARMv8 CRC) can
/// be added later.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = !0u32;
    for &byte in data {
        let idx = ((crc & 0xFF) as u8) ^ byte;
        crc = CRC32C_TABLE[idx as usize] ^ (crc >> 8);
    }
    !crc
}

/// Standard CRC32 (IEEE 802.3 polynomial 0xEDB88320, reflected).
///
/// This is the common CRC-32 used by gzip, PNG, and F2FS checkpoint blocks.
/// Distinct from `crc32c` which uses the Castagnoli polynomial.
///
/// Uses a table-driven software implementation.  Hardware-accelerated
/// variants are not provided because SSE4.2 / ARMv8 CRC instructions
/// implement Castagnoli exclusively.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = !0u32;
    for &byte in data {
        let idx = ((crc & 0xFF) as u8) ^ byte;
        crc = CRC32_TABLE[idx as usize] ^ (crc >> 8);
    }
    !crc
}

/// CRC32 (IEEE 802.3) lookup table — polynomial 0xEDB88320 (reflected).
#[rustfmt::skip]
const CRC32_TABLE: [u32; 256] = [
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB30A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,

    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
];

// ── ChaCha20 ─────────────────────────────────────────────────────────────────
// RFC 8439 implementation (256-bit key, 96-bit nonce, 32-bit counter).

/// ChaCha20 quarter round: operates on four 32-bit state words in-place.
#[inline(always)]
fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// ChaCha20 block function: process the 4x4 state matrix with 20 rounds
/// (10 double rounds) and return the result added to the input.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    // Initial state: "expand 32-byte k" constant (4 words) + key (8 words) +
    // block counter (1 word) + nonce (3 words).
    let mut state: [u32; 16] = [
        0x61707865, // "expa"
        0x3320646e, // "nd 3"
        0x79622d32, // "2-by"
        0x6b206574, // "te k"
        // Key words (8 × 32-bit little-endian).
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter, // Block counter.
        // Nonce words (3 × 32-bit little-endian).
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    let initial = state;

    // 10 double rounds = 20 rounds total.
    for _ in 0..10 {
        // Column rounds.
        chacha20_quarter_round(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds.
        chacha20_quarter_round(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add the original state to produce the 64-byte keystream block.
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    // Serialise to little-endian bytes.
    let mut block = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_le_bytes();
        block[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    block
}

/// Encrypt or decrypt `data` in-place using ChaCha20.
///
/// ChaCha20 is a stream cipher: encryption and decryption are the same
/// XOR operation with the keystream.
pub fn chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    let mut counter: u32 = 0;

    for chunk in data.chunks_mut(64) {
        let keystream = chacha20_block(key, counter, nonce);
        for (byte, ks) in chunk.iter_mut().zip(keystream.iter()) {
            *byte ^= ks;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Generate ChaCha20 keystream bytes without XOR'ing into plaintext.
/// Useful for generating random bytes from a CSPRNG seeded with ChaCha20.
pub fn chacha20_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8]) {
    let mut ctr = counter;
    for chunk in out.chunks_mut(64) {
        let keystream = chacha20_block(key, ctr, nonce);
        let len = chunk.len();
        chunk.copy_from_slice(&keystream[..len]);
        ctr = ctr.wrapping_add(1);
    }
}

// ── Constant-time comparison ────────────────────────────────────────────────

/// Compare two 32-byte arrays in constant time to prevent timing side-channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

// ── HMAC-SHA256 ──────────────────────────────────────────────────────────────
// RFC 2104 / NIST FIPS 198-1.

const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5c;
const HMAC_BLOCK_SIZE: usize = 64;

/// Compute the HMAC-SHA256 authentication code for `data` using `key`.
///
/// Per RFC 2104: HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
///
/// If `key` is longer than 64 bytes it is first hashed with SHA-256.
/// If shorter, it is zero-padded to 64 bytes.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; HMAC_BLOCK_SIZE];

    // If key is longer than block size, hash it first.
    let key_hashed: [u8; 32];
    let normalized_key: &[u8] = if key.len() > HMAC_BLOCK_SIZE {
        key_hashed = sha256(key);
        &key_hashed
    } else {
        key
    };

    key_block[..normalized_key.len()].copy_from_slice(normalized_key);

    // Inner hash: H((K ⊕ ipad) || message)
    let mut inner_input = Vec::with_capacity(HMAC_BLOCK_SIZE + data.len());
    for byte in &key_block {
        inner_input.push(byte ^ HMAC_IPAD);
    }
    inner_input.extend_from_slice(data);
    let inner_hash = sha256(&inner_input);

    // Outer hash: H((K ⊕ opad) || inner_hash)
    let mut outer_input = Vec::with_capacity(HMAC_BLOCK_SIZE + 32);
    for byte in &key_block {
        outer_input.push(byte ^ HMAC_OPAD);
    }
    outer_input.extend_from_slice(&inner_hash);
    sha256(&outer_input)
}

// ── HKDF-SHA256 ──────────────────────────────────────────────────────────────
// RFC 5869 — HMAC-based Key Derivation Function.

/// HKDF extract step: `HKDF-Extract(salt, IKM) -> PRK`.
///
/// Returns a 32-byte pseudorandom key.  If `salt` is empty, a string of
/// 32 zero bytes is used as the HMAC key per RFC 5869 §2.2.
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let effective_salt: &[u8] = if salt.is_empty() { &[0u8; 32] } else { salt };
    hmac_sha256(effective_salt, ikm)
}

/// HKDF expand step: `HKDF-Expand(PRK, info, L) -> OKM`.
///
/// Returns a `Vec<u8>` of exactly `output_len` bytes.  The output length
/// MUST NOT exceed `255 * 32 = 8160` bytes per RFC 5869 §2.3.
pub fn hkdf_sha256_expand(prk: &[u8; 32], info: &[u8], output_len: usize) -> Vec<u8> {
    assert!(
        output_len <= 255 * 32,
        "HKDF-Expand output length exceeds maximum"
    );

    let n = output_len.div_ceil(32);
    let mut okm = Vec::with_capacity(output_len);
    let mut t_prev: &[u8] = &[];

    for i in 0..n {
        let mut input = Vec::with_capacity(t_prev.len() + info.len() + 1);
        input.extend_from_slice(t_prev);
        input.extend_from_slice(info);
        input.push(i as u8 + 1);
        let t = hmac_sha256(prk, &input);
        okm.extend_from_slice(&t);
        // t_prev points into okm — safe because Vec never moves elements
        // after they are written, and we only append.
        let start = i * 32;
        t_prev = &okm[start..start + 32];
    }

    okm.truncate(output_len);
    okm
}

// ── Poly1305 ─────────────────────────────────────────────────────────────────
// RFC 8439 §2.5 — one-time authenticator.

/// Clamp the first 16 bytes of `r` per Poly1305 specification.
fn poly1305_clamp(key: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut r = [0u8; 16];
    let mut s = [0u8; 16];
    r.copy_from_slice(&key[..16]);
    s.copy_from_slice(&key[16..]);
    // Clamp r.
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
    (r, s)
}

/// Poly1305 one-time authenticator (RFC 8439).
///
/// `key` must be exactly 32 bytes.  Returns a 16-byte authentication tag.
pub fn poly1305_mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let (r_bytes, s_bytes) = poly1305_clamp(key);

    let r = [
        u64::from_le_bytes([
            r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3], r_bytes[4], r_bytes[5], r_bytes[6],
            r_bytes[7],
        ]),
        u64::from_le_bytes([
            r_bytes[8],
            r_bytes[9],
            r_bytes[10],
            r_bytes[11],
            r_bytes[12],
            r_bytes[13],
            r_bytes[14],
            r_bytes[15],
        ]),
    ];

    // Accumulator as three 64-bit limbs: acc = a0 + a1*2^64 + a2*2^128.
    let mut a0: u64 = 0;
    let mut a1: u64 = 0;
    let mut a2: u64 = 0;

    // Process 16-byte blocks.
    // For full blocks, the appended 0x01 byte is at position 16 (= bit 128
    // = 2^128), which adds 1 to the a2 limb.
    let (chunks, remainder) = data.as_chunks::<16>();
    for chunk in chunks {
        let mut block = [0u8; 17];
        block[..16].copy_from_slice(chunk);
        block[16] = 0x01;
        let n0 = u64::from_le_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]);
        let n1 = u64::from_le_bytes([
            block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
        ]);

        // Add n0 + n1*2^64 + 2^128 to the accumulator.
        let t0 = a0 as u128 + n0 as u128;
        let t1 = a1 as u128 + n1 as u128 + (t0 >> 64);
        a0 = t0 as u64;
        a1 = t1 as u64;
        // carry from t1 + 1 for the 0x01 byte at bit 128.
        a2 = a2.wrapping_add((t1 >> 64) as u64).wrapping_add(1);

        poly1305_mul_mod(&mut a0, &mut a1, &mut a2, r);
    }

    // Final partial block.
    // The 0x01 byte is appended at `len`, so it already contributes to n0/n1
    // directly (its position is < 128 bits). No extra +1 to a2.
    if !remainder.is_empty() {
        let mut block = [0u8; 17];
        let len = remainder.len();
        block[..len].copy_from_slice(remainder);
        block[len] = 0x01;
        let n0 = u64::from_le_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]);
        let n1 = u64::from_le_bytes([
            block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
        ]);

        let t0 = a0 as u128 + n0 as u128;
        let t1 = a1 as u128 + n1 as u128 + (t0 >> 64);
        a0 = t0 as u64;
        a1 = t1 as u64;
        // No +1 for 0x01 — already encoded in n0/n1 via LE interpretation.
        a2 = a2.wrapping_add((t1 >> 64) as u64);

        poly1305_mul_mod(&mut a0, &mut a1, &mut a2, r);
    }

    // Add s modulo 2^128.
    // a2 * 2^128 ≡ 0 (mod 2^128), so only a0 and a1 contribute.
    // Use u128 arithmetic for the additions to capture carries correctly.
    let s0 = u64::from_le_bytes([
        s_bytes[0], s_bytes[1], s_bytes[2], s_bytes[3], s_bytes[4], s_bytes[5], s_bytes[6],
        s_bytes[7],
    ]);
    let s1 = u64::from_le_bytes([
        s_bytes[8],
        s_bytes[9],
        s_bytes[10],
        s_bytes[11],
        s_bytes[12],
        s_bytes[13],
        s_bytes[14],
        s_bytes[15],
    ]);

    let t0 = a0 as u128 + s0 as u128;
    let carry0 = t0 >> 64;
    a0 = t0 as u64;
    let t1 = a1 as u128 + s1 as u128 + carry0;
    a1 = t1 as u64;
    // t1 may have a carry into a2 but it vanishes mod 2^128.

    // Output as 16-byte little-endian.
    let mut tag = [0u8; 16];
    tag[..8].copy_from_slice(&a0.to_le_bytes());
    tag[8..].copy_from_slice(&a1.to_le_bytes());
    tag
}

/// Multiply (a0,a1,a2) by r modulo 2^130 - 5.
///
/// Uses 128-bit arithmetic for intermediate products then reduces modulo
/// 2^130-5 using the identities 2^192 ≡ 5·2^62 and 2^128 ≡ 5·2^-2 (handled
/// via splitting: c2 = 4·c2_hi + c2_lo → c2·2^128 ≡ c2_hi·5 + c2_lo·2^128).
#[inline]
fn poly1305_mul_mod(a0: &mut u64, a1: &mut u64, a2: &mut u64, r: [u64; 2]) {
    let x0 = *a0 as u128;
    let x1 = *a1 as u128;
    let x2 = *a2 as u128;
    let r0 = r[0] as u128;
    let r1 = r[1] as u128;

    // Full product: P = h0 + h1·2^64 + h2·2^128 + h3·2^192
    let h0 = x0 * r0;
    let h1 = x0 * r1 + x1 * r0;
    let h2 = x1 * r1 + x2 * r0;
    let h3 = x2 * r1;

    // Step 1: carry propagation → get canonical 4-word representation.
    let c0 = h0 & 0xFFFF_FFFF_FFFF_FFFF;
    let c1 = (h1 + (h0 >> 64)) & 0xFFFF_FFFF_FFFF_FFFF;
    let s1 = h1 + (h0 >> 64);
    let c2 = (h2 + (s1 >> 64)) & 0xFFFF_FFFF_FFFF_FFFF;
    let s2 = h2 + (s1 >> 64);
    let c3 = h3 + (s2 >> 64);
    // P = c0 + c1·2^64 + c2·2^128 + c3·2^192

    // Step 2: reduce c3·2^192 using 2^192 = 2^130·2^62 ≡ 5·2^62.
    let c3s = c3 * 5;
    let mut r0_acc = c0 + ((c3s & 0x3) << 62);
    let mut r1_acc = c1 + ((c3s >> 2) & 0xFFFF_FFFF_FFFF_FFFF);

    // Step 3: reduce c2·2^128.
    // Write c2 = 4·c2_hi + c2_lo, then c2·2^128 = c2_hi·2^130 + c2_lo·2^128
    // ≡ c2_hi·5 + c2_lo·2^128.
    let c2_lo = c2 & 0x3;
    let c2_hi = c2 >> 2;
    r0_acc += c2_hi * 5;
    // c2_lo goes into the high limb.
    let mut r2_acc = c2_lo;

    // Step 4: propagate carries from r0 to r1, r1 to r2.
    let carry0 = r0_acc >> 64;
    r0_acc &= 0xFFFF_FFFF_FFFF_FFFF;
    r1_acc += carry0;
    let carry1 = r1_acc >> 64;
    r1_acc &= 0xFFFF_FFFF_FFFF_FFFF;
    r2_acc += carry1;

    *a0 = r0_acc as u64;
    *a1 = r1_acc as u64;
    *a2 = r2_acc as u64;
}

// ── ChaCha20-Poly1305 AEAD ───────────────────────────────────────────────────
// RFC 8439 — AEAD construction.

/// Encrypt `plaintext` with ChaCha20-Poly1305 AEAD.
///
/// Returns `(ciphertext, 16_byte_tag)` where ciphertext has the same length
/// as plaintext.  `key` is 32 bytes, `nonce` is 12 bytes, `aad` is
/// additional authenticated data (may be empty).
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // Generate Poly1305 one-time key from ChaCha20 with counter=0.
    let mut poly_key = [0u8; 32];
    chacha20_keystream(key, nonce, 0, &mut poly_key);

    // Encrypt plaintext with ChaCha20 starting at counter=1.
    let mut ciphertext = plaintext.to_vec();
    chacha20_encrypt_inner(key, nonce, 1, &mut ciphertext);

    // Build Poly1305 input: aad || pad(aad) || ciphertext || pad(ciphertext) ||
    // len(aad) || len(ciphertext)
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(aad);
    // Pad AAD to 16-byte boundary with zeros.
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    mac_input.resize(mac_input.len() + aad_pad, 0);
    mac_input.extend_from_slice(&ciphertext);
    // Pad ciphertext to 16-byte boundary with zeros.
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    mac_input.resize(mac_input.len() + ct_pad, 0);
    // Append lengths as 64-bit little-endian.
    mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    let tag = poly1305_mac(&poly_key, &mac_input);
    (ciphertext, tag)
}

/// Decrypt and verify `ciphertext` with ChaCha20-Poly1305 AEAD.
///
/// Returns `Ok(plaintext)` if the tag verifies, or `Err` if authentication
/// fails.
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    // Generate Poly1305 one-time key.
    let mut poly_key = [0u8; 32];
    chacha20_keystream(key, nonce, 0, &mut poly_key);

    // Build Poly1305 input.
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    mac_input.resize(mac_input.len() + aad_pad, 0);
    mac_input.extend_from_slice(ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    mac_input.resize(mac_input.len() + ct_pad, 0);
    mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    let computed_tag = poly1305_mac(&poly_key, &mac_input);

    // Constant-time tag comparison.
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= computed_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(Error::InvalidCredential);
    }

    // Decrypt.
    let mut plaintext = ciphertext.to_vec();
    chacha20_encrypt_inner(key, nonce, 1, &mut plaintext);
    Ok(plaintext)
}

/// Internal: encrypt/decrypt with ChaCha20 starting at a given counter.
/// XORs keystream with `data` in-place.
fn chacha20_encrypt_inner(key: &[u8; 32], nonce: &[u8; 12], start_counter: u32, data: &mut [u8]) {
    let mut counter = start_counter;
    for chunk in data.chunks_mut(64) {
        let keystream = chacha20_block(key, counter, nonce);
        for (byte, ks) in chunk.iter_mut().zip(keystream.iter()) {
            *byte ^= ks;
        }
        counter = counter.wrapping_add(1);
    }
}

// ── AES-128 ──────────────────────────────────────────────────────────────────
// NIST FIPS 197 implementation.

/// AES-128 S-box (SubBytes substitution table).
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES Round Constants (Rcon[i] = x^{i-1} in GF(2^8)).
const AES_RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// Expand a 16-byte AES-128 key into 11 round keys (176 bytes).
fn aes128_key_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut rk = [[0u8; 16]; 11];
    rk[0].copy_from_slice(key);

    for i in 1..11 {
        let mut temp = rk[i - 1][12..16].to_vec();
        // RotWord: circular left shift.
        temp.rotate_left(1);
        // SubWord: apply S-box to each byte.
        for b in &mut temp {
            *b = AES_SBOX[*b as usize];
        }
        // XOR with Rcon.
        temp[0] ^= AES_RCON[i];

        // XOR with previous round key word.
        for j in 0..4 {
            rk[i][j] = rk[i - 1][j] ^ temp[j];
        }
        for j in 4..8 {
            rk[i][j] = rk[i - 1][j] ^ rk[i][j - 4];
        }
        for j in 8..12 {
            rk[i][j] = rk[i - 1][j] ^ rk[i][j - 4];
        }
        for j in 12..16 {
            rk[i][j] = rk[i - 1][j] ^ rk[i][j - 4];
        }
    }
    rk
}

/// AddRoundKey: XOR state with round key.
#[inline(always)]
fn aes_add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

/// SubBytes: apply S-box substitution to each byte.
#[inline(always)]
fn aes_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

/// ShiftRows: rotate rows left by 0, 1, 2, 3 bytes.
#[inline(always)]
fn aes_shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift bytes [1,5,9,13] left by 1
    // Row 2: shift bytes [2,6,10,14] left by 2
    // Row 3: shift bytes [3,7,11,15] left by 3
    // State layout (column-major): 0 4  8 12
    //                               1 5  9 13
    //                               2 6 10 14
    //                               3 7 11 15
    let mut tmp = [0u8; 16];
    tmp.copy_from_slice(state);
    // Row 0: unchanged.
    state[1] = tmp[5];
    state[5] = tmp[9];
    state[9] = tmp[13];
    state[13] = tmp[1];
    state[2] = tmp[10];
    state[6] = tmp[14];
    state[10] = tmp[2];
    state[14] = tmp[6];
    state[3] = tmp[15];
    state[7] = tmp[3];
    state[11] = tmp[7];
    state[15] = tmp[11];
}

/// GF(2^8) multiplication by 2 (used in MixColumns).
#[inline(always)]
fn aes_xtime(x: u8) -> u8 {
    let hi = (x & 0x80) != 0;
    let r = x << 1;
    if hi {
        r ^ 0x1b
    } else {
        r
    }
}

/// MixColumns: mix each column using GF(2^8) arithmetic.
#[inline(always)]
fn aes_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let base = col * 4;
        let s0 = state[base];
        let s1 = state[base + 1];
        let s2 = state[base + 2];
        let s3 = state[base + 3];
        state[base] = aes_xtime(s0) ^ aes_xtime(s1) ^ s1 ^ s2 ^ s3;
        state[base + 1] = s0 ^ aes_xtime(s1) ^ aes_xtime(s2) ^ s2 ^ s3;
        state[base + 2] = s0 ^ s1 ^ aes_xtime(s2) ^ aes_xtime(s3) ^ s3;
        state[base + 3] = aes_xtime(s0) ^ s0 ^ s1 ^ s2 ^ aes_xtime(s3);
    }
}

/// Expand a 32-byte AES-256 key into 15 round keys (240 bytes).
fn aes256_key_expand(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut rk = [[0u8; 16]; 15];
    rk[0].copy_from_slice(&key[..16]);
    rk[1].copy_from_slice(&key[16..]);

    for i in 2..15 {
        let mut temp = rk[i - 1][12..16].to_vec();
        if i % 2 == 0 {
            // RotWord + SubWord + Rcon.
            temp.rotate_left(1);
            for b in &mut temp {
                *b = AES_SBOX[*b as usize];
            }
            temp[0] ^= AES_RCON[i / 2];
        } else {
            // SubWord only (i % 8 == 4).
            for b in &mut temp {
                *b = AES_SBOX[*b as usize];
            }
        }
        // w[i] = w[i-8] ^ temp.
        for j in 0..4 {
            rk[i][j] = rk[i - 2][j] ^ temp[j];
        }
        for j in 4..16 {
            rk[i][j] = rk[i - 2][j] ^ rk[i][j - 4];
        }
    }
    rk
}

/// Encrypt a single 16-byte block with AES-128, in place.
fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let rk = aes128_key_expand(key);
    aes_add_round_key(block, &rk[0]);

    for rk_round in &rk[1..10] {
        aes_sub_bytes(block);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, rk_round);
    }

    // Final round: no MixColumns.
    aes_sub_bytes(block);
    aes_shift_rows(block);
    aes_add_round_key(block, &rk[10]);
}

/// Encrypt a single 16-byte block with AES-256, in place.
fn aes256_encrypt_block(key: &[u8; 32], block: &mut [u8; 16]) {
    let rk = aes256_key_expand(key);
    aes_add_round_key(block, &rk[0]);

    for rk_round in &rk[1..14] {
        aes_sub_bytes(block);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, rk_round);
    }

    aes_sub_bytes(block);
    aes_shift_rows(block);
    aes_add_round_key(block, &rk[14]);
}

/// AES inverse S-box (used by decryption).
const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// Inverse ShiftRows: rotate rows right by 0, 1, 2, 3 bytes.
#[inline(always)]
fn aes_inv_shift_rows(state: &mut [u8; 16]) {
    let mut tmp = [0u8; 16];
    tmp.copy_from_slice(state);
    // Row 1: shift right by 1.
    state[1] = tmp[13];
    state[5] = tmp[1];
    state[9] = tmp[5];
    state[13] = tmp[9];
    // Row 2: shift right by 2.
    state[2] = tmp[10];
    state[6] = tmp[14];
    state[10] = tmp[2];
    state[14] = tmp[6];
    // Row 3: shift right by 3.
    state[3] = tmp[7];
    state[7] = tmp[11];
    state[11] = tmp[15];
    state[15] = tmp[3];
}

/// Inverse SubBytes: apply the inverse S-box to each byte.
#[inline(always)]
fn aes_inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_INV_SBOX[*b as usize];
    }
}

/// GF(2^8) multiplication used by InvMixColumns.
#[inline(always)]
fn aes_gmul(x: u8, y: u8) -> u8 {
    let mut p = 0u8;
    let mut a = x;
    let mut b = y;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80 != 0;
        a <<= 1;
        if hi {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// Inverse MixColumns: multiply each column by the inverse matrix.
#[inline(always)]
fn aes_inv_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let base = col * 4;
        let s0 = state[base];
        let s1 = state[base + 1];
        let s2 = state[base + 2];
        let s3 = state[base + 3];
        state[base] =
            aes_gmul(0x0e, s0) ^ aes_gmul(0x0b, s1) ^ aes_gmul(0x0d, s2) ^ aes_gmul(0x09, s3);
        state[base + 1] =
            aes_gmul(0x09, s0) ^ aes_gmul(0x0e, s1) ^ aes_gmul(0x0b, s2) ^ aes_gmul(0x0d, s3);
        state[base + 2] =
            aes_gmul(0x0d, s0) ^ aes_gmul(0x09, s1) ^ aes_gmul(0x0e, s2) ^ aes_gmul(0x0b, s3);
        state[base + 3] =
            aes_gmul(0x0b, s0) ^ aes_gmul(0x0d, s1) ^ aes_gmul(0x09, s2) ^ aes_gmul(0x0e, s3);
    }
}

/// Decrypt a single 16-byte block with AES-128, in place.
/// GCM/CTR decryption uses the encryption primitive, so this is only needed
/// for standalone block decryption (e.g. AES-128-XTS data-key usage and tests).
#[allow(dead_code)]
fn aes128_decrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let rk = aes128_key_expand(key);
    aes_add_round_key(block, &rk[10]);
    for rk_round in (1..10).rev() {
        aes_inv_shift_rows(block);
        aes_inv_sub_bytes(block);
        aes_add_round_key(block, &rk[rk_round]);
        aes_inv_mix_columns(block);
    }
    aes_inv_shift_rows(block);
    aes_inv_sub_bytes(block);
    aes_add_round_key(block, &rk[0]);
}

/// Decrypt a single 16-byte block with AES-256, in place.
fn aes256_decrypt_block(key: &[u8; 32], block: &mut [u8; 16]) {
    let rk = aes256_key_expand(key);
    aes_add_round_key(block, &rk[14]);
    for rk_round in (1..14).rev() {
        aes_inv_shift_rows(block);
        aes_inv_sub_bytes(block);
        aes_add_round_key(block, &rk[rk_round]);
        aes_inv_mix_columns(block);
    }
    aes_inv_shift_rows(block);
    aes_inv_sub_bytes(block);
    aes_add_round_key(block, &rk[0]);
}

// ── GCM (Galois/Counter Mode) ────────────────────────────────────────────────
// NIST SP 800-38D.

/// GF(2^128) multiplication used for GHASH.
/// Multiplies two 128-bit values in GF(2^128) with the irreducible polynomial
/// x^128 + x^7 + x^2 + x + 1.
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;

    for &xi_byte in x.iter() {
        let mut xi = xi_byte;
        for _bit in 0..8 {
            if xi & 0x80 != 0 {
                // z ^= v
                for j in 0..16 {
                    z[j] ^= v[j];
                }
            }
            // Check if the low bit of v[15] is set (v * x mod polynomial)
            let lsb = v[15] & 1;
            // v >>= 1 (big-endian shift right)
            for j in (1..16).rev() {
                v[j] = (v[j] >> 1) | (v[j - 1] << 7);
            }
            v[0] >>= 1;
            // If the bit shifted out was 1, XOR with the polynomial.
            if lsb != 0 {
                v[0] ^= 0xe1; // x^7 + x^2 + x + 1 in upper byte
            }
            xi <<= 1;
        }
    }
    z
}

/// Increment a 128-bit counter (big-endian, increment the last 4 bytes).
fn gcm_ctr_inc(counter: &mut [u8; 16]) {
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// GHASH of a single data string under key `h` (NIST SP 800-38D).
///
/// Every 16-byte block (final block zero-padded if short) is XORed into the
/// running tag and multiplied by `h` in GF(2^128).
fn ghash(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    for chunk in data.chunks(16) {
        for i in 0..16 {
            if i < chunk.len() {
                y[i] ^= chunk[i];
            }
        }
        y = gf128_mul(&y, h);
    }
    y
}

/// Compute the GHASH authentication tag contribution for (aad, ciphertext).
fn gcm_ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut data = Vec::new();
    data.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    data.resize(data.len() + aad_pad, 0);
    data.extend_from_slice(ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    data.resize(data.len() + ct_pad, 0);

    // Final block: len(AAD) || len(C) as 64-bit big-endian each.
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ciphertext.len() as u64).wrapping_mul(8);
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());
    data.extend_from_slice(&len_block);

    ghash(h, &data)
}

/// Encrypt `plaintext` with AES-128-GCM.
///
/// Returns `(ciphertext, 16_byte_tag)`.
/// `key` is 16 bytes, `nonce` is 12 bytes (96-bit IV), `aad` is optional
/// additional authenticated data.
pub fn aes128_gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // Hash subkey H = AES_K(0^128).
    let mut zero = [0u8; 16];
    aes128_encrypt_block(key, &mut zero);
    let h = zero;

    // Initial counter J0 = nonce || 0^31 || 1.
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;

    // Encrypt plaintext in CTR mode, starting from J0+1.
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut counter = j0;
    gcm_ctr_inc(&mut counter); // J0 + 1

    for chunk in plaintext.chunks(16) {
        let mut ctr_blk = counter;
        aes128_encrypt_block(key, &mut ctr_blk);
        let keystream = ctr_blk;
        for (i, p) in chunk.iter().enumerate() {
            ciphertext.push(p ^ keystream[i]);
        }
        gcm_ctr_inc(&mut counter);
    }

    // Authentication tag.
    let ghash = gcm_ghash(&h, aad, &ciphertext);
    let mut j0_blk = j0;
    aes128_encrypt_block(key, &mut j0_blk);
    let s = j0_blk;
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ghash[i] ^ s[i];
    }

    (ciphertext, tag)
}

/// Decrypt and verify `ciphertext` with AES-128-GCM.
///
/// Returns `Ok(plaintext)` if the tag verifies, or `Err` on authentication
/// failure.
pub fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    // Hash subkey H = AES_K(0^128).
    let mut zero = [0u8; 16];
    aes128_encrypt_block(key, &mut zero);
    let h = zero;

    // Verify tag before decrypting.
    let computed_ghash = gcm_ghash(&h, aad, ciphertext);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;
    let mut j0_blk = j0;
    aes128_encrypt_block(key, &mut j0_blk);
    let s = j0_blk;

    let mut computed_tag = [0u8; 16];
    let mut diff: u8 = 0;
    for i in 0..16 {
        computed_tag[i] = computed_ghash[i] ^ s[i];
        diff |= computed_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(Error::InvalidCredential);
    }

    // Decrypt in CTR mode.
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut counter = j0;
    gcm_ctr_inc(&mut counter); // J0 + 1

    for chunk in ciphertext.chunks(16) {
        let mut ctr_blk = counter;
        aes128_encrypt_block(key, &mut ctr_blk);
        let keystream = ctr_blk;
        for (i, c) in chunk.iter().enumerate() {
            plaintext.push(c ^ keystream[i]);
        }
        gcm_ctr_inc(&mut counter);
    }

    Ok(plaintext)
}

// ── AES-XTS (IEEE 1619) ─────────────────────────────────────────────────────
// XTS-AES is used for full-disk encryption.  The 128-bit tweak is formed from
// the sector id and encrypted with the tweak key; each 16-byte data block is
// XORed with the running tweak, encrypted with the data key, and XORed with
// the tweak again.  Between blocks the tweak is multiplied by `x` in
// GF(2^128) (reduction polynomial 0x87, big-endian representation).

/// Multiply a 128-bit tweak by `x` in GF(2^128) (XTS "alpha" step).
///
/// IEEE 1619 represents field elements as 16 big-endian bytes with reduction
/// polynomial x^128 + x^7 + x^2 + x + 1 (0x87).  Multiplying by x is a 1-bit
/// left shift; if the top bit was set, XOR the low byte with 0x87.
fn xts_mul_alpha(tweak: &[u8; 16]) -> [u8; 16] {
    let mut t = *tweak;
    let carry = t[0] >> 7;
    let mut i = 0;
    while i < 15 {
        t[i] = (t[i] << 1) | (t[i + 1] >> 7);
        i += 1;
    }
    t[15] <<= 1;
    if carry == 1 {
        t[15] ^= 0x87;
    }
    t
}

/// XOR each byte of `a` into `out`.
fn xor_bytes_into(out: &mut [u8], a: &[u8]) {
    for (o, x) in out.iter_mut().zip(a.iter()) {
        *o ^= x;
    }
}

/// Encrypt `data` in-place with AES-256-XTS (IEEE 1619).
///
/// `key` is 64 bytes: `key[..32]` is the data key and `key[32..]` is the
/// tweak key (both AES-256).  `sector_id` selects the initial tweak, encoded
/// little-endian in the first 8 bytes of the 16-byte tweak.  `data.len()`
/// must be a multiple of 16.
pub fn aes_xts_encrypt(key: &[u8; 64], sector_id: u64, data: &mut [u8]) {
    let tweak_key: &[u8; 32] = key[32..].try_into().expect("xts tweak key 32 bytes");

    // Initial tweak from the sector id (little-endian) in the low half.
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector_id.to_le_bytes());
    aes256_encrypt_block(tweak_key, &mut tweak);

    for chunk in data.chunks_mut(16) {
        let c: &mut [u8; 16] = chunk.try_into().expect("16-byte chunk");
        for (i, b) in c.iter_mut().enumerate() {
            *b ^= tweak[i];
        }
        aes256_encrypt_block(&key[..32].try_into().expect("xts data key 32 bytes"), c);
        for (i, b) in c.iter_mut().enumerate() {
            *b ^= tweak[i];
        }
        tweak = xts_mul_alpha(&tweak);
    }
}

/// Decrypt `data` in-place with AES-256-XTS (IEEE 1619).
pub fn aes_xts_decrypt(key: &[u8; 64], sector_id: u64, data: &mut [u8]) {
    let tweak_key: &[u8; 32] = key[32..].try_into().expect("xts tweak key 32 bytes");

    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector_id.to_le_bytes());
    aes256_encrypt_block(tweak_key, &mut tweak);

    for chunk in data.chunks_mut(16) {
        // Decrypt in place needs the original ciphertext for the second XOR,
        // so buffer the first XOR (tweak ^ ciphertext) in a temp block.
        let c: &mut [u8; 16] = chunk.try_into().expect("16-byte chunk");
        let mut buf = *c;
        xor_bytes_into(&mut buf, &tweak);
        aes256_decrypt_block(
            &key[..32].try_into().expect("xts data key 32 bytes"),
            &mut buf,
        );
        xor_bytes_into(&mut buf, &tweak);
        c.copy_from_slice(&buf);
        tweak = xts_mul_alpha(&tweak);
    }
}

// ── X25519 (Curve25519 ECDH) ─────────────────────────────────────────────────
// RFC 7748 — Elliptic-curve Diffie-Hellman key exchange.
//
// Montgomery form:  y^2 = x^3 + 486662·x^2 + x   over GF(2^255 - 19).
// Base point u-coordinate: 9.
//
// Field elements are stored as 5 limbs of 51 bits (little-endian).

/// Mask for 51-bit limbs: (1 << 51) - 1.
const MASK_51: u64 = (1u64 << 51) - 1; // 0x0007_FFFF_FFFF_FFFF

/// 2^255 - 19 as 5 51-bit limbs.
/// (2^255 - 1) - 18  decomposes as [MASK_51-18, MASK_51, MASK_51, MASK_51,
/// MASK_51].
const FE25519_PRIME: [u64; 5] = [MASK_51 - 18, MASK_51, MASK_51, MASK_51, MASK_51];

/// A field element in GF(2^255 - 19), stored as 5 51-bit limbs (little-endian).
type Fe25519 = [u64; 5];

/// Carry from the i-th limb to the next, reducing each limb.
///
/// After the forward sweep, limb 4 may still have bits ≥ 2^51.
/// Those bits represent multiples of 2^255, and since 2^255 ≡ 19 (mod p),
/// we fold them back to limb 0 and re-propagate.  The loop repeats until
/// limb 4 is fully reduced (never more than two iterations in practice).
#[inline]
fn fe25519_carry(x: &mut Fe25519) {
    loop {
        // Forward sweep: carry limbs 0→1→2→3→4.
        for i in 0..4 {
            let carry = x[i] >> 51;
            x[i] &= MASK_51;
            x[i + 1] = x[i + 1].wrapping_add(carry);
        }
        // Fold the carry out of limb 4 back to limb 0.
        let wrap = x[4] >> 51;
        if wrap == 0 {
            break;
        }
        x[4] &= MASK_51;
        x[0] = x[0].wrapping_add(wrap.wrapping_mul(19));
        // Loop again to propagate any new carry from limb 0.
    }
}

/// Fully reduce a field element to canonical form (< p).
fn fe25519_reduce(x: &mut Fe25519) {
    fe25519_carry(x);
    // After carry, the value is < 2^255 + tiny.  Subtract p if >= p.
    let (below, borrow) = fe25519_sub_internal(x, &FE25519_PRIME);
    if !borrow {
        // x >= p, so x - p < p. Use the reduced value.
        *x = below;
    }
    // Otherwise x < p already.
}

/// Internal: compute a - b with borrow propagation.  Returns (result,
/// borrow_out).
fn fe25519_sub_internal(a: &Fe25519, b: &Fe25519) -> (Fe25519, bool) {
    let mut out = [0u64; 5];
    let mut borrow: u64 = 0;
    for i in 0..5 {
        let (sub, br1) = a[i].overflowing_sub(b[i]);
        let (sub, br2) = sub.overflowing_sub(borrow);
        out[i] = sub;
        borrow = (br1 || br2) as u64;
    }
    (out, borrow != 0)
}

/// Field addition: a + b (mod p).
fn fe25519_add(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = a[i].wrapping_add(b[i]);
    }
    fe25519_reduce(&mut out);
    out
}

/// Field subtraction: a - b (mod p).
///
/// Subtracts at 51-bit limb boundaries (the native representation),
/// avoiding the u64 wrapping mismatch that occurs with the generic
/// `fe25519_sub_internal`.
fn fe25519_sub(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    // Subtract at 51-bit boundaries.  Each limb is in [0, 2^51), so
    // the difference without wrapping is in (-2^51, 2^51).  We borrow
    // 2^51 from the next limb whenever the result goes negative.
    let mut result = [0u64; 5];
    let mut borrow: i64 = 0;
    for i in 0..5 {
        let diff = (a[i] as i128) - (b[i] as i128) - (borrow as i128);
        if diff < 0 {
            result[i] = (diff + (1i128 << 51)) as u64;
            borrow = 1;
        } else {
            result[i] = diff as u64;
            borrow = 0;
        }
    }

    if borrow > 0 {
        // a < b.  Compute b - a (positive, in canonical 51-bit form),
        // then return p - (b - a).  This avoids the double-wrapping
        // that occurs when naively adding p to the wrapped diff.
        let mut b_minus_a = [0u64; 5];
        let mut b_borrow: i64 = 0;
        for i in 0..5 {
            let diff = (b[i] as i128) - (a[i] as i128) - (b_borrow as i128);
            if diff < 0 {
                b_minus_a[i] = (diff + (1i128 << 51)) as u64;
                b_borrow = 1;
            } else {
                b_minus_a[i] = diff as u64;
                b_borrow = 0;
            }
        }
        debug_assert_eq!(b_borrow, 0, "b > a guarantee");

        // p - (b - a): guaranteed non-negative since b-a < p (both a,b < p).
        let mut p_borrow: i64 = 0;
        for i in 0..5 {
            let diff = (FE25519_PRIME[i] as i128) - (b_minus_a[i] as i128) - (p_borrow as i128);
            if diff < 0 {
                result[i] = (diff + (1i128 << 51)) as u64;
                p_borrow = 1;
            } else {
                result[i] = diff as u64;
                p_borrow = 0;
            }
        }
        debug_assert_eq!(p_borrow, 0, "p > b-a guarantee");
    }
    // else a >= b: result limbs are already in [0, 2^51).  No carry needed.

    result
}

/// Field multiplication: a * b (mod p).
///
/// Each a[i], b[j] is at most 51 bits.  Every partial product a[i]·b[j] is
/// folded directly into the correct 51-bit limb of the accumulator using the
/// identity 2^255 ≡ 19 (mod p).  This avoids a separate 9-entry product array
/// and the attendant carry-splitting complexity.
fn fe25519_mul(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    let mut acc = [0u128; 5];

    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            let prod = (ai as u128) * (bj as u128);
            let pos = i + j;
            if pos < 5 {
                acc[pos] = acc[pos].wrapping_add(prod);
            } else {
                // 2^(pos·51) = 2^(255 + (pos-5)·51) ≡ 19 · 2^((pos-5)·51)
                acc[pos - 5] = acc[pos - 5].wrapping_add(prod.wrapping_mul(19));
            }
        }
    }

    // Carry chain: bring each limb below 2^51.
    for _pass in 0..2 {
        for i in 0..4 {
            acc[i + 1] = acc[i + 1].wrapping_add(acc[i] >> 51);
            acc[i] &= MASK_51 as u128;
        }
        // Fold the carry out of limb 4 back to limb 0 (2^255 ≡ 19).
        let wrap = acc[4] >> 51;
        acc[4] &= MASK_51 as u128;
        acc[0] = acc[0].wrapping_add(wrap.wrapping_mul(19));
    }

    // One final carry sweep guarantees each limb fits in u64.
    for i in 0..4 {
        acc[i + 1] = acc[i + 1].wrapping_add(acc[i] >> 51);
        acc[i] &= MASK_51 as u128;
    }
    // acc[4] may still have a tiny wrap — fold it once more.
    let wrap = acc[4] >> 51;
    acc[4] &= MASK_51 as u128;
    acc[0] = acc[0].wrapping_add(wrap.wrapping_mul(19));

    let mut result: Fe25519 = [
        acc[0] as u64,
        acc[1] as u64,
        acc[2] as u64,
        acc[3] as u64,
        acc[4] as u64,
    ];
    fe25519_reduce(&mut result);
    result
}

/// Field squaring: a^2 (mod p).  Marginally faster than general multiply.
fn fe25519_square(a: &Fe25519) -> Fe25519 {
    fe25519_mul(a, a)
}

/// Modular inverse using Fermat's little theorem: a^(p-2) mod p.
fn fe25519_inv(a: &Fe25519) -> Fe25519 {
    // p - 2 = 2^255 - 19 - 2 = 2^255 - 21
    // We compute a^(p-2) by repeated squaring.
    let sq = |x: &Fe25519| fe25519_square(x);
    let mul = |x: &Fe25519, y: &Fe25519| fe25519_mul(x, y);

    // Chain: 2^255 - 21.  Use addition-chain / square-and-multiply.
    // Start with a^1.
    let mut result = *a;

    // Raise to 2^255 - 21 via square-and-multiply.
    // 2^255 - 21 =
    // 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
    // 252 bits set to 1, except the lowest few bits.
    // Strategy: set result = a, then square 255 times, multiplying by a at
    // the positions where the exponent bit is 1.
    //
    // But (p-2) has most bits set, so it's more efficient to square 255 times
    // and multiply where needed.  Since most bits are 1, we do a squaring
    // followed by a multiply at each step.

    // Simpler approach: use 255 iterations of square-then-conditional-multiply.
    // Exponent in binary:
    // 2^255 - 21 = 2^255 - 16 - 4 - 1 = 2^255 - 0b10101
    // = 0x7FF...FEB
    // = all 1s from bit 254 down to bit 0, except bits 0, 2, 4 are 0.

    // Use a shorter chain: compute a^(2^255 - 21) as:
    //   a^(2^255 - 21) = a^(2^255 - 1) * a^(-20)
    // This is a bit complicated.  Let's just do the straightforward
    // square-and-multiply.

    // Exponent p-2 = 2^255 - 21.  Bits 2 and 4 are 0; bits 0,1,3,5..254 are 1.
    // (21 = 16+4+1, so subtracting from 2^255 clears bits 2,4; bit 0 = 1 since
    // result is odd.) Start with result = a (MSB bit 254 already consumed).
    let mut i: i32 = 253;
    while i >= 0 {
        result = sq(&result);
        // Bit i is 1 unless i == 2 or i == 4.
        if i != 2 && i != 4 {
            result = mul(&result, a);
        }
        i -= 1;
    }

    result
}

/// Conditional swap of two field elements if `swap` is true (constant-time).
fn fe25519_cswap(a: &mut Fe25519, b: &mut Fe25519, swap: bool) {
    let mask = if swap { !0u64 } else { 0u64 };
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// Montgomery ladder step for X25519.
/// Computes (x2, z2, x3, z3) ← ladder_step(x1, x2, z2, x3, z3).
fn x25519_ladder_step(
    x1: &Fe25519,
    x2: &mut Fe25519,
    z2: &mut Fe25519,
    x3: &mut Fe25519,
    z3: &mut Fe25519,
) {
    let a = fe25519_add(x2, z2); // A  = x2 + z2
    let aa = fe25519_square(&a); // AA = A^2
    let b = fe25519_sub(x2, z2); // B  = x2 - z2
    let bb = fe25519_square(&b); // BB = B^2
    let e = fe25519_sub(&aa, &bb); // E  = AA - BB
    let c = fe25519_add(x3, z3); // C  = x3 + z3
    let d = fe25519_sub(x3, z3); // D  = x3 - z3
    let da = fe25519_mul(&d, &a); // DA = D * A
    let cb = fe25519_mul(&c, &b); // CB = C * B
    *x3 = fe25519_square(&fe25519_add(&da, &cb)); // x3 = (DA + CB)^2
    let tmp = fe25519_sub(&da, &cb); // (DA - CB)
    *z3 = fe25519_mul(x1, &fe25519_square(&tmp)); // z3 = x1 * (DA - CB)^2
    *x2 = fe25519_mul(&aa, &bb); // x2 = AA * BB
                                 // a24 = 121665 = (486662-2)/4
    let a24: Fe25519 = [121665, 0, 0, 0, 0];
    *z2 = fe25519_mul(&e, &fe25519_add(&aa, &fe25519_mul(&a24, &e)));
    // z2 = E * (AA + a24 * E)
}

/// X25519 scalar multiplication: compute `scalar * u_coord`.
///
/// Returns the u-coordinate of the result point.
/// `scalar` is 32 bytes (clamped internally).
/// `u_coord` is the u-coordinate of the input point (32 bytes, little-endian).
pub fn x25519(scalar: &[u8; 32], u_coord: &[u8; 32]) -> [u8; 32] {
    // Clamp scalar: clear bits 0, 1, 2; set bit 254; clear bit 255.
    let mut clamped = *scalar;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    // Decode u-coordinate.
    let u = fe25519_from_bytes(u_coord);

    // Montgomery ladder.
    let x1 = u;
    let mut x2 = FE25519_ONE;
    let mut z2 = FE25519_ZERO;
    let mut x3 = u;
    let mut z3 = FE25519_ONE;

    let mut swap: bool = false;

    for i in (0..255).rev() {
        let bit = (clamped[i >> 3] >> (i & 7)) & 1;
        let do_swap = (bit == 1) ^ swap;
        fe25519_cswap(&mut x2, &mut x3, do_swap);
        fe25519_cswap(&mut z2, &mut z3, do_swap);
        swap = bit == 1;

        x25519_ladder_step(&x1, &mut x2, &mut z2, &mut x3, &mut z3);
    }
    fe25519_cswap(&mut x2, &mut x3, swap);
    fe25519_cswap(&mut z2, &mut z3, swap);

    // Result u-coordinate = x2 * z2^(-1).
    let z2_inv = fe25519_inv(&z2);
    let result_pt = fe25519_mul(&x2, &z2_inv);
    fe25519_to_bytes(&result_pt)
}

const FE25519_ZERO: Fe25519 = [0, 0, 0, 0, 0];
const FE25519_ONE: Fe25519 = [1, 0, 0, 0, 0];

/// Decode a 32-byte little-endian integer into a field element.
///
/// Reads the 32 LE bytes as a 255-bit integer (top bit cleared) and
/// decomposes it into 5 limbs of 51 bits each using u128 arithmetic.
fn fe25519_from_bytes(bytes: &[u8; 32]) -> Fe25519 {
    let lo = u128::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    let hi_raw = u128::from_le_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]);
    let hi = hi_raw & 0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128;

    let mut out = [0u64; 5];

    // total = lo + hi * 2^128.  Extract 51-bit limbs by repeatedly
    // shifting down.  u128 wrapping on `hi << 77` naturally discards
    // the bits that go past bit 127; `hi >> 51` captures them.
    out[0] = (lo & (MASK_51 as u128)) as u64;

    let v1 = (lo >> 51) | (hi.wrapping_shl(77));
    let hi1 = hi >> 51;
    out[1] = (v1 & (MASK_51 as u128)) as u64;

    let v2 = (v1 >> 51) | (hi1.wrapping_shl(77));
    let hi2 = hi1 >> 51;
    out[2] = (v2 & (MASK_51 as u128)) as u64;

    let v3 = (v2 >> 51) | (hi2.wrapping_shl(77));
    let hi3 = hi2 >> 51;
    out[3] = (v3 & (MASK_51 as u128)) as u64;

    let v4 = (v3 >> 51) | (hi3.wrapping_shl(77));
    out[4] = (v4 & (MASK_51 as u128)) as u64;

    out
}

/// Encode a field element into 32 bytes little-endian.
///
/// Reverses the decomposition performed by `fe25519_from_bytes`.
fn fe25519_to_bytes(fe: &Fe25519) -> [u8; 32] {
    let t = *fe;

    // Reconstruct total = limb[0] + limb[1]*2^51 + limb[2]*2^102
    //                         + limb[3]*2^153 + limb[4]*2^204
    // Then pack into lo (bits 0-127) and hi (bits 128-255).

    let total_lo = (t[0] as u128) | ((t[1] as u128) << 51) | ((t[2] as u128) << 102);
    // In u128, (t[2] << 102) wraps, keeping only the low 26 bits.
    // The upper 25 bits of limb[2] go into hi.

    let total_hi = (t[2] as u128 >> 26) // upper 25 bits of limb[2]
        | ((t[3] as u128) << 25)         // limb[3]
        | ((t[4] as u128) << (25 + 51)); // limb[4]

    let lo = total_lo; // u128 wrapping already cleared overflow bits
    let hi = total_hi & 0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128;

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&lo.to_le_bytes());
    out[16..].copy_from_slice(&hi.to_le_bytes());
    out
}

/// Generate an X25519 key pair.
///
/// Returns `(private_key, public_key)` where each is 32 bytes.
/// `private_key` is the 32-byte secret scalar.
/// `public_key` is the result of `x25519(private_key, base_point)`.
pub fn x25519_keygen() -> ([u8; 32], [u8; 32]) {
    // No RNG dependency in this bare-metal kernel.  Derive a deterministic
    // private key from a constant salt via SHA-256 and clamp it per RFC 7748.
    // NOTE: this is NOT cryptographically random — acceptable only for the
    // recovery prototype; production must use a true entropy source.
    let mut private = sha256(b"protofire-x25519-keygen");
    // Clamp per RFC 7748 §5.
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let public = x25519(&private, &X25519_BASE_POINT_BYTES);
    (private, public)
}

/// The X25519 base point (u-coordinate = 9) as bytes.
const X25519_BASE_POINT_BYTES: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

// ── Salt generation ─────────────────────────────────────────────────────────

/// Generate a 16-byte deterministic salt bound to `username`.
///
/// The salt is `sha256(username)[..16]`.  This is deterministic per user and
/// therefore recoverable for a known username; acceptable for the recovery
/// prototype but not for production password storage (which must use a random
/// per-user salt).
pub fn generate_salt(username: &str) -> [u8; 16] {
    // Deterministic per-user salt: sha256(username)[..16].
    // NOTE: deterministic salts are recoverable for a known username; this is
    // acceptable for the recovery prototype but not for production password
    // storage (which must use a random per-user salt).
    let hash = sha256(username.as_bytes());
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&hash[..16]);
    salt
}

// ── RSA / Big-Integer Arithmetic
// ────────────────────────────────────────────── Stack-allocated limb arrays
// for RSA verification (2048-bit and 4096-bit keys). Uses Montgomery
// multiplication for modular arithmetic — no division needed.

/// Maximum RSA modulus size: 4096 bits = 64 × u64 limbs = 512 bytes.
const RSA_MAX_LIMBS: usize = 64;
const RSA_MAX_BYTES: usize = RSA_MAX_LIMBS * 8;

/// Convert big-endian bytes to u64 limbs (little-endian).  Returns the number
/// of non-zero limbs (counting from the most-significant side).
fn rsa_bytes_to_limbs(bytes: &[u8], limbs: &mut [u64; RSA_MAX_LIMBS]) -> usize {
    assert!(bytes.len() <= RSA_MAX_LIMBS * 8);
    limbs.fill(0);
    for (i, &b) in bytes.iter().enumerate() {
        let pos = bytes.len() - 1 - i;
        limbs[pos / 8] |= (b as u64) << ((pos % 8) * 8);
    }
    let mut n = bytes.len().div_ceil(8);
    while n > 1 && limbs[n - 1] == 0 {
        n -= 1;
    }
    n
}

/// Convert u64 limbs to big-endian bytes of length `out_len`.
fn rsa_limbs_to_bytes(limbs: &[u64; RSA_MAX_LIMBS], num_limbs: usize, out: &mut [u8]) {
    let n = out.len();
    out.fill(0);
    #[allow(clippy::needless_range_loop)]
    for li in 0..num_limbs {
        let limb = limbs[li];
        for bi in 0..8 {
            let bp = li * 8 + bi;
            if bp < n {
                out[n - 1 - bp] = (limb >> (bi * 8)) as u8;
            }
        }
    }
}

/// Bit-length of a limb array.
fn rsa_limbs_bitlen(limbs: &[u64; RSA_MAX_LIMBS], num_limbs: usize) -> usize {
    for i in (0..num_limbs).rev() {
        if limbs[i] != 0 {
            return i * 64 + 64 - (limbs[i].leading_zeros() as usize);
        }
    }
    0
}

// ── Montgomery multiplication ────────────────────────────────────────────────

/// Compute the modular inverse of an odd `a` modulo 2^64 via Newton iteration.
fn rsa_modinv_u64(a: u64) -> u64 {
    // x_{n+1} = x_n * (2 - a * x_n)  mod 2^(2^(n+1))
    let mut x = a; // correct mod 2^3 for odd a
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // mod 2^6
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // mod 2^12
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // mod 2^24
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // mod 2^48
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // mod 2^96 (full 2^64)
    x
}

/// Montgomery multiplication: `result = a * b * R^(-1) mod n` where
/// R = 2^(num_limbs * 64).  Uses CIOS (Coarsely Integrated Operand Scanning).
///
/// `nprime0` = -n[0]^(-1) mod 2^64 (precomputed).
///
/// Inputs a, b must be < n and in Montgomery form (scaled by R).
/// `result`, `a`, `b`, `n` all have `num_limbs` limbs.
fn rsa_mont_mul(
    result: &mut [u64; RSA_MAX_LIMBS],
    a: &[u64; RSA_MAX_LIMBS],
    b: &[u64; RSA_MAX_LIMBS],
    n: &[u64; RSA_MAX_LIMBS],
    num_limbs: usize,
    nprime0: u64,
) {
    // Temporary t of length num_limbs + 2.
    let mut t = [0u64; RSA_MAX_LIMBS + 2];
    let t_len = num_limbs + 2;

    #[allow(clippy::needless_range_loop)]
    for i in 0..num_limbs {
        // t += a[i] * b
        let mut carry: u64 = 0;
        for j in 0..num_limbs {
            let prod = (a[i] as u128) * (b[j] as u128) + (t[j] as u128) + (carry as u128);
            t[j] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        // Propagate carry through remaining t entries
        let mut pos = num_limbs;
        while carry != 0 && pos < t_len {
            let sum = (t[pos] as u128) + (carry as u128);
            t[pos] = sum as u64;
            carry = (sum >> 64) as u64;
            pos += 1;
        }

        // m = t[0] * nprime0 mod 2^64
        let m = t[0].wrapping_mul(nprime0);

        // t += m * n
        carry = 0;
        for j in 0..num_limbs {
            let prod = (m as u128) * (n[j] as u128) + (t[j] as u128) + (carry as u128);
            t[j] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        pos = num_limbs;
        while carry != 0 && pos < t_len {
            let sum = (t[pos] as u128) + (carry as u128);
            t[pos] = sum as u64;
            carry = (sum >> 64) as u64;
            pos += 1;
        }

        // t >>= 64 (right-shift by one limb)
        for j in 0..t_len - 1 {
            t[j] = t[j + 1];
        }
        t[t_len - 1] = 0;
    }

    // Final reduction.  `t` may carry a nonzero guard limb at `t[num_limbs]`
    // even when the truncated `t[0..num_limbs]` is below `n`: `t < 2n` while
    // `n < R < 2n` for a full-size modulus, so the true value can be
    // `t[0..num_limbs] + R`.  Compare the FULL `t` (guard limbs included)
    // against `n` and subtract once; `t < 2n` guarantees the borrow clears
    // the guard limbs, leaving a result below `n`.
    let mut ge = true;
    for i in (0..=num_limbs + 1).rev() {
        let nv = if i < num_limbs { n[i] } else { 0 };
        if t[i] > nv {
            break;
        }
        if t[i] < nv {
            ge = false;
            break;
        }
    }
    if ge {
        let mut borrow: u64 = 0;
        for i in 0..=num_limbs + 1 {
            let nv = if i < num_limbs { n[i] } else { 0 };
            let (s1, b1) = t[i].overflowing_sub(nv);
            let (s2, b2) = s1.overflowing_sub(borrow);
            t[i] = s2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }
    result[..num_limbs].copy_from_slice(&t[..num_limbs]);
}

/// Convert `a` into Montgomery form: `a_mont = a * R mod n`.
fn rsa_to_mont(
    a: &[u64; RSA_MAX_LIMBS],
    n: &[u64; RSA_MAX_LIMBS],
    num_limbs: usize,
    nprime0: u64,
) -> [u64; RSA_MAX_LIMBS] {
    // R^2 mod n, precomputed.
    let mut r_sq = [0u64; RSA_MAX_LIMBS];
    r_sq[0] = 1; // R = 2^(64*num_limbs) ≡ 1 limb
                 // Compute R^2 mod n via repeated Montgomery squaring.
                 // R = 2^(64*num_limbs).  We want R^2 mod n.
                 // In Montgomery form, an integer x is represented as x*R mod n.
                 // To convert a to Montgomery form, compute a * R mod n.
                 // We compute this as MontMul(a, R^2 mod n, n, nprime0).
                 //
                 // First compute R mod n: start with 1, shift left by 64*num_limbs bits mod n.
    let mut r_mod_n = [0u64; RSA_MAX_LIMBS];
    r_mod_n[0] = 1;
    for _ in 0..num_limbs {
        // Multiply R by 2^64 mod n: shift left 64, subtract n as needed.
        // This is: for 64 times: r_mod_n *= 2; if r_mod_n >= n: r_mod_n -= n
        for _bit in 0..64 {
            // r_mod_n <<= 1
            let mut carry: u64 = 0;
            #[allow(clippy::needless_range_loop)]
            for i in 0..num_limbs {
                let next_carry = r_mod_n[i] >> 63;
                r_mod_n[i] = (r_mod_n[i] << 1) | carry;
                carry = next_carry;
            }
            // If r_mod_n >= n, subtract n.
            let mut ge = true;
            for i in (0..num_limbs).rev() {
                if r_mod_n[i] > n[i] {
                    break;
                }
                if r_mod_n[i] < n[i] {
                    ge = false;
                    break;
                }
            }
            if ge || carry > 0 {
                let mut borrow: u64 = 0;
                for i in 0..num_limbs {
                    let (s1, b1) = r_mod_n[i].overflowing_sub(n[i]);
                    let (s2, b2) = s1.overflowing_sub(borrow);
                    r_mod_n[i] = s2;
                    borrow = (b1 as u64) + (b2 as u64);
                }
            }
        }
    }

    // Now r_mod_n = R mod n.  Compute R^2 mod n = MontMul(R mod n, R mod n).
    // But wait, R and R_mod_n aren't in Montgomery form.  MontMul expects
    // inputs in Montgomery form.  So we can't use it directly.
    //
    // To compute a * R mod n (Montgomery form of a), we use:
    //   MontMul(a, R^2 mod n) = a * R^2 * R^(-1) mod n = a * R mod n.
    //
    // We still need R^2 mod n.  Let's compute it:
    //   R^2 mod n = (R mod n) * (R mod n) mod n
    //
    // Compute (R mod n)^2 via schoolbook multiply then modular reduction.
    let mut r2_prod = [0u64; 2 * RSA_MAX_LIMBS];
    r2_prod[..2 * num_limbs].fill(0);
    for i in 0..num_limbs {
        let av = r_mod_n[i];
        if av == 0 {
            continue;
        }
        let mut carry: u64 = 0;
        #[allow(clippy::needless_range_loop)]
        for j in 0..num_limbs {
            let idx = i + j;
            let prod =
                (av as u128) * (r_mod_n[j] as u128) + (r2_prod[idx] as u128) + (carry as u128);
            r2_prod[idx] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        let mut pos = i + num_limbs;
        while carry != 0 {
            let sum = (r2_prod[pos] as u128) + (carry as u128);
            r2_prod[pos] = sum as u64;
            carry = (sum >> 64) as u64;
            pos += 1;
        }
    }
    // Reduce r2_prod mod n using shift-subtract: copy r2_prod into a working
    // buffer and repeatedly subtract n << shift.
    let mut work = [0u64; 2 * RSA_MAX_LIMBS];
    work.copy_from_slice(&r2_prod);
    let n_bits = rsa_limbs_bitlen(n, num_limbs);
    'reduce: loop {
        let w_bits = {
            let mut bits = 0;
            for i in (0..2 * num_limbs).rev() {
                if work[i] != 0 {
                    bits = i * 64 + 64 - (work[i].leading_zeros() as usize);
                    break;
                }
            }
            bits
        };
        if w_bits < n_bits {
            break;
        }
        // Candidate shift: subtracting n << (w_bits - n_bits) can overshoot
        // (n << shift has the same bit length as work but may be larger), so
        // if sub > work, drop shift by one (always safe because
        // n << (shift - 1) < 2^(w_bits - 1) <= work).
        let mut shift = w_bits - n_bits;
        let mut sub = [0u64; 2 * RSA_MAX_LIMBS];
        loop {
            sub.fill(0);
            let limb_shift = shift / 64;
            let bit_shift = shift % 64;
            #[allow(clippy::needless_range_loop)]
            for i in 0..num_limbs {
                let idx = i + limb_shift;
                sub[idx] |= n[i] << bit_shift;
                if bit_shift > 0 && idx + 1 < 2 * RSA_MAX_LIMBS {
                    sub[idx + 1] |= n[i] >> (64 - bit_shift);
                }
            }
            // Check work >= sub.
            let mut ge = true;
            for i in (0..2 * num_limbs).rev() {
                if work[i] > sub[i] {
                    break;
                }
                if work[i] < sub[i] {
                    ge = false;
                    break;
                }
            }
            if ge {
                // work -= sub
                let mut borrow: u64 = 0;
                for i in 0..2 * num_limbs {
                    let (s1, b1) = work[i].overflowing_sub(sub[i]);
                    let (s2, b2) = s1.overflowing_sub(borrow);
                    work[i] = s2;
                    borrow = (b1 as u64) + (b2 as u64);
                }
                break;
            }
            // sub > work: either we already had shift == 0 (work < n, done) or
            // we drop shift by one and retry.
            if shift == 0 {
                break 'reduce;
            }
            shift -= 1;
        }
    }
    // Copy reduced result to r_sq.
    r_sq[..num_limbs].copy_from_slice(&work[..num_limbs]);

    // Now compute a * R mod n = MontMul(a, R^2 mod n).
    let mut result = [0u64; RSA_MAX_LIMBS];
    rsa_mont_mul(&mut result, a, &r_sq, n, num_limbs, nprime0);
    result
}

/// Modular exponentiation via Montgomery ladder: `result = base^exp mod n`.
/// `exp_bits` is the bit-length of the exponent.
fn rsa_mod_pow(
    result: &mut [u64; RSA_MAX_LIMBS],
    base: &[u64; RSA_MAX_LIMBS],
    exp: &[u64; RSA_MAX_LIMBS],
    exp_bits: usize,
    n: &[u64; RSA_MAX_LIMBS],
    num_limbs: usize,
    nprime0: u64,
) {
    // Convert base to Montgomery form.
    let base_mont = rsa_to_mont(base, n, num_limbs, nprime0);

    // R mod n in Montgomery form: MontMul(R mod n, R^2 mod n) — but actually
    // 1 in Montgomery form is just R mod n.
    // Since Montgomery form of x is x*R mod n, the value 1 is represented as R mod
    // n. Let's compute R mod n.
    let mut one_mont = [0u64; RSA_MAX_LIMBS];
    one_mont[0] = 1;
    // Shift left by 64*num_limbs mod n (same as r_mod_n in rsa_to_mont).
    for _ in 0..num_limbs {
        for _bit in 0..64 {
            let mut carry: u64 = 0;
            #[allow(clippy::needless_range_loop)]
            for i in 0..num_limbs {
                let next_carry = one_mont[i] >> 63;
                one_mont[i] = (one_mont[i] << 1) | carry;
                carry = next_carry;
            }
            let mut ge = true;
            for i in (0..num_limbs).rev() {
                if one_mont[i] > n[i] {
                    break;
                }
                if one_mont[i] < n[i] {
                    ge = false;
                    break;
                }
            }
            if ge || carry > 0 {
                let mut borrow: u64 = 0;
                for i in 0..num_limbs {
                    let (s1, b1) = one_mont[i].overflowing_sub(n[i]);
                    let (s2, b2) = s1.overflowing_sub(borrow);
                    one_mont[i] = s2;
                    borrow = (b1 as u64) + (b2 as u64);
                }
            }
        }
    }

    // Start with result = 1 (in Montgomery form).
    result[..num_limbs].copy_from_slice(&one_mont[..num_limbs]);
    result[num_limbs..].fill(0);

    let mut base_copy = [0u64; RSA_MAX_LIMBS];
    base_copy[..num_limbs].copy_from_slice(&base_mont[..num_limbs]);

    // Left-to-right square-and-multiply.
    for bit in (0..exp_bits).rev() {
        // Square: result = MontMul(result, result).
        let mut sq = [0u64; RSA_MAX_LIMBS];
        rsa_mont_mul(&mut sq, result, result, n, num_limbs, nprime0);
        result[..num_limbs].copy_from_slice(&sq[..num_limbs]);

        // Check if exponent bit is set.
        let exp_limb = bit / 64;
        let exp_bit = bit % 64;
        if exp_limb < RSA_MAX_LIMBS && (exp[exp_limb] >> exp_bit) & 1 != 0 {
            let mut mul_res = [0u64; RSA_MAX_LIMBS];
            rsa_mont_mul(&mut mul_res, result, &base_copy, n, num_limbs, nprime0);
            result[..num_limbs].copy_from_slice(&mul_res[..num_limbs]);
        }
    }

    // Convert back from Montgomery form: result * 1 * R^(-1) mod n.
    let mut one = [0u64; RSA_MAX_LIMBS];
    one[0] = 1;
    let mut unmont = [0u64; RSA_MAX_LIMBS];
    rsa_mont_mul(&mut unmont, result, &one, n, num_limbs, nprime0);
    result[..num_limbs].copy_from_slice(&unmont[..num_limbs]);
}

// ── MGF1 ─────────────────────────────────────────────────────────────────────

/// MGF1 based on SHA-256 (RFC 8017 Appendix B.2.1).
/// Fills `output` with mask bytes generated from `seed`.
fn mgf1_sha256(seed: &[u8], output: &mut [u8]) {
    let n_blocks = output.len().div_ceil(32);
    let mut counter_bytes = [0u8; 4];
    let mut hasher_input = Vec::with_capacity(seed.len() + 4);
    hasher_input.extend_from_slice(seed);
    hasher_input.extend_from_slice(&counter_bytes);

    for counter in 0u32..(n_blocks as u32) {
        let offset = counter as usize * 32;
        let remaining = output.len() - offset;
        let take = remaining.min(32);

        // Update counter bytes.
        counter_bytes.copy_from_slice(&counter.to_be_bytes());
        let input_len = hasher_input.len();
        hasher_input[input_len - 4..].copy_from_slice(&counter_bytes);

        let hash = sha256(&hasher_input);
        output[offset..offset + take].copy_from_slice(&hash[..take]);
    }
}

// ── RSA-PSS Verification (RFC 8017 §8.1.2, §9.1.2) ───────────────────────────

/// Raw RSA public-key operation: compute `m = s^e mod n` and return the
/// `k`-byte big-endian encoded message `EM` alongside the modulus length `k`.
///
/// Returns `None` when the inputs are invalid: modulus larger than
/// [`RSA_MAX_LIMBS`] limbs, a signature whose length differs from the modulus,
/// or a signature value `s >= n`.
fn rsa_public_key_op(
    n_bytes: &[u8],
    e_bytes: &[u8],
    signature: &[u8],
) -> Option<([u8; RSA_MAX_BYTES], usize)> {
    let k = n_bytes.len(); // modulus length in bytes
    if k > RSA_MAX_LIMBS * 8 {
        return None;
    }
    if signature.len() != k {
        return None;
    }

    let num_limbs = k.div_ceil(8);

    // Parse modulus n.
    let mut n = [0u64; RSA_MAX_LIMBS];
    rsa_bytes_to_limbs(n_bytes, &mut n);

    // Parse signature s.
    let mut s = [0u64; RSA_MAX_LIMBS];
    rsa_bytes_to_limbs(signature, &mut s);

    // If s >= n, invalid.
    let mut s_ge_n = true;
    for i in (0..num_limbs).rev() {
        if s[i] > n[i] {
            break;
        }
        if s[i] < n[i] {
            s_ge_n = false;
            break;
        }
    }
    if s_ge_n {
        return None;
    }

    // Parse exponent e.
    let mut e_limbs = [0u64; RSA_MAX_LIMBS];
    let e_num = rsa_bytes_to_limbs(e_bytes, &mut e_limbs);
    let e_bits = rsa_limbs_bitlen(&e_limbs, e_num);

    // Precompute Montgomery constant nprime0 = -n[0]^(-1) mod 2^64.
    // If inv * n[0] ≡ 1 (mod 2^64), then (-inv) * n[0] ≡ -1 (mod 2^64).
    let inv = rsa_modinv_u64(n[0]);
    let nprime0_correct = 0u64.wrapping_sub(inv);

    // Compute m = s^e mod n.
    let mut m_limbs = [0u64; RSA_MAX_LIMBS];
    rsa_mod_pow(
        &mut m_limbs,
        &s,
        &e_limbs,
        e_bits,
        &n,
        num_limbs,
        nprime0_correct,
    );

    // Convert m to EM bytes (k bytes, big-endian).
    let mut em = [0u8; RSA_MAX_BYTES];
    rsa_limbs_to_bytes(&m_limbs, num_limbs, &mut em[..k]);
    Some((em, k))
}

/// Return the bit length of the RSA modulus `n_bytes`.
fn rsa_mod_bits(n_bytes: &[u8]) -> usize {
    let mut n = [0u64; RSA_MAX_LIMBS];
    let num = rsa_bytes_to_limbs(n_bytes, &mut n);
    rsa_limbs_bitlen(&n, num)
}

/// Verify an RSA-PSS signature.
///
/// TLS 1.3 parameters: Hash=SHA-256, MGF=MGF1(SHA-256), salt_len=32.
///
/// `n` = RSA modulus (big-endian bytes, 256/512 bytes for 2048/4096-bit keys).
/// `e` = public exponent (big-endian bytes, typically `[1, 0, 1]` = 65537).
/// `message` = 32-byte hash to verify (the TLS transcript hash).
/// `signature` = the raw signature bytes (big-endian, same length as `n`).
#[must_use]
pub fn rsa_pss_verify(
    n_bytes: &[u8],
    e_bytes: &[u8],
    message: &[u8; 32],
    signature: &[u8],
) -> bool {
    let (em, k) = match rsa_public_key_op(n_bytes, e_bytes, signature) {
        Some(v) => v,
        None => return false,
    };

    // EMSA-PSS-VERIFY (RFC 8017 §9.1.2).
    // 1. mHash = Hash(M) -- `message` is already the 32-byte transcript hash.
    let m_hash = *message;

    // 2. Check EM rightmost byte == 0xBC.
    if em[k - 1] != 0xBC {
        return false;
    }

    // 3. Split EM: maskedDB = EM[0..k-hLen-1], H = EM[k-hLen-1..k-1] hLen = 32
    //    (SHA-256).
    let h_len: usize = 32;
    if k < h_len + 1 {
        return false;
    }
    let db_len = k - h_len - 1;
    let masked_db = &em[..db_len];
    let h_val = &em[db_len..db_len + h_len];

    // 4. dbMask = MGF1(H, db_len).
    let mut db_mask = [0u8; RSA_MAX_BYTES];
    let db_mask_slice = &mut db_mask[..db_len];
    mgf1_sha256(h_val, db_mask_slice);

    // 5. DB = maskedDB XOR dbMask.
    let mut db = [0u8; RSA_MAX_BYTES];
    for i in 0..db_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // 6. Set leftmost 8*kLen - 2*hLen - 16 bits of DB to 0. kLen = k (bytes).  8k -
    //    2*256 - 16 = 8k
    //    - 528 bits. That's (8k - 528) bits = (k - 66) bytes.  Wait, let me
    //      recalculate. emBits = 8
    //    * k - (8 * k - bitlen(n)) rounded down to a multiple of 8? No. Actually,
    //      RFC 8017 §9.1.1
    //    says: emBits = modBits - 1 where modBits = bitlen(n). The leftmost 8*emLen
    // - emBits bits    of the leftmost octet of DB shall be 0.
    //
    //    modBits = bitlen(n)
    //    emBits = modBits - 1
    //    emLen = k
    //    Bits to zero = 8 * emLen - emBits = 8k - (modBits - 1)
    let mod_bits = rsa_mod_bits(n_bytes);
    let em_bits = mod_bits - 1;
    let zero_bits = 8 * k - em_bits;

    // Zero the most significant bits of DB.
    if zero_bits > 0 {
        let full_bytes = zero_bits / 8;
        #[allow(clippy::needless_range_loop)]
        for i in 0..full_bytes.min(db_len) {
            if db[i] != 0 {
                return false;
            }
        }
        let rem_bits = zero_bits % 8;
        if rem_bits > 0 && full_bytes < db_len {
            let mask = 0xFFu8 >> rem_bits;
            db[full_bytes] &= mask;
        }
    }

    // RFC 8017 §9.1.2, steps 9-15 (EMSA-PSS-VERIFY):
    //   9. Set the leftmost 8*emLen - emBits bits of the leftmost byte of DB to 0.
    //   10. The emLen - hLen - sLen - 2 leftmost bytes of DB must be 0x00.
    //   11. The byte at position emLen - hLen - sLen - 2 of DB must be 0x01.
    //   12. Let salt be the last sLen bytes of DB.
    //   13. Let M' = 0x00...00 || Hash(M) || salt  (8 bytes of 0x00)
    //   14. Let H' = Hash(M').
    //   15. Output "valid" iff H == H'.
    let s_len: usize = 32; // saltLen for TLS 1.3 RSA-PSS

    // Step 9: Set leftmost bits to 0 (same as the masking done above).
    let zero_bits_step9 = 8 * k - em_bits;
    if zero_bits_step9 > 0 {
        let full_bytes = zero_bits_step9 / 8;
        #[allow(clippy::needless_range_loop)]
        for byte_idx in 0..full_bytes.min(db_len) {
            if db[byte_idx] != 0 {
                return false;
            }
        }
        let rem_bits = zero_bits_step9 % 8;
        if rem_bits > 0 && full_bytes < db_len {
            db[full_bytes] &= 0xFFu8 >> rem_bits;
        }
    }

    // Step 10: The leftmost emLen - hLen - sLen - 2 bytes of DB must be 0x00.
    if db_len < s_len + 2 {
        return false;
    }
    let ps_len = db_len - s_len - 1; // length of PS in bytes
    #[allow(clippy::needless_range_loop)]
    for byte_idx in 0..ps_len {
        // Wait, step 10 says "emLen - hLen - sLen - 2 leftmost bytes".
        // db_len = k - h_len - 1.
        // ps_bytes = db_len - s_len - 1 = k - h_len - 1 - s_len - 1 = k - h_len - s_len
        // - 2. That matches step 10.
        if db[byte_idx] != 0 {
            return false;
        }
    }

    // Step 11: The byte at position emLen - hLen - sLen - 2 must be 0x01.
    // That's db[ps_len] = 0x01.
    if db[ps_len] != 0x01 {
        return false;
    }

    // Step 12: salt = last sLen bytes of DB.
    let salt = &db[db_len - s_len..db_len];

    // Step 13-14: H' = SHA-256(0x00 * 8 || mHash || salt).
    let mut m_prime = [0u8; 8 + 32 + RSA_MAX_BYTES]; // 8 + 32 + 512 max
    let m_prime_len = 8 + 32 + s_len;
    // First 8 bytes are 0x00 (already initialized to 0).
    m_prime[8..8 + 32].copy_from_slice(&m_hash);
    m_prime[8 + 32..8 + 32 + s_len].copy_from_slice(salt);
    let h_prime = sha256(&m_prime[..m_prime_len]);

    // Step 15: H == H'.
    constant_time_eq(&h_prime, &h_val.try_into().unwrap_or([0u8; 32]))
}

// ── RSASSA-PKCS1-v1_5 Verification (RFC 8017 §8.2, §9.2) ────────────────────

/// DER prefix of the SHA-256 `DigestInfo` value (RFC 8017 §9.2):
///
/// ```text
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,   -- sha256WithRSAEncryption
///     digest OCTET STRING }                  -- 32-byte SHA-256 digest
/// ```
///
/// This is the fixed 19-byte header that precedes the digest inside an
/// EMSA-PKCS1-v1_5 encoded message.
const DIGEST_INFO_PREFIX_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Verify an RSASSA-PKCS1-v1_5 signature (RFC 8017 §8.2) over `message` using
/// SHA-256 as the message digest.
///
/// This is the signature scheme mandated by X.509 for `sha256WithRSAEncryption`
/// certificate chain signatures, as opposed to the RSA-PSS scheme used for the
/// TLS 1.3 CertificateVerify handshake message.
#[must_use]
pub fn rsa_pkcs1v15_verify(
    n_bytes: &[u8],
    e_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let (em, k) = match rsa_public_key_op(n_bytes, e_bytes, signature) {
        Some(v) => v,
        None => return false,
    };

    let hash = sha256(message);

    // EMSA-PKCS1-v1_5-ENCODE (RFC 8017 §9.2):
    //   EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || Digest
    // where PS is at least 8 bytes of 0xFF, and EM is exactly k bytes (the
    // modulus length).  A well-formed signature uses every remaining byte for
    // PS, so the layout is fully determined once `k` is known.
    let digest_info_len = DIGEST_INFO_PREFIX_SHA256.len() + hash.len();
    if k < digest_info_len + 11 {
        return false;
    }
    if em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }
    let mut idx = 2;
    while idx < k && em[idx] == 0xFF {
        idx += 1;
    }
    if idx < 2 + 8 {
        // PS must be at least 8 bytes long.
        return false;
    }
    if idx >= k || em[idx] != 0x00 {
        return false;
    }
    let di_start = idx + 1;
    if di_start + digest_info_len != k {
        return false;
    }
    if em[di_start..di_start + DIGEST_INFO_PREFIX_SHA256.len()] != DIGEST_INFO_PREFIX_SHA256 {
        return false;
    }
    constant_time_eq(
        &hash,
        // Bound the slice at `k`: `em` is `[u8; RSA_MAX_BYTES]` with only the
        // first `k` bytes populated, so an open-ended range would compare the
        // digest against trailing zero padding and always fail.
        &em[di_start + DIGEST_INFO_PREFIX_SHA256.len()..k],
    )
}

// ── Salt generation ─────────────────────────────────────────────────────────
// ── ECDSA P-256 (secp256r1) signature verification ─────────────────────────
// NIST FIPS 186-5 / SEC 2.
//
// Implements field arithmetic modulo the P-256 prime, point operations on
// the curve y² = x³ + ax + b, and the ECDSA verification formula:
//   u₁ = e·s⁻¹ mod n,  u₂ = r·s⁻¹ mod n,  R = u₁·G + u₂·Q,  check R.x ≡ r (mod
// n).

/// P-256 prime: 2^256 - 2^224 + 2^192 + 2^96 - 1.
const P256_PRIME: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// P-256 curve coefficient a = -3 mod p.
const P256_A: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFC,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// P-256 curve coefficient b.
/// 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B (LE).
#[allow(dead_code)]
const P256_B: [u64; 4] = [
    0x3BCE_3C3E_27D2_604B,
    0x651D_06B0_CC53_B0F6,
    0xB3EB_BD55_7698_86BC,
    0x5AC6_35D8_AA3A_93E7,
];

/// P-256 generator G affine x.
/// 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296 (LE).
const P256_GX: [u64; 4] = [
    0xF4A1_3945_D898_C296,
    0x7703_7D81_2DEB_33A0,
    0xF8BC_E6E5_63A4_40F2,
    0x6B17_D1F2_E12C_4247,
];

/// P-256 generator G affine y.
/// 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5 (LE).
const P256_GY: [u64; 4] = [
    0xCBB6_4068_37BF_51F5,
    0x2BCE_3357_6B31_5ECE,
    0x8EE7_EB4A_7C0F_9E16,
    0x4FE3_42E2_FE1A_7F9B,
];

/// P-256 curve order n.
/// 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 (LE).
const P256_ORDER: [u64; 4] = [
    0xF3B9_CAC2_FC63_2551,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

/// c = 2^256 - P256_PRIME, so 2^256 ≡ c (mod p).
/// c = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000001 (LE).
const P256_C: [u64; 4] = [
    0x0000_0000_0000_0001,
    0xFFFF_FFFF_0000_0000,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFE,
];

/// c_n = 2^256 - P256_ORDER, so 2^256 ≡ c_n (mod n).
/// c_n = 0xFFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF (LE).
const P256_ORDER_C: [u64; 4] = [
    0x0C46_353D_039C_DAAF,
    0x4319_0552_58E8_617B,
    0x0000_0000_0000_0000,
    0x0000_0000_FFFF_FFFF,
];

// ── 256-bit field element ──────────────────────────────────────────────────

/// A 256-bit field element stored as four 64-bit limbs (little-endian).
#[derive(Clone, Copy)]
struct Fe256([u64; 4]);

impl Fe256 {
    const ZERO: Self = Fe256([0; 4]);
    const ONE: Self = Fe256([1, 0, 0, 0]);

    fn from_limbs(limbs: [u64; 4]) -> Self {
        Fe256(limbs)
    }

    /// Create from a big-endian byte slice, reducing mod p if needed.
    fn from_bytes_be(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks(8).enumerate() {
            let mut val = 0u64;
            for &b in chunk {
                val = (val << 8) | (b as u64);
            }
            limbs[3 - i] = val;
        }
        Fe256(limbs)
    }

    fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Compare against a 4-limb constant.
    fn cmp_limbs(&self, other: &[u64; 4]) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other[i]) {
                core::cmp::Ordering::Equal => {}
                ord => return ord,
            }
        }
        core::cmp::Ordering::Equal
    }

    /// Modular addition: (self + rhs) mod p.
    fn add(&self, rhs: &Fe256) -> Fe256 {
        let mut carry = 0u64;
        let mut r = [0u64; 4];
        for ((&a, &b), r_item) in self.0.iter().zip(rhs.0.iter()).zip(r.iter_mut()) {
            let (s, c1) = a.overflowing_add(b);
            let (s2, c2) = s.overflowing_add(carry);
            *r_item = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        // Conditional subtraction of p if carry or r >= p.
        if carry > 0 || Fe256(r).cmp_limbs(&P256_PRIME) >= core::cmp::Ordering::Equal {
            let mut borrow = 0u64;
            for (r_item, &p_limb) in r.iter_mut().zip(P256_PRIME.iter()) {
                let (s1, b1) = r_item.overflowing_sub(p_limb);
                let (s2, b2) = s1.overflowing_sub(borrow);
                *r_item = s2;
                borrow = (b1 as u64) + (b2 as u64);
            }
        }
        Fe256(r)
    }

    /// Modular subtraction: (self - rhs) mod p.
    fn sub(&self, rhs: &Fe256) -> Fe256 {
        let mut borrow = 0u64;
        let mut r = [0u64; 4];
        for ((&a, &b), r_item) in self.0.iter().zip(rhs.0.iter()).zip(r.iter_mut()) {
            let (s1, b1) = a.overflowing_sub(b);
            let (s2, b2) = s1.overflowing_sub(borrow);
            *r_item = s2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        if borrow > 0 {
            let mut carry = 0u64;
            for (r_item, &p_limb) in r.iter_mut().zip(P256_PRIME.iter()) {
                let (s, c) = r_item.overflowing_add(p_limb);
                let (s2, c2) = s.overflowing_add(carry);
                *r_item = s2;
                carry = (c as u64) + (c2 as u64);
            }
        }
        Fe256(r)
    }

    /// Modular multiplication using Barrett reduction.
    fn mul(&self, rhs: &Fe256) -> Fe256 {
        let mut prod = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let idx = i + j;
                let (lo, hi) = mul_wide(self.0[i], rhs.0[j]);
                let (s1, c1) = prod[idx].overflowing_add(lo);
                let (s2, c2) = s1.overflowing_add(carry);
                prod[idx] = s2;
                carry = hi + (c1 as u64) + (c2 as u64);
            }
            // Propagate the carry out of this row fully.
            let mut idx = i + 4;
            while carry > 0 && idx < 8 {
                let (s, c) = prod[idx].overflowing_add(carry);
                prod[idx] = s;
                carry = c as u64;
                idx += 1;
            }
        }
        barrett_reduce(&prod)
    }

    /// Modular square: self² mod p.
    fn square(&self) -> Fe256 {
        self.mul(self)
    }

    /// Modular inverse via Fermat's little theorem: self^(p-2) mod p.
    fn invert(&self) -> Fe256 {
        // p - 2: subtract 2 from the lowest limb (index 0).
        let mut r = Fe256::ONE;
        let base = *self;
        let mut exp = P256_PRIME;
        exp[0] -= 2;
        for limb_idx in (0..4).rev() {
            let mut limb = exp[limb_idx];
            for _ in 0..64 {
                // Square the running result, then multiply by base on set bits.
                r = r.square();
                if limb & 0x8000_0000_0000_0000 != 0 {
                    r = r.mul(&base);
                }
                limb <<= 1;
            }
        }
        r
    }
}

/// Multiply two u64 values, returning (low, high).
#[inline]
fn mul_wide(a: u64, b: u64) -> (u64, u64) {
    let p = (a as u128) * (b as u128);
    (p as u64, (p >> 64) as u64)
}

/// Reduce a 512-bit value (8 little-endian limbs) modulo a 256-bit modulus.
///
/// Uses the Solinas-style folding identity `2^256 = c (mod m)`, where
/// `c = 2^256 - m` (for m = P-256's prime p and curve order n, `c < 2^224`):
/// for `x = x_hi·2^256 + x_lo`, `x = x_lo + x_hi·c (mod m)`.
///
/// Repeatedly folding the high limbs shrinks x to below 2^256, after which
/// at most two conditional subtractions of m finish the reduction.  For both
/// P-256 moduli, x_hi·c < 2^481, so the intermediate never exceeds 8 limbs
/// (verified against an independent big-integer reference).
fn reduce_512_mod(s: &[u64; 8], c: &[u64; 4], modulus: &[u64; 4]) -> Fe256 {
    let mut v = [0u64; 8];
    v.copy_from_slice(s);

    // Fold the high half into the low half until only the low 4 limbs matter.
    for _ in 0..16 {
        if v[4] == 0 && v[5] == 0 && v[6] == 0 && v[7] == 0 {
            break;
        }
        let hi = [v[4], v[5], v[6], v[7]];
        let lo = [v[0], v[1], v[2], v[3]];
        let prod = mul_256_by_256(&hi, c); // hi·c, at most 8 limbs
        let mut out = [0u64; 8];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s1, c1) = lo[i].overflowing_add(prod[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            out[i] = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        for i in 4..8 {
            let (s1, c1) = prod[i].overflowing_add(carry);
            out[i] = s1;
            carry = c1 as u64;
        }
        // lo + hi·c < 2^256 + 2^481 < 2^512 for both P-256 moduli.
        debug_assert!(carry == 0);
        v = out;
    }

    // Final conditional subtraction (v < 2^256 < 2·m, so ≤ 1 subtraction in
    // practice; loop twice for safety).
    let mut r = [v[0], v[1], v[2], v[3]];
    for _ in 0..3 {
        if Fe256(r).cmp_limbs(modulus) >= core::cmp::Ordering::Equal {
            let mut borrow = 0u64;
            for i in 0..4 {
                let (s1, b1) = r[i].overflowing_sub(modulus[i]);
                let (s2, b2) = s1.overflowing_sub(borrow);
                r[i] = s2;
                borrow = (b1 as u64) + (b2 as u64);
            }
        } else {
            break;
        }
    }
    Fe256(r)
}

/// Fast reduction modulo P-256 prime: x mod p.
fn barrett_reduce(s: &[u64; 8]) -> Fe256 {
    reduce_512_mod(s, &P256_C, &P256_PRIME)
}

// ── Curve points ───────────────────────────────────────────────────────────

/// Affine point on the P-256 curve, or the point at infinity.
#[derive(Clone, Copy)]
struct P256Point {
    x: Fe256,
    y: Fe256,
    is_infinity: bool,
}

impl P256Point {
    const INFINITY: Self = P256Point {
        x: Fe256::ZERO,
        y: Fe256::ZERO,
        is_infinity: true,
    };

    fn is_infinity(&self) -> bool {
        self.is_infinity
    }

    /// Point addition: self + other.
    fn add(&self, other: &P256Point) -> P256Point {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
        // Check for same x.
        if self.x.cmp_limbs(&other.x.0) == core::cmp::Ordering::Equal {
            if self.y.cmp_limbs(&other.y.0) == core::cmp::Ordering::Equal {
                if self.y.is_zero() {
                    return P256Point::INFINITY;
                }
                return self.double();
            }
            return P256Point::INFINITY; // P + (-P) = O
        }
        // λ = (y₂ - y₁) / (x₂ - x₁)
        let dx = other.x.sub(&self.x);
        let dy = other.y.sub(&self.y);
        let lambda = dy.mul(&dx.invert());
        let lambda2 = lambda.square();
        let x3 = lambda2.sub(&self.x).sub(&other.x);
        let y3 = lambda.mul(&self.x.sub(&x3)).sub(&self.y);
        P256Point {
            x: x3,
            y: y3,
            is_infinity: false,
        }
    }

    /// Point doubling: 2 * self.
    fn double(&self) -> P256Point {
        if self.is_infinity() || self.y.is_zero() {
            return P256Point::INFINITY;
        }
        // λ = (3x² + a) / (2y)
        let x2 = self.x.square();
        let three_x2 = x2.add(&x2).add(&x2);
        let a_fe = Fe256::from_limbs(P256_A);
        let numerator = three_x2.add(&a_fe);
        let denominator = self.y.add(&self.y);
        let lambda = numerator.mul(&denominator.invert());
        let x3 = lambda.square().sub(&self.x).sub(&self.x);
        let y3 = lambda.mul(&self.x.sub(&x3)).sub(&self.y);
        P256Point {
            x: x3,
            y: y3,
            is_infinity: false,
        }
    }

    /// Scalar multiplication: k * self, using double-and-add (MSB-first).
    fn mul_scalar(&self, k: &[u64; 4]) -> P256Point {
        let mut result = P256Point::INFINITY;
        let addend = *self;
        for limb_idx in (0..4).rev() {
            let mut limb = k[limb_idx];
            for _ in 0..64 {
                // Double the running result, then add `self` on set bits.
                result = result.double();
                if limb & 0x8000_0000_0000_0000 != 0 {
                    result = result.add(&addend);
                }
                limb <<= 1;
            }
        }
        result
    }
}

fn p256_generator() -> P256Point {
    P256Point {
        x: Fe256::from_limbs(P256_GX),
        y: Fe256::from_limbs(P256_GY),
        is_infinity: false,
    }
}

// ── ECDSA verification ─────────────────────────────────────────────────────

/// Parse a big-endian integer from bytes into an Fe256 (reduced mod n).
fn parse_ecdsa_int(bytes: &[u8]) -> Option<Fe256> {
    if bytes.is_empty() {
        return None;
    }
    // Strip leading zeros.
    let mut start = 0;
    while start < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    let trimmed = &bytes[start..];
    if trimmed.len() > 33 || (trimmed.len() == 33 && trimmed[0] > 0) {
        return None;
    }
    let mut arr = [0u8; 32];
    let copy_start = 32usize.saturating_sub(trimmed.len());
    let copy_len = trimmed.len().min(32);
    arr[copy_start..copy_start + copy_len].copy_from_slice(&trimmed[..copy_len]);
    Some(Fe256::from_bytes_be(&arr))
}

/// Modular inverse and multiplication modulo the curve order n.
impl Fe256 {
    fn invert_mod_n(&self) -> Fe256 {
        let mut r = Fe256::ONE;
        let base = *self;
        let mut exp = P256_ORDER;
        exp[0] -= 2;
        for limb_idx in (0..4).rev() {
            let mut limb = exp[limb_idx];
            for _ in 0..64 {
                // Square the running result, then multiply by base on set bits.
                r = r.mul_mod_n(&r);
                if limb & 0x8000_0000_0000_0000 != 0 {
                    r = r.mul_mod_n(&base);
                }
                limb <<= 1;
            }
        }
        r
    }

    fn mul_mod_n(&self, rhs: &Fe256) -> Fe256 {
        let mut prod = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let idx = i + j;
                let (lo, hi) = mul_wide(self.0[i], rhs.0[j]);
                let (s1, c1) = prod[idx].overflowing_add(lo);
                let (s2, c2) = s1.overflowing_add(carry);
                prod[idx] = s2;
                carry = hi + (c1 as u64) + (c2 as u64);
            }
            // Propagate the carry out of this row fully.
            let mut idx = i + 4;
            while carry > 0 && idx < 8 {
                let (s, c) = prod[idx].overflowing_add(carry);
                prod[idx] = s;
                carry = c as u64;
                idx += 1;
            }
        }
        reduce_mod_n(&prod)
    }
}

/// Fast reduction modulo the curve order n.
/// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551.
fn reduce_mod_n(x: &[u64; 8]) -> Fe256 {
    reduce_512_mod(x, &P256_ORDER_C, &P256_ORDER)
}

/// Multiply two 256-bit values (4 limbs each), returning 8 limbs.
fn mul_256_by_256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut prod = [0u64; 8];
    for (i, &av) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &bv) in b.iter().enumerate() {
            let idx = i + j;
            let (lo, hi) = mul_wide(av, bv);
            let (s1, c1) = prod[idx].overflowing_add(lo);
            let (s2, c2) = s1.overflowing_add(carry);
            prod[idx] = s2;
            carry = hi + (c1 as u64) + (c2 as u64);
        }
        // Propagate the carry out of this row fully (it may overflow limb
        // i+4 and need to continue into i+5, i+6, ...).
        let mut idx = i + 4;
        while carry > 0 && idx < 8 {
            let (s, c) = prod[idx].overflowing_add(carry);
            prod[idx] = s;
            carry = c as u64;
            idx += 1;
        }
    }
    prod
}

/// ECDSA P-256 signature verification.
///
/// Verifies that `(r, s)` is a valid signature over `message_hash` (32-byte
/// SHA-256 digest) using the given uncompressed public key (65 bytes:
/// 0x04 || x || y).
///
/// Returns `true` if the signature is valid per NIST FIPS 186-5.
pub fn ecdsa_p256_verify(public_key: &[u8], message_hash: &[u8; 32], r: &[u8], s: &[u8]) -> bool {
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return false;
    }
    let mut px = [0u8; 32];
    let mut py = [0u8; 32];
    px.copy_from_slice(&public_key[1..33]);
    py.copy_from_slice(&public_key[33..65]);
    let qx = Fe256::from_bytes_be(&px);
    let qy = Fe256::from_bytes_be(&py);

    let (rn, sn) = match (parse_ecdsa_int(r), parse_ecdsa_int(s)) {
        (Some(rv), Some(sv)) => (rv, sv),
        _ => return false,
    };
    if rn.is_zero() || sn.is_zero() {
        return false;
    }
    if rn.cmp_limbs(&P256_ORDER) >= core::cmp::Ordering::Equal
        || sn.cmp_limbs(&P256_ORDER) >= core::cmp::Ordering::Equal
    {
        return false;
    }

    let e = {
        let mut e_bytes = [0u8; 32];
        e_bytes.copy_from_slice(message_hash);
        Fe256::from_bytes_be(&e_bytes)
    };

    let w = sn.invert_mod_n();
    let u1 = e.mul_mod_n(&w);
    let u2 = rn.mul_mod_n(&w);

    let g = p256_generator();
    let q = P256Point {
        x: qx,
        y: qy,
        is_infinity: false,
    };
    let point = g.mul_scalar(&u1.0).add(&q.mul_scalar(&u2.0));

    if point.is_infinity() {
        return false;
    }

    // Verify R.x ≡ r (mod n).
    point.x.reduce_mod_n().cmp_limbs(&rn.0) == core::cmp::Ordering::Equal
}

impl Fe256 {
    /// Reduce self modulo the curve order n.
    fn reduce_mod_n(&self) -> Fe256 {
        reduce_mod_n(&{
            let mut v = [0u64; 8];
            v[..4].copy_from_slice(&self.0);
            v
        })
    }
}

/// Parse a DER-encoded ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }.
///
/// Returns `Some((r_bytes, s_bytes))` on success, stripping leading zero
/// sign bytes from each integer.
pub fn parse_ecdsa_der_signature(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if der.len() < 8 || der[0] != 0x30 {
        return None;
    }
    let seq_len = der[1] as usize;
    if der.len() < 2 + seq_len {
        return None;
    }
    let content = &der[2..2 + seq_len];

    if content.is_empty() || content[0] != 0x02 {
        return None;
    }
    let r_len = content[1] as usize;
    if content.len() < 2 + r_len {
        return None;
    }
    let r_raw = &content[2..2 + r_len];
    let r = if r_raw.len() > 32 && r_raw[0] == 0 {
        &r_raw[1..]
    } else {
        r_raw
    };

    let after_r = &content[2 + r_len..];
    if after_r.is_empty() || after_r[0] != 0x02 {
        return None;
    }
    let s_len = after_r[1] as usize;
    if after_r.len() < 2 + s_len {
        return None;
    }
    let s_raw = &after_r[2..2 + s_len];
    let s = if s_raw.len() > 32 && s_raw[0] == 0 {
        &s_raw[1..]
    } else {
        s_raw
    };

    Some((r.to_vec(), s.to_vec()))
}

// ── PBKDF2-HMAC-SHA256 (RFC 8018 §5.2) ───────────────────────────────────────

/// Derive a key from a passphrase using PBKDF2-HMAC-SHA256.
///
/// Returns `dklen` bytes of derived key material.
///
/// Used by the LUKS2 disk-encryption driver to turn a passphrase into a
/// keyslot key (the KDF in the LUKS2 header's keyslot configuration).
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    assert!(iterations > 0, "PBKDF2 iteration count must be positive");

    const H_LEN: usize = 32; // HMAC-SHA256 output length
    let num_blocks = dklen.div_ceil(H_LEN);

    let mut result = Vec::with_capacity(dklen);

    for block in 1..=num_blocks {
        // U_1 = PRF(password, salt || INT_32_BE(i))
        let mut u = Vec::with_capacity(salt.len() + 4);
        u.extend_from_slice(salt);
        u.extend_from_slice(&(block as u32).to_be_bytes());
        let mut u_last = hmac_sha256(password, &u);

        // T_i = U_1 XOR U_2 XOR ... XOR U_c
        let mut block_out = u_last;
        for _ in 1..iterations {
            u.clear();
            u.extend_from_slice(&u_last);
            u_last = hmac_sha256(password, &u);
            for (a, b) in block_out.iter_mut().zip(u_last.iter()) {
                *a ^= b;
            }
        }

        result.extend_from_slice(&block_out);
    }

    result.truncate(dklen);
    result
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_output() {
        let hex = sha256_hex(b"abc");
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn constant_time_eq_match() {
        let a = sha256(b"password");
        let b = sha256(b"password");
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_mismatch() {
        let a = sha256(b"password");
        let b = sha256(b"wrong");
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn generate_salt_is_deterministic_length() {
        let s1 = generate_salt("alice");
        let s2 = generate_salt("alice");
        assert_eq!(s1.len(), 16);
        assert_eq!(s2.len(), 16);
        // Salts differ because the counter advances.
    }

    // ── ChaCha20 test vectors (RFC 8439 §2.4.2) ──

    #[test]
    fn chacha20_block_quarter_round_vector() {
        // Test quarter round from RFC 8439 §2.1.1.
        let mut state: [u32; 16] = [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
            0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
            0x2098d9d6, 0x91dbd320,
        ];
        super::chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        assert_eq!(state[2], 0xbdb886dc);
        assert_eq!(state[7], 0xcfacafd2);
        assert_eq!(state[8], 0xe46bea80);
        assert_eq!(state[13], 0xccc07c79);
    }

    #[test]
    fn chacha20_block_test_vector() {
        // Test vector verified against independent Python implementation.
        // Key + nonce from RFC 8439 §2.4.2.
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter: u32 = 1;

        let block = super::chacha20_block(&key, counter, &nonce);

        // Expected output cross-verified with independent Python implementation.
        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(block, expected);
    }

    #[test]
    fn chacha20_encrypt_test_vector() {
        // Cross-verified with independent Python implementation.
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut data = plaintext.to_vec();
        super::chacha20_encrypt(&key, &nonce, &mut data);

        // Ciphertext cross-verified with independent Python implementation.
        let expected_ciphertext: [u8; 114] = [
            0xe3, 0x64, 0x7a, 0x29, 0xde, 0xd3, 0x15, 0x28, 0xef, 0x56, 0xba, 0xc7, 0x0f, 0x7a,
            0x7a, 0xc3, 0xb7, 0x35, 0xc7, 0x44, 0x4d, 0xa4, 0x2d, 0x99, 0x82, 0x3e, 0xf9, 0x93,
            0x8c, 0x8e, 0xbf, 0xdc, 0xf0, 0x5b, 0xb7, 0x1a, 0x82, 0x2c, 0x62, 0x98, 0x1a, 0xa1,
            0xea, 0x60, 0x8f, 0x47, 0x93, 0x3f, 0x2e, 0xd7, 0x55, 0xb6, 0x2d, 0x93, 0x12, 0xae,
            0x72, 0x03, 0x76, 0x74, 0xf3, 0xe9, 0x3e, 0x24, 0x4c, 0x23, 0x28, 0xd3, 0x2f, 0x75,
            0xbc, 0xc1, 0x5b, 0xb7, 0x57, 0x4f, 0xde, 0x0c, 0x6f, 0xcd, 0xf8, 0x7b, 0x7a, 0xa2,
            0x5b, 0x59, 0x72, 0x97, 0x0c, 0x2a, 0xe6, 0xcc, 0xed, 0x86, 0xa1, 0x0b, 0xe9, 0x49,
            0x6f, 0xc6, 0x1c, 0x40, 0x7d, 0xfd, 0xc0, 0x15, 0x10, 0xed, 0x8f, 0x4e, 0xb3, 0x5d,
            0x0d, 0x62,
        ];
        assert_eq!(data, expected_ciphertext);

        // Decrypt: apply ChaCha20 again to recover plaintext.
        super::chacha20_encrypt(&key, &nonce, &mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn chacha20_keystream_is_reproducible() {
        let key = sha256(b"test-key-seed");
        let nonce = sha256(b"test-nonce-seed");
        let nonce_12: [u8; 12] = [
            nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
            nonce[8], nonce[9], nonce[10], nonce[11],
        ];

        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        super::chacha20_keystream(&key, &nonce_12, 0, &mut out1);
        super::chacha20_keystream(&key, &nonce_12, 0, &mut out2);
        assert_eq!(out1, out2);
    }

    // ── HMAC-SHA256 test vectors (RFC 4231) ──

    #[test]
    fn hmac_sha256_rfc4231_tc1() {
        // Key = 20 × 0x0b, Data = "Hi There"
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = super::hmac_sha256(&key, data);
        let expected =
            hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(mac, expected);
    }

    #[test]
    fn hmac_sha256_rfc4231_tc2() {
        // Key = "Jefe", Data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = super::hmac_sha256(key, data);
        let expected =
            hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(mac, expected);
    }

    #[test]
    fn hmac_sha256_key_longer_than_block() {
        // Key longer than 64 bytes — internally hashed first.
        let key = [0xaa; 80];
        let data = b"Test message";
        let mac = super::hmac_sha256(&key, data);

        // Verify the result has correct length and is non-zero.
        let sum: u32 = mac.iter().map(|&b| b as u32).sum();
        assert!(sum > 0);
    }

    #[test]
    fn hmac_sha256_empty_message() {
        let key = b"secret";
        let mac1 = super::hmac_sha256(key, b"");
        let mac2 = super::hmac_sha256(key, b"");
        assert_eq!(mac1, mac2);
    }

    // ── HKDF-SHA256 test vectors (RFC 5869 Appendix A.1) ──

    #[test]
    fn hkdf_sha256_extract_rfc5869() {
        // Extract with salt.
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let prk = super::hkdf_sha256_extract(&salt, &ikm);
        let expected =
            hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        assert_eq!(prk, expected);
    }

    #[test]
    fn hkdf_sha256_expand_rfc5869() {
        // Expand from known PRK.
        let prk = hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let info: &[u8] = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let okm = super::hkdf_sha256_expand(&prk, info, 42);
        assert_eq!(okm.len(), 42);
        let expected_first_32 =
            hex_to_bytes("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
        assert_eq!(&okm[..32], &expected_first_32);
        // Remaining bytes.
        assert_eq!(
            &okm[32..],
            &[0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65]
        );
    }

    #[test]
    fn hkdf_sha256_extract_empty_salt() {
        // Empty salt → uses 32 zero bytes.
        let ikm = b"test input keying material";
        let prk = super::hkdf_sha256_extract(&[], ikm);
        let sum: u32 = prk.iter().map(|&b| b as u32).sum();
        assert!(sum > 0);
    }

    #[test]
    fn hkdf_sha256_round_trip() {
        // Extract + expand with no info.
        let ikm = sha256(b"master secret");
        let salt = sha256(b"random salt value");
        let prk = super::hkdf_sha256_extract(&salt, &ikm);
        let okm = super::hkdf_sha256_expand(&prk, b"", 64);
        assert_eq!(okm.len(), 64);
        // Output should differ from input.
        assert_ne!(&okm[..32], &ikm[..]);
    }

    // ── Poly1305 test vectors (RFC 8439 §2.5.2) ──

    #[test]
    fn poly1305_rfc8439_test_vector() {
        // Key from RFC 8439 §2.5.2.
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let message = b"Cryptographic Forum Research Group";
        let tag = super::poly1305_mac(&key, message);
        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(tag, expected);
    }

    #[test]
    fn poly1305_empty_message() {
        let key: [u8; 32] = [0x00; 32];
        let tag = super::poly1305_mac(&key, b"");
        // With an all-zero key and empty message, the tag should still
        // be computed (s value is 0, r is clamped from 0).
        let sum: u32 = tag.iter().map(|&b| b as u32).sum();
        assert_eq!(sum, 0); // r clamped to 0 → accumulator = 0, s = 0 → tag = 0
    }

    /// Trace through the RFC 8439 test vector step by step, comparing with
    /// Python reference intermediate values.
    #[test]
    fn poly1305_debug_trace_rfc8439() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];

        let (r_bytes, s_bytes) = super::poly1305_clamp(&key);
        let r0 = u64::from_le_bytes(r_bytes[..8].try_into().unwrap());
        let r1 = u64::from_le_bytes(r_bytes[8..].try_into().unwrap());
        let s0 = u64::from_le_bytes(s_bytes[..8].try_into().unwrap());
        let s1 = u64::from_le_bytes(s_bytes[8..].try_into().unwrap());

        // Check clamped r matches Python reference values.
        assert_eq!(r0, 0x036d555408bed685, "r0 mismatch");
        assert_eq!(r1, 0x0806d5400e52447c, "r1 mismatch");
        assert_eq!(s0, 0xfdb20dfb8a800301, "s0 mismatch");
        assert_eq!(s1, 0x1bf54941aff6bf4a, "s1 mismatch");

        let msg = b"Cryptographic Forum Research Group";

        let mut a0: u64 = 0;
        let mut a1: u64 = 0;
        let mut a2: u64 = 0;

        // ── Block 0: bytes 0..16 ──
        {
            let mut block = [0u8; 17];
            block[..16].copy_from_slice(&msg[..16]);
            block[16] = 0x01;
            let n0 = u64::from_le_bytes(block[..8].try_into().unwrap());
            let n1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
            assert_eq!(n0, 0x72676f7470797243, "blk0 n0");
            assert_eq!(n1, 0x06f46206369687061, "blk0 n1");

            let t0 = a0 as u128 + n0 as u128;
            let t1 = a1 as u128 + n1 as u128 + (t0 >> 64);
            a0 = t0 as u64;
            a1 = t1 as u64;
            a2 = a2.wrapping_add((t1 >> 64) as u64);

            // After add: a0=0x72676f7470797243, a1=0x06f46206369687061, a2=0x0
            // Wait, Python says a2=0x1 after block 0 add. Why?
            // Because n has the 0x01 high byte, making n a 129-bit number.
            // In Python: n = int.from_bytes(chunk + b'\x01', 'little')
            // n = n0 + n1*2^64 + 2^128 (the 0x01 byte is at position 16, i.e. bit 128)
            // So a2 should have 1 added!
            assert_eq!(a0, 0x72676f7470797243, "blk0 after add a0");
            assert_eq!(a1, 0x06f46206369687061, "blk0 after add a1");
            // The 0x01 at byte 16 sets bit 128 → a2 += 1
            // But my code doesn't add this! Let me check...
            // In Python: t1 = 0 + n1 + carry0 = n1
            // a2 = (acc >> 128) + (t1 >> 64) = 0 + (n1 >> 64)
            // n1 = 0x06f46206369687061, n1 >> 64 = 0
            // So a2 = 0. But Python says a2=1???
            //
            // Wait, I think my Python trace was also decomposed wrong.
            // The actual acc is computed correctly by Python's big int:
            // acc_after_add = n = 0x16f4620636968706172676f7470797243
            // a0 = 0x72676f7470797243, a1 = 0x6f46206369687061, a2 = 0x1
            //
            // But in my u128 decomposition:
            // t0 = n0 = 0x72676f7470797243, carry0 = 0
            // t1 = n1 = 0x06f46206369687061... wait, n1 is 8 bytes LE from block[8..16].
            // Let me check: block[8..16] = "ic Fo" (the last 8 bytes of the first 16-char
            // chunk) That's [105, 99, 32, 70, 111, 0, 0, ...]  — no.
            //
            // The chunk is "Cryptographic F" (bytes 0-15):
            // bytes: [67, 114, 121, 112, 116, 111, 103, 114, 97, 112, 104, 105, 99, 32, 70,
            // 111] block[0..16] = these 16 bytes
            // n0 = LE bytes 0-7: [67, 114, 121, 112, 116, 111, 103, 114] = "Cryptogr"
            // n1 = LE bytes 8-15: [97, 112, 104, 105, 99, 32, 70, 111] = "aphic Fo"
            //
            // Actually, the LE interpretation means:
            // n0 = 0x72676f7470797243 (from bytes 0-7 reversed)
            // n1 = 0x6f46206369687061 (from bytes 8-15, but check the endianness!)
            //
            // Wait, u64::from_le_bytes takes the bytes in little-endian order.
            // So n1 = u64::from_le_bytes([97, 112, 104, 105, 99, 32, 70, 111])
            //      = 111*2^56 + 70*2^48 + 32*2^40 + 99*2^32 + 105*2^24 + 104*2^16 + 112*2^8
            // + 97      = 0x6f46206369687061
            //
            // But the 0x01 at block[16] is the high bit of a 17-byte number.
            // The 17-byte number is: n0 + n1*2^64 + 0x01*2^128 + 0*2^136...
            // = n0 + n1*2^64 + 2^128
            //
            // So when we add this to acc, we need: a2 += 1 (for the 2^128 term)!
            // MY CODE IS MISSING THIS!

            // a2 should be incremented by 1 due to the 0x01 high byte!
            a2 = a2.wrapping_add(1); // FIX: the 0x01 at byte 16 represents bit 128 = 2^128

            assert_eq!(a0, 0x72676f7470797243, "blk0 after add a0");
            assert_eq!(a1, 0x06f46206369687061, "blk0 after add a1");
            assert_eq!(
                a2, 0x1,
                "blk0 after add a2 — need +1 for 0x01 byte at bit 128"
            );

            super::poly1305_mul_mod(&mut a0, &mut a1, &mut a2, [r0, r1]);
            assert_eq!(a0, 0x47ddeb88e69c83fc, "blk0 after mul a0");
            assert_eq!(a1, 0xc88c77849d64ae91, "blk0 after mul a1");
            assert_eq!(a2, 0x2, "blk0 after mul a2");
        }

        // ── Block 1: bytes 16..32 ──
        {
            let mut block = [0u8; 17];
            block[..16].copy_from_slice(&msg[16..32]);
            block[16] = 0x01;
            let n0 = u64::from_le_bytes(block[..8].try_into().unwrap());
            let n1 = u64::from_le_bytes(block[8..16].try_into().unwrap());

            let t0 = a0 as u128 + n0 as u128;
            let t1 = a1 as u128 + n1 as u128 + (t0 >> 64);
            a0 = t0 as u64;
            a1 = t1 as u64;
            a2 = a2.wrapping_add((t1 >> 64) as u64);
            a2 = a2.wrapping_add(1); // FIX: 0x01 byte → +1 to a2

            assert_eq!(a0, 0xad5150db0709f96e, "blk1 after add a0");
            assert_eq!(a1, 0x37febea505c820f2, "blk1 after add a1");
            assert_eq!(a2, 0x4, "blk1 after add a2");

            super::poly1305_mul_mod(&mut a0, &mut a1, &mut a2, [r0, r1]);
            assert_eq!(a0, 0xcccfb4ea344b30de, "blk1 after mul a0");
            assert_eq!(a1, 0xd8adaf23b0337fa7, "blk1 after mul a1");
            assert_eq!(a2, 0x2, "blk1 after mul a2");
        }

        // ── Block 2 (partial): bytes 32..34 ──
        {
            let remainder = &msg[32..];
            let mut block = [0u8; 17];
            block[..remainder.len()].copy_from_slice(remainder);
            block[remainder.len()] = 0x01;
            let n0 = u64::from_le_bytes(block[..8].try_into().unwrap());
            let n1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
            // remainder = "up" = [117, 112]. block = [117, 112, 0x01, 0, 0, 0, 0, 0] (9
            // meaningful bytes) n0 = LE of first 8 bytes = [117, 112, 1, 0, 0,
            // 0, 0, 0] = 117 + 112*256 + 1*65536 = 117 + 28672 + 65536 = 94325
            // = 0x17075
            assert_eq!(n0, 0x0000000000017075, "blk2 n0");

            // For partial block, the 0x01 byte is at len=2, so it's already in n0.
            // No +1 to a2 needed.
            let t0 = a0 as u128 + n0 as u128;
            let t1 = a1 as u128 + n1 as u128 + (t0 >> 64);
            a0 = t0 as u64;
            a1 = t1 as u64;
            a2 = a2.wrapping_add((t1 >> 64) as u64);

            assert_eq!(a0, 0xcccfb4ea344ca153, "blk2 after add a0");
            assert_eq!(a1, 0xd8adaf23b0337fa7, "blk2 after add a1");
            assert_eq!(a2, 0x2, "blk2 after add a2");

            super::poly1305_mul_mod(&mut a0, &mut a1, &mut a2, [r0, r1]);
            assert_eq!(a0, 0xc8844335369d03a7, "blk2 after mul a0");
            assert_eq!(a1, 0x8d31b7caff946c77, "blk2 after mul a1");
            assert_eq!(a2, 0x2, "blk2 after mul a2");
        }

        // ── Final: add s modulo 2^128 (no reduce needed). ──
        let t0 = a0 as u128 + s0 as u128;
        let carry0 = t0 >> 64;
        a0 = t0 as u64;
        let t1 = a1 as u128 + s1 as u128 + carry0;
        a1 = t1 as u64;

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&a0.to_le_bytes());
        tag[8..].copy_from_slice(&a1.to_le_bytes());
        assert_eq!(
            tag,
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9
            ],
            "final tag mismatch — got {tag:02x?}"
        );
    }

    // ── ChaCha20-Poly1305 AEAD test vectors (RFC 8439 §2.8.2) ──

    #[test]
    fn chacha20_poly1305_rfc8439_aead_vector() {
        // RFC 8439 §2.8.2: known ciphertext + tag for a fixed key/nonce/AAD/plaintext.
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct_and_tag: [u8; 130] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
            0xd0, 0x60, 0x06, 0x91,
        ];
        let (ciphertext, tag) = super::chacha20_poly1305_encrypt(&key, &nonce, &aad, plaintext);
        let mut combined = ciphertext.clone();
        combined.extend_from_slice(&tag);
        assert_eq!(
            combined,
            expected_ct_and_tag.to_vec(),
            "RFC 8439 §2.8.2 ciphertext+tag"
        );

        // Decrypt must recover the plaintext and reject a tampered tag.
        let decrypted = super::chacha20_poly1305_decrypt(&key, &nonce, &aad, &ciphertext, &tag)
            .expect("RFC 8439 AEAD decrypt");
        assert_eq!(decrypted, plaintext);
        let mut bad_tag = tag;
        bad_tag[15] ^= 0x80;
        assert!(
            super::chacha20_poly1305_decrypt(&key, &nonce, &aad, &ciphertext, &bad_tag).is_err()
        );
    }

    #[test]
    fn chacha20_poly1305_encrypt_decrypt_round_trip() {
        let key = sha256(b"test-aead-key-32-bytes-long!!");
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&sha256(b"test-nonce-12")[..12]);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, ChaCha20-Poly1305!";

        let (ciphertext, tag) = super::chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());

        let decrypted = super::chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag)
            .expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chacha20_poly1305_tag_verification_fails_with_wrong_key() {
        let key1 = sha256(b"key-1-32-bytes-long!!!!!!!!!");
        let key2 = sha256(b"key-2-32-bytes-long!!!!!!!!!");
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&sha256(b"nonce-12-bytes!")[..12]);
        let plaintext = b"sensitive data";

        let (ciphertext, tag) = super::chacha20_poly1305_encrypt(&key1, &nonce, b"", plaintext);

        let result = super::chacha20_poly1305_decrypt(&key2, &nonce, b"", &ciphertext, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn chacha20_poly1305_tag_verification_fails_with_wrong_ciphertext() {
        let key = sha256(b"aead-key-32-bytes-long!!!!!!");
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&sha256(b"12-byte-nonce")[..12]);
        let plaintext = b"tamper-resistant data";

        let (mut ciphertext, tag) = super::chacha20_poly1305_encrypt(&key, &nonce, b"", plaintext);
        // Flip a bit in the ciphertext.
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }

        let result = super::chacha20_poly1305_decrypt(&key, &nonce, b"", &ciphertext, &tag);
        assert!(result.is_err());
    }

    // ── AES-128 test vectors (NIST FIPS 197 Appendix B) ──

    #[test]
    fn aes128_encrypt_block_known_vector() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let expected: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];
        let mut result = plaintext;
        super::aes128_encrypt_block(&key, &mut result);
        assert_eq!(result, expected);
    }

    #[test]
    fn aes128_decrypt_matches_encrypt_known_vector() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let expected_ct: [u8; 16] = [
            0x89, 0xed, 0x5e, 0x6a, 0x05, 0xca, 0x76, 0x33, 0x81, 0x35, 0x08, 0x5f, 0xe2, 0x1c,
            0x40, 0xbd,
        ];
        let mut block = plaintext;
        super::aes128_encrypt_block(&key, &mut block);
        assert_eq!(block, expected_ct);

        super::aes128_decrypt_block(&key, &mut block);
        assert_eq!(block, plaintext);
    }

    #[test]
    fn aes256_encrypt_decrypt_known_vector() {
        // FIPS 197 Appendix C.3 AES-256: key 0x000102..0f1011..1f,
        // plaintext 0x00112233445566778899aabbccddeeff
        // ciphertext 0x8ea2b7ca516745bfeafc49904b496089.
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let mut block: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        super::aes256_encrypt_block(&key, &mut block);
        assert_eq!(block, expected);

        super::aes256_decrypt_block(&key, &mut block);
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
    }

    #[test]
    fn inv_sbox_is_inverse_of_sbox() {
        #[allow(clippy::needless_range_loop)]
        for i in 0..256usize {
            let out = AES_SBOX[i];
            assert_eq!(AES_INV_SBOX[out as usize], i as u8);
        }
    }

    // ── AES-128-GCM test vectors ──

    #[test]
    fn aes128_gcm_encrypt_decrypt_round_trip() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce: [u8; 12] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        ];
        let aad = b"authenticated";
        let plaintext = b"Hello, AES-128-GCM!";

        let (ciphertext, tag) = super::aes128_gcm_encrypt(&key, &nonce, aad, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());

        let decrypted = super::aes128_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag)
            .expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes128_gcm_tag_verification_fails_with_wrong_key() {
        let key1: [u8; 16] = [0x00; 16];
        let key2: [u8; 16] = [0x01; 16];
        let nonce: [u8; 12] = [0x00; 12];
        let plaintext = b"sensitive";

        let (ciphertext, tag) = super::aes128_gcm_encrypt(&key1, &nonce, b"", plaintext);
        let result = super::aes128_gcm_decrypt(&key2, &nonce, b"", &ciphertext, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn aes128_gcm_empty_plaintext() {
        let key: [u8; 16] = [0x42; 16];
        let nonce: [u8; 12] = [0x00; 12];
        let (ciphertext, tag) = super::aes128_gcm_encrypt(&key, &nonce, b"", b"");
        assert_eq!(ciphertext.len(), 0);
        assert_eq!(tag.len(), 16);
        // Should be able to decrypt empty ciphertext.
        let decrypted = super::aes128_gcm_decrypt(&key, &nonce, b"", &ciphertext, &tag)
            .expect("empty decryption");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn aes128_gcm_known_vector() {
        // NIST GCM spec test case 3 (AES-128).
        let key: [u8; 16] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let nonce: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let aad = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let plaintext = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
        ];
        let expected_ct = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
            0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
            0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85,
        ];
        let expected_tag = [
            0xda, 0x80, 0xce, 0x83, 0x0c, 0xfd, 0xa0, 0x2d, 0xa2, 0xa2, 0x18, 0xa1, 0x74, 0x4f,
            0x4c, 0x76,
        ];
        let (ciphertext, tag) = super::aes128_gcm_encrypt(&key, &nonce, &aad, &plaintext);
        assert_eq!(ciphertext, expected_ct);
        assert_eq!(tag, expected_tag);

        // Decryption must round-trip and reject a corrupted tag.
        let decrypted =
            super::aes128_gcm_decrypt(&key, &nonce, &aad, &ciphertext, &tag).expect("GCM decrypt");
        assert_eq!(decrypted, plaintext);
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        assert!(super::aes128_gcm_decrypt(&key, &nonce, &aad, &ciphertext, &bad_tag).is_err());
    }

    // ── CRC-32 test vectors ──

    #[test]
    fn crc32_known_vector() {
        // CRC-32 (IEEE 802.3, polynomial 0xEDB88320) of "123456789" = 0xCBF43926.
        assert_eq!(super::crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32c_known_vector() {
        // CRC-32C (Castagnoli, polynomial 0x82F63B78) of "123456789" = 0xE3069283.
        assert_eq!(super::crc32c(b"123456789"), 0xE306_9283);
    }

    // ── AES-XTS test vectors (IEEE 1619) ──

    #[test]
    fn aes_xts_encrypt_decrypt_round_trip() {
        let key = [0x37u8; 64];
        let mut data = alloc::vec![0u8; 512];
        #[allow(clippy::needless_range_loop)]
        for i in 0..512 {
            data[i] = (i & 0xFF) as u8;
        }
        let mut enc = data.clone();
        super::aes_xts_encrypt(&key, 12345, &mut enc);
        let mut dec = enc.clone();
        super::aes_xts_decrypt(&key, 12345, &mut dec);
        assert_eq!(dec, data, "XTS round-trip should recover plaintext");
    }

    #[test]
    fn aes_xts_encrypt_decrypt_different_sectors_differ() {
        let key = [0x11u8; 64];
        let data = alloc::vec![0xABu8; 64];
        let mut enc1 = data.clone();
        let mut enc2 = data.clone();
        super::aes_xts_encrypt(&key, 0, &mut enc1);
        super::aes_xts_encrypt(&key, 1, &mut enc2);
        assert_ne!(enc1, enc2, "adjacent sectors must encrypt differently");
    }

    #[test]
    fn aes_xts_known_vector() {
        // NIST XTS-AES-256 test vector (IEEE 1619 / CAVS):
        // key = 2718281828459045235360287471352662497757247093699959574966967627
        //        3141592653589793238462643383279502884197169399375105820974944592
        // tweak = ff000000000000000000000000000000  (sector_id = 255, LE)
        // data = 000102030405060708090a0b0c0d0e0f
        // ct   = 1c3b3a102f770386e4836c99e370cf9b
        let key: [u8; 64] = [
            0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45, 0x23, 0x53, 0x60, 0x28, 0x74, 0x71,
            0x35, 0x26, 0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69, 0x99, 0x59, 0x57, 0x49,
            0x66, 0x96, 0x76, 0x27, 0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84,
            0x62, 0x64, 0x33, 0x83, 0x27, 0x95, 0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37,
            0x51, 0x05, 0x82, 0x09, 0x74, 0x94, 0x45, 0x92,
        ];
        let mut data: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let expected: [u8; 16] = [
            0x1c, 0x3b, 0x3a, 0x10, 0x2f, 0x77, 0x03, 0x86, 0xe4, 0x83, 0x6c, 0x99, 0xe3, 0x70,
            0xcf, 0x9b,
        ];
        // sector_id 255 (0xff) encodes little-endian as ff 00 00 00 00 00 00 00,
        // matching the NIST tweak ff000000000000000000000000000000.
        super::aes_xts_encrypt(&key, 255, &mut data);
        assert_eq!(data, expected);

        super::aes_xts_decrypt(&key, 255, &mut data);
        assert_eq!(
            data,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f
            ]
        );
    }

    #[test]
    fn rsa_pss_verify_known_vector() {
        // Generated with Python `cryptography` (RSA-2048, PSS-MGF1-SHA256,
        // salt length 32) over "RSA-PSS test message for protofire crypto".
        let n: [u8; 256] = [
            0xa1, 0x33, 0x63, 0xd6, 0x9c, 0x6e, 0xeb, 0x78, 0x1f, 0xc0, 0x58, 0xbc, 0x90, 0x0e,
            0x3c, 0x15, 0x3f, 0xeb, 0xe6, 0x7f, 0xc2, 0x2e, 0xe1, 0x85, 0xd6, 0x2d, 0x15, 0x7e,
            0xbb, 0x3f, 0x82, 0x50, 0xc6, 0x93, 0x82, 0x0f, 0x57, 0x67, 0x82, 0xf4, 0x7c, 0x8a,
            0x03, 0x39, 0x1f, 0x77, 0x64, 0x05, 0x20, 0x7a, 0x11, 0x62, 0xf8, 0x93, 0x47, 0x37,
            0x25, 0x42, 0xc4, 0x2e, 0x8c, 0xe4, 0x98, 0xbd, 0x17, 0x8b, 0xfa, 0x66, 0x18, 0x03,
            0x3b, 0xc4, 0xe9, 0x00, 0xb1, 0xbc, 0x5c, 0x5b, 0x4c, 0x0d, 0x9a, 0x64, 0xe1, 0x60,
            0xeb, 0x83, 0xd0, 0x85, 0x43, 0xcd, 0x34, 0xee, 0x18, 0xa5, 0xc4, 0x68, 0x61, 0x1e,
            0x34, 0x09, 0xa0, 0xac, 0x75, 0xd6, 0x84, 0x83, 0x62, 0xfe, 0xb9, 0x17, 0x75, 0x2e,
            0xdf, 0xa7, 0x9e, 0xd9, 0x76, 0xe8, 0x16, 0x80, 0xd4, 0xc8, 0xfd, 0x83, 0x8c, 0x99,
            0xbe, 0x7c, 0x27, 0x0e, 0x66, 0x53, 0x67, 0x1c, 0x32, 0x09, 0x59, 0x1d, 0x17, 0xed,
            0xbc, 0x7c, 0x9d, 0xbb, 0x15, 0x60, 0x25, 0xc1, 0x6c, 0xeb, 0x48, 0x8b, 0xb1, 0xfc,
            0xc9, 0x42, 0xf6, 0x93, 0xf7, 0xa8, 0x59, 0x29, 0xf8, 0x3f, 0x8b, 0x24, 0x57, 0x15,
            0x85, 0x65, 0x75, 0x86, 0x11, 0xe7, 0x9c, 0xca, 0xd7, 0x74, 0x89, 0xef, 0x48, 0xe1,
            0xc2, 0x4b, 0x67, 0xb8, 0xd9, 0xd7, 0x53, 0x17, 0x1a, 0x50, 0xd3, 0xc4, 0x1b, 0xed,
            0x65, 0x4e, 0x55, 0xbf, 0xa0, 0x08, 0x07, 0x4c, 0xcc, 0xfb, 0x84, 0xc0, 0x76, 0xd6,
            0xce, 0xdd, 0xd8, 0xaa, 0x2b, 0xfd, 0xc4, 0x76, 0x79, 0x08, 0x40, 0x68, 0xa5, 0xcd,
            0xab, 0x27, 0xf0, 0x02, 0xeb, 0x1e, 0xd7, 0xd5, 0xd3, 0xc4, 0x0f, 0xe1, 0x1f, 0xe1,
            0xec, 0x41, 0xe3, 0x31, 0x7d, 0xb7, 0x80, 0x2a, 0x3a, 0x17, 0x63, 0x41, 0x73, 0x98,
            0xfb, 0x25, 0xcb, 0x33,
        ];
        let e: [u8; 3] = [0x01, 0x00, 0x01];
        let message: [u8; 32] = [
            0xf2, 0x85, 0x35, 0xea, 0x7d, 0xe4, 0xbf, 0x16, 0xc4, 0x3d, 0x69, 0x85, 0x0e, 0x2b,
            0x5c, 0xee, 0x53, 0x33, 0xe2, 0x18, 0x05, 0xe8, 0x55, 0xa1, 0xc1, 0x4c, 0x44, 0x8a,
            0x4e, 0x25, 0xc0, 0x9d,
        ];
        let signature: [u8; 256] = [
            0x66, 0x69, 0x4e, 0xbd, 0xf4, 0x46, 0x6c, 0xb4, 0x1d, 0x5a, 0xd1, 0x78, 0xdd, 0x09,
            0xcd, 0xef, 0xfa, 0x38, 0xe0, 0xce, 0xec, 0xa5, 0xe1, 0x0a, 0x05, 0x3c, 0xa5, 0xdf,
            0xb4, 0x50, 0x62, 0x4f, 0x79, 0x79, 0x7f, 0x89, 0xed, 0x2a, 0x40, 0xbe, 0xd5, 0x59,
            0x4f, 0x11, 0x33, 0xb3, 0xa0, 0xf8, 0x45, 0x5e, 0x10, 0x1b, 0x7a, 0xeb, 0x6b, 0x82,
            0x2b, 0x0e, 0x79, 0x7d, 0xba, 0x85, 0xff, 0x97, 0x9b, 0x1d, 0xa1, 0x77, 0xcd, 0x30,
            0x71, 0x45, 0x3c, 0xea, 0x00, 0xfc, 0xbb, 0x78, 0x1c, 0x86, 0x69, 0xd6, 0x33, 0x46,
            0xfb, 0x1c, 0x36, 0x4b, 0x85, 0xf5, 0xd4, 0x1c, 0x90, 0xc9, 0x02, 0xa0, 0x6b, 0x07,
            0x09, 0x4c, 0xa2, 0x9a, 0x81, 0xb1, 0xe5, 0x01, 0x4c, 0xf6, 0x6a, 0xf3, 0xf4, 0x33,
            0x89, 0x15, 0xaf, 0x34, 0x18, 0xd0, 0xfa, 0x37, 0xa9, 0x7a, 0x08, 0xa5, 0xd6, 0x04,
            0x42, 0x20, 0xb9, 0x10, 0x4f, 0x13, 0x70, 0x53, 0xfd, 0x3c, 0x8a, 0x54, 0x6a, 0x38,
            0xa7, 0x96, 0x11, 0x94, 0x17, 0x02, 0x17, 0xe4, 0x50, 0xda, 0x8e, 0xfe, 0x3f, 0xd6,
            0x27, 0xa8, 0x99, 0xad, 0xd5, 0xe6, 0xb2, 0xd7, 0x84, 0xfa, 0xa5, 0x78, 0xda, 0x40,
            0x7c, 0x6b, 0xd2, 0x03, 0x0f, 0x39, 0x45, 0xe8, 0x53, 0xb2, 0x6c, 0x79, 0xb0, 0x1f,
            0xa3, 0x62, 0x82, 0xfd, 0xba, 0xe9, 0x4e, 0x51, 0x69, 0x49, 0x9b, 0x5b, 0xca, 0x81,
            0x96, 0x5e, 0x64, 0x52, 0xfc, 0xcf, 0xdd, 0xc1, 0x00, 0x58, 0x72, 0xa7, 0x11, 0xb4,
            0x28, 0x9b, 0xb7, 0x09, 0x01, 0xf9, 0x73, 0xb7, 0x2e, 0x64, 0x02, 0x9d, 0x2f, 0xa0,
            0x0b, 0x02, 0xc1, 0x71, 0xb9, 0x7c, 0x5e, 0xcc, 0xe1, 0x6a, 0xf7, 0x71, 0x0e, 0x6c,
            0xe0, 0x5a, 0xda, 0x4e, 0xcc, 0x78, 0x9f, 0xe2, 0xda, 0x4f, 0x94, 0xf2, 0x15, 0xb3,
            0xac, 0x92, 0x4d, 0x63,
        ];
        assert!(super::rsa_pss_verify(&n, &e, &message, &signature));

        // Flipping a bit in the message hash must invalidate the signature.
        let mut bad_hash = message;
        bad_hash[0] ^= 0x01;
        assert!(!super::rsa_pss_verify(&n, &e, &bad_hash, &signature));

        // Flipping a bit in the signature must also invalidate it.
        let mut bad_sig = signature;
        bad_sig[0] ^= 0x01;
        assert!(!super::rsa_pss_verify(&n, &e, &message, &bad_sig));
    }

    #[test]
    fn rsa_pkcs1v15_verify_known_vector() {
        // X.509 `sha256WithRSAEncryption` (RSASSA-PKCS1-v1_5) signature over the
        // demo leaf certificate's TBS, produced by openssl with the demo root CA
        // key (both fixtures live in the TLS certificate tests).  This regression
        // vector pins two past bugs: the Montgomery-multiplication final
        // reduction (a nonzero guard limb could be truncated, yielding the wrong
        // `s^e mod n`), and the digest comparison slicing past `k` into the
        // zeroed tail of the `em` scratch array.
        let message = hex_to_bytes_vec(
            concat!(
            "3082022ba003020102021458de22c0610386d5ea9be01a3bb4940590202630300d06092a864886f70d01010b05003021",
            "311f301d06035504030c1650726f746f666972652044656d6f20526f6f74204341301e170d3236303832373131353135",
            "325a170d3336303832343131353135325a3021311f301d06035504030c1664656d6f2e70726f746f666972652e657861",
            "6d706c6530820122300d06092a864886f70d01010105000382010f003082010a0282010100e81886fa632cb0666b310e",
            "bc402ecc2f84d93f268278d1ea35b6c658bde9fa7823a55541df3ce2fead33daa1e9a75b06d812ffe6eb7b98847936ef",
            "6412f2c67860e2a94422e1ce5faa6fb821e82613952715c15210a18d00a19cfccf321d4b59236685e5126a4a9f8680c9",
            "83c8d61edf4dcbb367ff3b7a93198e949c1df377d859248179c1f025fabd0189b4baf1f437b797b02dd8128d6d7d28ae",
            "9ec5f425e5b585627792809a2b28f8c812d7c985fb10ebd32fe5e1ed369032d4478a8ade9d08c30d089bdbcb8c0fe66e",
            "5fe4994b30994c2f7a469e14bdda004226c98a9d19720063049a33257d0bcbce8c723eaf0fe17e37621f820909f8241b",
            "be394bf0fb0203010001a3733071300c0603551d130101ff0402300030210603551d11041a3018821664656d6f2e7072",
            "6f746f666972652e6578616d706c65301d0603551d0e04160414ca9acd6530d985b767d2e501e50f9fc526950dbd301f",
            "0603551d23041830168014ab25b50f8ba632d6d40f47cc532f2e6adc01f240",
            ),
        );
        assert_eq!(message.len(), 559);
        let n: [u8; 256] = [
            0xab, 0xbd, 0x9c, 0x4c, 0x21, 0x23, 0xef, 0xd4, 0x0f, 0xa0, 0xd8, 0xfa, 0x24, 0xb1,
            0x08, 0x8a, 0x60, 0x56, 0x55, 0xa1, 0xf9, 0x77, 0x8f, 0x36, 0xc7, 0x12, 0x9d, 0x13,
            0x38, 0x6c, 0x10, 0x8e, 0x7a, 0xfd, 0x34, 0x34, 0x73, 0xed, 0x21, 0x0b, 0x0b, 0x50,
            0x65, 0x85, 0xd9, 0x05, 0x3a, 0x42, 0x62, 0x59, 0x53, 0x92, 0xe9, 0x0a, 0x87, 0xe2,
            0xea, 0xc5, 0x7b, 0x5c, 0x1b, 0x1f, 0xae, 0xf3, 0x31, 0x5e, 0x7b, 0x47, 0xaf, 0x32,
            0x74, 0xee, 0xf2, 0x18, 0xe6, 0x16, 0x13, 0xd0, 0x66, 0xb8, 0x43, 0x44, 0x51, 0x0d,
            0x94, 0x9c, 0xfc, 0x99, 0xc0, 0x0d, 0xa2, 0xa3, 0x58, 0xe3, 0xfa, 0x86, 0xc8, 0xf4,
            0xd1, 0x54, 0x72, 0x64, 0xbf, 0xa6, 0x81, 0x69, 0x9c, 0x0d, 0x92, 0x4c, 0xbd, 0xf8,
            0x6c, 0x39, 0x41, 0x20, 0xaa, 0x52, 0x95, 0xa3, 0x03, 0x0a, 0xc4, 0xf5, 0xe5, 0x24,
            0x90, 0x90, 0x7a, 0x7b, 0xa2, 0x72, 0xf0, 0x3c, 0xee, 0x23, 0xba, 0x56, 0xd4, 0x3a,
            0x0f, 0xef, 0xcd, 0xc2, 0x20, 0x5b, 0xc8, 0x8e, 0x86, 0x55, 0x7f, 0xb1, 0x08, 0xb6,
            0xc8, 0x49, 0x43, 0xbd, 0x40, 0x8c, 0x35, 0x81, 0x45, 0x22, 0x84, 0xcf, 0x64, 0x42,
            0x09, 0x56, 0x7d, 0xeb, 0x91, 0xe2, 0x95, 0xa3, 0x05, 0x59, 0x39, 0xde, 0xdb, 0xba,
            0xfd, 0x2a, 0x2e, 0xaa, 0x70, 0x1d, 0x2a, 0x03, 0x0c, 0xef, 0x1a, 0xf8, 0xc9, 0xf8,
            0x72, 0xcf, 0x76, 0x54, 0xd6, 0xc3, 0xe6, 0xee, 0x19, 0x8e, 0x72, 0xac, 0xf9, 0x3f,
            0x3e, 0x95, 0x57, 0x9e, 0xc9, 0x8f, 0x88, 0x73, 0xcf, 0x60, 0x68, 0xc3, 0x9d, 0xf1,
            0x40, 0x62, 0x49, 0xfe, 0xe9, 0xf8, 0x68, 0x6a, 0xd1, 0x0f, 0x3a, 0x23, 0xa5, 0x64,
            0x1b, 0xe6, 0x3d, 0xfe, 0x24, 0xaf, 0xc6, 0x54, 0x49, 0x49, 0xed, 0x62, 0x6a, 0x46,
            0x07, 0x99, 0x2e, 0xa1,
        ];
        let e: [u8; 3] = [0x01, 0x00, 0x01];
        let signature: [u8; 256] = [
            0x25, 0xfd, 0x7d, 0x1b, 0xcc, 0xb4, 0x38, 0x4a, 0x54, 0x7c, 0x1f, 0xf2, 0xc5, 0xa6,
            0xd6, 0x0a, 0xb0, 0xba, 0xfb, 0x65, 0x38, 0x0b, 0xa3, 0x16, 0x20, 0x32, 0xb1, 0x91,
            0xfa, 0x0f, 0x1a, 0x53, 0xa2, 0x26, 0xb9, 0x5b, 0x30, 0x2f, 0x2e, 0xa2, 0x2f, 0x1c,
            0x88, 0x27, 0x93, 0x5b, 0x16, 0xb7, 0xa5, 0x02, 0x97, 0xe5, 0xa7, 0xb0, 0xed, 0x31,
            0x91, 0x5a, 0x8e, 0x8f, 0xcd, 0xb1, 0xa9, 0x48, 0xb8, 0x28, 0x2f, 0xdc, 0x95, 0x53,
            0x39, 0xc4, 0x0a, 0x28, 0x90, 0xbd, 0xa6, 0x45, 0xd7, 0xb9, 0x0f, 0x52, 0x9f, 0x55,
            0x89, 0xb0, 0x7d, 0xef, 0x1a, 0x3f, 0xc7, 0x7d, 0x27, 0x75, 0x1e, 0xd7, 0xf6, 0x88,
            0x29, 0xb6, 0x2c, 0xdf, 0x2e, 0x33, 0xd2, 0x41, 0xa7, 0x62, 0x79, 0x07, 0x45, 0x83,
            0xa3, 0xdc, 0x51, 0x6b, 0x39, 0x0a, 0x8d, 0x20, 0x85, 0xb6, 0x7c, 0x5b, 0x68, 0x00,
            0xe5, 0x45, 0xf2, 0xa8, 0xde, 0x5e, 0xe0, 0x33, 0xdb, 0x89, 0x77, 0x9a, 0xb3, 0x3b,
            0x7b, 0x7c, 0x5d, 0x67, 0x51, 0xa8, 0x64, 0x05, 0xbf, 0xce, 0x2c, 0x61, 0x8c, 0xb4,
            0xd1, 0x99, 0x82, 0x93, 0x8d, 0x12, 0x24, 0xaa, 0x28, 0x40, 0x90, 0xe0, 0x81, 0x44,
            0x91, 0xec, 0x37, 0xb7, 0x96, 0x11, 0x00, 0x74, 0x1e, 0xb2, 0x5a, 0xae, 0x2a, 0x47,
            0x9e, 0xbe, 0x04, 0x7f, 0x2c, 0x4b, 0xdd, 0xaf, 0xcf, 0x74, 0xb2, 0x31, 0x74, 0x64,
            0xcc, 0xf3, 0x55, 0x85, 0x4a, 0x82, 0x29, 0xfe, 0x56, 0x58, 0x6f, 0xc9, 0x6a, 0x91,
            0xb3, 0x5f, 0x35, 0xfd, 0x6b, 0xa2, 0x65, 0x44, 0xe3, 0x76, 0x3f, 0x53, 0x40, 0x0d,
            0x68, 0x2e, 0xe2, 0x9a, 0x38, 0xef, 0x2a, 0x5b, 0x93, 0x99, 0x3f, 0x97, 0xeb, 0x50,
            0xe9, 0x5b, 0xcb, 0x71, 0x1c, 0x71, 0x61, 0xb2, 0x74, 0xdd, 0x7c, 0x19, 0x4b, 0x80,
            0x06, 0xc6, 0xdb, 0x12,
        ];
        assert!(super::rsa_pkcs1v15_verify(&n, &e, &message, &signature));

        // Flipping a bit in the signature must invalidate it.
        let mut bad_sig = signature;
        bad_sig[0] ^= 0x01;
        assert!(!super::rsa_pkcs1v15_verify(&n, &e, &message, &bad_sig));

        // Flipping a bit in the message must also invalidate it.
        let mut bad_msg = message;
        bad_msg[0] ^= 0x01;
        assert!(!super::rsa_pkcs1v15_verify(&n, &e, &bad_msg, &signature));
    }

    // ── X25519 test vectors (RFC 7748 §5.2) ──

    // ── Field arithmetic sanity tests ──

    #[test]
    fn fe25519_add_sub_identity() {
        use super::fe25519_add;
        use super::fe25519_from_bytes;
        use super::fe25519_sub;
        use super::fe25519_to_bytes;

        let a_bytes = [0x42u8; 32];
        let b_bytes = [0x13u8; 32];
        let a = fe25519_from_bytes(&a_bytes);
        let b = fe25519_from_bytes(&b_bytes);
        let sum = fe25519_add(&a, &b);
        let diff = fe25519_sub(&sum, &b);
        let a_back = fe25519_to_bytes(&diff);
        // a_back should equal a mod p.
        // Since a is small (< p), it should be exact.
        assert_eq!(a_back, a_bytes, "add-sub identity failed");
    }

    #[test]
    fn fe25519_mul_identity() {
        use super::fe25519_from_bytes;
        use super::fe25519_mul;
        use super::fe25519_to_bytes;

        let one: super::Fe25519 = [1, 0, 0, 0, 0];
        let a_bytes = [0x2a; 32];
        let a = fe25519_from_bytes(&a_bytes);
        let result = fe25519_mul(&a, &one);
        let result_bytes = fe25519_to_bytes(&result);
        assert_eq!(result_bytes, a_bytes, "mul-by-one identity failed");
    }

    #[test]
    fn fe25519_encode_decode_roundtrip() {
        use super::fe25519_from_bytes;
        use super::fe25519_to_bytes;

        // Random-looking bytes.
        let bytes: [u8; 32] = [
            0x9a, 0xd6, 0x3b, 0x88, 0xf7, 0x2c, 0x15, 0x4e, 0x3d, 0x92, 0xa1, 0xbf, 0x60, 0x7d,
            0x41, 0x33, 0x8c, 0xde, 0xab, 0x54, 0x19, 0x72, 0xef, 0xc6, 0x0a, 0xbb, 0x33, 0x99,
            0x4d, 0x28, 0x1e, 0x7f,
        ];
        let fe = fe25519_from_bytes(&bytes);
        let recovered = fe25519_to_bytes(&fe);
        assert_eq!(recovered, bytes, "encode-decode roundtrip failed");
    }

    #[test]
    fn x25519_rfc7748_first_iteration() {
        // After 1 iteration: scalar = 1, u = 9 → output.
        let scalar: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let u_coord: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];
        let result = super::x25519(&scalar, &u_coord);
        assert_eq!(result, expected);
    }

    #[test]
    fn x25519_rfc7748_second_iteration() {
        // After 2 iterations: uses the output of iteration 1 as new u.
        let scalar: [u8; 32] = [
            0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d,
            0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e,
            0x79, 0x18, 0xba, 0x0d,
        ];
        let u_coord: [u8; 32] = [
            0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38,
            0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49,
            0xc7, 0x15, 0xa4, 0x93,
        ];
        let expected: [u8; 32] = [
            0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8,
            0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64,
            0x7a, 0xac, 0x79, 0x57,
        ];
        let result = super::x25519(&scalar, &u_coord);
        assert_eq!(result, expected);
    }

    #[test]
    fn x25519_basepoint_multiply() {
        // Scalar multiply with the base point (u=9).
        // Arbitrary scalar, just verify it produces consistent output.
        let scalar: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let u_coord: [u8; 32] = [
            0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let result1 = super::x25519(&scalar, &u_coord);
        let result2 = super::x25519(&scalar, &u_coord);
        assert_eq!(result1, result2, "X25519 should be deterministic");

        // Result should be non-zero for non-zero scalar.
        let sum: u64 = result1.iter().map(|&b| b as u64).sum();
        assert!(sum > 0, "X25519 result should be non-zero");
    }

    #[test]
    fn x25519_keygen_produces_valid_keys() {
        let (private, public) = super::x25519_keygen();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
        // Public key should be non-zero for a random private key.
        let sum: u64 = public.iter().map(|&b| b as u64).sum();
        assert!(sum > 0);
    }

    fn hex_to_bytes(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let h = hex.as_bytes()[i * 2];
            let l = hex.as_bytes()[i * 2 + 1];
            *byte = hex_nibble(h) << 4 | hex_nibble(l);
        }
        bytes
    }

    fn hex_nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("invalid hex char"),
        }
    }

    fn hex_to_bytes_vec(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex length must be even");
        let bytes = hex.as_bytes();
        let mut out = Vec::with_capacity(hex.len() / 2);
        for i in 0..hex.len() / 2 {
            out.push(hex_nibble(bytes[i * 2]) << 4 | hex_nibble(bytes[i * 2 + 1]));
        }
        out
    }
}

#[cfg(test)]
mod ecdsa_tests {
    use super::*;

    #[test]
    fn fe_add_sub_identity() {
        let a = Fe256::from_bytes_be(&[0xAB; 32]);
        let b = Fe256::from_bytes_be(&[0x12; 32]);
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        assert_eq!(diff.0, a.0);
    }

    #[test]
    fn fe_mul_identity() {
        let mut v = [0u8; 32];
        v[31] = 42;
        let a = Fe256::from_bytes_be(&v);
        let inv = a.invert();
        let prod = a.mul(&inv);
        assert!(prod.0[0] == 1 && prod.0[1] == 0 && prod.0[2] == 0 && prod.0[3] == 0);
    }

    #[test]
    fn fe_mul_commutative() {
        let mut va = [0u8; 32];
        va[31] = 123;
        let mut vb = [0u8; 32];
        vb[31] = 200;
        let a = Fe256::from_bytes_be(&va);
        let b = Fe256::from_bytes_be(&vb);
        assert_eq!(a.mul(&b).0, b.mul(&a).0);
    }

    #[test]
    fn point_double_and_add() {
        let g = p256_generator();
        let g2 = g.double();
        let g2b = g.add(&g);
        assert_eq!(g2.x.0, g2b.x.0);
        assert_eq!(g2.y.0, g2b.y.0);
    }

    #[test]
    fn point_on_curve() {
        let g = p256_generator();
        let mut v = [0u8; 32];
        v[31] = 100;
        let k = Fe256::from_bytes_be(&v);
        let p = g.mul_scalar(&k.0);
        let x3 = p.x.square().mul(&p.x);
        let ax = p.x.mul(&Fe256::from_limbs(P256_A));
        let b = Fe256::from_limbs(P256_B);
        let rhs = x3.add(&ax).add(&b);
        let lhs = p.y.square();
        assert_eq!(lhs.0, rhs.0);
    }

    #[test]
    fn point_mul_order_is_infinity() {
        let g = p256_generator();
        let p = g.mul_scalar(&P256_ORDER);
        assert!(p.is_infinity());
    }

    #[test]
    fn parse_der_signature_works() {
        let der = [
            0x30, 0x0A, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x00, 0xFF, 0xFE,
        ];
        let (r, s) = parse_ecdsa_der_signature(&der).expect("parse DER signature");
        assert!(!r.is_empty());
        assert!(!s.is_empty());
    }

    #[test]
    fn ecdsa_verify_zero_signature_fails() {
        let pubkey = [
            0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63,
            0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39,
            0x45, 0xD8, 0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E,
            0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E,
            0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
        ];
        let hash = [0u8; 32];
        let r = [0u8; 32];
        let s = [0u8; 32];
        assert!(!ecdsa_p256_verify(&pubkey, &hash, &r, &s));
    }

    #[test]
    fn ecdsa_p256_verify_known_vector() {
        // Generated with Python `cryptography` (fixed private key d =
        // 0x9B4F49110F2B5C9C9B2A4A0B7D62D3A9C0A5E7F2B8D4E6A1C3F5B7D9A2C4E6F8),
        // signing "ECDSA P-256 test message for protofire crypto".
        let public_key: [u8; 65] = [
            0x04, 0x12, 0xbe, 0x33, 0x72, 0x61, 0x56, 0x8a, 0x6f, 0x7a, 0x2e, 0xca, 0xea, 0x09,
            0x68, 0x50, 0x1c, 0x96, 0x73, 0xae, 0x0d, 0xa1, 0x72, 0xcb, 0xbc, 0x29, 0x45, 0x28,
            0xd3, 0xeb, 0x6a, 0xbf, 0x20, 0x85, 0x13, 0x32, 0xf5, 0x9c, 0x0f, 0x01, 0x76, 0xe6,
            0x5e, 0x1e, 0xcf, 0x83, 0xaa, 0xf9, 0x9c, 0x8d, 0x09, 0x2b, 0x85, 0xc4, 0x44, 0x13,
            0x0c, 0xd4, 0x74, 0x50, 0xad, 0xe6, 0x7a, 0x00, 0x23,
        ];
        let message_hash: [u8; 32] = [
            0xec, 0x3c, 0x1d, 0xc8, 0x6c, 0x6c, 0x13, 0xb6, 0xe9, 0xe7, 0x9d, 0x43, 0xc2, 0xf2,
            0x0f, 0xfc, 0xa9, 0x0b, 0xc7, 0xab, 0x15, 0x53, 0x98, 0xe6, 0x9c, 0xc3, 0x3b, 0x5a,
            0x97, 0x7d, 0xb6, 0x34,
        ];
        let r: [u8; 32] = [
            0x43, 0x20, 0xc0, 0xa4, 0x9a, 0x9a, 0xa4, 0x11, 0xf3, 0x37, 0x03, 0x3f, 0x45, 0xd0,
            0x93, 0xaa, 0x57, 0x6c, 0x57, 0xcc, 0x78, 0x3d, 0x6e, 0x6a, 0x5f, 0x3d, 0xf6, 0x6c,
            0x7a, 0x6b, 0xd8, 0x9e,
        ];
        let s: [u8; 32] = [
            0x45, 0x94, 0x53, 0x7f, 0x16, 0x69, 0xc9, 0xab, 0x59, 0xab, 0x40, 0xd2, 0xaa, 0xd9,
            0x8a, 0x7f, 0xa3, 0xcd, 0x75, 0x90, 0x72, 0xfe, 0xfe, 0x6b, 0x21, 0x25, 0xeb, 0xd7,
            0x3b, 0x89, 0x5b, 0x26,
        ];
        assert!(ecdsa_p256_verify(&public_key, &message_hash, &r, &s));

        // A flipped bit in the message hash must invalidate the signature.
        let mut bad_hash = message_hash;
        bad_hash[0] ^= 0x01;
        assert!(!ecdsa_p256_verify(&public_key, &bad_hash, &r, &s));
    }

    #[test]
    fn ecdsa_verify_rejects_bad_public_key() {
        let hash = [1u8; 32];
        let r = [2u8; 32];
        let s = [3u8; 32];
        assert!(!ecdsa_p256_verify(&[0x04, 0x00], &hash, &r, &s));
        let mut bad_pk = [0u8; 65];
        bad_pk[0] = 0x03;
        assert!(!ecdsa_p256_verify(&bad_pk, &hash, &r, &s));
    }
}

#[cfg(test)]
mod field_debug_tests {
    use super::*;

    #[test]
    fn fe25519_mul_reference() {
        // a = 123456789012345678901234567890, b = 987654321012345
        let a: Fe25519 = [1091739049724626, 54825827883118, 0, 0, 0];
        let b: Fe25519 = [987654321012345, 0, 0, 0, 0];
        let got = fe25519_mul(&a, &b);
        let want: Fe25519 = [79892000831810, 1259430764839786, 24046971441578, 0, 0];
        assert_eq!(got, want, "mul mismatch: got {got:?}");
    }

    #[test]
    fn fe25519_square_reference() {
        let a: Fe25519 = [1091739049724626, 54825827883118, 0, 0, 0];
        let got = fe25519_square(&a);
        let want: Fe25519 = [
            1715883656418372,
            1665434582479255,
            2159184764567970,
            1334875056299,
            0,
        ];
        assert_eq!(got, want, "sq mismatch: got {got:?}");
    }

    #[test]
    fn fe25519_sub_reference() {
        let a: Fe25519 = [1091739049724626, 54825827883118, 0, 0, 0];
        let b: Fe25519 = [987654321012345, 0, 0, 0, 0];
        let got = fe25519_sub(&a, &b);
        let want: Fe25519 = [104084728712281, 54825827883118, 0, 0, 0];
        assert_eq!(got, want, "sub mismatch: got {got:?}");
    }

    #[test]
    fn fe25519_add_reference() {
        let a: Fe25519 = [1091739049724626, 54825827883118, 0, 0, 0];
        let b: Fe25519 = [987654321012345, 0, 0, 0, 0];
        let got = fe25519_add(&a, &b);
        let want: Fe25519 = [2079393370736971, 54825827883118, 0, 0, 0];
        assert_eq!(got, want, "add mismatch: got {got:?}");
    }

    #[test]
    fn fe25519_inv_reference() {
        let a: Fe25519 = [1091739049724626, 54825827883118, 0, 0, 0];
        let got = fe25519_inv(&a);
        let want: Fe25519 = [
            981237069453266,
            194231194608803,
            290761331866964,
            216053795122436,
            2154218031290001,
        ];
        assert_eq!(got, want, "inv mismatch: got {got:?}");
    }
}

#[cfg(test)]
mod x25519_correctness_tests {
    // RFC 7748 §6.1 fixed scalar DH vector (validated against Python reference).
    #[test]
    fn x25519_rfc7748_canonical_vector() {
        let scalar: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let u: [u8; 32] = [
            0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let expected: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let result = super::x25519(&scalar, &u);
        assert_eq!(
            result, expected,
            "canonical X25519 vector mismatch: got {result:02x?}"
        );
    }
}
