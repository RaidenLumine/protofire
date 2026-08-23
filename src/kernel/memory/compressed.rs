//! src/kernel/memory/compressed.rs
//! Page-level memory compression (zswap-style) for reclaimed anonymous pages.
//!
//! When the page reclaimer cannot write a page to a swap device it keeps the
//! content in memory.  Compressing that content lets the kernel retain many
//! more pages than the raw 4 KiB content store — a page of zeros or a page
//! of repeated bytes costs a couple of bytes, and typical data pages compress
//! several-fold.  Decompression happens on demand when a compressed page is
//! faulted back in.
//!
//! Encoding (one tag byte + payload):
//! - `0x00` — zero page (no payload)
//! - `0x01` — single repeated byte (one payload byte)
//! - `0x02` — LZSS token stream (see [`lzss_compress`])

use alloc::vec::Vec;

use super::paging::PAGE_SIZE;

/// Budget for the compressed-page cache.  When the total encoded size of
/// cached pages exceeds this, oldest entries are evicted to the raw content
/// store (which preserves correctness at the cost of the 4 KiB/page savings).
pub const MAX_COMPRESSED_CACHE_BYTES: usize = 16 * 1024 * 1024;

/// Encoded form of a compressed 4 KiB page.
#[derive(Debug, Clone)]
pub struct CompressedPage {
    data: Vec<u8>,
}

impl CompressedPage {
    /// Number of bytes the compressed representation occupies.
    pub fn encoded_len(&self) -> usize {
        self.data.len()
    }

    /// Return the encoded byte stream (tag byte + payload).  Used by the
    /// filesystem compression layer to persist the encoding on disk.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Decompress into `output`, which must be exactly `PAGE_SIZE` bytes.
    ///
    /// Returns `false` on malformed input or a size mismatch.
    pub fn decompress(&self, output: &mut [u8]) -> bool {
        decompress_page(&self.data, output)
    }
}

/// Compress a 4 KiB chunk for persistent file storage.
///
/// Unlike [`compress_page`], this never fails: an incompressible chunk is
/// stored with the raw tag `0x03` followed by the original bytes, so every
/// chunk has a lossless encoding the filesystem can round-trip.
pub fn compress_chunk(input: &[u8]) -> CompressedPage {
    debug_assert!(
        input.len() == PAGE_SIZE,
        "compressed chunk must be one page"
    );
    match compress_page(input) {
        Some(page) => page,
        None => {
            let mut data = Vec::with_capacity(1 + input.len());
            data.push(0x03);
            data.extend_from_slice(input);
            CompressedPage { data }
        }
    }
}

/// Compress a full page of `PAGE_SIZE` bytes.
///
/// Returns `None` when the page is incompressible (the encoded form would not
/// be smaller than the raw page) or `input.len()` is not exactly one page.
pub fn compress_page(input: &[u8]) -> Option<CompressedPage> {
    if input.len() != PAGE_SIZE {
        return None;
    }

    // Zero page — the single most common reclaim candidate.
    if input.iter().all(|&b| b == 0) {
        return Some(CompressedPage {
            data: alloc::vec![0x00],
        });
    }

    // Single repeated byte (RLE).
    let first = input[0];
    if input[1..].iter().all(|&b| b == first) {
        return Some(CompressedPage {
            data: alloc::vec![0x01, first],
        });
    }

    // General LZSS.  Only worth storing when strictly smaller than the raw
    // page; otherwise the caller falls back to the raw content store.
    let stream = lzss_compress(input);
    if 1 + stream.len() < PAGE_SIZE {
        let mut data = Vec::with_capacity(1 + stream.len());
        data.push(0x02);
        data.extend_from_slice(&stream);
        Some(CompressedPage { data })
    } else {
        None
    }
}

/// Decompress an encoded page into `output`, which must be exactly
/// `PAGE_SIZE` bytes.  Returns `false` on malformed input or size mismatch.
pub fn decompress_page(encoded: &[u8], output: &mut [u8]) -> bool {
    if output.len() != PAGE_SIZE || encoded.is_empty() {
        return false;
    }
    match encoded[0] {
        0x00 => {
            output.fill(0);
            encoded.len() == 1
        }
        0x01 => {
            if encoded.len() != 2 {
                return false;
            }
            output.fill(encoded[1]);
            true
        }
        0x02 => lzss_decompress(&encoded[1..], output),
        0x03 => {
            // Raw incompressible page: [0x03] + PAGE_SIZE original bytes.
            if encoded.len() != 1 + PAGE_SIZE {
                return false;
            }
            output.copy_from_slice(&encoded[1..]);
            true
        }
        _ => false,
    }
}

// ── LZSS ──────────────────────────────────────────────────────────────

const HASH_BITS: usize = 12;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MIN_MATCH: usize = 3;
/// Maximum match length: 3..=10.  The length-minus-3 code is stored in the
/// 3 bits below the `0x80` marker (bit 7) of the match token, so the marker
/// cannot be used as data — keeping the code at 3 bits leaves bit 7
/// unambiguous as the literal-vs-match discriminator.
const MAX_MATCH: usize = 10;
/// Maximum back-reference distance: 1..=4096 (distance-minus-1 in 12 bits).
const MAX_DIST: usize = 4096;

/// Hash three bytes into a `HASH_SIZE`-entry table index.
fn hash3(bytes: &[u8]) -> usize {
    let a = bytes[0] as usize;
    let b = bytes[1] as usize;
    let c = bytes[2] as usize;
    ((a << 8) ^ (b << 4) ^ c) & (HASH_SIZE - 1)
}

/// Append pending literals as one or more literal-run tokens.
///
/// Literal token: one byte `count - 1` (0..128) followed by `count` bytes.
fn flush_literals(out: &mut Vec<u8>, literals: &mut Vec<u8>) {
    let mut i = 0;
    while i < literals.len() {
        let chunk = core::cmp::min(literals.len() - i, 128);
        out.push((chunk - 1) as u8);
        out.extend_from_slice(&literals[i..i + chunk]);
        i += chunk;
    }
    literals.clear();
}

/// Greedy LZSS compressor over a single 4 KiB page.
///
/// Emits a self-delimiting token stream:
/// - Literal run: `0x00..=0x7F` (count = byte + 1) followed by `count` bytes.
/// - Match: two bytes `0x80 | (len-3 << 4) | (dist-1 >> 8)` and
///   `(dist-1) & 0xFF`, copying `len` (3..=10) bytes from `dist` (1..=4096)
///   bytes back.  Bit 7 of the first byte is the literal-vs-match marker; the
///   length code occupies only the 3 bits below it.
///
/// A single-entry hash table of the last seen position for each 3-byte
/// sequence (LZ4-style) provides the match candidates.
fn lzss_compress(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(256);
    let mut literals: Vec<u8> = Vec::with_capacity(128);
    let mut hash_tab: Vec<u16> = alloc::vec![u16::MAX; HASH_SIZE];
    let len = input.len();
    let mut pos = 0usize;

    while pos < len {
        let mut best_len = 0usize;
        let mut best_dist = 0usize;

        // Look for the longest match at `pos` against a previously seen
        // 3-byte sequence within the 4 KiB back window.
        if pos >= MIN_MATCH && len - pos >= MIN_MATCH {
            let h = hash3(&input[pos..pos + MIN_MATCH]);
            let cand = hash_tab[h] as usize;
            if cand != usize::from(u16::MAX) && pos - cand <= MAX_DIST {
                let max_len = core::cmp::min(len - pos, MAX_MATCH);
                let mut mlen = 0usize;
                while mlen < max_len && input[cand + mlen] == input[pos + mlen] {
                    mlen += 1;
                }
                if mlen >= MIN_MATCH {
                    best_len = mlen;
                    best_dist = pos - cand;
                }
            }
        }

        if best_len >= MIN_MATCH {
            flush_literals(&mut out, &mut literals);
            let len_code = (best_len - MIN_MATCH) as u16; // 0..15
            let dist_code = (best_dist - 1) as u16; // 0..4095
            out.push(0x80 | ((len_code << 4) as u8) | ((dist_code >> 8) as u8));
            out.push((dist_code & 0xFF) as u8);
            // Record the hash for every position consumed by the match.
            for p in pos..pos + best_len {
                if p + MIN_MATCH <= len {
                    hash_tab[hash3(&input[p..])] = p as u16;
                }
            }
            pos += best_len;
        } else {
            literals.push(input[pos]);
            if pos + MIN_MATCH <= len {
                hash_tab[hash3(&input[pos..])] = pos as u16;
            }
            pos += 1;
            if literals.len() == 128 {
                flush_literals(&mut out, &mut literals);
            }
        }
    }
    flush_literals(&mut out, &mut literals);
    out
}

/// Decode an LZSS token stream into `out`, which must be exactly
/// `PAGE_SIZE` bytes.  Returns `false` on malformed input.
fn lzss_decompress(src: &[u8], out: &mut [u8]) -> bool {
    let mut ip = 0usize;
    let mut op = 0usize;

    while ip < src.len() {
        let b = src[ip];
        if b & 0x80 == 0 {
            // Literal run.
            let count = (b as usize) + 1;
            ip += 1;
            if ip + count > src.len() || op + count > out.len() {
                return false;
            }
            out[op..op + count].copy_from_slice(&src[ip..ip + count]);
            op += count;
            ip += count;
        } else {
            // Match.
            if ip + 1 >= src.len() {
                return false;
            }
            let len = (((b >> 4) & 0x07) as usize) + MIN_MATCH;
            let dist = ((((b & 0x0F) as usize) << 8) | (src[ip + 1] as usize)) + 1;
            ip += 2;
            if dist > op || op + len > out.len() {
                return false;
            }
            // Forward overlapping copy (byte-by-byte) so matches may
            // reference bytes produced earlier in the same match.
            for k in 0..len {
                out[op + k] = out[op + k - dist];
            }
            op += len;
        }
    }
    op == out.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn round_trip(input: Vec<u8>) -> Option<CompressedPage> {
        let page = compress_page(&input)?;
        let mut out = vec![0u8; PAGE_SIZE];
        assert!(page.decompress(&mut out), "decompress round trip");
        assert_eq!(out, input, "decompressed content matches original");
        Some(page)
    }

    #[test]
    fn zero_page_compresses_to_one_byte() {
        let page = compress_page(&[0u8; PAGE_SIZE]).expect("zero page compresses");
        assert_eq!(page.encoded_len(), 1);
        round_trip(vec![0u8; PAGE_SIZE]);
    }

    #[test]
    fn repeated_byte_page_compresses_to_two_bytes() {
        let page = compress_page(&[0xA5u8; PAGE_SIZE]).expect("rle page compresses");
        assert_eq!(page.encoded_len(), 2);
        round_trip(vec![0xA5u8; PAGE_SIZE]);
    }

    #[test]
    fn repeated_word_page_round_trips() {
        // A repeated 8-byte word is highly compressible and exercises the
        // match path (long runs of the same 3-byte sequence).
        let mut input = vec![0u8; PAGE_SIZE];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = match i % 8 {
                0 => 0x11,
                1 => 0x22,
                2 => 0x33,
                3 => 0x44,
                4 => 0x55,
                5 => 0x66,
                6 => 0x77,
                _ => 0x88,
            };
        }
        let page = round_trip(input).expect("compressible page compresses");
        assert!(page.encoded_len() < PAGE_SIZE / 4);
    }

    #[test]
    fn text_like_page_round_trips() {
        // Program-text-like content: repeated short lines compress well.
        let mut input = vec![0u8; PAGE_SIZE];
        let line = b"  let value = compute(input, &mut table); // kernel path\n";
        for chunk in input.chunks_mut(line.len()) {
            let n = line.len().min(chunk.len());
            chunk[..n].copy_from_slice(&line[..n]);
        }
        let page = round_trip(input).expect("text-like page compresses");
        assert!(page.encoded_len() < PAGE_SIZE / 3);
    }

    #[test]
    fn incompressible_page_returns_none() {
        // Deterministic pseudo-random data (LFSR) — no long runs or repeats,
        // so LZSS cannot beat the raw page size.
        let mut input = vec![0u8; PAGE_SIZE];
        let mut state: u32 = 0x1234_5678;
        for byte in input.iter_mut() {
            // xorshift32
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = (state & 0xFF) as u8;
        }
        assert!(compress_page(&input).is_none());
    }

    #[test]
    fn rejects_wrong_sized_input_and_output() {
        assert!(compress_page(&[0u8; 512]).is_none());
        assert!(!decompress_page(&[0x00], &mut [0u8; 512]));
        assert!(!decompress_page(&[], &mut [0u8; PAGE_SIZE]));
        assert!(!decompress_page(&[0x7F], &mut [0u8; PAGE_SIZE])); // bad tag
    }

    #[test]
    fn decompress_rejects_truncated_lzss_stream() {
        // A valid repeated-word page, then truncate the token stream.
        let mut input = vec![0u8; PAGE_SIZE];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = (i % 4) as u8;
        }
        let page = compress_page(&input).expect("compress");
        let truncated = &page.data[..page.data.len() - 1];
        let mut out = vec![0u8; PAGE_SIZE];
        assert!(!decompress_page(truncated, &mut out));
    }

    #[test]
    fn compress_decompress_rejects_corrupted_rle() {
        // Tag 0x01 with no payload byte.
        assert!(!decompress_page(&[0x01], &mut [0u8; PAGE_SIZE]));
        // Zero-tag with trailing garbage.
        assert!(!decompress_page(&[0x00, 0x01], &mut [0u8; PAGE_SIZE]));
    }
}
