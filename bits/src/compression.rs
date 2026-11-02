//! src/kernel/compression.rs
//!
//! Shared decompression primitives for filesystem drivers.
//!
//! Provides a minimal ZSTD decompressor.  Currently handles:
//! - Raw blocks (uncompressed data stored directly)
//! - RLE blocks (single byte repeated)
//!
//! Compressed blocks with sequences and Huffman/FSE will be added
//! incrementally.  The frame header parser handles all standard formats
//! so that frames with unsupported block types produce a clean error.

use crate::Error;

// ── Constants ──────────────────────────────────────────────────────────────

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

const MIN_WINDOW_LOG: u32 = 10;
const MAX_WINDOW_LOG: u32 = 31;

const BLOCK_RAW: u32 = 0;
const BLOCK_RLE: u32 = 1;
const BLOCK_COMPRESSED: u32 = 2;

// ── Public API ─────────────────────────────────────────────────────────────

/// Decompress a single ZSTD frame from `src` into `dst`.
///
/// Returns the number of bytes written to `dst`.  Returns `Error::Unsupported`
/// for compressed blocks (which require full FSE/Huffman decoding not yet
/// implemented), and `Error::InvalidArgument` for malformed input.
pub fn zstd_decompress(src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
    if src.len() < 5 {
        return Err(Error::InvalidArgument);
    }
    if src[0..4] != ZSTD_MAGIC {
        return Err(Error::InvalidArgument);
    }

    let fhd = src[4];
    let single_segment = (fhd & 0x20) != 0;
    let content_checksum = (fhd & 0x04) != 0;
    let fcs_flag = fhd >> 6;
    let did_flag = fhd & 0x03;

    let mut pos = 5usize;
    if pos > src.len() {
        return Err(Error::InvalidArgument);
    }

    // Window descriptor (absent for single-segment frames).
    if !single_segment {
        if pos >= src.len() {
            return Err(Error::InvalidArgument);
        }
        let wd = src[pos];
        pos += 1;
        let exponent = (wd >> 3) as u32;
        let wlog = MIN_WINDOW_LOG + exponent;
        if wlog > MAX_WINDOW_LOG {
            return Err(Error::InvalidArgument);
        }
    }

    // Frame content size.
    match fcs_flag {
        0 if single_segment => pos += 1,
        1 => pos += 2,
        2 => pos += 4,
        3 => pos += 8,
        _ => {}
    }

    // Dictionary ID.
    pos += did_flag as usize;

    // Content checksum is the last 4 bytes — strip if present.
    let effective = if content_checksum && src.len() >= pos + 4 {
        src.len() - 4
    } else {
        src.len()
    };

    let mut output_pos: usize = 0;
    let mut last_block = false;

    while !last_block && pos + 3 <= effective {
        let bh0 = src[pos];
        let bh1 = src[pos + 1];
        let bh2 = src[pos + 2];
        pos += 3;

        last_block = (bh0 & 0x01) != 0;
        let block_type = ((bh0 >> 1) & 0x03) as u32;
        let block_size = ((bh0 as u32) >> 3) | ((bh1 as u32) << 5) | ((bh2 as u32) << 13);

        let block_end = pos + block_size as usize;
        if block_end > effective {
            return Err(Error::InvalidArgument);
        }

        match block_type {
            BLOCK_RAW => {
                let n = block_size as usize;
                if output_pos + n > dst.len() {
                    return Err(Error::InvalidArgument);
                }
                dst[output_pos..output_pos + n].copy_from_slice(&src[pos..pos + n]);
                output_pos += n;
            }
            BLOCK_RLE => {
                if pos >= effective {
                    return Err(Error::InvalidArgument);
                }
                let byte = src[pos];
                let n = block_size as usize;
                if output_pos + n > dst.len() {
                    return Err(Error::InvalidArgument);
                }
                dst[output_pos..output_pos + n].fill(byte);
                output_pos += n;
            }
            BLOCK_COMPRESSED => {
                return Err(Error::Unsupported);
            }
            _ => return Err(Error::InvalidArgument),
        }

        pos = block_end;
    }

    Ok(output_pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Pre-computed ZSTD frame for "Hello ZSTD Raw Block!" (21 bytes),
    /// compressed with `zstd -3`.  The data is small enough that zstd
    /// emits a Raw_Block.
    const ZSTD_RAW_FRAME: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, // magic
        0x04, // FHD: checksum, no single-segment
        0x58, // window descriptor
        0xa9, 0x00, 0x00, // block header: last, raw, size=21
        // Raw data: "Hello ZSTD Raw Block!"
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x5a, 0x53, 0x54, 0x44, 0x20, 0x52, 0x61, 0x77, 0x20,
        0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x21, // Content checksum (XXH32)
        0xe5, 0x98, 0xb9, 0x24,
    ];

    #[test]
    fn zstd_decompress_raw_block() {
        let mut dst = vec![0u8; 64];
        let n = zstd_decompress(ZSTD_RAW_FRAME, &mut dst).expect("decompress raw block");
        assert_eq!(n, 21);
        assert_eq!(&dst[..n], b"Hello ZSTD Raw Block!");
    }

    #[test]
    fn zstd_decompress_too_small_dst() {
        let mut dst = [0u8; 5];
        assert!(zstd_decompress(ZSTD_RAW_FRAME, &mut dst).is_err());
    }

    #[test]
    fn zstd_decompress_bad_magic() {
        let bad = [0x00, 0x00, 0x00, 0x00, 0x04, 0x58, 0xa9, 0x00];
        let mut dst = [0u8; 64];
        assert!(zstd_decompress(&bad, &mut dst).is_err());
    }

    #[test]
    fn zstd_decompress_truncated() {
        let mut dst = [0u8; 64];
        // Only the magic + partial header (insufficient for any block).
        assert!(zstd_decompress(&ZSTD_RAW_FRAME[..5], &mut dst).is_err());
    }
}
