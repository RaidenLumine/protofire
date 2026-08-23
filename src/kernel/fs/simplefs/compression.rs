//! src/kernel/fs/simplefs/compression.rs
//! Chunked per-file transparent compression for V4 volumes.
//!
//! A compressed file's data extent holds a self-describing stream:
//!
//! ```text
//! [magic u32][chunk_count u32][offsets u32(chunk_count+1)][chunk0][chunk1]...
//! ```
//!
//! Each chunk covers one [`COMPRESSED_CHUNK_SIZE`] (4096, one memory page) of
//! logical file content and is encoded with the memory compressed-page codec
//! (zero / RLE / LZSS, with a raw fallback).  `offsets[i]` is the byte offset
//! of chunk `i` relative to the start of the chunk data, so a random read
//! decompresses only the chunks it intersects.  The inode's `size` field is
//! the logical (uncompressed) length; `block_count` is the physical extent
//! size in 512-byte blocks.

use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::memory::compressed::{compress_chunk, decompress_page};
use crate::{Error, Result};

use super::constants::*;

/// Encode a logical file into its compressed extent payload.
pub(crate) fn encode_file(contents: &[u8]) -> Vec<u8> {
    let chunk_count = contents.len().div_ceil(COMPRESSED_CHUNK_SIZE);
    let mut chunks = Vec::with_capacity(chunk_count);
    for index in 0..chunk_count {
        let start = index * COMPRESSED_CHUNK_SIZE;
        let end = ((index + 1) * COMPRESSED_CHUNK_SIZE).min(contents.len());
        let mut page = [0_u8; COMPRESSED_CHUNK_SIZE];
        page[..end - start].copy_from_slice(&contents[start..end]);
        chunks.push(compress_chunk(&page));
    }

    let data_start = 8 + (chunk_count + 1) * 4;
    let mut offsets = vec![0_u32; chunk_count + 1];
    let mut cursor = 0_u32;
    for (index, chunk) in chunks.iter().enumerate() {
        offsets[index] = cursor;
        cursor = cursor
            .checked_add(chunk.encoded_len() as u32)
            .expect("compressed stream length fits u32");
    }
    offsets[chunk_count] = cursor;

    let mut out = Vec::with_capacity(data_start + cursor as usize);
    out.extend_from_slice(&COMPRESSED_MAGIC.to_le_bytes());
    out.extend_from_slice(&(chunk_count as u32).to_le_bytes());
    for offset in &offsets {
        out.extend_from_slice(&offset.to_le_bytes());
    }
    for chunk in &chunks {
        out.extend_from_slice(chunk.as_bytes());
    }
    out
}

/// Decode the logical bytes `[offset, offset+count)` from a compressed
/// extent payload, decompressing only the intersecting chunks.
pub(crate) fn decode_file(encoded: &[u8], offset: usize, count: usize) -> Result<Vec<u8>> {
    if encoded.len() < 8 {
        return Err(Error::InvalidArgument);
    }
    let magic = u32::from_le_bytes(
        encoded[0..4]
            .try_into()
            .map_err(|_| Error::InvalidArgument)?,
    );
    if magic != COMPRESSED_MAGIC {
        return Err(Error::InvalidArgument);
    }
    let chunk_count = u32::from_le_bytes(
        encoded[4..8]
            .try_into()
            .map_err(|_| Error::InvalidArgument)?,
    ) as usize;
    let data_start = 8_usize
        .checked_add(
            (chunk_count + 1)
                .checked_mul(4)
                .ok_or(Error::InvalidArgument)?,
        )
        .ok_or(Error::InvalidArgument)?;
    if encoded.len() < data_start {
        return Err(Error::InvalidArgument);
    }

    let mut offsets = vec![0_u32; chunk_count + 1];
    for (index, offset) in offsets.iter_mut().enumerate() {
        let base = 8 + index * 4;
        *offset = u32::from_le_bytes(
            encoded
                .get(base..base + 4)
                .ok_or(Error::InvalidArgument)?
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
    }

    if count == 0 {
        return Ok(Vec::new());
    }
    let first_chunk = offset / COMPRESSED_CHUNK_SIZE;
    let last_chunk = (offset + count).div_ceil(COMPRESSED_CHUNK_SIZE);
    if last_chunk > chunk_count {
        return Err(Error::InvalidArgument);
    }

    let mut out = vec![0_u8; count];
    for chunk_index in first_chunk..last_chunk {
        let chunk_start = data_start + offsets[chunk_index] as usize;
        let chunk_end = data_start + offsets[chunk_index + 1] as usize;
        let chunk_bytes = encoded
            .get(chunk_start..chunk_end)
            .ok_or(Error::InvalidArgument)?;
        let mut page = [0_u8; COMPRESSED_CHUNK_SIZE];
        if !decompress_page(chunk_bytes, &mut page) {
            return Err(Error::DeviceError);
        }

        let chunk_logical_start = chunk_index * COMPRESSED_CHUNK_SIZE;
        let chunk_logical_end = chunk_logical_start + COMPRESSED_CHUNK_SIZE;
        let req_start = offset;
        let req_end = offset + count;
        let is = req_start.max(chunk_logical_start);
        let ie = req_end.min(chunk_logical_end);
        if is >= ie {
            continue;
        }
        let src = is - chunk_logical_start;
        let dst = is - req_start;
        let len = ie - is;
        out[dst..dst + len].copy_from_slice(&page[src..src + len]);
    }
    Ok(out)
}
