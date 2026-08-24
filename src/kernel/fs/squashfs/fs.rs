//! src/kernel/fs/squashfs/fs.rs
//!
//! Low-level SquashFS operations: superblock, inode table, directory reads,
//! file data reads with decompression.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::Error;

use super::types::{
    parse_dir_entries, DirInode, FileInode, ParsedDirEntry, Superblock, COMPRESSION_LZ4,
    COMPRESSION_ZSTD, METADATA_UNCOMPRESSED, SUPERBLOCK_SIZE,
};

// ── Superblock ────────────────────────────────────────────────────────────

pub fn read_superblock(device: &Arc<dyn BlockDevice>) -> Result<Superblock, Error> {
    let mut buf = [0u8; SUPERBLOCK_SIZE];
    read_device_bytes(device, 0, &mut buf)?;
    Superblock::parse(&buf).ok_or(Error::InvalidArgument)
}

// ── Inode table loading ───────────────────────────────────────────────────

/// Load and decompress the entire inode table.
///
/// The metadata blocks (inode table, directory table, xattr tables, …) form
/// a chain of independently compressed blocks beginning immediately after
/// the superblock.  The decompressed inode table bytes are parsed on demand
/// via [`parse_inode`](super::types::parse_inode).
pub fn load_inode_table(device: &Arc<dyn BlockDevice>, sb: &Superblock) -> Result<Vec<u8>, Error> {
    read_metadata(device, sb, SUPERBLOCK_SIZE as u64)
}

// ── Directory reading ─────────────────────────────────────────────────────

/// Read directory entries from a directory inode.
pub fn read_dir_entries(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    dir_inode: &DirInode,
) -> Result<Vec<ParsedDirEntry>, Error> {
    if dir_inode.file_size == 0 {
        return Ok(Vec::new());
    }

    // Directory metadata blocks follow the inode table in the metadata
    // region, indexed by `start_block`.  Each block carries its own 2-byte
    // size header, so decode it through `read_metadata` rather than reading
    // the raw block (which would include the header as garbage bytes).
    let meta_block_size = 8192u64;
    let data_offset = SUPERBLOCK_SIZE as u64 + dir_inode.start_block as u64 * meta_block_size;
    let data = read_metadata(device, sb, data_offset)?;
    Ok(parse_dir_entries(&data))
}

// ── File data reading ─────────────────────────────────────────────────────

/// Read file data at an arbitrary offset + length.
///
/// `start_block` is the index of the first data block.  Each data block
/// carries a 2-byte header: the compressed size with the MSB (0x8000) set
/// when the block is compressed (the project's inverted convention, matching
/// the metadata headers).
pub fn read_file(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    file: &FileInode,
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize, Error> {
    if offset >= file.file_size {
        return Ok(0);
    }

    let available = file.file_size.saturating_sub(offset);
    let n = (buffer.len() as u64).min(available) as usize;

    let block_size = sb.block_size.max(1) as u64;
    let base = SUPERBLOCK_SIZE as u64 + file.start_block * block_size;

    // Read the data-block size header.
    let mut hdr_buf = [0u8; 2];
    read_device_bytes(device, base, &mut hdr_buf)?;
    let hdr = u16::from_le_bytes(hdr_buf);
    let compressed = hdr & 0x8000 != 0;
    let block_len = (hdr & !0x8000) as usize;

    let content: Vec<u8> = if compressed {
        let comp = read_device_vec(device, base + 2, block_len)?;
        let mut out = vec![0u8; sb.block_size as usize];
        let written = match sb.compression {
            COMPRESSION_ZSTD => crate::kernel::compression::zstd_decompress(&comp, &mut out)?,
            COMPRESSION_LZ4 => lz4_decompress(&comp, &mut out)?,
            _ => return Err(Error::Unsupported),
        };
        out.truncate(written);
        out
    } else {
        read_device_vec(device, base + 2, block_len)?
    };

    let start = (offset as usize).min(content.len());
    let end = (start + n).min(content.len());
    let actual = end.saturating_sub(start);
    buffer[..actual].copy_from_slice(&content[start..end]);
    Ok(actual)
}

// ── Metadata block reading ────────────────────────────────────────────────

/// Size of one uncompressed SquashFS metadata block.
const METADATA_BLOCK_SIZE: usize = 8192;

/// Read and decompress a metadata block chain at an absolute byte position.
///
/// Reads independently compressed metadata blocks (8 KiB uncompressed each)
/// starting at `pos` until `uncompressed_size` bytes of decompressed data
/// have been collected, or the chain terminates.  Used for the xattr ID
/// table and xattr data blocks.
pub fn read_metadata_block(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    pos: u64,
    uncompressed_size: usize,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(uncompressed_size);
    let mut disk_off = pos;

    while output.len() < uncompressed_size {
        // Read the 2-byte header: compressed size + flag.
        let mut hdr_buf = [0u8; 2];
        if read_device_bytes(device, disk_off, &mut hdr_buf).is_err() {
            break;
        }
        let hdr = u16::from_le_bytes(hdr_buf);
        // This driver follows the project convention (see the recovered
        // original): a set MSB marks a *compressed* block; a clear MSB marks
        // an uncompressed one.  (This is the inverse of the real SquashFS
        // spec, where 0x8000 means "uncompressed".)
        let compressed = hdr & METADATA_UNCOMPRESSED != 0;
        let size = (hdr & !METADATA_UNCOMPRESSED) as usize;
        disk_off += 2;

        if size == 0 {
            break;
        }

        let comp_data = read_device_vec(device, disk_off, size)?;
        disk_off += size as u64;

        let mut out_block = vec![0u8; METADATA_BLOCK_SIZE];

        if compressed {
            match sb.compression {
                COMPRESSION_LZ4 => {
                    let n = lz4_decompress(&comp_data, &mut out_block)?;
                    out_block.truncate(n);
                }
                _ => {
                    // Unsupported compression for metadata — return what we
                    // have so far.
                    return Err(Error::Unsupported);
                }
            }
        } else {
            let n = out_block.len().min(comp_data.len());
            out_block[..n].copy_from_slice(&comp_data[..n]);
            out_block.truncate(comp_data.len());
        }

        output.extend_from_slice(&out_block);

        // If the block was smaller than METADATA_BLOCK_SIZE, it's the last one.
        if size < METADATA_BLOCK_SIZE {
            break;
        }
    }

    Ok(output)
}

/// Read and decompress a SquashFS metadata block chain.
///
/// SquashFS stores metadata (inode table, directory table) as a sequence
/// of independently compressed blocks, each 8 KiB uncompressed.
pub fn read_metadata(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    start_byte: u64,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut disk_off = start_byte;

    loop {
        // Read the 2-byte header: compressed size + flag.
        let mut hdr_buf = [0u8; 2];
        if read_device_bytes(device, disk_off, &mut hdr_buf).is_err() {
            break;
        }
        let hdr = u16::from_le_bytes(hdr_buf);
        // Same inverted-MSb convention as `read_metadata_block`: a set MSB
        // marks a compressed block.
        let compressed = hdr & METADATA_UNCOMPRESSED != 0;
        let size = (hdr & !METADATA_UNCOMPRESSED) as usize;
        disk_off += 2;

        if size == 0 {
            break;
        }

        let comp_data = read_device_vec(device, disk_off, size)?;
        disk_off += size as u64;

        let mut out_block = vec![0u8; METADATA_BLOCK_SIZE];

        if compressed {
            match sb.compression {
                COMPRESSION_LZ4 => {
                    let n = lz4_decompress(&comp_data, &mut out_block)?;
                    out_block.truncate(n);
                }
                _ => {
                    // If we don't support the compression algorithm, we can't
                    // read metadata. Return what we have so far.
                    return Err(Error::Unsupported);
                }
            }
        } else {
            let n = out_block.len().min(comp_data.len());
            out_block[..n].copy_from_slice(&comp_data[..n]);
            out_block.truncate(comp_data.len());
        }

        output.extend_from_slice(&out_block);

        // If the block was smaller than METADATA_BLOCK_SIZE, it's the last one.
        if size < METADATA_BLOCK_SIZE {
            break;
        }
    }

    Ok(output)
}

// ── LZ4 block decompressor ────────────────────────────────────────────────

/// Decompress an LZ4-compressed block into `out`. Returns the number of
/// uncompressed bytes written.
///
/// This implements a minimal LZ4 block decoder supporting the standard
/// LZ4 block format (literals + match copy-back).
pub fn lz4_decompress(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut src = 0;
    let mut dst = 0;
    let out_len = out.len();

    loop {
        if src >= input.len() {
            break;
        }

        // Read token: upper 4 bits = literal length, lower 4 bits = match length.
        let token = input[src];
        src += 1;

        let mut literal_len = (token >> 4) as usize;
        let mut match_len = (token & 0x0F) as usize;

        // Read additional literal length bytes.
        if literal_len == 15 {
            while src < input.len() {
                let b = input[src] as usize;
                src += 1;
                literal_len += b;
                if b != 255 {
                    break;
                }
            }
        }

        // Copy literals.
        if literal_len > 0 {
            if src + literal_len > input.len() || dst + literal_len > out_len {
                // Truncated or overflow — stop gracefully.
                return Ok(dst);
            }
            out[dst..dst + literal_len].copy_from_slice(&input[src..src + literal_len]);
            src += literal_len;
            dst += literal_len;
        }

        // Check for end of block (last sequence has no match).
        if src >= input.len() {
            break;
        }

        // Read match offset (little-endian u16).
        if src + 2 > input.len() {
            break;
        }
        let offset = u16::from_le_bytes([input[src], input[src + 1]]) as usize;
        src += 2;

        if offset == 0 {
            return Err(Error::InvalidArgument); // invalid offset
        }

        // Read additional match length bytes.
        if match_len == 15 {
            while src < input.len() {
                let b = input[src] as usize;
                src += 1;
                match_len += b;
                if b != 255 {
                    break;
                }
            }
        }
        match_len += 4; // base match length is 4 (minimum match size)

        // Copy match: overlapping region, copy byte-by-byte.
        for i in 0..match_len {
            if dst + i >= out_len {
                break;
            }
            if offset > dst + i {
                return Err(Error::InvalidArgument);
            }
            let b = out[dst + i - offset];
            out[dst + i] = b;
        }
        dst += match_len.min(out_len.saturating_sub(dst));
    }

    Ok(dst)
}

// ── Block-device byte I/O ─────────────────────────────────────────────────

fn read_device_bytes(
    device: &Arc<dyn BlockDevice>,
    byte_offset: u64,
    buf: &mut [u8],
) -> Result<(), Error> {
    if buf.is_empty() {
        return Ok(());
    }

    let dev_bs = device.block_size() as u64;
    let start_lba = byte_offset / dev_bs;
    let start_off = (byte_offset % dev_bs) as usize;
    let end_byte = byte_offset + buf.len() as u64;
    let end_lba = end_byte.div_ceil(dev_bs);

    let total_blocks = (end_lba - start_lba) as usize;
    let mut scratch = vec![0u8; total_blocks * dev_bs as usize];

    for i in 0..total_blocks {
        let lba = start_lba + i as u64;
        let block_buf = &mut scratch[i * dev_bs as usize..][..dev_bs as usize];
        device.read_blocks(lba, block_buf)?;
    }

    buf.copy_from_slice(&scratch[start_off..start_off + buf.len()]);
    Ok(())
}

fn read_device_vec(
    device: &Arc<dyn BlockDevice>,
    byte_offset: u64,
    len: usize,
) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; len];
    read_device_bytes(device, byte_offset, &mut buf)?;
    Ok(buf)
}
