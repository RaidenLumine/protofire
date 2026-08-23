//! src/kernel/fs/ext4/journal.rs
//! JBD2 journal subsystem — replay and write-ahead logging.
use super::constants::*;
use super::types::*;
use crate::kernel::crypto::crc32c;
use crate::kernel::fs::block::BLOCK_SIZE;
use crate::kernel::fs::block_cache::BlockCache;
use crate::{Error, Result};
use alloc::vec;
use alloc::vec::Vec;

/// JBD2 tag flag bits.
const JBD2_FLAG_ESCAPE: u32 = 0x01;
const JBD2_FLAG_LAST_TAG: u32 = 0x04;
const JBD2_FLAG_CHECKSUM: u32 = 0x08; // v3 checksum tag (CRC32C after data block)
                                      // ─── journal (jbd2) constants ────────────────────────────────────────────────
/// jbd2 magic value.
pub(crate) const JBD2_MAGIC: u32 = 0xC03B_3998;
/// Journal block types.
pub(crate) const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
pub(crate) const JBD2_COMMIT_BLOCK: u32 = 2;
pub(crate) const JBD2_SUPERBLOCK_V1: u32 = 3;
pub(crate) const JBD2_SUPERBLOCK_V2: u32 = 4;
pub(crate) const JBD2_REVOKE_BLOCK: u32 = 5;
/// Size of a journal superblock in bytes.
pub(crate) const JBD2_SUPERBLOCK_SIZE: usize = 1024;
/// Offsets within the journal superblock.
pub(crate) const J_S_MAGIC: usize = 0x00; // u32 BE
pub(crate) const J_S_BLOCKTYPE: usize = 0x0C; // u32 BE
pub(crate) const J_S_SEQUENCE: usize = 0x10; // u32 BE
pub(crate) const J_S_MAXLEN: usize = 0x18; // u32 BE
pub(crate) const J_S_BLOCKSIZE: usize = 0x1C; // u32 BE
pub(crate) const J_S_START: usize = 0x20; // u32 BE
#[allow(dead_code)] // spec-defined offset — informational
pub(crate) const J_S_FIRST: usize = 0x28; // u32 BE
pub(crate) const J_S_ERRNO: usize = 0x30; // u32 BE
                                          // Spec-defined superblock offsets — not yet used by the current journal
                                          // implementation, but kept for completeness.
#[allow(dead_code)] // spec-defined offset — informational
pub(crate) const J_S_FEATURE_COMPAT: usize = 0x40; // u32 BE
#[allow(dead_code)] // spec-defined offset — informational
pub(crate) const J_S_FEATURE_INCOMPAT: usize = 0x44; // u32 BE
#[allow(dead_code)] // spec-defined offset — informational
pub(crate) const J_S_FEATURE_RO_COMPAT: usize = 0x48; // u32 BE
#[allow(dead_code)] // spec-defined offset — informational
pub(crate) const J_S_UUID: usize = 0x50; // 16 bytes
/// Journal superblock parsed data.
#[derive(Debug)]
pub(crate) struct Jbd2Superblock {
    start: u32,  // first journal block to replay
    maxlen: u32, // journal size in blocks
    block_size: u32,
    pub(crate) errno: u32,
}
/// Read a big-endian u32 from `data` at `offset`.
pub(crate) fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}
/// Write a big-endian u32 into `data` at `offset`.
pub(crate) fn write_u32_be(data: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_be_bytes();
    data[offset] = bytes[0];
    data[offset + 1] = bytes[1];
    data[offset + 2] = bytes[2];
    data[offset + 3] = bytes[3];
}
/// Simple journal header (12 bytes) at the start of every journal block.
struct Jbd2Header {
    magic: u32,
    block_type: u32,
}
fn parse_jbd2_header(raw: &[u8]) -> Jbd2Header {
    Jbd2Header {
        magic: read_u32_be(raw, 0),
        block_type: read_u32_be(raw, 4),
    }
}
/// Descriptor block tag (v1/v2, 8 bytes per tag without checksum).
/// Points to one metadata block in the journal.
#[derive(Debug, Clone, Copy)]
struct Jbd2BlockTag {
    block_nr: u32,
    flags: u32,
}
fn parse_block_tag(raw: &[u8]) -> Jbd2BlockTag {
    Jbd2BlockTag {
        block_nr: read_u32_be(raw, 0),
        flags: read_u32_be(raw, 4),
    }
}
/// Parse a journal superblock from 1024 bytes.
fn parse_jbd2_superblock(raw: &[u8]) -> Option<Jbd2Superblock> {
    let magic = read_u32_be(raw, J_S_MAGIC);
    if magic != JBD2_MAGIC {
        return None;
    }
    let block_type = read_u32_be(raw, J_S_BLOCKTYPE);
    if block_type != JBD2_SUPERBLOCK_V2 && block_type != JBD2_SUPERBLOCK_V1 {
        return None;
    }
    Some(Jbd2Superblock {
        start: read_u32_be(raw, J_S_START),
        maxlen: read_u32_be(raw, J_S_MAXLEN),
        block_size: read_u32_be(raw, J_S_BLOCKSIZE),
        errno: read_u32_be(raw, J_S_ERRNO),
    })
}
pub(crate) fn replay_ext4_journal(
    cache: &BlockCache,
    sb: &Ext4Superblock,
    bgs: &[Ext4BgDescriptor],
) -> Result<()> {
    // Read the journal inode.
    let journal_inode = super::fs::read_inode_raw(cache, sb, bgs, EXT4_JOURNAL_INO)?;
    if journal_inode.size_low == 0 {
        // No journal present — clean mount.
        return Ok(());
    }
    let block_size = sb.block_size();
    let mut buf = vec![0u8; block_size];
    // Read the journal superblock (first block of journal inode).
    let journal_start_block = journal_inode.block_48(0) & 0xFFFF_FFFF; // low 32 bits
    if journal_start_block == 0 {
        return Ok(());
    }
    let j_lba = journal_start_block * (block_size as u64 / BLOCK_SIZE as u64);
    let sector_count = block_size / BLOCK_SIZE;
    for i in 0..sector_count {
        cache.read_cached(
            j_lba + i as u64,
            &mut buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
        )?;
    }
    let jsb = match parse_jbd2_superblock(&buf[..JBD2_SUPERBLOCK_SIZE.min(buf.len())]) {
        Some(jsb) => jsb,
        None => {
            // No valid journal superblock — treat as clean.
            return Ok(());
        }
    };
    // If errno is 0, the journal is clean — nothing to replay.
    if jsb.errno == 0 {
        return Ok(());
    }
    let journal_block_size = if jsb.block_size == 0 {
        block_size as u32
    } else {
        jsb.block_size
    };
    // The on-disk journal block size must match the filesystem block size,
    // otherwise the derived sector count would index past the cache buffer.
    if journal_block_size as usize != block_size {
        return Err(Error::InvalidArgument);
    }
    // Journal superblock feature flags for v3 checksum detection.
    let jsb_features_compat = read_u32_be(&buf, J_S_FEATURE_COMPAT);
    let _has_v3_checksums = (jsb_features_compat & 0x02) != 0; // bit 1 = journal checksum feature

    // Journal blocks are stored in a circular buffer starting at
    // journal_start_block.  The superblock lives at journal block offset 0;
    // data blocks occupy offsets 1 .. maxlen-1.  jsb.start is the journal
    // block index where replay should begin (always >= 1 for a dirty journal).
    let journal_area_start = journal_start_block;
    let journal_total_blocks = jsb.maxlen; // includes superblock at offset 0
                                           // Walk from jsb.start forward, replaying transactions.
    let start_offset = jsb.start;
    let mut offset = start_offset;
    let mut replay_count = 0u64;
    // Revoke set: block numbers that have been revoked and must not be replayed.
    let mut revoke_set: Vec<u32> = Vec::new();

    // Loop until we return to the starting offset (wrapped around)
    // or encounter end of valid journal blocks.
    let mut first_pass = true;
    loop {
        // Avoid infinite loop: if we've wrapped around and are back at start, stop.
        if !first_pass && offset == start_offset {
            break;
        }
        first_pass = false;

        // Never land on the superblock (offset 0) when wrapping.
        if offset == 0 {
            offset = 1;
        }
        if offset >= journal_total_blocks {
            offset = 1;
        }
        let block_idx = journal_area_start + offset as u64;
        let lba = block_idx * (journal_block_size as u64 / BLOCK_SIZE as u64);
        let sectors = journal_block_size as usize / BLOCK_SIZE;
        for i in 0..sectors {
            cache.read_cached(
                lba + i as u64,
                &mut buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
            )?;
        }
        let hdr = parse_jbd2_header(&buf);
        if hdr.magic != JBD2_MAGIC {
            // No more valid journal blocks.
            break;
        }
        match hdr.block_type {
            JBD2_DESCRIPTOR_BLOCK => {
                // Descriptor block: contains metadata blocks.
                // The tag array starts at offset 12 (after the header).
                // Determine tag size: v3 checksum tags have 4 bytes of checksum
                // appended after each 8-byte tag entry, making each tag 12 bytes.
                let tag_size_checksum = 12; // v3 with per-tag CRC32C trailer
                let tag_size_no_csum = 8; // v1/v2 without checksum
                                          // We detect v3 checksum tags by reading the first tag's flags:
                                          // if bit 2 (JBD2_FLAG_CHECKSUM) is set, use 12-byte tags.
                let first_tag_off = 12usize;
                let using_csum_tags = if first_tag_off + 8 <= buf.len() {
                    let ftag = parse_block_tag(&buf[first_tag_off..]);
                    ftag.block_nr != 0 && (ftag.flags & JBD2_FLAG_CHECKSUM) != 0
                } else {
                    false
                };
                let tag_size = if using_csum_tags {
                    tag_size_checksum
                } else {
                    tag_size_no_csum
                };
                let max_tags = (journal_block_size as usize - 12) / tag_size;
                let mut tag_offset = 12usize;
                let mut blocks_written = 0usize;
                for _ in 0..max_tags {
                    if tag_offset + tag_size_no_csum.min(tag_size) > buf.len() {
                        break;
                    }
                    let tag = parse_block_tag(&buf[tag_offset..]);
                    if using_csum_tags {
                        tag_offset += tag_size_checksum;
                    } else {
                        tag_offset += tag_size_no_csum;
                    }
                    if tag.block_nr == 0 {
                        break; // end of tags
                    }
                    // Skip escape/deleted tags (bit 0).
                    if tag.flags & JBD2_FLAG_ESCAPE != 0 {
                        continue;
                    }
                    // Skip revoked blocks.
                    if revoke_set.contains(&tag.block_nr) {
                        blocks_written += 1; // still consumes a journal data slot
                        continue;
                    }
                    // The data block follows the descriptor block.
                    // We're now at the data block position.
                    let data_block_idx = block_idx + 1 + blocks_written as u64;
                    let data_lba = data_block_idx * (journal_block_size as u64 / BLOCK_SIZE as u64);
                    let mut data_buf = vec![0u8; block_size];
                    for i in 0..sector_count {
                        cache.read_cached(
                            data_lba + i as u64,
                            &mut data_buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
                        )?;
                    }
                    // If v3 checksum tag: verify CRC32C of the data block.
                    if tag.flags & JBD2_FLAG_CHECKSUM != 0 {
                        // The checksum (u32 LE) is stored immediately after the data block
                        // in the journal.  Read it from the journal.
                        let csum_lba = data_lba + sector_count as u64;
                        let mut csum_raw = [0u8; 4];
                        cache.read_cached(csum_lba, &mut csum_raw)?;
                        let stored_csum = u32::from_le_bytes(csum_raw);
                        // Compute CRC32C over the data block itself.
                        let computed = crc32c(&data_buf);
                        if computed != stored_csum {
                            crate::println!(
                                "[ext4] CRC32C mismatch on journal data block {:x} (tag block_nr={}): expected={:08x} computed={:08x}",
                                data_block_idx, tag.block_nr, stored_csum, computed
                            );
                            // During replay, warn but continue — we're in recovery.
                        }
                    }
                    // Write the data block to its on-disk location.
                    let target_lba = tag.block_nr as u64 * (block_size as u64 / BLOCK_SIZE as u64);
                    for i in 0..sector_count {
                        cache.write_back(
                            target_lba + i as u64,
                            &data_buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
                        )?;
                    }
                    blocks_written += 1;
                    replay_count += 1;
                    // JBD2_FLAG_LAST_TAG marks the final tag in this
                    // descriptor block — stop scanning further tags.
                    if tag.flags & JBD2_FLAG_LAST_TAG != 0 {
                        break;
                    }
                }
                // Skip past the descriptor block and all data blocks (and any
                // checksum trailers — they take an extra sector each when present).
                offset = (offset + 1 + blocks_written as u32) % journal_total_blocks;
            }
            JBD2_COMMIT_BLOCK => {
                // CRC32C verification for v3 (checksum-enabled) commit
                // blocks.  The checksum is a u32 LE at byte 28 of the
                // commit block header.  v1/v2 blocks have 0 here and
                // are silently accepted.
                if buf.len() >= 32 {
                    let csum_off = 28usize;
                    let stored = u32::from_le_bytes([
                        buf[csum_off],
                        buf[csum_off + 1],
                        buf[csum_off + 2],
                        buf[csum_off + 3],
                    ]);
                    if stored != 0 {
                        let saved = [
                            buf[csum_off],
                            buf[csum_off + 1],
                            buf[csum_off + 2],
                            buf[csum_off + 3],
                        ];
                        buf[csum_off..csum_off + 4].fill(0);
                        let computed = crc32c(&buf);
                        buf[csum_off..csum_off + 4].copy_from_slice(&saved);
                        if computed != stored {
                            crate::println!(
                                "[ext4] CRC32C mismatch on journal commit block: expected={:08x} computed={:08x}",
                                stored, computed
                            );
                            // During journal replay, warn but don't
                            // abort — we're already in a recovery path.
                        }
                    }
                }
                offset = (offset + 1) % journal_total_blocks;
            }
            JBD2_REVOKE_BLOCK => {
                // Revoke block: read the list of revoked block numbers.
                // The header is 12 bytes (magic + block_type + sequence).
                // After the header comes an array of u32 BE block numbers.
                let revoke_hdr_size = 12usize;
                let revoke_entry_size = 4usize; // u32 BE per entry
                let max_revoke =
                    ((journal_block_size as usize - revoke_hdr_size) / revoke_entry_size).min(1024);
                for i in 0..max_revoke {
                    let rev_off = revoke_hdr_size + i * revoke_entry_size;
                    if rev_off + revoke_entry_size > buf.len() {
                        break;
                    }
                    let rblock = read_u32_be(&buf, rev_off);
                    if rblock == 0 {
                        break; // zero-terminated list of revoke records
                    }
                    if !revoke_set.contains(&rblock) {
                        revoke_set.push(rblock);
                    }
                }
                offset = (offset + 1) % journal_total_blocks;
            }
            _ => {
                // Unknown block type — stop replay.
                break;
            }
        }
    }
    // Mark the journal as clean.
    if replay_count > 0 {
        // Write back a clean journal superblock with errno = 0.
        let mut jsb_buf = vec![0u8; JBD2_SUPERBLOCK_SIZE];
        jsb_buf[..buf.len().min(JBD2_SUPERBLOCK_SIZE)]
            .copy_from_slice(&buf[..buf.len().min(JBD2_SUPERBLOCK_SIZE)]);
        // Update errno to 0 (clean) and increment sequence.
        write_u32_be(&mut jsb_buf, J_S_ERRNO, 0);
        let new_seq = read_u32_be(&jsb_buf, J_S_SEQUENCE).wrapping_add(1);
        write_u32_be(&mut jsb_buf, J_S_SEQUENCE, new_seq);
        write_u32_be(&mut jsb_buf, J_S_START, offset);
        // Write the updated superblock back.
        for i in 0..(JBD2_SUPERBLOCK_SIZE / BLOCK_SIZE) {
            cache.write_back(
                j_lba + i as u64,
                &jsb_buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
            )?;
        }
        cache.flush()?;
    }
    Ok(())
}
/// Manages write-ahead logging to the ext4 journal's circular buffer.
///
/// Each transaction writes: descriptor block (with tags pointing to data
/// blocks) → data blocks → commit block.  The journal superblock is marked
/// dirty (`errno = 1`) at transaction start and clean (`errno = 0`) at
/// commit.
pub(crate) struct JournalWriter {
    /// Starting block of the journal area (from journal inode block[0]).
    pub(crate) journal_start: u64,
    /// Total journal blocks (from superblock maxlen).
    maxlen: u32,
    /// Journal block size (in bytes; 0 = filesystem block size).
    block_size: u32,
    /// Current offset (in journal blocks) for the next write.
    pub(crate) offset: u32,
    /// Current transaction sequence number.
    sequence: u32,
    /// LBA of the journal superblock (first block of journal area).
    pub(crate) jsb_lba: u64,
    /// Number of 512-byte sectors per journal block.
    pub(crate) sectors_per_block: u64,
    /// Pre-allocated buffer for superblock I/O.
    pub(crate) jsb_buf: Vec<u8>,
}
impl JournalWriter {
    /// Open the journal for writing.
    ///
    /// Reads the journal superblock and initialises the write cursor.
    /// Returns `None` if the journal inode has no data blocks or the
    /// superblock is invalid.
    pub(crate) fn open(
        cache: &BlockCache,
        journal_inode: &Ext4Inode,
        sb: &Ext4Superblock,
    ) -> Option<Self> {
        let fs_block_size = sb.block_size();
        let journal_start_block = journal_inode.block_48(0) & 0xFFFF_FFFF;
        if journal_start_block == 0 {
            return None;
        }
        let j_lba = journal_start_block * (fs_block_size as u64 / BLOCK_SIZE as u64);
        let _sector_count = fs_block_size / BLOCK_SIZE;
        // Read the journal superblock.
        let mut jsb_buf = vec![0u8; JBD2_SUPERBLOCK_SIZE];
        for i in 0..(JBD2_SUPERBLOCK_SIZE / BLOCK_SIZE) {
            let mut sector_buf = [0u8; BLOCK_SIZE];
            if cache
                .read_cached(j_lba + i as u64, &mut sector_buf)
                .is_err()
            {
                return None;
            }
            jsb_buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].copy_from_slice(&sector_buf);
        }
        let jsb = parse_jbd2_superblock(&jsb_buf)?;
        let block_size = if jsb.block_size == 0 {
            fs_block_size as u32
        } else {
            jsb.block_size
        };
        let sectors_per_block = block_size as u64 / BLOCK_SIZE as u64;
        Some(Self {
            journal_start: journal_start_block,
            maxlen: jsb.maxlen,
            block_size,
            offset: jsb.start,
            sequence: read_u32_be(&jsb_buf, J_S_SEQUENCE),
            jsb_lba: j_lba,
            sectors_per_block,
            jsb_buf,
        })
    }
    /// Begin a new transaction: mark the journal superblock as dirty
    /// (`errno = 1`) and write it to disk.
    pub(crate) fn begin_tx(&mut self, cache: &BlockCache) -> Result<()> {
        // Mark dirty.
        write_u32_be(&mut self.jsb_buf, J_S_ERRNO, 1);
        write_u32_be(&mut self.jsb_buf, J_S_SEQUENCE, self.sequence);
        write_u32_be(&mut self.jsb_buf, J_S_START, self.offset);
        self.write_jsb(cache)
    }
    /// Write a metadata block to the journal.
    ///
    /// `block_nr` is the filesystem block number where this data will
    /// ultimately reside.  `data` must be exactly one journal block in
    /// length.
    pub(crate) fn write_block(
        &mut self,
        cache: &BlockCache,
        block_nr: u64,
        data: &[u8],
    ) -> Result<()> {
        let jb_size = self.block_size as usize;
        let fs_block_size = jb_size; // journal block size == fs block size
        if data.len() != fs_block_size {
            return Err(Error::InvalidArgument);
        }
        // Ensure offset 0 (superblock) is never overwritten.
        if self.offset == 0 {
            self.offset = 1;
        }
        // ── descriptor block ──────────────────────────────────────────
        let desc_offset = self.offset;
        let mut desc_buf = vec![0u8; jb_size];
        // Header (12 bytes).
        write_u32_be(&mut desc_buf, 0, JBD2_MAGIC);
        write_u32_be(&mut desc_buf, 4, JBD2_DESCRIPTOR_BLOCK);
        write_u32_be(&mut desc_buf, 8, self.sequence);
        // One tag (8 bytes): block_nr, flags=0.
        write_u32_be(&mut desc_buf, 12, block_nr as u32);
        write_u32_be(&mut desc_buf, 16, 0);
        // Zero-fill the end-of-tags marker (block_nr=0, flags=0) — already
        // zero from vec! initialisation.
        self.write_journal_block(cache, desc_offset, &desc_buf)?;
        self.advance();
        // ── data block ────────────────────────────────────────────────
        let data_offset = self.offset;
        self.write_journal_block(cache, data_offset, data)?;
        self.advance();
        Ok(())
    }
    /// Commit the current transaction: write the commit block and mark
    /// the journal superblock clean.
    pub(crate) fn commit_tx(&mut self, cache: &BlockCache) -> Result<()> {
        let jb_size = self.block_size as usize;
        // ── commit block ──────────────────────────────────────────────
        if self.offset == 0 {
            self.offset = 1;
        }
        let mut commit_buf = vec![0u8; jb_size];
        write_u32_be(&mut commit_buf, 0, JBD2_MAGIC);
        write_u32_be(&mut commit_buf, 4, JBD2_COMMIT_BLOCK);
        write_u32_be(&mut commit_buf, 8, self.sequence);
        self.write_journal_block(cache, self.offset, &commit_buf)?;
        self.advance();
        // ── mark clean ────────────────────────────────────────────────
        self.sequence = self.sequence.wrapping_add(1);
        write_u32_be(&mut self.jsb_buf, J_S_ERRNO, 0);
        write_u32_be(&mut self.jsb_buf, J_S_SEQUENCE, self.sequence);
        write_u32_be(&mut self.jsb_buf, J_S_START, self.offset);
        self.write_jsb(cache)?;
        cache.flush()?;
        Ok(())
    }
    /// Write a single journal block at the given offset.
    fn write_journal_block(&self, cache: &BlockCache, j_offset: u32, data: &[u8]) -> Result<()> {
        let phys_block = self.journal_start + j_offset as u64 % self.maxlen as u64;
        let lba = phys_block * self.sectors_per_block;
        for i in 0..self.sectors_per_block as usize {
            cache.write_back(lba + i as u64, &data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE])?;
        }
        Ok(())
    }
    /// Advance the circular-buffer offset past the current block, skipping
    /// offset 0 (the superblock).
    fn advance(&mut self) {
        self.offset = (self.offset + 1) % self.maxlen;
        if self.offset == 0 {
            self.offset = 1;
        }
    }
    /// Write the cached journal superblock back to disk.
    fn write_jsb(&self, cache: &BlockCache) -> Result<()> {
        for i in 0..(JBD2_SUPERBLOCK_SIZE / BLOCK_SIZE) {
            cache.write_back(
                self.jsb_lba + i as u64,
                &self.jsb_buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
            )?;
        }
        Ok(())
    }
}
// ─── end journal write support ───────────────────────────────────────────
