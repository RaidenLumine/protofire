//! src/kernel/fs/f2fs/types.rs
//! F2FS on-disk structures, in-memory caches, and serialisation helpers.
//!
//! All multi-byte fields are little-endian.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::kernel::fs::vfs::NodeKind;

use super::constants::*;

// ─── F2FS Superblock ──────────────────────────────────────────────────

/// Parsed F2FS superblock from block 0.
#[derive(Debug, Clone)]
pub(crate) struct F2fsSuperblock {
    pub(crate) magic: u32,
    pub(crate) major_ver: u16,
    pub(crate) minor_ver: u16,
    pub(crate) log_sectorsize: u32,
    pub(crate) log_sectors_per_block: u32,
    pub(crate) log_blocksize: u32,
    pub(crate) log_blocks_per_seg: u32,
    pub(crate) segs_per_sec: u32,
    pub(crate) secs_per_zone: u32,
    pub(crate) checksum_offset: u32,
    pub(crate) block_count: u64,
    pub(crate) section_count: u32,
    pub(crate) segment_count: u32,
    pub(crate) segment_count_main: u32,
    pub(crate) segment0_blkaddr: u32,
    pub(crate) cp_blkaddr: u32,
    pub(crate) sit_blkaddr: u32,
    pub(crate) nat_blkaddr: u32,
    pub(crate) ssa_blkaddr: u32,
    pub(crate) main_blkaddr: u32,
    pub(crate) root_ino: u32,
    pub(crate) node_ino: u32,
    pub(crate) meta_ino: u32,
    pub(crate) cp_payload: u32,
    pub(crate) feature: u32,
    pub(crate) nat_entry_cnt: u32,
    pub(crate) sit_entry_cnt: u32,
    pub(crate) node_count: u32,
}

impl F2fsSuperblock {
    /// Block size in bytes = 2 ^ log_blocksize.
    pub(crate) fn block_size(&self) -> usize {
        1usize << self.log_blocksize
    }

    /// Number of blocks per segment = 2 ^ log_blocks_per_seg.
    pub(crate) fn blocks_per_seg(&self) -> u32 {
        1u32 << self.log_blocks_per_seg
    }
}

/// Parse a [`F2fsSuperblock`] from a 4096-byte raw buffer.
pub(crate) fn parse_f2fs_superblock(raw: &[u8]) -> F2fsSuperblock {
    F2fsSuperblock {
        magic: u32::from_le_bytes([
            raw[F2FS_SB_MAGIC_OFF],
            raw[F2FS_SB_MAGIC_OFF + 1],
            raw[F2FS_SB_MAGIC_OFF + 2],
            raw[F2FS_SB_MAGIC_OFF + 3],
        ]),
        major_ver: u16::from_le_bytes([raw[F2FS_SB_MAJOR_VER_OFF], raw[F2FS_SB_MAJOR_VER_OFF + 1]]),
        minor_ver: u16::from_le_bytes([raw[F2FS_SB_MINOR_VER_OFF], raw[F2FS_SB_MINOR_VER_OFF + 1]]),
        log_sectorsize: u32::from_le_bytes([
            raw[F2FS_SB_LOG_SECTORSIZE_OFF],
            raw[F2FS_SB_LOG_SECTORSIZE_OFF + 1],
            raw[F2FS_SB_LOG_SECTORSIZE_OFF + 2],
            raw[F2FS_SB_LOG_SECTORSIZE_OFF + 3],
        ]),
        log_sectors_per_block: u32::from_le_bytes([
            raw[F2FS_SB_LOG_SECTORS_PER_BLOCK_OFF],
            raw[F2FS_SB_LOG_SECTORS_PER_BLOCK_OFF + 1],
            raw[F2FS_SB_LOG_SECTORS_PER_BLOCK_OFF + 2],
            raw[F2FS_SB_LOG_SECTORS_PER_BLOCK_OFF + 3],
        ]),
        log_blocksize: u32::from_le_bytes([
            raw[F2FS_SB_LOG_BLOCKSIZE_OFF],
            raw[F2FS_SB_LOG_BLOCKSIZE_OFF + 1],
            raw[F2FS_SB_LOG_BLOCKSIZE_OFF + 2],
            raw[F2FS_SB_LOG_BLOCKSIZE_OFF + 3],
        ]),
        log_blocks_per_seg: u32::from_le_bytes([
            raw[F2FS_SB_LOG_BLOCKS_PER_SEG_OFF],
            raw[F2FS_SB_LOG_BLOCKS_PER_SEG_OFF + 1],
            raw[F2FS_SB_LOG_BLOCKS_PER_SEG_OFF + 2],
            raw[F2FS_SB_LOG_BLOCKS_PER_SEG_OFF + 3],
        ]),
        segs_per_sec: u32::from_le_bytes([
            raw[F2FS_SB_SEGS_PER_SEC_OFF],
            raw[F2FS_SB_SEGS_PER_SEC_OFF + 1],
            raw[F2FS_SB_SEGS_PER_SEC_OFF + 2],
            raw[F2FS_SB_SEGS_PER_SEC_OFF + 3],
        ]),
        secs_per_zone: u32::from_le_bytes([
            raw[F2FS_SB_SECS_PER_ZONE_OFF],
            raw[F2FS_SB_SECS_PER_ZONE_OFF + 1],
            raw[F2FS_SB_SECS_PER_ZONE_OFF + 2],
            raw[F2FS_SB_SECS_PER_ZONE_OFF + 3],
        ]),
        checksum_offset: u32::from_le_bytes([
            raw[F2FS_SB_CHECKSUM_OFFSET_OFF],
            raw[F2FS_SB_CHECKSUM_OFFSET_OFF + 1],
            raw[F2FS_SB_CHECKSUM_OFFSET_OFF + 2],
            raw[F2FS_SB_CHECKSUM_OFFSET_OFF + 3],
        ]),
        block_count: u64::from_le_bytes([
            raw[F2FS_SB_BLOCK_COUNT_OFF],
            raw[F2FS_SB_BLOCK_COUNT_OFF + 1],
            raw[F2FS_SB_BLOCK_COUNT_OFF + 2],
            raw[F2FS_SB_BLOCK_COUNT_OFF + 3],
            raw[F2FS_SB_BLOCK_COUNT_OFF + 4],
            raw[F2FS_SB_BLOCK_COUNT_OFF + 5],
            raw[F2FS_SB_BLOCK_COUNT_OFF + 6],
            raw[F2FS_SB_BLOCK_COUNT_OFF + 7],
        ]),
        section_count: u32::from_le_bytes([
            raw[F2FS_SB_SECTION_COUNT_OFF],
            raw[F2FS_SB_SECTION_COUNT_OFF + 1],
            raw[F2FS_SB_SECTION_COUNT_OFF + 2],
            raw[F2FS_SB_SECTION_COUNT_OFF + 3],
        ]),
        segment_count: u32::from_le_bytes([
            raw[F2FS_SB_SEGMENT_COUNT_OFF],
            raw[F2FS_SB_SEGMENT_COUNT_OFF + 1],
            raw[F2FS_SB_SEGMENT_COUNT_OFF + 2],
            raw[F2FS_SB_SEGMENT_COUNT_OFF + 3],
        ]),
        segment_count_main: u32::from_le_bytes([
            raw[F2FS_SB_SEGMENT_COUNT_MAIN_OFF],
            raw[F2FS_SB_SEGMENT_COUNT_MAIN_OFF + 1],
            raw[F2FS_SB_SEGMENT_COUNT_MAIN_OFF + 2],
            raw[F2FS_SB_SEGMENT_COUNT_MAIN_OFF + 3],
        ]),
        segment0_blkaddr: u32::from_le_bytes([
            raw[F2FS_SB_SEGMENT0_BLKADDR_OFF],
            raw[F2FS_SB_SEGMENT0_BLKADDR_OFF + 1],
            raw[F2FS_SB_SEGMENT0_BLKADDR_OFF + 2],
            raw[F2FS_SB_SEGMENT0_BLKADDR_OFF + 3],
        ]),
        cp_blkaddr: u32::from_le_bytes([
            raw[F2FS_SB_CP_BLKADDR_OFF],
            raw[F2FS_SB_CP_BLKADDR_OFF + 1],
            raw[F2FS_SB_CP_BLKADDR_OFF + 2],
            raw[F2FS_SB_CP_BLKADDR_OFF + 3],
        ]),
        sit_blkaddr: u32::from_le_bytes([
            raw[F2FS_SB_SIT_BLKADDR_OFF],
            raw[F2FS_SB_SIT_BLKADDR_OFF + 1],
            raw[F2FS_SB_SIT_BLKADDR_OFF + 2],
            raw[F2FS_SB_SIT_BLKADDR_OFF + 3],
        ]),
        nat_blkaddr: u32::from_le_bytes([
            raw[F2FS_SB_NAT_BLKADDR_OFF],
            raw[F2FS_SB_NAT_BLKADDR_OFF + 1],
            raw[F2FS_SB_NAT_BLKADDR_OFF + 2],
            raw[F2FS_SB_NAT_BLKADDR_OFF + 3],
        ]),
        ssa_blkaddr: u32::from_le_bytes([
            raw[F2FS_SB_SSA_BLKADDR_OFF],
            raw[F2FS_SB_SSA_BLKADDR_OFF + 1],
            raw[F2FS_SB_SSA_BLKADDR_OFF + 2],
            raw[F2FS_SB_SSA_BLKADDR_OFF + 3],
        ]),
        main_blkaddr: u32::from_le_bytes([
            raw[F2FS_SB_MAIN_BLKADDR_OFF],
            raw[F2FS_SB_MAIN_BLKADDR_OFF + 1],
            raw[F2FS_SB_MAIN_BLKADDR_OFF + 2],
            raw[F2FS_SB_MAIN_BLKADDR_OFF + 3],
        ]),
        root_ino: u32::from_le_bytes([
            raw[F2FS_SB_ROOT_INO_OFF],
            raw[F2FS_SB_ROOT_INO_OFF + 1],
            raw[F2FS_SB_ROOT_INO_OFF + 2],
            raw[F2FS_SB_ROOT_INO_OFF + 3],
        ]),
        node_ino: u32::from_le_bytes([
            raw[F2FS_SB_NODE_INO_OFF],
            raw[F2FS_SB_NODE_INO_OFF + 1],
            raw[F2FS_SB_NODE_INO_OFF + 2],
            raw[F2FS_SB_NODE_INO_OFF + 3],
        ]),
        meta_ino: u32::from_le_bytes([
            raw[F2FS_SB_META_INO_OFF],
            raw[F2FS_SB_META_INO_OFF + 1],
            raw[F2FS_SB_META_INO_OFF + 2],
            raw[F2FS_SB_META_INO_OFF + 3],
        ]),
        cp_payload: u32::from_le_bytes([
            raw[F2FS_SB_CP_PAYLOAD_OFF],
            raw[F2FS_SB_CP_PAYLOAD_OFF + 1],
            raw[F2FS_SB_CP_PAYLOAD_OFF + 2],
            raw[F2FS_SB_CP_PAYLOAD_OFF + 3],
        ]),
        feature: u32::from_le_bytes([
            raw[F2FS_SB_FEATURE_OFF],
            raw[F2FS_SB_FEATURE_OFF + 1],
            raw[F2FS_SB_FEATURE_OFF + 2],
            raw[F2FS_SB_FEATURE_OFF + 3],
        ]),
        nat_entry_cnt: u32::from_le_bytes([
            raw[F2FS_SB_NAT_ENTRY_CNT_OFF],
            raw[F2FS_SB_NAT_ENTRY_CNT_OFF + 1],
            raw[F2FS_SB_NAT_ENTRY_CNT_OFF + 2],
            raw[F2FS_SB_NAT_ENTRY_CNT_OFF + 3],
        ]),
        sit_entry_cnt: u32::from_le_bytes([
            raw[F2FS_SB_SIT_ENTRY_CNT_OFF],
            raw[F2FS_SB_SIT_ENTRY_CNT_OFF + 1],
            raw[F2FS_SB_SIT_ENTRY_CNT_OFF + 2],
            raw[F2FS_SB_SIT_ENTRY_CNT_OFF + 3],
        ]),
        node_count: u32::from_le_bytes([
            raw[F2FS_SB_NODE_COUNT_OFF],
            raw[F2FS_SB_NODE_COUNT_OFF + 1],
            raw[F2FS_SB_NODE_COUNT_OFF + 2],
            raw[F2FS_SB_NODE_COUNT_OFF + 3],
        ]),
    }
}

/// Serialise a [`F2fsSuperblock`] into a 4096-byte raw buffer.
pub(crate) fn write_f2fs_superblock(sb: &F2fsSuperblock, raw: &mut [u8]) {
    raw[F2FS_SB_MAGIC_OFF..F2FS_SB_MAGIC_OFF + 4].copy_from_slice(&sb.magic.to_le_bytes());
    raw[F2FS_SB_MAJOR_VER_OFF..F2FS_SB_MAJOR_VER_OFF + 2]
        .copy_from_slice(&sb.major_ver.to_le_bytes());
    raw[F2FS_SB_MINOR_VER_OFF..F2FS_SB_MINOR_VER_OFF + 2]
        .copy_from_slice(&sb.minor_ver.to_le_bytes());
    raw[F2FS_SB_LOG_SECTORSIZE_OFF..F2FS_SB_LOG_SECTORSIZE_OFF + 4]
        .copy_from_slice(&sb.log_sectorsize.to_le_bytes());
    raw[F2FS_SB_LOG_SECTORS_PER_BLOCK_OFF..F2FS_SB_LOG_SECTORS_PER_BLOCK_OFF + 4]
        .copy_from_slice(&sb.log_sectors_per_block.to_le_bytes());
    raw[F2FS_SB_LOG_BLOCKSIZE_OFF..F2FS_SB_LOG_BLOCKSIZE_OFF + 4]
        .copy_from_slice(&sb.log_blocksize.to_le_bytes());
    raw[F2FS_SB_LOG_BLOCKS_PER_SEG_OFF..F2FS_SB_LOG_BLOCKS_PER_SEG_OFF + 4]
        .copy_from_slice(&sb.log_blocks_per_seg.to_le_bytes());
    raw[F2FS_SB_SEGS_PER_SEC_OFF..F2FS_SB_SEGS_PER_SEC_OFF + 4]
        .copy_from_slice(&sb.segs_per_sec.to_le_bytes());
    raw[F2FS_SB_SECS_PER_ZONE_OFF..F2FS_SB_SECS_PER_ZONE_OFF + 4]
        .copy_from_slice(&sb.secs_per_zone.to_le_bytes());
    raw[F2FS_SB_CHECKSUM_OFFSET_OFF..F2FS_SB_CHECKSUM_OFFSET_OFF + 4]
        .copy_from_slice(&sb.checksum_offset.to_le_bytes());
    raw[F2FS_SB_BLOCK_COUNT_OFF..F2FS_SB_BLOCK_COUNT_OFF + 8]
        .copy_from_slice(&sb.block_count.to_le_bytes());
    raw[F2FS_SB_SECTION_COUNT_OFF..F2FS_SB_SECTION_COUNT_OFF + 4]
        .copy_from_slice(&sb.section_count.to_le_bytes());
    raw[F2FS_SB_SEGMENT_COUNT_OFF..F2FS_SB_SEGMENT_COUNT_OFF + 4]
        .copy_from_slice(&sb.segment_count.to_le_bytes());
    raw[F2FS_SB_SEGMENT_COUNT_MAIN_OFF..F2FS_SB_SEGMENT_COUNT_MAIN_OFF + 4]
        .copy_from_slice(&sb.segment_count_main.to_le_bytes());
    raw[F2FS_SB_SEGMENT0_BLKADDR_OFF..F2FS_SB_SEGMENT0_BLKADDR_OFF + 4]
        .copy_from_slice(&sb.segment0_blkaddr.to_le_bytes());
    raw[F2FS_SB_CP_BLKADDR_OFF..F2FS_SB_CP_BLKADDR_OFF + 4]
        .copy_from_slice(&sb.cp_blkaddr.to_le_bytes());
    raw[F2FS_SB_SIT_BLKADDR_OFF..F2FS_SB_SIT_BLKADDR_OFF + 4]
        .copy_from_slice(&sb.sit_blkaddr.to_le_bytes());
    raw[F2FS_SB_NAT_BLKADDR_OFF..F2FS_SB_NAT_BLKADDR_OFF + 4]
        .copy_from_slice(&sb.nat_blkaddr.to_le_bytes());
    raw[F2FS_SB_SSA_BLKADDR_OFF..F2FS_SB_SSA_BLKADDR_OFF + 4]
        .copy_from_slice(&sb.ssa_blkaddr.to_le_bytes());
    raw[F2FS_SB_MAIN_BLKADDR_OFF..F2FS_SB_MAIN_BLKADDR_OFF + 4]
        .copy_from_slice(&sb.main_blkaddr.to_le_bytes());
    raw[F2FS_SB_ROOT_INO_OFF..F2FS_SB_ROOT_INO_OFF + 4].copy_from_slice(&sb.root_ino.to_le_bytes());
    raw[F2FS_SB_NODE_INO_OFF..F2FS_SB_NODE_INO_OFF + 4].copy_from_slice(&sb.node_ino.to_le_bytes());
    raw[F2FS_SB_META_INO_OFF..F2FS_SB_META_INO_OFF + 4].copy_from_slice(&sb.meta_ino.to_le_bytes());
    raw[F2FS_SB_CP_PAYLOAD_OFF..F2FS_SB_CP_PAYLOAD_OFF + 4]
        .copy_from_slice(&sb.cp_payload.to_le_bytes());
    raw[F2FS_SB_FEATURE_OFF..F2FS_SB_FEATURE_OFF + 4].copy_from_slice(&sb.feature.to_le_bytes());
    raw[F2FS_SB_NAT_ENTRY_CNT_OFF..F2FS_SB_NAT_ENTRY_CNT_OFF + 4]
        .copy_from_slice(&sb.nat_entry_cnt.to_le_bytes());
    raw[F2FS_SB_SIT_ENTRY_CNT_OFF..F2FS_SB_SIT_ENTRY_CNT_OFF + 4]
        .copy_from_slice(&sb.sit_entry_cnt.to_le_bytes());
    raw[F2FS_SB_NODE_COUNT_OFF..F2FS_SB_NODE_COUNT_OFF + 4]
        .copy_from_slice(&sb.node_count.to_le_bytes());
}

// ─── NAT Entry ────────────────────────────────────────────────────────

/// A NAT (Node Address Table) entry — maps a NID to its physical block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct F2fsNatEntry {
    /// Physical block address.  0 means the NID is free.
    pub(crate) block_addr: u32,
    /// Parent inode NID (lower 32 bits).
    pub(crate) ino: u32,
}

/// Parse a [`F2fsNatEntry`] from 8 raw bytes.
pub(crate) fn parse_nat_entry(raw: &[u8]) -> F2fsNatEntry {
    F2fsNatEntry {
        block_addr: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        ino: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
    }
}

/// Serialise a [`F2fsNatEntry`] into 8 bytes.
pub(crate) fn write_nat_entry(entry: &F2fsNatEntry, raw: &mut [u8]) {
    raw[0..4].copy_from_slice(&entry.block_addr.to_le_bytes());
    raw[4..8].copy_from_slice(&entry.ino.to_le_bytes());
}

// ─── SIT Entry ────────────────────────────────────────────────────────

/// A SIT (Segment Information Table) entry — tracks validity of blocks in
/// one segment.
#[derive(Debug, Clone)]
pub(crate) struct F2fsSitEntry {
    /// Number of valid blocks in this segment.
    pub(crate) vblocks: u16,
    /// Bitmap of valid blocks (1 bit per block, up to 512 bits = 64 bytes).
    pub(crate) valid_map: [u8; 64],
}

impl F2fsSitEntry {
    /// Check whether the block at `offset` within the segment is valid.
    pub(crate) fn is_valid(&self, offset: u16) -> bool {
        let byte = self.valid_map[offset as usize / 8];
        (byte >> (offset % 8)) & 1 != 0
    }

    /// Mark the block at `offset` as valid.
    pub(crate) fn mark_valid(&mut self, offset: u16) {
        let idx = offset as usize / 8;
        let bit = offset % 8;
        if (self.valid_map[idx] >> bit) & 1 == 0 {
            self.valid_map[idx] |= 1 << bit;
            self.vblocks += 1;
        }
    }

    /// Mark the block at `offset` as invalid.
    pub(crate) fn mark_invalid(&mut self, offset: u16) {
        let idx = offset as usize / 8;
        let bit = offset % 8;
        if (self.valid_map[idx] >> bit) & 1 != 0 {
            self.valid_map[idx] &= !(1 << bit);
            self.vblocks = self.vblocks.saturating_sub(1);
        }
    }
}

/// Parse a [`F2fsSitEntry`] from 66 raw bytes.
pub(crate) fn parse_sit_entry(raw: &[u8]) -> F2fsSitEntry {
    let vblocks = u16::from_le_bytes([raw[0], raw[1]]);
    let mut valid_map = [0u8; 64];
    valid_map.copy_from_slice(&raw[2..66]);
    F2fsSitEntry { vblocks, valid_map }
}

/// Serialise a [`F2fsSitEntry`] into 66 bytes.
///
/// Only used by the unit tests to build a SIT block image; the driver's
/// v1 checkpoint flush never writes SIT entries back to the SIT area.
#[cfg(test)]
pub(crate) fn write_sit_entry(entry: &F2fsSitEntry, raw: &mut [u8]) {
    raw[0..2].copy_from_slice(&entry.vblocks.to_le_bytes());
    raw[2..66].copy_from_slice(&entry.valid_map);
}

// ─── Checkpoint ───────────────────────────────────────────────────────

/// Parsed F2FS checkpoint.
#[derive(Debug, Clone)]
pub(crate) struct F2fsCheckpoint {
    /// Checkpoint version (monotonic counter — larger = newer).
    pub(crate) check_ver: u64,
    /// Current NAT version.
    pub(crate) nat_ver: u64,
    /// Current SIT version.
    pub(crate) sit_ver: u64,
    /// Hint for the next free NID.
    pub(crate) next_free_nid: u32,
    /// Number of valid blocks in the volume.
    pub(crate) valid_block_count: u32,
    /// Number of valid inode-blocks (nodes).
    pub(crate) valid_node_count: u32,
    /// Number of valid (non-orphan) inodes.
    pub(crate) valid_inode_count: u32,
    /// Number of NAT journal entries stored in this checkpoint.
    pub(crate) nat_journal_entries: u32,
    /// Inline NAT journal: recent NAT updates batched in the CP block.
    pub(crate) nat_journal: Vec<NatJournalEntry>,
    /// Number of SIT journal entries stored in this checkpoint.
    pub(crate) sit_journal_entries: u32,
    /// Inline SIT journal: recent SIT updates batched in the CP block.
    ///
    /// v1 never serialises SIT journal entries to the CP block, so this
    /// vector is always empty; kept for crash-recovery layout parity.
    #[allow(dead_code)]
    pub(crate) sit_journal: Vec<SitJournalEntry>,
    /// Orphan inode NIDs for crash recovery.
    ///
    /// v1 does not track orphan inodes; kept for crash-recovery layout
    /// parity.
    #[allow(dead_code)]
    pub(crate) orphan_inodes: Vec<u32>,
    /// Which CP copy (0 or 1) won the race.
    pub(crate) cp_copy: u8,
}

/// A single NAT journal entry (stored inline in the checkpoint block).
#[derive(Debug, Clone, Copy)]
pub(crate) struct NatJournalEntry {
    pub(crate) nid: u32,
    pub(crate) ne: F2fsNatEntry,
}

/// A single SIT journal entry (stored inline in the checkpoint block).
///
/// v1 never populates the SIT journal (see [`F2fsCheckpoint::sit_journal`]),
/// so this type is kept only for on-disk checkpoint layout parity.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct SitJournalEntry {
    pub(crate) segno: u32,
    /// Updated valid-block count for this segment.
    pub(crate) vblocks: u16,
}

/// Parse a raw checkpoint block into an [`F2fsCheckpoint`].
///
/// `cp_copy` identifies which copy this is (0 or 1) for toggling writes.
pub(crate) fn parse_f2fs_checkpoint(raw: &[u8], cp_copy: u8) -> F2fsCheckpoint {
    let check_ver = u64::from_le_bytes([
        raw[F2FS_CP_CHECK_VER_OFF],
        raw[F2FS_CP_CHECK_VER_OFF + 1],
        raw[F2FS_CP_CHECK_VER_OFF + 2],
        raw[F2FS_CP_CHECK_VER_OFF + 3],
        raw[F2FS_CP_CHECK_VER_OFF + 4],
        raw[F2FS_CP_CHECK_VER_OFF + 5],
        raw[F2FS_CP_CHECK_VER_OFF + 6],
        raw[F2FS_CP_CHECK_VER_OFF + 7],
    ]);
    let nat_ver = u64::from_le_bytes([
        raw[F2FS_CP_NAT_VER_OFF],
        raw[F2FS_CP_NAT_VER_OFF + 1],
        raw[F2FS_CP_NAT_VER_OFF + 2],
        raw[F2FS_CP_NAT_VER_OFF + 3],
        raw[F2FS_CP_NAT_VER_OFF + 4],
        raw[F2FS_CP_NAT_VER_OFF + 5],
        raw[F2FS_CP_NAT_VER_OFF + 6],
        raw[F2FS_CP_NAT_VER_OFF + 7],
    ]);
    let sit_ver = u64::from_le_bytes([
        raw[F2FS_CP_SIT_VER_OFF],
        raw[F2FS_CP_SIT_VER_OFF + 1],
        raw[F2FS_CP_SIT_VER_OFF + 2],
        raw[F2FS_CP_SIT_VER_OFF + 3],
        raw[F2FS_CP_SIT_VER_OFF + 4],
        raw[F2FS_CP_SIT_VER_OFF + 5],
        raw[F2FS_CP_SIT_VER_OFF + 6],
        raw[F2FS_CP_SIT_VER_OFF + 7],
    ]);
    let next_free_nid = u32::from_le_bytes([
        raw[F2FS_CP_NEXT_FREE_NID_OFF],
        raw[F2FS_CP_NEXT_FREE_NID_OFF + 1],
        raw[F2FS_CP_NEXT_FREE_NID_OFF + 2],
        raw[F2FS_CP_NEXT_FREE_NID_OFF + 3],
    ]);
    let valid_block_count = u32::from_le_bytes([
        raw[F2FS_CP_VALID_BLOCK_COUNT_OFF],
        raw[F2FS_CP_VALID_BLOCK_COUNT_OFF + 1],
        raw[F2FS_CP_VALID_BLOCK_COUNT_OFF + 2],
        raw[F2FS_CP_VALID_BLOCK_COUNT_OFF + 3],
    ]);
    let valid_node_count = u32::from_le_bytes([
        raw[F2FS_CP_VALID_NODE_COUNT_OFF],
        raw[F2FS_CP_VALID_NODE_COUNT_OFF + 1],
        raw[F2FS_CP_VALID_NODE_COUNT_OFF + 2],
        raw[F2FS_CP_VALID_NODE_COUNT_OFF + 3],
    ]);
    let valid_inode_count = u32::from_le_bytes([
        raw[F2FS_CP_VALID_INODE_COUNT_OFF],
        raw[F2FS_CP_VALID_INODE_COUNT_OFF + 1],
        raw[F2FS_CP_VALID_INODE_COUNT_OFF + 2],
        raw[F2FS_CP_VALID_INODE_COUNT_OFF + 3],
    ]);
    let nat_journal_entries = u32::from_le_bytes([
        raw[F2FS_CP_NAT_JOURNAL_COUNT_OFF],
        raw[F2FS_CP_NAT_JOURNAL_COUNT_OFF + 1],
        raw[F2FS_CP_NAT_JOURNAL_COUNT_OFF + 2],
        raw[F2FS_CP_NAT_JOURNAL_COUNT_OFF + 3],
    ]);
    let sit_journal_entries = u32::from_le_bytes([
        raw[F2FS_CP_SIT_JOURNAL_COUNT_OFF],
        raw[F2FS_CP_SIT_JOURNAL_COUNT_OFF + 1],
        raw[F2FS_CP_SIT_JOURNAL_COUNT_OFF + 2],
        raw[F2FS_CP_SIT_JOURNAL_COUNT_OFF + 3],
    ]);

    // Parse NAT journal entries (each 12 bytes: nid=4 + ne=8).
    let mut nat_journal = Vec::with_capacity(core::cmp::min(
        nat_journal_entries as usize,
        F2FS_MAX_NAT_JOURNAL_ENTRIES,
    ));
    let mut offset = F2FS_CP_NAT_JOURNAL_OFF;
    for _ in 0..nat_journal_entries as usize {
        if offset + 12 > raw.len() {
            break;
        }
        let nid = u32::from_le_bytes([
            raw[offset],
            raw[offset + 1],
            raw[offset + 2],
            raw[offset + 3],
        ]);
        let ne = parse_nat_entry(&raw[offset + 4..offset + 12]);
        nat_journal.push(NatJournalEntry { nid, ne });
        offset += 12;
    }

    // For v1 we don't parse SIT journal entries (they follow the NAT
    // journal with a similar layout).  We simply track the count.
    let sit_journal = Vec::new();

    F2fsCheckpoint {
        check_ver,
        nat_ver,
        sit_ver,
        next_free_nid,
        valid_block_count,
        valid_node_count,
        valid_inode_count,
        nat_journal_entries,
        nat_journal,
        sit_journal_entries,
        sit_journal,
        orphan_inodes: Vec::new(),
        cp_copy,
    }
}

/// Serialise a [`F2fsCheckpoint`] into a raw 4096-byte block.
pub(crate) fn write_f2fs_checkpoint(cp: &F2fsCheckpoint, raw: &mut [u8]) {
    raw[F2FS_CP_CHECK_VER_OFF..F2FS_CP_CHECK_VER_OFF + 8]
        .copy_from_slice(&cp.check_ver.to_le_bytes());
    raw[F2FS_CP_NAT_VER_OFF..F2FS_CP_NAT_VER_OFF + 8].copy_from_slice(&cp.nat_ver.to_le_bytes());
    raw[F2FS_CP_SIT_VER_OFF..F2FS_CP_SIT_VER_OFF + 8].copy_from_slice(&cp.sit_ver.to_le_bytes());
    raw[F2FS_CP_NEXT_FREE_NID_OFF..F2FS_CP_NEXT_FREE_NID_OFF + 4]
        .copy_from_slice(&cp.next_free_nid.to_le_bytes());
    raw[F2FS_CP_VALID_BLOCK_COUNT_OFF..F2FS_CP_VALID_BLOCK_COUNT_OFF + 4]
        .copy_from_slice(&cp.valid_block_count.to_le_bytes());
    raw[F2FS_CP_VALID_NODE_COUNT_OFF..F2FS_CP_VALID_NODE_COUNT_OFF + 4]
        .copy_from_slice(&cp.valid_node_count.to_le_bytes());
    raw[F2FS_CP_VALID_INODE_COUNT_OFF..F2FS_CP_VALID_INODE_COUNT_OFF + 4]
        .copy_from_slice(&cp.valid_inode_count.to_le_bytes());

    // Serialise NAT journal entries.
    let nat_count = cp.nat_journal.len() as u32;
    raw[F2FS_CP_NAT_JOURNAL_COUNT_OFF..F2FS_CP_NAT_JOURNAL_COUNT_OFF + 4]
        .copy_from_slice(&nat_count.to_le_bytes());
    let mut offset = F2FS_CP_NAT_JOURNAL_OFF;
    for entry in &cp.nat_journal {
        if offset + 12 > raw.len() {
            break;
        }
        raw[offset..offset + 4].copy_from_slice(&entry.nid.to_le_bytes());
        write_nat_entry(&entry.ne, &mut raw[offset + 4..offset + 12]);
        offset += 12;
    }

    // SIT journal count (entries not serialised for v1).
    raw[F2FS_CP_SIT_JOURNAL_COUNT_OFF..F2FS_CP_SIT_JOURNAL_COUNT_OFF + 4]
        .copy_from_slice(&cp.sit_journal_entries.to_le_bytes());
}

// ─── F2FS Inode ───────────────────────────────────────────────────────

/// An F2FS inode, occupying exactly one 4 KiB block on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct F2fsInode {
    /// File type + permission bits.
    pub(crate) i_mode: u16,
    /// Owner user ID.
    pub(crate) i_uid: u32,
    /// Owner group ID.
    pub(crate) i_gid: u32,
    /// Hard-link count.
    pub(crate) i_links: u32,
    /// File size in bytes.
    pub(crate) i_size: u64,
    /// Block count in 512-byte sectors.
    pub(crate) i_blocks: u64,
    /// Access time (seconds).
    pub(crate) i_atime: u64,
    /// Change time (seconds).
    pub(crate) i_ctime: u64,
    /// Modification time (seconds).
    pub(crate) i_mtime: u64,
    /// Access time (nanoseconds component).
    pub(crate) i_atime_nsec: u32,
    /// Change time (nanoseconds component).
    pub(crate) i_ctime_nsec: u32,
    /// Modification time (nanoseconds component).
    pub(crate) i_mtime_nsec: u32,
    /// Extended attribute NID (0 if unused).
    pub(crate) i_xattr_nid: u32,
    /// Inode flags.
    pub(crate) i_flags: u32,
    /// Direct block addresses.  0 = hole, 0xFFFFFFFF = newly allocated.
    pub(crate) i_addr: [u32; F2FS_ADDRS_PER_INODE],
}

impl F2fsInode {
    /// Return the [`NodeKind`] derived from `i_mode`.
    pub(crate) fn kind(&self) -> NodeKind {
        match self.i_mode & F2FS_S_IFMT {
            F2FS_S_IFDIR => NodeKind::Directory,
            F2FS_S_IFREG => NodeKind::File,
            F2FS_S_IFCHR | F2FS_S_IFBLK => NodeKind::Device,
            F2FS_S_IFLNK => NodeKind::Symlink,
            _ => NodeKind::File,
        }
    }

    /// File size in bytes.
    pub(crate) fn file_size(&self) -> u64 {
        self.i_size
    }

    /// Permission bits only (lower 12 bits of `i_mode`).
    pub(crate) fn permission_mode(&self) -> u16 {
        self.i_mode & 0o777
    }
}

/// Parse an [`F2fsInode`] from a 4096-byte raw inode block.
pub(crate) fn parse_f2fs_inode(raw: &[u8]) -> F2fsInode {
    let i_mode = u16::from_le_bytes([raw[F2FS_INODE_MODE_OFF], raw[F2FS_INODE_MODE_OFF + 1]]);
    let i_uid = u32::from_le_bytes([
        raw[F2FS_INODE_UID_OFF],
        raw[F2FS_INODE_UID_OFF + 1],
        raw[F2FS_INODE_UID_OFF + 2],
        raw[F2FS_INODE_UID_OFF + 3],
    ]);
    let i_gid = u32::from_le_bytes([
        raw[F2FS_INODE_GID_OFF],
        raw[F2FS_INODE_GID_OFF + 1],
        raw[F2FS_INODE_GID_OFF + 2],
        raw[F2FS_INODE_GID_OFF + 3],
    ]);
    let i_links = u32::from_le_bytes([
        raw[F2FS_INODE_LINKS_OFF],
        raw[F2FS_INODE_LINKS_OFF + 1],
        raw[F2FS_INODE_LINKS_OFF + 2],
        raw[F2FS_INODE_LINKS_OFF + 3],
    ]);
    let i_size = u64::from_le_bytes([
        raw[F2FS_INODE_SIZE_OFF],
        raw[F2FS_INODE_SIZE_OFF + 1],
        raw[F2FS_INODE_SIZE_OFF + 2],
        raw[F2FS_INODE_SIZE_OFF + 3],
        raw[F2FS_INODE_SIZE_OFF + 4],
        raw[F2FS_INODE_SIZE_OFF + 5],
        raw[F2FS_INODE_SIZE_OFF + 6],
        raw[F2FS_INODE_SIZE_OFF + 7],
    ]);
    let i_blocks = u64::from_le_bytes([
        raw[F2FS_INODE_BLOCKS_OFF],
        raw[F2FS_INODE_BLOCKS_OFF + 1],
        raw[F2FS_INODE_BLOCKS_OFF + 2],
        raw[F2FS_INODE_BLOCKS_OFF + 3],
        raw[F2FS_INODE_BLOCKS_OFF + 4],
        raw[F2FS_INODE_BLOCKS_OFF + 5],
        raw[F2FS_INODE_BLOCKS_OFF + 6],
        raw[F2FS_INODE_BLOCKS_OFF + 7],
    ]);
    let i_atime = u64::from_le_bytes([
        raw[F2FS_INODE_ATIME_OFF],
        raw[F2FS_INODE_ATIME_OFF + 1],
        raw[F2FS_INODE_ATIME_OFF + 2],
        raw[F2FS_INODE_ATIME_OFF + 3],
        raw[F2FS_INODE_ATIME_OFF + 4],
        raw[F2FS_INODE_ATIME_OFF + 5],
        raw[F2FS_INODE_ATIME_OFF + 6],
        raw[F2FS_INODE_ATIME_OFF + 7],
    ]);
    let i_ctime = u64::from_le_bytes([
        raw[F2FS_INODE_CTIME_OFF],
        raw[F2FS_INODE_CTIME_OFF + 1],
        raw[F2FS_INODE_CTIME_OFF + 2],
        raw[F2FS_INODE_CTIME_OFF + 3],
        raw[F2FS_INODE_CTIME_OFF + 4],
        raw[F2FS_INODE_CTIME_OFF + 5],
        raw[F2FS_INODE_CTIME_OFF + 6],
        raw[F2FS_INODE_CTIME_OFF + 7],
    ]);
    let i_mtime = u64::from_le_bytes([
        raw[F2FS_INODE_MTIME_OFF],
        raw[F2FS_INODE_MTIME_OFF + 1],
        raw[F2FS_INODE_MTIME_OFF + 2],
        raw[F2FS_INODE_MTIME_OFF + 3],
        raw[F2FS_INODE_MTIME_OFF + 4],
        raw[F2FS_INODE_MTIME_OFF + 5],
        raw[F2FS_INODE_MTIME_OFF + 6],
        raw[F2FS_INODE_MTIME_OFF + 7],
    ]);
    let i_atime_nsec = u32::from_le_bytes([
        raw[F2FS_INODE_ATIME_NSEC_OFF],
        raw[F2FS_INODE_ATIME_NSEC_OFF + 1],
        raw[F2FS_INODE_ATIME_NSEC_OFF + 2],
        raw[F2FS_INODE_ATIME_NSEC_OFF + 3],
    ]);
    let i_ctime_nsec = u32::from_le_bytes([
        raw[F2FS_INODE_CTIME_NSEC_OFF],
        raw[F2FS_INODE_CTIME_NSEC_OFF + 1],
        raw[F2FS_INODE_CTIME_NSEC_OFF + 2],
        raw[F2FS_INODE_CTIME_NSEC_OFF + 3],
    ]);
    let i_mtime_nsec = u32::from_le_bytes([
        raw[F2FS_INODE_MTIME_NSEC_OFF],
        raw[F2FS_INODE_MTIME_NSEC_OFF + 1],
        raw[F2FS_INODE_MTIME_NSEC_OFF + 2],
        raw[F2FS_INODE_MTIME_NSEC_OFF + 3],
    ]);
    let i_xattr_nid = u32::from_le_bytes([
        raw[F2FS_INODE_XATTR_NID_OFF],
        raw[F2FS_INODE_XATTR_NID_OFF + 1],
        raw[F2FS_INODE_XATTR_NID_OFF + 2],
        raw[F2FS_INODE_XATTR_NID_OFF + 3],
    ]);
    let i_flags = u32::from_le_bytes([
        raw[F2FS_INODE_FLAGS_OFF],
        raw[F2FS_INODE_FLAGS_OFF + 1],
        raw[F2FS_INODE_FLAGS_OFF + 2],
        raw[F2FS_INODE_FLAGS_OFF + 3],
    ]);

    let mut i_addr = [0u32; F2FS_ADDRS_PER_INODE];
    #[allow(clippy::needless_range_loop)]
    for i in 0..F2FS_ADDRS_PER_INODE {
        let off = F2FS_INODE_ADDR_OFF + i * 4;
        i_addr[i] = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
    }

    F2fsInode {
        i_mode,
        i_uid,
        i_gid,
        i_links,
        i_size,
        i_blocks,
        i_atime,
        i_ctime,
        i_mtime,
        i_atime_nsec,
        i_ctime_nsec,
        i_mtime_nsec,
        i_xattr_nid,
        i_flags,
        i_addr,
    }
}

/// Serialise an [`F2fsInode`] into a 4096-byte raw buffer.
pub(crate) fn write_f2fs_inode(inode: &F2fsInode, raw: &mut [u8]) {
    raw[F2FS_INODE_MODE_OFF..F2FS_INODE_MODE_OFF + 2].copy_from_slice(&inode.i_mode.to_le_bytes());
    raw[F2FS_INODE_UID_OFF..F2FS_INODE_UID_OFF + 4].copy_from_slice(&inode.i_uid.to_le_bytes());
    raw[F2FS_INODE_GID_OFF..F2FS_INODE_GID_OFF + 4].copy_from_slice(&inode.i_gid.to_le_bytes());
    raw[F2FS_INODE_LINKS_OFF..F2FS_INODE_LINKS_OFF + 4]
        .copy_from_slice(&inode.i_links.to_le_bytes());
    raw[F2FS_INODE_SIZE_OFF..F2FS_INODE_SIZE_OFF + 8].copy_from_slice(&inode.i_size.to_le_bytes());
    raw[F2FS_INODE_BLOCKS_OFF..F2FS_INODE_BLOCKS_OFF + 8]
        .copy_from_slice(&inode.i_blocks.to_le_bytes());
    raw[F2FS_INODE_ATIME_OFF..F2FS_INODE_ATIME_OFF + 8]
        .copy_from_slice(&inode.i_atime.to_le_bytes());
    raw[F2FS_INODE_CTIME_OFF..F2FS_INODE_CTIME_OFF + 8]
        .copy_from_slice(&inode.i_ctime.to_le_bytes());
    raw[F2FS_INODE_MTIME_OFF..F2FS_INODE_MTIME_OFF + 8]
        .copy_from_slice(&inode.i_mtime.to_le_bytes());
    raw[F2FS_INODE_ATIME_NSEC_OFF..F2FS_INODE_ATIME_NSEC_OFF + 4]
        .copy_from_slice(&inode.i_atime_nsec.to_le_bytes());
    raw[F2FS_INODE_CTIME_NSEC_OFF..F2FS_INODE_CTIME_NSEC_OFF + 4]
        .copy_from_slice(&inode.i_ctime_nsec.to_le_bytes());
    raw[F2FS_INODE_MTIME_NSEC_OFF..F2FS_INODE_MTIME_NSEC_OFF + 4]
        .copy_from_slice(&inode.i_mtime_nsec.to_le_bytes());
    raw[F2FS_INODE_XATTR_NID_OFF..F2FS_INODE_XATTR_NID_OFF + 4]
        .copy_from_slice(&inode.i_xattr_nid.to_le_bytes());
    raw[F2FS_INODE_FLAGS_OFF..F2FS_INODE_FLAGS_OFF + 4]
        .copy_from_slice(&inode.i_flags.to_le_bytes());

    for i in 0..F2FS_ADDRS_PER_INODE {
        let off = F2FS_INODE_ADDR_OFF + i * 4;
        raw[off..off + 4].copy_from_slice(&inode.i_addr[i].to_le_bytes());
    }
}

// ─── Directory Entry ──────────────────────────────────────────────────

/// Parsed F2FS directory entry.
#[derive(Debug, Clone)]
pub(crate) struct F2fsDirEntry {
    /// Child inode NID.
    pub(crate) ino: u32,
    /// File type code (F2FS_FT_*).
    pub(crate) file_type: u8,
    /// Decoded filename.
    pub(crate) name: String,
}

/// Parse all directory entries from a raw data block.
///
/// F2FS directory entries use a compact variable-length on-disk format:
///   [0..2]   rec_len: u16       total record length (aligned to 4 bytes)
///   [2..4]   name_len: u16      filename length in bytes
///   [4]      file_type: u8      F2FS_FT_*
///   [5..9]   hash_code: u32     filename hash
///   [9..13]  ino: u32           child NID
///   [13..]   name: [u8; name_len]
///
/// Deleted entries have `ino == 0` and are skipped.
pub(crate) fn parse_f2fs_dir_entries(data: &[u8]) -> Vec<F2fsDirEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset + 13 <= data.len() {
        let rec_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        if rec_len < 13 || rec_len == 0 {
            break;
        }
        let name_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let file_type = data[offset + 4];
        let ino = u32::from_le_bytes([
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
        ]);

        // A directory entry with ino==0 is a deleted (freed) entry; skip.
        if ino != 0 && name_len <= rec_len.saturating_sub(13) {
            let name_bytes = &data[offset + 13..offset + 13 + name_len];
            let name = String::from_utf8_lossy(name_bytes).to_string();
            entries.push(F2fsDirEntry {
                ino,
                file_type,
                name,
            });
        }

        offset += rec_len;
    }

    entries
}

/// Compute the on-disk size of a directory entry given the filename.
/// Minimum entry is 13 bytes (header) + name_len, rounded up to 4-byte
/// alignment.
pub(crate) fn dir_entry_size(name_len: usize) -> usize {
    let raw = 13usize + name_len;
    (raw + 3) & !3 // round up to multiple of 4
}

/// Serialise a single directory entry into a buffer.  Returns the number
/// of bytes written.
pub(crate) fn write_f2fs_dir_entry(
    ino: u32,
    name: &str,
    file_type: u8,
    hash_code: u32,
    buf: &mut [u8],
) -> usize {
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len();
    let rec_len = dir_entry_size(name_len);

    // rec_len (u16 LE)
    buf[0..2].copy_from_slice(&(rec_len as u16).to_le_bytes());
    // name_len (u16 LE)
    buf[2..4].copy_from_slice(&(name_len as u16).to_le_bytes());
    // file_type (u8)
    buf[4] = file_type;
    // hash_code (u32 LE)
    buf[5..9].copy_from_slice(&hash_code.to_le_bytes());
    // ino (u32 LE)
    buf[9..13].copy_from_slice(&ino.to_le_bytes());
    // name bytes
    let copy_len = core::cmp::min(name_len, rec_len.saturating_sub(13));
    buf[13..13 + copy_len].copy_from_slice(&name_bytes[..copy_len]);
    // Zero out the rest of the record
    for b in buf[13 + copy_len..rec_len].iter_mut() {
        *b = 0;
    }

    rec_len
}

// ─── Memory Caches ────────────────────────────────────────────────────

/// In-memory NAT cache — maps NID → block address.
#[derive(Debug, Clone)]
pub(crate) struct F2fsNatCache {
    /// Entries indexed by NID.  entry.block_addr == 0 means the NID is
    /// free and available for allocation.
    pub(crate) entries: Vec<F2fsNatEntry>,
}

/// In-memory SIT cache — tracks validity for each segment.
#[derive(Debug, Clone)]
pub(crate) struct F2fsSitCache {
    /// Entries indexed by segment number.
    pub(crate) entries: Vec<F2fsSitEntry>,
    /// Segment numbers whose `vblocks == 0` (fully free).
    pub(crate) free_segments: Vec<u32>,
}
