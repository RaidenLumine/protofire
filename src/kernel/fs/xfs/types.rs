//! src/kernel/fs/xfs/types.rs
//!
//! On-disk data structures for XFS (v4/v5).

use alloc::vec::Vec;

// ── Superblock ──────────────────────────────────────────────────────────────

pub const XFS_SUPER_MAGIC: u32 = 0x5846_5342; // "XFSB"

/// v5 ("CRC-enabled") superblock has bit 3 set in sb_versionnum.
pub const XFS_SB_VERSION_5: u16 = 0x0008;

/// Data fork offset within the inode buffer:
/// v4 inodes have the data fork at byte 100 (after di_next_unlinked),
/// v5 inodes have it at byte 176 (after di_crc, di_changecount, di_lsn,
/// di_flags2, di_cowextsize, di_crtime, and padding).
pub const XFS_INODE_DATA_FORK_OFFSET_V4: usize = 100;
pub const XFS_INODE_DATA_FORK_OFFSET_V5: usize = 176;

/// Long-format B+tree block (xfs_btree_lblock) record offset.
/// v4: magic(4) + level(2) + numrecs(2) + leftsib(8) + rightsib(8) + blkno(8) =
/// 32 v5: v4(32) + crc(4) + uuid(16) + owner(8) + lsn(8) = 56 (blkno moved, lsn
/// added)     Actually v5 layout:
/// magic(4)+level(2)+numrecs(2)+crc(4)+uuid(16)+owner(8)+blkno(8)+lsn(8)=56
pub const XFS_BTREE_LBLOCK_REC_OFFSET_V4: usize = 32;
pub const XFS_BTREE_LBLOCK_REC_OFFSET_V5: usize = 56;

/// BMAP B+tree block magic — v4.
pub const XFS_BMAP_MAGIC_V4: u32 = 0x424D_4150; // "BMAP"
/// BMAP B+tree block magic — v5 (CRC-enabled).
pub const XFS_BMAP_MAGIC_V5: u32 = 0x424D_4133; // "BMA3"

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Superblock {
    pub magic: u32,
    pub block_size: u32,
    pub blocks_per_ag: u32,
    pub ag_count: u32,
    pub root_ino: u64,
    pub inode_size: u16,
    pub inodes_per_block: u16,
    pub features2: u32,
    pub sector_size: u32,
    pub log_blocks: u32,
    pub log_start: u64,
    pub versionnum: u16,
    pub features_incompat: u32,
    pub features_log: u16,
    pub features_ro_compat: u32,
    pub sb_meta_uuid: [u8; 16],
}

impl Superblock {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 256 {
            return None;
        }
        let magic = be32(buf, 0);
        if magic != XFS_SUPER_MAGIC {
            return None;
        }
        let versionnum = be16(buf, 0x68);
        let is_v5 = versionnum & XFS_SB_VERSION_5 != 0;
        // For v5, the superblock is always 512 bytes and includes CRC + UUID
        // at offsets 224 and 248.  For v4, these fields are zero / undefined.
        let features_ro_compat = if buf.len() > 212 { be32(buf, 212) } else { 0 };
        let mut meta_uuid = [0u8; 16];
        if is_v5 && buf.len() >= 264 {
            meta_uuid.copy_from_slice(&buf[248..264]);
        }
        Some(Self {
            magic,
            block_size: be32(buf, 4),
            blocks_per_ag: be32(buf, 20),
            ag_count: be32(buf, 24),
            root_ino: be64(buf, 8),
            inode_size: be16(buf, 100),
            inodes_per_block: be16(buf, 102),
            features2: be32(buf, 114),
            sector_size: be32(buf, 120),
            log_blocks: be32(buf, 148),
            log_start: be64(buf, 140),
            versionnum,
            features_incompat: be32(buf, 128),
            features_log: be16(buf, 0xAC),
            features_ro_compat,
            sb_meta_uuid: meta_uuid,
        })
    }

    /// Returns `true` if this is a v5 (CRC-enabled) filesystem.
    pub fn is_v5(&self) -> bool {
        self.versionnum & XFS_SB_VERSION_5 != 0
    }

    /// Byte offset in the inode buffer where the data fork starts.
    pub fn inode_data_offset(&self) -> usize {
        if self.is_v5() {
            XFS_INODE_DATA_FORK_OFFSET_V5
        } else {
            XFS_INODE_DATA_FORK_OFFSET_V4
        }
    }

    /// Byte offset in a long-format B+tree block where records start.
    pub fn btree_lblock_rec_offset(&self) -> usize {
        if self.is_v5() {
            XFS_BTREE_LBLOCK_REC_OFFSET_V5
        } else {
            XFS_BTREE_LBLOCK_REC_OFFSET_V4
        }
    }

    /// BMAP B+tree block magic for this filesystem version.
    pub fn bmap_magic(&self) -> u32 {
        if self.is_v5() {
            XFS_BMAP_MAGIC_V5
        } else {
            XFS_BMAP_MAGIC_V4
        }
    }
}

// ── Journal info ─────────────────────────────────────────────────────────────

/// Parsed journal metadata.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct JournalInfo {
    /// Whether the filesystem has an internal journal.
    pub has_journal: bool,
    /// Whether the journal needs replay (dirty unmount).
    pub is_dirty: bool,
    /// Starting block of the journal.
    pub log_start: u64,
    /// Size of the journal in blocks.
    pub log_blocks: u32,
    /// Journal format version: 1 = v4, 2 = v5.
    pub log_version: u8,
}

// ── AG structures ───────────────────────────────────────────────────────────

// Spec constant — reserved for AGF parsing.
#[allow(dead_code)]
pub const XFS_AGF_MAGIC: u32 = 0x5841_4746; // "XAGF"

// ── B+tree structures ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BtreeBlock {
    pub magic: u32,
    pub level: u16,
    pub num_recs: u16,
    pub data: Vec<u8>,
}

impl BtreeBlock {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 {
            return None;
        }
        let magic = be32(buf, 0);
        let level = be16(buf, 4);
        let num_recs = be16(buf, 6);
        let data = buf[16..].to_vec();
        Some(Self {
            magic,
            level,
            num_recs,
            data,
        })
    }

    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    pub fn is_btree_node(&self) -> bool {
        self.magic == 0x424D_4150 || self.magic == 0x4142_3342 || self.magic == 0x424E_4F43
    }
}

#[derive(Debug, Clone)]
pub struct BtreeRecord {
    pub key: u32,
    pub block: u32,
}

/// Parse 32-bit-key B+tree records.
pub fn parse_btree_records(data: &[u8], num_recs: usize, rec_size: usize) -> Vec<BtreeRecord> {
    let mut recs = Vec::with_capacity(num_recs);
    for i in 0..num_recs {
        let off = i * rec_size;
        if off + 8 > data.len() {
            break;
        }
        recs.push(BtreeRecord {
            key: be32(data, off),
            block: be32(data, off + 4),
        });
    }
    recs
}

// ── Inode ───────────────────────────────────────────────────────────────────

pub const XFS_INODE_MAGIC: u16 = 0x494E;
pub const XFS_DINODE_FMT_LOCAL: u8 = 0;
pub const XFS_DINODE_FMT_EXTENTS: u8 = 1;
pub const XFS_DINODE_FMT_BTREE: u8 = 2;

/// v5 (CRC-enabled) inode version number (`di_version = 3`).
pub const XFS_DINODE_VERSION_5: u8 = 3;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct InodeCore {
    pub magic: u16,
    pub mode: u16,
    pub version: u8,
    pub format: u8,
    pub attr_format: u8,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    pub num_extents: u32,
    /// Number of attribute fork extents (`di_anextents`).  Only meaningful
    /// when `attr_format` is [`XFS_DINODE_FMT_EXTENTS`].
    pub attr_num_extents: u16,
    pub fork_offset: u16,
    pub is_v5: bool,
}

impl InodeCore {
    pub fn parse(buf: &[u8], _inode_size: usize) -> Option<Self> {
        if buf.len() < 100 {
            return None;
        }
        let magic = be16(buf, 0);
        if magic != XFS_INODE_MAGIC {
            return None;
        }
        let version = buf[4];
        let is_v5 = version == XFS_DINODE_VERSION_5;
        let fork_offset = be16(buf, 20);
        let attr_num_extents = if buf.len() > 37 {
            u16::from_be_bytes([buf[36], buf[37]])
        } else {
            0
        };
        Some(Self {
            magic,
            mode: be16(buf, 2),
            version,
            format: buf[5],
            attr_format: buf[6],
            uid: be32(buf, 8),
            gid: be32(buf, 12),
            nlink: be32(buf, 16),
            size: be64(buf, 24),
            num_extents: be32(buf, 32),
            attr_num_extents,
            fork_offset,
            is_v5,
        })
    }

    /// Return the byte range of the attribute fork within the inode buffer.
    /// Returns `None` if there is no attribute fork.
    pub fn attr_fork_range(&self, inode_size: usize) -> Option<(usize, usize)> {
        let fo = self.fork_offset as usize;
        if fo == 0 || fo >= inode_size {
            return None;
        }
        Some((fo, inode_size))
    }

    /// Return the byte range of the data fork within the inode buffer.
    /// Data fork always starts at byte 100 and extends to `fork_offset`
    /// (or to the end of the inode if `fork_offset == 0`).
    #[allow(dead_code)]
    pub fn data_fork_range(&self, inode_size: usize) -> (usize, usize) {
        let start = 100;
        let end = if self.fork_offset == 0 {
            inode_size
        } else {
            self.fork_offset as usize
        };
        (start, end)
    }

    pub fn is_dir(&self) -> bool {
        self.mode & 0o040000 != 0
    }

    pub fn file_type(&self) -> u16 {
        self.mode & 0o170000
    }
}

// ── Extents ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Extent {
    pub start_block: u64,
    pub block_count: u64,
    pub start_offset: u64,
}

/// Parse extent list from inode's data/attr fork (16-byte records).
///
/// Each record is 16 bytes:
/// ```text
/// bytes 0-7:  start_offset (u64 BE, bit 7 of byte 0 = hi flag)
/// bytes 8-11: start_block low 32 bits (u32 BE)
/// bytes 12-15: block_count (u32 BE)
/// ```
/// The upper 2 bits of start_block come from bits 5-6 of byte 0,
/// giving a total of 34 bits for the physical block number.
pub fn parse_extents(buf: &[u8], fork_offset: usize, num_extents: u32) -> Vec<Extent> {
    let mut extents = Vec::with_capacity(num_extents as usize);
    let num = num_extents as usize;
    for i in 0..num {
        let off = fork_offset + i * 16;
        if off + 16 > buf.len() {
            break;
        }
        let start_off_lo = be64(buf, off);
        let start_block_lo = be32(buf, off + 8) as u64;
        let start_off_hi: u64 = (buf[off] as u64 >> 7) & 0x01;
        let start_block_hi: u64 = (buf[off] as u64 >> 6) & 0x03;
        let block_count = be32(buf, off + 12) as u64;

        let start_block = start_block_lo | (start_block_hi << 32);
        let start_offset = start_off_lo | (start_off_hi << 63);

        extents.push(Extent {
            start_block,
            block_count,
            start_offset,
        });
    }
    extents
}

// ── Directory entries ───────────────────────────────────────────────────────

/// Directory DA-blkinfo magic constants (u16 at offset 8 in xfs_da_blkinfo_t).
#[allow(dead_code)]
pub const XFS_DIR2_LEAF1_MAGIC: u16 = 0xd2f1; // v4 leaf format (single-leaf dir)
#[allow(dead_code)]
pub const XFS_DIR2_LEAFN_MAGIC: u16 = 0xd2ff; // v4 leaf in node-format dir
#[allow(dead_code)]
pub const XFS_DA_NODE_MAGIC: u16 = 0xfebe; // v4 directory/attr node block

/// Attribute leaf block magic (v4).
#[allow(dead_code)]
pub(crate) const XFS_ATTR_LEAF_MAGIC: u16 = 0xfbee;

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub inode: u64,
    pub name: Vec<u8>,
}

/// Parse shortform directory entries from inode's data fork.
pub fn parse_shortform_dir(data: &[u8], offset: usize) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    if offset + 4 > data.len() {
        return entries;
    }
    let _parent_ino = be64(data, offset);
    let count = data[offset + 8] as usize;
    let mut pos = offset + 12;

    for _ in 0..count {
        if pos + 3 > data.len() {
            break;
        }
        let name_len = data[pos] as usize;
        let ino = be64(data, pos + 2);
        pos += 10;
        if pos + name_len > data.len() {
            break;
        }
        let name = data[pos..pos + name_len].to_vec();
        entries.push(DirEntry { inode: ino, name });
        pos += name_len;
    }
    entries
}

/// Parse a single xfs_dir2_data_entry at the given byte offset within a
/// directory data block.  Returns `None` if the offset or data is out of
/// bounds.
pub(crate) fn parse_data_entry_at(data: &[u8], offset: usize) -> Option<DirEntry> {
    if offset + 24 > data.len() {
        return None;
    }
    let entry_len = be16(data, offset + 4) as usize;
    if entry_len == 0 || offset + entry_len > data.len() {
        return None;
    }
    let name_len = data[offset + 10] as usize;
    if name_len == 0 || offset + 24 + name_len > data.len() {
        return None;
    }
    let inode = be64(data, offset + 16);
    let name_start = offset + 24;
    let name = data[name_start..name_start + name_len].to_vec();
    Some(DirEntry { inode, name })
}

/// Parse block-format directory entries from a directory block.
pub fn parse_block_dir(data: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset + 16 <= data.len() {
        let entry_len = be16(data, offset + 4) as usize;
        if entry_len == 0 || offset + entry_len > data.len() {
            offset += 8;
            if offset >= data.len() {
                break;
            }
            continue;
        }
        if let Some(entry) = parse_data_entry_at(data, offset) {
            entries.push(entry);
        }
        offset += entry_len;
    }
    entries
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn be16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}
pub(crate) fn be32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
pub(crate) fn be64(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}
