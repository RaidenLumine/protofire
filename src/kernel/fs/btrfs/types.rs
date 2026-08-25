//! src/kernel/fs/btrfs/types.rs
//!
//! Btrfs on-disk structures and parsers.
//! On-disk data structures for Btrfs.
//!
//! Reference: <https://btrfs.readthedocs.io/en/latest/On-disk-Format.html>

//
// NOTE: The Btrfs driver is a work-in-progress.  This file defines the
// complete on-disk format, but only a subset of fields are wired through.
// The module-level annotation below suppresses dead-code warnings on
// intentionally-defined-but-not-yet-used structures.
#![allow(dead_code)]

use alloc::vec::Vec;

// ── Superblock ────────────────────────────────────────────────────────────

pub const BTRFS_MAGIC: [u8; 8] = *b"_BHRfS_M";
pub const SUPERBLOCK_OFFSET: u64 = 0x10000; // 64 KiB
pub const SUPERBLOCK_SIZE: usize = 4096;

#[derive(Debug, Clone)]
pub struct Superblock {
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub generation: u64,
    pub root_tree_root: u64,
    pub chunk_tree_root: u64,
    pub log_tree_root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sector_size: u32,
    pub node_size: u32,
    pub leaf_size: u32,
    pub stripe_size: u32,
    pub chunk_root_gen: u64,
    pub compat_flags: u64,
    pub incompat_flags: u64,
    /// Checksum type: 0 = CRC32C (the only type currently verified).
    pub csum_type: u16,
}

impl Superblock {
    pub fn parse(buf: &[u8; SUPERBLOCK_SIZE]) -> Option<Self> {
        if buf[0x40..0x48] != BTRFS_MAGIC {
            return None;
        }
        Some(Self {
            fsid: buf[0x20..0x30].try_into().ok()?,
            bytenr: get_u64(buf, 0x30),
            generation: get_u64(buf, 0x38),
            root_tree_root: get_u64(buf, 0x48),
            chunk_tree_root: get_u64(buf, 0x50),
            log_tree_root: get_u64(buf, 0x58),
            total_bytes: get_u64(buf, 0x60),
            bytes_used: get_u64(buf, 0x68),
            root_dir_objectid: get_u64(buf, 0x70),
            num_devices: get_u64(buf, 0x78),
            sector_size: get_u32(buf, 0x88),
            node_size: get_u32(buf, 0x8C),
            leaf_size: get_u32(buf, 0x90),
            stripe_size: get_u32(buf, 0x9C),
            chunk_root_gen: get_u64(buf, 0xB0),
            compat_flags: get_u64(buf, 0xB8),
            incompat_flags: get_u64(buf, 0xC0),
            csum_type: get_u16(buf, 0xD4),
        })
    }
}

// ── B-tree structures ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub objectid: u64,
    pub ty: u8,
    pub offset: u64,
}

impl Key {
    pub const RAW_SIZE: usize = 17;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 17 {
            return None;
        }
        Some(Self {
            objectid: get_u64(buf, 0),
            ty: buf[8],
            offset: get_u64(buf, 9),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Item {
    pub key: Key,
    pub data_offset: u32,
    pub data_size: u32,
}

pub const ITEM_HEADER_SIZE: usize = 25;

impl Item {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 25 {
            return None;
        }
        Some(Self {
            key: Key::parse(buf)?,
            data_offset: get_u32(buf, 17),
            data_size: get_u32(buf, 21),
        })
    }
}

#[derive(Debug, Clone)]
pub struct NodeHeader {
    pub bytenr: u64,
    pub generation: u64,
    pub owner: u64,
    pub nritems: u32,
    pub level: u8,
}

impl NodeHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 101 {
            return None;
        }
        Some(Self {
            bytenr: get_u64(buf, 64),
            generation: get_u64(buf, 72),
            owner: get_u64(buf, 80),
            nritems: get_u32(buf, 88),
            level: buf[92],
        })
    }
}

// ── Key types ─────────────────────────────────────────────────────────────

pub const KEY_INODE_ITEM: u8 = 1;
pub const KEY_EXTENT_DATA: u8 = 108;
pub const KEY_DIR_ITEM: u8 = 84;
pub const KEY_ROOT_ITEM: u8 = 132;
pub const KEY_ROOT_BACKREF: u8 = 144;
pub const KEY_ROOT_REF: u8 = 156;
pub const KEY_DEV_ITEM: u8 = 216;
pub const KEY_CHUNK_ITEM: u8 = 228;

// ── Object IDs ───────────────────────────────────────────────────────────

pub const FS_TREE_OBJECTID: u64 = 5;

// ── Items ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InodeItem {
    pub generation: u64,
    pub transid: u64,
    pub size: u64,
    pub nbytes: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub flags: u64,
}

impl InodeItem {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 160 {
            return None;
        }
        Some(Self {
            generation: get_u64(buf, 0),
            transid: get_u64(buf, 8),
            size: get_u64(buf, 16),
            nbytes: get_u64(buf, 24),
            mode: get_u32(buf, 72),
            uid: get_u32(buf, 80),
            gid: get_u32(buf, 84),
            nlink: get_u32(buf, 88),
            flags: get_u64(buf, 104),
        })
    }

    pub fn is_dir(&self) -> bool {
        self.mode & 0o040000 != 0
    }
    pub fn is_file(&self) -> bool {
        self.mode & 0o100000 != 0
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0o120000 == 0o120000
    }
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub inode: u64,
    pub file_type: u8,
    pub name: Vec<u8>,
}

pub fn parse_dir_entry(buf: &[u8]) -> Option<DirEntry> {
    // btrfs_dir_item layout:
    //   location key (17) + transid (8) + data_len (2) + name_len (2) + type (1)
    //   = 30 bytes before the name.
    if buf.len() < 31 {
        return None;
    }
    let child_key = Key::parse(buf)?;
    let name_len = get_u16(buf, 27) as usize;
    if 30 + name_len > buf.len() {
        return None;
    }
    let name = buf[30..30 + name_len].to_vec();
    let file_type = buf[29];
    Some(DirEntry {
        inode: child_key.objectid,
        file_type,
        name,
    })
}

#[derive(Debug, Clone)]
pub struct ExtentData {
    /// 0 = inline, 1 = regular, 2 = prealloc.
    pub extent_type: u8,
    /// Compression algorithm: 0 = none, 1 = zlib, 2 = lzo, 3 = zstd.
    pub compression: u8,
    /// Uncompressed size (ram_bytes in the on-disk item).
    pub ram_bytes: u64,
    /// Byte address of the on-disk data.
    pub disk_bytenr: u64,
    /// Size of the on-disk data (compressed size when compression != 0).
    pub disk_num_bytes: u64,
    /// Number of uncompressed bytes this extent contributes.
    pub num_bytes: u64,
    /// Logical offset within the file.
    pub offset: u64,
}

impl ExtentData {
    /// Parse a `btrfs_file_extent_item`.
    ///
    /// On-disk layout:
    ///   0-7   generation
    ///   8-15  ram_bytes (uncompressed size)
    ///   16    compression  (0=none, 1=zlib, 2=lzo, 3=zstd)
    ///   17    encryption
    ///   18-19 other_encoding
    ///   20    type         (0=inline, 1=regular, 2=prealloc)
    ///   —— type 1 (regular) ——
    ///   21-28 disk_bytenr
    ///   29-36 disk_num_bytes
    ///   37-44 offset
    ///   45-52 num_bytes
    ///   —— type 0 (inline) ——
    ///   21..  inline data
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 21 {
            return None;
        }
        let _gen = get_u64(buf, 0);
        let ram_bytes = get_u64(buf, 8);
        let compression = buf[16];
        let extent_type = buf[20];
        match extent_type {
            0 => {
                // Inline data: the data follows directly after the header (byte 21).
                let inline_size = (buf.len().saturating_sub(21)) as u64;
                Some(Self {
                    extent_type: 0,
                    compression,
                    ram_bytes,
                    disk_bytenr: 0,
                    disk_num_bytes: inline_size,
                    num_bytes: inline_size,
                    offset: 0,
                })
            }
            1 => {
                if buf.len() < 53 {
                    return None;
                }
                Some(Self {
                    extent_type: 1,
                    compression,
                    ram_bytes,
                    disk_bytenr: get_u64(buf, 21),
                    disk_num_bytes: get_u64(buf, 29),
                    offset: get_u64(buf, 37),
                    num_bytes: get_u64(buf, 45),
                })
            }
            2 => {
                // Prealloc — no data, just a reservation.
                if buf.len() < 53 {
                    return None;
                }
                Some(Self {
                    extent_type: 2,
                    compression,
                    ram_bytes,
                    disk_bytenr: get_u64(buf, 21),
                    disk_num_bytes: get_u64(buf, 29),
                    offset: get_u64(buf, 37),
                    num_bytes: get_u64(buf, 45),
                })
            }
            _ => None,
        }
    }
}

// ── Root item (subvolume metadata) ────────────────────────────────────────

/// Parsed btrfs_root_item — key fields for subvolume traversal.
#[derive(Debug, Clone)]
pub struct RootItem {
    /// Root directory inode number for this subvolume.
    pub root_dirid: u64,
    /// Byte address of the root node of this subvolume's tree.
    pub root_bytenr: u64,
    /// Tree height (0 = leaf-only).
    pub root_level: u8,
    /// Root flags.
    pub flags: u64,
}

impl RootItem {
    /// Parse a btrfs_root_item from raw bytes.
    ///
    /// Layout (offsets within root_item, not the containing leaf):
    ///   inode (btrfs_inode_item) 0-159   (160 bytes)
    ///   generation                160-167
    ///   root_dirid                168-175
    ///   bytenr                    176-183
    ///   byte_limit                184-191
    ///   bytes_used                192-199
    ///   last_snapshot             200-207
    ///   flags                     208-215
    ///   refs                      216-219
    ///   drop_progress (disk_key)  220-236
    ///   drop_level                237
    ///   level                     238
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 240 {
            return None;
        }
        Some(Self {
            root_dirid: get_u64(buf, 168),
            root_bytenr: get_u64(buf, 176),
            flags: get_u64(buf, 208),
            root_level: buf[238],
        })
    }
}

/// Parsed btrfs_dev_item — describes a device in a multi-device filesystem.
///
/// On-disk layout (98 bytes):
///   0-7    devid
///   8-15   total_bytes
///   16-23  bytes_used
///   24-27  io_align
///   28-31  io_width
///   32-35  sector_size
///   36-43  type
///   44-51  generation
///   52-59  start_offset
///   60-63  dev_group
///   64     seek_speed
///   65     bandwidth
///   66-81  dev_uuid (16 bytes)
///   82-97  fsid (16 bytes)
#[derive(Debug, Clone)]
pub struct DevItem {
    pub devid: u64,
    pub total_bytes: u64,
    pub dev_uuid: [u8; 16],
}

impl DevItem {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 98 {
            return None;
        }
        let uuid: [u8; 16] = buf[66..82].try_into().ok()?;
        Some(Self {
            devid: get_u64(buf, 0),
            total_bytes: get_u64(buf, 8),
            dev_uuid: uuid,
        })
    }
}

/// A single stripe within a chunk — maps to a physical device + offset.
///
/// On-disk layout (32 bytes):
///   0-7    devid
///   8-15   offset (physical byte address on the device)
///   16-31  dev_uuid (16 bytes)
#[derive(Debug, Clone)]
pub struct Stripe {
    pub devid: u64,
    pub offset: u64,
}

impl Stripe {
    pub const RAW_SIZE: usize = 32;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 32 {
            return None;
        }
        Some(Self {
            devid: get_u64(buf, 0),
            offset: get_u64(buf, 8),
        })
    }
}

/// Parsed btrfs_chunk item — maps a logical address range to physical stripes.
///
/// On-disk layout (variable; header is 48 bytes + N × 32-byte stripes):
///   0-7    size (length of the chunk in bytes)
///   8-15   owner
///   16-23  stripe_length
///   24-31  type (flags: DATA, METADATA, SYSTEM, RAID levels)
///   32-35  io_align
///   36-39  io_width
///   40-43  sector_size
///   44-45  num_stripes (u16)
///   46-47  sub_stripes (u16)
///   48+    stripes[num_stripes]
#[derive(Debug, Clone)]
pub struct ChunkItemData {
    pub size: u64,
    pub stripe_length: u64,
    pub chunk_type: u64,
    pub num_stripes: u16,
    pub stripes: Vec<Stripe>,
}

impl ChunkItemData {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 48 {
            return None;
        }
        let size = get_u64(buf, 0);
        let stripe_length = get_u64(buf, 16);
        let chunk_type = get_u64(buf, 24);
        let num_stripes = get_u16(buf, 44);
        let num = num_stripes as usize;
        let stripes_end = 48usize.checked_add(num.checked_mul(Stripe::RAW_SIZE)?)?;
        if stripes_end > buf.len() {
            return None;
        }
        let mut stripes = Vec::with_capacity(num);
        for i in 0..num {
            stripes.push(Stripe::parse(&buf[48 + i * Stripe::RAW_SIZE..])?);
        }
        Some(Self {
            size,
            stripe_length,
            chunk_type,
            num_stripes,
            stripes,
        })
    }
}

fn get_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}
fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
fn get_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
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
