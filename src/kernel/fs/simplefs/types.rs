//! src/kernel/fs/simplefs/types.rs
//!
//! Pure type definitions — format version, on-disk structures, builder types,
//! and runtime health metadata.

use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::fs::vfs::GroupId;
use crate::kernel::fs::vfs::NodeKind;
use crate::kernel::fs::vfs::OwnerId;
use crate::kernel::fs::vfs::PermissionMode;
use crate::kernel::fs::vfs::SecurityDescriptor;
use crate::kernel::fs::vfs::VolumeCheckReport;
use crate::Error;
use crate::Result;

use super::super::block::BLOCK_SIZE;
use super::constants::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SimpleFsFormatVersion {
    V2,
    V3PersistentSecurityDescriptors,
    /// V4 builds on V3 (persistent security descriptors + two-phase commit)
    /// and adds a persistent xattr table plus per-inode data-reduction flags
    /// (transparent compression and cross-file deduplication).
    V4PersistentSecurityDescriptorsWithXattrs,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SimpleFsRuntimeMountPolicy {
    Public,
}

impl SimpleFsRuntimeMountPolicy {
    pub(crate) const fn supports_format(
        self,
        format_version: SimpleFsFormatVersion,
        device_read_only: bool,
    ) -> bool {
        match self {
            Self::Public => format_version.supports_runtime_mount(device_read_only),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct PersistentSecurityDescriptorLayout {
    pub(crate) mode_offset: usize,
    pub(crate) owner_uid_offset: usize,
    pub(crate) owner_gid_offset: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct OnDiskPersistentSecurityDescriptor {
    pub(crate) owner_uid: OwnerId,
    pub(crate) owner_gid: GroupId,
    pub(crate) mode: PermissionMode,
}

impl OnDiskPersistentSecurityDescriptor {
    pub(crate) const fn security_descriptor(self) -> SecurityDescriptor {
        SecurityDescriptor::new(self.owner_uid, self.owner_gid, self.mode)
    }
}

impl SimpleFsFormatVersion {
    pub(crate) const fn on_disk_value(self) -> u32 {
        match self {
            Self::V2 => 2,
            Self::V3PersistentSecurityDescriptors => 3,
            Self::V4PersistentSecurityDescriptorsWithXattrs => 4,
        }
    }

    pub(crate) const fn persistent_security_descriptor_layout(
        self,
    ) -> Option<PersistentSecurityDescriptorLayout> {
        match self {
            Self::V2 => None,
            // V3 and V4 keep the current 32-byte inode geometry but consume
            // the bytes that V2 leaves reserved: mode in bytes 2..4 and
            // owner/group after the size field in bytes 24..32.
            Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => {
                Some(PersistentSecurityDescriptorLayout {
                    mode_offset: 2,
                    owner_uid_offset: 24,
                    owner_gid_offset: 28,
                })
            }
        }
    }

    pub(crate) const fn supports_runtime_mount(self, _device_read_only: bool) -> bool {
        match self {
            Self::V2 => true,
            // V3/V4 with the pending-commit two-phase protocol (see
            // flush_metadata) is crash-safe on writable devices.
            // check_and_repair detects and clears any stale
            // pending_commit flag left by an interrupted commit.
            Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => true,
        }
    }

    /// Whether the format carries a persistent extended-attribute table in
    /// the superblock geometry (V4+).  V4 also persists per-inode
    /// compression / dedup flags in the inode flags byte.
    pub(crate) const fn supports_persistent_xattrs(self) -> bool {
        matches!(self, Self::V4PersistentSecurityDescriptorsWithXattrs)
    }

    pub(crate) fn ensure_runtime_mount_supported(
        self,
        device_read_only: bool,
        mount_policy: SimpleFsRuntimeMountPolicy,
    ) -> Result<()> {
        if mount_policy.supports_format(self, device_read_only) {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }

    pub(crate) const fn inode_size(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => INODE_SIZE,
        }
    }

    pub(crate) const fn dirent_size(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => DIRENT_SIZE,
        }
    }

    pub(crate) const fn dirent_name_max_len(self) -> usize {
        self.dirent_size() - 8
    }

    pub(crate) const fn inode_capacity(self, table_blocks: usize) -> usize {
        table_blocks * BLOCK_SIZE / self.inode_size()
    }

    pub(crate) const fn dirent_capacity(self, table_blocks: usize) -> usize {
        table_blocks * BLOCK_SIZE / self.dirent_size()
    }

    pub(crate) fn inode_table_bytes(self, count: usize) -> Result<usize> {
        count
            .checked_mul(self.inode_size())
            .ok_or(Error::InvalidArgument)
    }

    pub(crate) fn dirent_table_bytes(self, count: usize) -> Result<usize> {
        count
            .checked_mul(self.dirent_size())
            .ok_or(Error::InvalidArgument)
    }

    pub(crate) fn inode_table_entry_offset(
        self,
        table_block: usize,
        index: usize,
    ) -> Result<usize> {
        table_block
            .checked_mul(BLOCK_SIZE)
            .and_then(|base| {
                index
                    .checked_mul(self.inode_size())
                    .and_then(|offset| base.checked_add(offset))
            })
            .ok_or(Error::InvalidArgument)
    }

    pub(crate) fn dirent_table_entry_offset(
        self,
        table_block: usize,
        index: usize,
    ) -> Result<usize> {
        table_block
            .checked_mul(BLOCK_SIZE)
            .and_then(|base| {
                index
                    .checked_mul(self.dirent_size())
                    .and_then(|offset| base.checked_add(offset))
            })
            .ok_or(Error::InvalidArgument)
    }

    pub(crate) const fn inode_kind_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 0,
        }
    }

    pub(crate) const fn inode_flags_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 1,
        }
    }

    pub(crate) const fn inode_entry_start_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 4,
        }
    }

    pub(crate) const fn inode_entry_count_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 8,
        }
    }

    pub(crate) const fn inode_data_block_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 12,
        }
    }

    pub(crate) const fn inode_block_count_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 16,
        }
    }

    pub(crate) const fn inode_size_field_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 20,
        }
    }

    /// Offset of the data-checksum u32 within an inode entry (V2 only).
    /// Returns `None` for V3/V4 where those bytes carry `owner_gid`.
    pub(crate) const fn data_checksum_offset(self) -> Option<usize> {
        match self {
            Self::V2 => Some(28),
            Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => None,
        }
    }

    pub(crate) const fn dirent_inode_index_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 0,
        }
    }

    pub(crate) const fn dirent_kind_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 4,
        }
    }

    pub(crate) const fn dirent_name_len_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 5,
        }
    }

    pub(crate) const fn dirent_name_offset(self) -> usize {
        match self {
            Self::V2
            | Self::V3PersistentSecurityDescriptors
            | Self::V4PersistentSecurityDescriptorsWithXattrs => 8,
        }
    }

    pub(crate) fn parse_supported(raw: u32) -> Result<Self> {
        if raw == Self::V2.on_disk_value() {
            return Ok(Self::V2);
        }

        if raw == Self::V3PersistentSecurityDescriptors.on_disk_value() {
            return Ok(Self::V3PersistentSecurityDescriptors);
        }

        if raw == Self::V4PersistentSecurityDescriptorsWithXattrs.on_disk_value() {
            return Ok(Self::V4PersistentSecurityDescriptorsWithXattrs);
        }

        Err(Error::Unsupported)
    }

    /// Number of bytes a fixed-capacity xattr table occupies for `count`
    /// records.
    pub(crate) fn xattr_table_bytes(self, count: usize) -> Result<usize> {
        count
            .checked_mul(XATTR_RECORD_SIZE)
            .ok_or(Error::InvalidArgument)
    }

    /// Number of xattr records a `table_blocks`-sized xattr table can hold.
    pub(crate) const fn xattr_capacity(self, table_blocks: usize) -> usize {
        table_blocks * BLOCK_SIZE / XATTR_RECORD_SIZE
    }

    /// Byte offset of the `index`-th xattr record in an xattr table image.
    pub(crate) fn xattr_table_entry_offset(
        self,
        table_block: usize,
        index: usize,
    ) -> Result<usize> {
        table_block
            .checked_mul(BLOCK_SIZE)
            .and_then(|base| {
                index
                    .checked_mul(XATTR_RECORD_SIZE)
                    .and_then(|offset| base.checked_add(offset))
            })
            .ok_or(Error::InvalidArgument)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParsedSuperblock {
    pub(crate) format_version: SimpleFsFormatVersion,
    pub(crate) record: SuperblockRecord,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct OnDiskInode {
    pub(crate) kind: NodeKind,
    pub(crate) deleted: bool,
    pub(crate) entry_start: u32,
    pub(crate) entry_count: u32,
    pub(crate) data_block: u32,
    pub(crate) block_count: u32,
    pub(crate) size: u32,
    pub(crate) persistent_security: Option<OnDiskPersistentSecurityDescriptor>,
    /// XOR-rotate checksum over file content. Persisted at inode bytes 28..31
    /// for V2; V3 uses those bytes for owner_gid so the checksum stays 0.
    pub(crate) data_checksum: u32,
    /// V4+: the file's data extent holds a chunked compressed stream and
    /// `size` is the logical (uncompressed) length.
    ///
    /// Parsed from the on-disk `INODE_FLAG_COMPRESSED` bit at mount time but
    /// not yet consumed by the read/write path (transparent compression is
    /// not wired in), so it is kept for wire-format compatibility.
    #[allow(dead_code)]
    pub(crate) compressed: bool,
    /// V4+: the file's extent is a member of the cross-file dedup pool
    /// (refcount >= 1), shared with at least one other inode of identical
    /// `(data_block, block_count)`.
    pub(crate) deduped: bool,
}

impl OnDiskInode {
    pub(crate) const fn runtime_security_descriptor(self) -> Option<SecurityDescriptor> {
        match self.persistent_security {
            Some(persistent) => Some(persistent.security_descriptor()),
            None => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OnDiskDirEntry {
    pub(crate) inode_index: u32,
    pub(crate) kind: NodeKind,
    pub(crate) name: String,
}

/// Fixed-size on-disk xattr record (V4+).  The four u32 header fields
/// precede the fixed-size name/value byte arrays, so the struct is padding
/// free and the table can be treated as a plain byte array.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct XattrRecord {
    /// Index of the inode this attribute is attached to.
    pub(crate) inode_index: u32,
    /// Byte length of the attribute name (<= XATTR_NAME_MAX).
    pub(crate) name_len: u32,
    /// Byte length of the attribute value (<= XATTR_VALUE_MAX).
    pub(crate) value_len: u32,
    /// `XATTR_STATUS_LIVE` (0) or `XATTR_STATUS_DELETED` (1).
    pub(crate) status: u32,
    pub(crate) name: [u8; XATTR_NAME_MAX],
    pub(crate) value: [u8; XATTR_VALUE_MAX],
}

impl Default for XattrRecord {
    fn default() -> Self {
        Self {
            inode_index: 0,
            name_len: 0,
            value_len: 0,
            status: XATTR_STATUS_DELETED,
            name: [0_u8; XATTR_NAME_MAX],
            value: [0_u8; XATTR_VALUE_MAX],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResolvedChildEntry {
    pub(crate) entry_index: usize,
    pub(crate) inode_index: usize,
    pub(crate) inode: OnDiskInode,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SuperblockRecord {
    pub(crate) inode_count: usize,
    pub(crate) dirent_count: usize,
    pub(crate) active_inode_table_block: usize,
    pub(crate) active_dirent_table_block: usize,
    pub(crate) shadow_inode_table_block: usize,
    pub(crate) shadow_dirent_table_block: usize,
    pub(crate) inode_table_blocks: usize,
    pub(crate) dirent_table_blocks: usize,
    pub(crate) data_block_start: usize,
    pub(crate) generation: u32,
    /// Non-zero if a metadata commit was in progress when the system
    /// stopped.  The value is the target generation number.
    pub(crate) pending_commit: u32,
    /// V4+: active xattr table slot. Zero for V2/V3.
    pub(crate) active_xattr_table_block: usize,
    /// V4+: shadow xattr table slot. Zero for V2/V3.
    pub(crate) shadow_xattr_table_block: usize,
    /// V4+: size of each xattr table slot in blocks.
    pub(crate) xattr_table_blocks: usize,
    /// Number of xattr records in the active xattr table.
    pub(crate) xattr_count: usize,
}

pub(crate) struct BuilderNode<'a> {
    pub(crate) name: String,
    pub(crate) kind: NodeKind,
    pub(crate) data: &'a [u8],
    pub(crate) children: Vec<usize>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct BuilderInode {
    pub(crate) kind: u8,
    pub(crate) entry_start: u32,
    pub(crate) entry_count: u32,
    pub(crate) data_block: u32,
    pub(crate) block_count: u32,
    pub(crate) size: u32,
}

pub(crate) struct BuilderDirEntry {
    pub(crate) inode_index: u32,
    pub(crate) kind: u8,
    pub(crate) name: String,
}
#[derive(Clone, Copy)]
pub(crate) struct RuntimeHealthSnapshot {
    pub(crate) primary_superblock_matches: bool,
    pub(crate) secondary_superblock_matches: bool,
    pub(crate) active_metadata_matches: bool,
    pub(crate) shadow_metadata_matches: bool,
}

impl RuntimeHealthSnapshot {
    pub(crate) fn issue_count(self) -> usize {
        usize::from(!self.primary_superblock_matches)
            + usize::from(!self.secondary_superblock_matches)
            + usize::from(!self.active_metadata_matches)
            + usize::from(!self.shadow_metadata_matches)
    }

    pub(crate) fn is_clean(self) -> bool {
        self.issue_count() == 0
    }

    pub(crate) fn report(
        self,
        orphan_data_blocks: usize,
        checksum_failures: usize,
        staging_orphans_cleaned: usize,
        orphan_blocks_cleaned: usize,
        interrupted_commits: usize,
    ) -> VolumeCheckReport {
        VolumeCheckReport {
            issues_detected: self.issue_count() + orphan_data_blocks + checksum_failures,
            repairs_applied: 0,
            orphan_data_blocks,
            checksum_failures,
            staging_orphans_cleaned,
            orphan_blocks_cleaned,
            interrupted_commits,
        }
    }

    pub(crate) fn repaired_report(
        self,
        repaired: Self,
        orphan_data_blocks: usize,
        checksum_failures: usize,
        staging_orphans_cleaned: usize,
        orphan_blocks_cleaned: usize,
        interrupted_commits: usize,
    ) -> VolumeCheckReport {
        VolumeCheckReport {
            issues_detected: self.issue_count() + orphan_data_blocks + checksum_failures,
            repairs_applied: self.issue_count().saturating_sub(repaired.issue_count()),
            orphan_data_blocks,
            checksum_failures,
            staging_orphans_cleaned,
            orphan_blocks_cleaned,
            interrupted_commits,
        }
    }
}

pub(crate) struct RuntimeMetadataImage {
    pub(crate) inode_table: Vec<u8>,
    pub(crate) dirent_table: Vec<u8>,
    /// V4+: serialized active xattr table. Empty for V2/V3.
    pub(crate) xattr_table: Vec<u8>,
}
