//! src/kernel/fs/vfs/types.rs
//!
//! VFS type definitions: node kinds, security descriptors, metadata, and
//! access-query types.
use alloc::string::String;
use alloc::vec::Vec;

use crate::abi::fs as fs_abi;
use crate::kernel::process::{
    IntegrityLevel, SecurityToken, DEFAULT_GUEST_GROUP_ID, DEFAULT_GUEST_USER_ID,
};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeKind {
    Directory,
    File,
    Device,
    Symlink,
}

pub type OwnerId = u32;
pub type GroupId = u32;
pub type PermissionMode = u16;

pub const ROOT_OWNER_ID: OwnerId = 0;
pub const ROOT_GROUP_ID: GroupId = 0;
pub const DEFAULT_DIRECTORY_MODE: PermissionMode = 0o755;
pub const DEFAULT_FILE_MODE: PermissionMode = 0o644;
pub const DEFAULT_DEVICE_MODE: PermissionMode = 0o660;
pub const ACCESS_READ_BIT: PermissionMode = 0b100;
pub const ACCESS_WRITE_BIT: PermissionMode = 0b010;
pub const ACCESS_EXECUTE_BIT: PermissionMode = 0b001;
pub const MAX_PERMISSION_MODE: PermissionMode = 0o777;
const OWNER_MODE_SHIFT: u16 = 6;
const GROUP_MODE_SHIFT: u16 = 3;
const MODE_ACCESS_MASK: PermissionMode = 0b111;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityDescriptor {
    pub owner_uid: OwnerId,
    pub owner_gid: GroupId,
    pub mode: PermissionMode,
}

impl SecurityDescriptor {
    /// Create a new security descriptor with the given owner, group, and mode.
    pub const fn new(owner_uid: OwnerId, owner_gid: GroupId, mode: PermissionMode) -> Self {
        Self {
            owner_uid,
            owner_gid,
            mode,
        }
    }

    /// Create a security descriptor owned by root with the given mode.
    pub const fn root(mode: PermissionMode) -> Self {
        Self::new(ROOT_OWNER_ID, ROOT_GROUP_ID, mode)
    }

    /// Create a security descriptor owned by guest with the given mode.
    pub const fn guest(mode: PermissionMode) -> Self {
        Self::new(DEFAULT_GUEST_USER_ID, DEFAULT_GUEST_GROUP_ID, mode)
    }

    /// Create a root-owned security descriptor with the default mode for the
    /// given node kind.
    pub const fn root_for_kind(kind: NodeKind) -> Self {
        Self::root(default_mode_for_kind(kind))
    }

    /// Convert this descriptor into a PermissionMetadataRecord.
    pub const fn permission_metadata_record(self) -> PermissionMetadataRecord {
        PermissionMetadataRecord {
            owner_uid: self.owner_uid,
            owner_gid: self.owner_gid,
            mode: self.mode,
        }
    }

    /// Return the owner permission bits (read/write/execute).
    pub const fn owner_mode_bits(self) -> PermissionMode {
        (self.mode >> OWNER_MODE_SHIFT) & MODE_ACCESS_MASK
    }

    /// Return the group permission bits (read/write/execute).
    pub const fn group_mode_bits(self) -> PermissionMode {
        (self.mode >> GROUP_MODE_SHIFT) & MODE_ACCESS_MASK
    }

    /// Return the other permission bits (read/write/execute).
    pub const fn other_mode_bits(self) -> PermissionMode {
        self.mode & MODE_ACCESS_MASK
    }

    /// Return the permission bits granted to the given security token.
    pub const fn granted_mode_bits_for(self, security_token: SecurityToken) -> PermissionMode {
        if security_token.user_id == self.owner_uid {
            self.owner_mode_bits()
        } else if security_token.belongs_to_group(self.owner_gid) {
            self.group_mode_bits()
        } else {
            self.other_mode_bits()
        }
    }

    /// Return true if the given security token has the required access.
    pub const fn grants_access(self, required_access: u16, security_token: SecurityToken) -> bool {
        let granted_access = self.granted_mode_bits_for(security_token);
        required_access & !granted_access == 0
    }

    /// Return an access query candidate view for the given security token.
    pub const fn access_query_candidate_view_for(
        self,
        security_token: SecurityToken,
    ) -> AccessQueryCandidateView {
        let bypasses_discretionary_permissions =
            security_token.may_bypass_discretionary_permissions();
        let mut granted_mode_bits = if bypasses_discretionary_permissions {
            MODE_ACCESS_MASK
        } else {
            self.granted_mode_bits_for(security_token)
        };

        if matches!(security_token.integrity, IntegrityLevel::Low) {
            granted_mode_bits &= !ACCESS_WRITE_BIT;
        }

        AccessQueryCandidateView {
            granted_mode_bits,
            can_read: granted_mode_bits & ACCESS_READ_BIT != 0,
            can_write: granted_mode_bits & ACCESS_WRITE_BIT != 0,
            can_execute: granted_mode_bits & ACCESS_EXECUTE_BIT != 0,
            bypasses_discretionary_permissions,
        }
    }

    /// Return a full access query result for the given required access and
    /// security token.
    pub const fn access_query_for(
        self,
        required_access: PermissionMode,
        security_token: SecurityToken,
    ) -> AccessQueryResult {
        let candidate = self.access_query_candidate_view_for(security_token);
        AccessQueryResult {
            required_access,
            granted_mode_bits: candidate.granted_mode_bits,
            allowed: required_access & !candidate.granted_mode_bits == 0,
            can_read: candidate.can_read,
            can_write: candidate.can_write,
            can_execute: candidate.can_execute,
            bypasses_discretionary_permissions: candidate.bypasses_discretionary_permissions,
        }
    }

    pub(crate) fn apply_update(self, update: SecurityDescriptorUpdate) -> Result<Self> {
        let updated_mode = update.mode.unwrap_or(self.mode);
        if updated_mode & !MAX_PERMISSION_MODE != 0 {
            return Err(Error::InvalidArgument);
        }

        Ok(Self {
            owner_uid: update.owner_uid.unwrap_or(self.owner_uid),
            owner_gid: update.owner_gid.unwrap_or(self.owner_gid),
            mode: updated_mode,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecurityDescriptorUpdate {
    pub(crate) owner_uid: Option<OwnerId>,
    pub(crate) owner_gid: Option<GroupId>,
    pub(crate) mode: Option<PermissionMode>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl SecurityDescriptorUpdate {
    pub(crate) const fn owner_uid(mut self, owner_uid: OwnerId) -> Self {
        self.owner_uid = Some(owner_uid);
        self
    }

    pub(crate) const fn owner_gid(mut self, owner_gid: GroupId) -> Self {
        self.owner_gid = Some(owner_gid);
        self
    }

    pub(crate) const fn mode(mut self, mode: PermissionMode) -> Self {
        self.mode = Some(mode);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub kind: NodeKind,
    pub size: usize,
    pub security: SecurityDescriptor,
    /// Creation time in Unix epoch seconds (0 if unavailable).
    pub created: u64,
    /// Last modification time in Unix epoch seconds (0 if unavailable).
    pub modified: u64,
    /// Last access time in Unix epoch seconds (0 if unavailable).
    pub accessed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataAbiCandidateView {
    pub kind: usize,
    pub size: usize,
    pub owner_uid: OwnerId,
    pub owner_gid: GroupId,
    pub mode: PermissionMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionMetadataRecord {
    pub owner_uid: OwnerId,
    pub owner_gid: GroupId,
    pub mode: PermissionMode,
}

impl MetadataAbiCandidateView {
    pub const fn public_file_stat_record(self) -> fs_abi::FileStat {
        self.exposure_boundary().public_file_stat_record()
    }

    pub const fn public_directory_entry_record(
        self,
        name_len: usize,
    ) -> fs_abi::DirectoryEntryRecord {
        self.exposure_boundary()
            .public_directory_entry_record(name_len)
    }

    pub(crate) const fn exposure_boundary(self) -> FsMetadataAbiExposureBoundary {
        FsMetadataAbiExposureBoundary::from_candidate_view(self)
    }

    pub const fn permission_metadata_record(self) -> PermissionMetadataRecord {
        PermissionMetadataRecord {
            owner_uid: self.owner_uid,
            owner_gid: self.owner_gid,
            mode: self.mode,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FsMetadataAbiPromotionCandidates {
    pub(crate) owner_uid: OwnerId,
    pub(crate) owner_gid: GroupId,
    pub(crate) mode: PermissionMode,
}

impl FsMetadataAbiPromotionCandidates {
    const fn from_candidate_view(candidate: MetadataAbiCandidateView) -> Self {
        let permission_metadata = candidate.permission_metadata_record();
        Self {
            owner_uid: permission_metadata.owner_uid,
            owner_gid: permission_metadata.owner_gid,
            mode: permission_metadata.mode,
        }
    }

    pub(crate) const fn current_public_record_tail_words(self) -> usize {
        let _ = self;
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FsMetadataAbiExposureBoundary {
    pub(crate) metadata: MetadataAbiCandidateView,
    pub(crate) promotion_candidates: FsMetadataAbiPromotionCandidates,
}

impl FsMetadataAbiExposureBoundary {
    const fn from_candidate_view(metadata: MetadataAbiCandidateView) -> Self {
        Self {
            metadata,
            promotion_candidates: FsMetadataAbiPromotionCandidates::from_candidate_view(metadata),
        }
    }

    pub(crate) const fn public_file_stat_record(self) -> fs_abi::FileStat {
        let _ = self.promotion_candidates.current_public_record_tail_words();
        fs_abi::FileStat::new(self.metadata.kind, self.metadata.size)
    }

    pub(crate) const fn public_directory_entry_record(
        self,
        name_len: usize,
    ) -> fs_abi::DirectoryEntryRecord {
        let _ = self.promotion_candidates.current_public_record_tail_words();
        fs_abi::DirectoryEntryRecord::new(self.metadata.kind, self.metadata.size, name_len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessQueryCandidateView {
    pub granted_mode_bits: PermissionMode,
    pub can_read: bool,
    pub can_write: bool,
    pub can_execute: bool,
    pub bypasses_discretionary_permissions: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessQueryResult {
    pub required_access: PermissionMode,
    pub granted_mode_bits: PermissionMode,
    pub allowed: bool,
    pub can_read: bool,
    pub can_write: bool,
    pub can_execute: bool,
    pub bypasses_discretionary_permissions: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataAccessQueryContext {
    pub metadata: MetadataAbiCandidateView,
    pub access: AccessQueryResult,
}

impl MetadataAccessQueryContext {
    pub const fn public_access_query_record(self) -> fs_abi::AccessQueryRecord {
        fs_abi::AccessQueryRecord::new(
            self.access.required_access,
            self.access.granted_mode_bits,
            access_query_public_flags(self.access),
        )
    }
}

impl Metadata {
    /// Create new metadata for a node of the given kind and size, with default
    /// root permissions.
    pub const fn new(kind: NodeKind, size: usize) -> Self {
        Self {
            kind,
            size,
            security: SecurityDescriptor::root_for_kind(kind),
            created: 0,
            modified: 0,
            accessed: 0,
        }
    }

    /// Set the security descriptor for this metadata, returning the updated
    /// value.
    pub const fn with_security(mut self, security: SecurityDescriptor) -> Self {
        self.security = security;
        self
    }

    /// Set the timestamps for this metadata, returning the updated value.
    pub const fn with_timestamps(mut self, created: u64, modified: u64, accessed: u64) -> Self {
        self.created = created;
        self.modified = modified;
        self.accessed = accessed;
        self
    }

    /// Return the public ABI file stat record for this metadata.
    pub const fn public_stat_record(&self) -> fs_abi::FileStat {
        self.abi_candidate_view().public_file_stat_record()
    }

    /// Return the ABI candidate view for this metadata.
    pub const fn abi_candidate_view(&self) -> MetadataAbiCandidateView {
        build_metadata_abi_candidate_view(self.kind, self.size, self.security)
    }

    /// Return the permission metadata record for this metadata.
    pub const fn permission_metadata_record(&self) -> PermissionMetadataRecord {
        self.abi_candidate_view().permission_metadata_record()
    }

    /// Return an access query candidate view for the given security token.
    pub const fn access_query_candidate_view_for(
        &self,
        security_token: SecurityToken,
    ) -> AccessQueryCandidateView {
        self.security
            .access_query_candidate_view_for(security_token)
    }

    /// Return a metadata access query context for the given required access and
    /// security token.
    pub const fn access_query_context_for(
        &self,
        required_access: PermissionMode,
        security_token: SecurityToken,
    ) -> MetadataAccessQueryContext {
        build_metadata_access_query_context(
            self.kind,
            self.size,
            self.security,
            required_access,
            security_token,
        )
    }

    /// Return an access query result for the given required access and security
    /// token.
    pub const fn access_query_for(
        &self,
        required_access: PermissionMode,
        security_token: SecurityToken,
    ) -> AccessQueryResult {
        self.access_query_context_for(required_access, security_token)
            .access
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub kind: NodeKind,
    pub size: usize,
    pub name: String,
    pub security: SecurityDescriptor,
}

impl DirectoryEntry {
    /// Create a new directory entry with the given kind, size, and name.
    pub fn new(kind: NodeKind, size: usize, name: String) -> Self {
        Self {
            kind,
            size,
            security: SecurityDescriptor::root_for_kind(kind),
            name,
        }
    }

    /// Set the security descriptor for this entry, returning the updated value.
    pub fn with_security(mut self, security: SecurityDescriptor) -> Self {
        self.security = security;
        self
    }
}

/// An extended attribute (xattr) — a name/value pair attached to a file or
/// directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrEntry {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl XattrEntry {
    pub fn new(name: Vec<u8>, value: Vec<u8>) -> Self {
        Self { name, value }
    }
}

impl DirectoryEntry {
    /// Return the public ABI directory entry record.
    pub fn public_record(&self) -> fs_abi::DirectoryEntryRecord {
        self.abi_candidate_view()
            .public_directory_entry_record(self.name.len())
    }

    /// Return the ABI candidate view for this entry.
    pub const fn abi_candidate_view(&self) -> MetadataAbiCandidateView {
        build_metadata_abi_candidate_view(self.kind, self.size, self.security)
    }

    /// Return the permission metadata record for this entry.
    pub const fn permission_metadata_record(&self) -> PermissionMetadataRecord {
        self.abi_candidate_view().permission_metadata_record()
    }

    /// Return an access query candidate view for the given security token.
    pub const fn access_query_candidate_view_for(
        &self,
        security_token: SecurityToken,
    ) -> AccessQueryCandidateView {
        self.security
            .access_query_candidate_view_for(security_token)
    }

    /// Return a metadata access query context for the given required access and
    /// security token.
    pub const fn access_query_context_for(
        &self,
        required_access: PermissionMode,
        security_token: SecurityToken,
    ) -> MetadataAccessQueryContext {
        build_metadata_access_query_context(
            self.kind,
            self.size,
            self.security,
            required_access,
            security_token,
        )
    }

    /// Return an access query result for the given required access and security
    /// token.
    pub const fn access_query_for(
        &self,
        required_access: PermissionMode,
        security_token: SecurityToken,
    ) -> AccessQueryResult {
        self.access_query_context_for(required_access, security_token)
            .access
    }
}

impl NodeKind {
    pub const fn public_abi_kind(self) -> usize {
        match self {
            Self::Directory => fs_abi::FILE_KIND_DIRECTORY,
            Self::File => fs_abi::FILE_KIND_FILE,
            Self::Device => fs_abi::FILE_KIND_DEVICE,
            Self::Symlink => fs_abi::FILE_KIND_SYMLINK,
        }
    }
}

const fn build_metadata_abi_candidate_view(
    kind: NodeKind,
    size: usize,
    security: SecurityDescriptor,
) -> MetadataAbiCandidateView {
    MetadataAbiCandidateView {
        kind: kind.public_abi_kind(),
        size,
        owner_uid: security.owner_uid,
        owner_gid: security.owner_gid,
        mode: security.mode,
    }
}

const fn build_metadata_access_query_context(
    kind: NodeKind,
    size: usize,
    security: SecurityDescriptor,
    required_access: PermissionMode,
    security_token: SecurityToken,
) -> MetadataAccessQueryContext {
    MetadataAccessQueryContext {
        metadata: build_metadata_abi_candidate_view(kind, size, security),
        access: security.access_query_for(required_access, security_token),
    }
}

const fn access_query_public_flags(access: AccessQueryResult) -> u32 {
    let mut flags = 0;
    if access.allowed {
        flags |= fs_abi::ACCESS_QUERY_FLAG_ALLOWED;
    }
    if access.can_read {
        flags |= fs_abi::ACCESS_QUERY_FLAG_CAN_READ;
    }
    if access.can_write {
        flags |= fs_abi::ACCESS_QUERY_FLAG_CAN_WRITE;
    }
    if access.can_execute {
        flags |= fs_abi::ACCESS_QUERY_FLAG_CAN_EXECUTE;
    }
    if access.bypasses_discretionary_permissions {
        flags |= fs_abi::ACCESS_QUERY_FLAG_BYPASSES_DISCRETIONARY_PERMISSIONS;
    }
    flags
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityDescriptorMutationSupport {
    LayoutDerivedOnly,
    PersistentReadOnly,
    Persistent,
}

impl SecurityDescriptorMutationSupport {
    pub const fn provides_persistent_metadata(self) -> bool {
        !matches!(self, Self::LayoutDerivedOnly)
    }

    pub const fn supports_persistent_updates(self) -> bool {
        matches!(self, Self::Persistent)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VolumeCheckReport {
    pub issues_detected: usize,
    pub repairs_applied: usize,
    /// Number of data blocks within the referenced range that are not
    /// reachable from any live inode. Blocks beyond the highest inode
    /// reference are treated as free space and not counted.
    pub orphan_data_blocks: usize,
    /// Number of live non-empty file inodes whose stored data checksum
    /// does not match the current on-disk content. Inodes with a
    /// checksum of zero (not yet computed) are skipped.
    pub checksum_failures: usize,
    /// Number of orphaned staging entries cleaned up during the check.
    /// Orphaned staging entries are directories left in registered
    /// staging roots after an incomplete install/update (e.g. due to
    /// a crash before publish or abort).
    pub staging_orphans_cleaned: usize,
    /// Number of orphan data blocks that were zeroed out during the
    /// check.  Orphan data blocks are blocks within the referenced
    /// range that are not reachable from any live inode.  Zeroing them
    /// ensures stale file content cannot be recovered.
    pub orphan_blocks_cleaned: usize,
    /// Number of superblock slots that had a pending-commit marker set,
    /// indicating that a metadata commit was interrupted by a crash.
    /// The marker is cleared by the repair process.
    pub interrupted_commits: usize,
}

impl VolumeCheckReport {
    /// Return true if no issues, orphan blocks, or checksum failures were
    /// detected.
    pub const fn is_clean(self) -> bool {
        self.issues_detected == 0 && self.orphan_data_blocks == 0 && self.checksum_failures == 0
    }

    /// Return true if at least one repair was applied.
    pub const fn repaired(self) -> bool {
        self.repairs_applied != 0
    }
}

pub const fn default_mode_for_kind(kind: NodeKind) -> PermissionMode {
    match kind {
        NodeKind::Directory => DEFAULT_DIRECTORY_MODE,
        NodeKind::File => DEFAULT_FILE_MODE,
        NodeKind::Device => DEFAULT_DEVICE_MODE,
        NodeKind::Symlink => 0o777,
    }
}
