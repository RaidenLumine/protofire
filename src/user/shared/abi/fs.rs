//! src/user/shared/abi/fs.rs
//!
//! src/abi/fs.rs
//! Shared filesystem ABI records, file kinds, and directory entry layouts.

use core::mem::offset_of;
use core::mem::size_of;

// These numeric tags cross the kernel/user boundary and therefore must remain
// stable.
pub const FILE_KIND_UNKNOWN: usize = 0;
pub const FILE_KIND_DIRECTORY: usize = 1;
pub const FILE_KIND_FILE: usize = 2;
pub const FILE_KIND_DEVICE: usize = 3;
pub const FILE_KIND_SYMLINK: usize = 4;
// Match the conventional "use current working directory as dirfd base"
// sentinel.
pub const AT_FDCWD: usize = (-100_isize) as usize;
pub const ACCESS_READ_BIT: u16 = 0b100;
pub const ACCESS_WRITE_BIT: u16 = 0b010;
pub const ACCESS_EXECUTE_BIT: u16 = 0b001;
pub const ACCESS_QUERY_KNOWN_ACCESS_MASK: u16 =
    ACCESS_READ_BIT | ACCESS_WRITE_BIT | ACCESS_EXECUTE_BIT;
pub const ACCESS_QUERY_FLAG_ALLOWED: u32 = 1 << 0;
pub const ACCESS_QUERY_FLAG_CAN_READ: u32 = 1 << 1;
pub const ACCESS_QUERY_FLAG_CAN_WRITE: u32 = 1 << 2;
pub const ACCESS_QUERY_FLAG_CAN_EXECUTE: u32 = 1 << 3;
pub const ACCESS_QUERY_FLAG_BYPASSES_DISCRETIONARY_PERMISSIONS: u32 = 1 << 4;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size metadata record returned by `stat`.
pub struct FileStat {
    pub kind: usize,
    pub size: usize,
}

impl FileStat {
    pub const fn new(kind: usize, size: usize) -> Self {
        Self { kind, size }
    }
}

pub const FILE_STAT_SIZE: usize = size_of::<FileStat>();
pub const FILE_STAT_KIND_OFFSET: usize = offset_of!(FileStat, kind);
pub const FILE_STAT_SIZE_OFFSET: usize = offset_of!(FileStat, size);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size effective-access record returned by `access_query`.
pub struct AccessQueryRecord {
    pub required_access: u16,
    pub granted_mode_bits: u16,
    pub flags: u32,
}

impl AccessQueryRecord {
    pub const fn new(required_access: u16, granted_mode_bits: u16, flags: u32) -> Self {
        Self {
            required_access,
            granted_mode_bits,
            flags,
        }
    }
}

pub const ACCESS_QUERY_RECORD_SIZE: usize = size_of::<AccessQueryRecord>();
pub const ACCESS_QUERY_RECORD_REQUIRED_ACCESS_OFFSET: usize =
    offset_of!(AccessQueryRecord, required_access);
pub const ACCESS_QUERY_RECORD_GRANTED_MODE_BITS_OFFSET: usize =
    offset_of!(AccessQueryRecord, granted_mode_bits);
pub const ACCESS_QUERY_RECORD_FLAGS_OFFSET: usize = offset_of!(AccessQueryRecord, flags);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size ownership/mode record returned by `permission_metadata`.
pub struct PermissionMetadataRecord {
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mode: u16,
    pub reserved: u16,
}

impl PermissionMetadataRecord {
    pub const fn new(owner_uid: u32, owner_gid: u32, mode: u16) -> Self {
        Self {
            owner_uid,
            owner_gid,
            mode,
            reserved: 0,
        }
    }
}

pub const PERMISSION_METADATA_RECORD_SIZE: usize = size_of::<PermissionMetadataRecord>();
pub const PERMISSION_METADATA_RECORD_OWNER_UID_OFFSET: usize =
    offset_of!(PermissionMetadataRecord, owner_uid);
pub const PERMISSION_METADATA_RECORD_OWNER_GID_OFFSET: usize =
    offset_of!(PermissionMetadataRecord, owner_gid);
pub const PERMISSION_METADATA_RECORD_MODE_OFFSET: usize =
    offset_of!(PermissionMetadataRecord, mode);
pub const PERMISSION_METADATA_RECORD_RESERVED_OFFSET: usize =
    offset_of!(PermissionMetadataRecord, reserved);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size header written at the start of a `read_dir` output buffer.
///
/// The entry name bytes follow immediately after the header at `name_offset`
/// and occupy `name_len` UTF-8 bytes without a trailing NUL.
pub struct DirectoryEntryRecord {
    pub kind: usize,
    pub size: usize,
    pub name_offset: usize,
    pub name_len: usize,
}

impl DirectoryEntryRecord {
    pub const fn new(kind: usize, size: usize, name_len: usize) -> Self {
        Self {
            kind,
            size,
            // The variable-length UTF-8 name bytes are packed immediately after the header.
            name_offset: DIRECTORY_ENTRY_RECORD_SIZE,
            name_len,
        }
    }
}

pub const DIRECTORY_ENTRY_RECORD_SIZE: usize = size_of::<DirectoryEntryRecord>();
pub const DIRECTORY_ENTRY_RECORD_KIND_OFFSET: usize = offset_of!(DirectoryEntryRecord, kind);
pub const DIRECTORY_ENTRY_RECORD_SIZE_OFFSET: usize = offset_of!(DirectoryEntryRecord, size);
pub const DIRECTORY_ENTRY_RECORD_NAME_OFFSET_OFFSET: usize =
    offset_of!(DirectoryEntryRecord, name_offset);
pub const DIRECTORY_ENTRY_RECORD_NAME_LEN_OFFSET: usize =
    offset_of!(DirectoryEntryRecord, name_len);

// ── Extended attribute (xattr) limits ─────────────────────────────────

/// Maximum byte length of an xattr name.
pub const XATTR_NAME_MAX: usize = 64;
/// Maximum byte length of an xattr value.
pub const XATTR_VALUE_MAX: usize = 256;

// ── fcntl command constants (Linux-compatible values) ──────────────────

/// Duplicate `fd` to the lowest free descriptor `>= arg`.
pub const F_DUPFD: usize = 0;
/// Return the per-fd flags (see [`FD_CLOEXEC`]).
pub const F_GETFD: usize = 1;
/// Set the per-fd flags to `arg` (bitmask of [`FD_CLOEXEC`]).
pub const F_SETFD: usize = 2;
/// Return the open file status flags (access mode | [`O_NONBLOCK`]).
pub const F_GETFL: usize = 3;
/// Set the open file status flags.  Only [`O_NONBLOCK`] is settable.
pub const F_SETFL: usize = 4;
/// Grow/shrink the pipe buffer to `arg` bytes (rounded, clamped).
pub const F_SETPIPE_SZ: usize = 1031;
/// Return the current pipe buffer capacity in bytes.
pub const F_GETPIPE_SZ: usize = 1032;

/// Close-on-exec per-fd flag (bit 0 of the [`F_GETFD`]/[`F_SETFD`] value).
pub const FD_CLOEXEC: usize = 1;

/// Non-blocking I/O status flag (Linux `O_NONBLOCK` value 0o4000).
pub const O_NONBLOCK: usize = 0o4000;

// ── File flags (SetFileFlags / GetFileFlags) ─────────────────────────

/// Per-file transparent compression (SimpleFs V4+).
pub const FILE_FLAG_COMPRESSED: u32 = 1 << 0;
/// Per-file dedup-pool membership (informational; SimpleFs V4+).
pub const FILE_FLAG_DEDUPED: u32 = 1 << 1;
/// All known file flags.
pub const FILE_FLAG_KNOWN_MASK: u32 = FILE_FLAG_COMPRESSED | FILE_FLAG_DEDUPED;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size file-flags record returned by `get_file_flags`.
pub struct FileFlagsRecord {
    pub flags: u32,
}

impl FileFlagsRecord {
    pub const fn new(flags: u32) -> Self {
        Self { flags }
    }
}

pub const FILE_FLAGS_RECORD_SIZE: usize = size_of::<FileFlagsRecord>();
pub const FILE_FLAGS_RECORD_FLAGS_OFFSET: usize = offset_of!(FileFlagsRecord, flags);

// ── Security descriptor update flags ──────────────────────────────────

/// Update file mode bits.
pub const SECURITY_DESCRIPTOR_UPDATE_MODE: usize = 1 << 0;
/// Update owner UID.
pub const SECURITY_DESCRIPTOR_UPDATE_OWNER_UID: usize = 1 << 1;
/// Update owner GID.
pub const SECURITY_DESCRIPTOR_UPDATE_OWNER_GID: usize = 1 << 2;
/// All known security descriptor update flags.
pub const SECURITY_DESCRIPTOR_UPDATE_KNOWN_FLAGS: usize = SECURITY_DESCRIPTOR_UPDATE_MODE
    | SECURITY_DESCRIPTOR_UPDATE_OWNER_UID
    | SECURITY_DESCRIPTOR_UPDATE_OWNER_GID;

// ── Mount / block-device enumeration constants ─────────────────────────

/// Maximum length of a block device name (not including NUL terminator).
pub const BLOCK_DEVICE_NAME_MAX: usize = 63;
/// Maximum length of a mount-source device string.
pub const MOUNT_DEVICE_MAX: usize = 63;
/// Maximum length of a filesystem-type name string.
pub const MOUNT_FS_NAME_MAX: usize = 31;
/// Maximum length of a mount-point path.
pub const MOUNT_PATH_MAX: usize = 255;

// ── Mount / block-device enumeration records ───────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Fixed-size block device info record.
pub struct BlockDeviceInfoRecord {
    /// NUL-terminated UTF-8 device name.
    pub name: [u8; BLOCK_DEVICE_NAME_MAX],
    /// Block size in bytes.
    pub block_size: u64,
    /// Total number of blocks.
    pub block_count: u64,
    /// Non-zero if the device is read-only.
    pub read_only: u64,
}

impl Default for BlockDeviceInfoRecord {
    fn default() -> Self {
        Self {
            name: [0u8; BLOCK_DEVICE_NAME_MAX],
            block_size: 0,
            block_count: 0,
            read_only: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Fixed-size mount info record.
pub struct MountInfoRecord {
    /// NUL-terminated UTF-8 mount-point path.
    pub path: [u8; MOUNT_PATH_MAX],
    /// NUL-terminated UTF-8 filesystem type name.
    pub fs_name: [u8; MOUNT_FS_NAME_MAX],
    /// NUL-terminated UTF-8 device.
    pub device: [u8; MOUNT_DEVICE_MAX],
    /// Mount flags.
    pub flags: u64,
    /// Reserved for alignment.
    pub reserved: u64,
}

impl Default for MountInfoRecord {
    fn default() -> Self {
        Self {
            path: [0u8; MOUNT_PATH_MAX],
            fs_name: [0u8; MOUNT_FS_NAME_MAX],
            device: [0u8; MOUNT_DEVICE_MAX],
            flags: 0,
            reserved: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AccessQueryRecord;
    use super::DirectoryEntryRecord;
    use super::FileStat;
    use super::PermissionMetadataRecord;
    use super::ACCESS_EXECUTE_BIT;
    use super::ACCESS_QUERY_FLAG_ALLOWED;
    use super::ACCESS_QUERY_FLAG_BYPASSES_DISCRETIONARY_PERMISSIONS;
    use super::ACCESS_QUERY_FLAG_CAN_EXECUTE;
    use super::ACCESS_QUERY_FLAG_CAN_READ;
    use super::ACCESS_QUERY_FLAG_CAN_WRITE;
    use super::ACCESS_QUERY_KNOWN_ACCESS_MASK;
    use super::ACCESS_QUERY_RECORD_FLAGS_OFFSET;
    use super::ACCESS_QUERY_RECORD_GRANTED_MODE_BITS_OFFSET;
    use super::ACCESS_QUERY_RECORD_REQUIRED_ACCESS_OFFSET;
    use super::ACCESS_QUERY_RECORD_SIZE;
    use super::ACCESS_READ_BIT;
    use super::ACCESS_WRITE_BIT;
    use super::AT_FDCWD;
    use super::DIRECTORY_ENTRY_RECORD_KIND_OFFSET;
    use super::DIRECTORY_ENTRY_RECORD_NAME_LEN_OFFSET;
    use super::DIRECTORY_ENTRY_RECORD_NAME_OFFSET_OFFSET;
    use super::DIRECTORY_ENTRY_RECORD_SIZE;
    use super::DIRECTORY_ENTRY_RECORD_SIZE_OFFSET;
    use super::FD_CLOEXEC;
    use super::FILE_KIND_DEVICE;
    use super::FILE_KIND_DIRECTORY;
    use super::FILE_KIND_FILE;
    use super::FILE_KIND_UNKNOWN;
    use super::FILE_STAT_KIND_OFFSET;
    use super::FILE_STAT_SIZE;
    use super::FILE_STAT_SIZE_OFFSET;
    use super::F_DUPFD;
    use super::F_GETFD;
    use super::F_GETFL;
    use super::F_GETPIPE_SZ;
    use super::F_SETFD;
    use super::F_SETFL;
    use super::F_SETPIPE_SZ;
    use super::O_NONBLOCK;
    use super::PERMISSION_METADATA_RECORD_MODE_OFFSET;
    use super::PERMISSION_METADATA_RECORD_OWNER_GID_OFFSET;
    use super::PERMISSION_METADATA_RECORD_OWNER_UID_OFFSET;
    use super::PERMISSION_METADATA_RECORD_RESERVED_OFFSET;
    use super::PERMISSION_METADATA_RECORD_SIZE;

    #[test]
    fn file_kind_values_are_stable() {
        assert_eq!(FILE_KIND_UNKNOWN, 0);
        assert_eq!(FILE_KIND_DIRECTORY, 1);
        assert_eq!(FILE_KIND_FILE, 2);
        assert_eq!(FILE_KIND_DEVICE, 3);
    }

    #[test]
    fn at_fdcwd_matches_compatibility_sentinel() {
        assert_eq!(AT_FDCWD, (-100_isize) as usize);
    }

    #[test]
    fn access_query_bits_and_flags_are_stable() {
        assert_eq!(ACCESS_READ_BIT, 0b100);
        assert_eq!(ACCESS_WRITE_BIT, 0b010);
        assert_eq!(ACCESS_EXECUTE_BIT, 0b001);
        assert_eq!(ACCESS_QUERY_KNOWN_ACCESS_MASK, 0b111);
        assert_eq!(ACCESS_QUERY_FLAG_ALLOWED, 1);
        assert_eq!(ACCESS_QUERY_FLAG_CAN_READ, 2);
        assert_eq!(ACCESS_QUERY_FLAG_CAN_WRITE, 4);
        assert_eq!(ACCESS_QUERY_FLAG_CAN_EXECUTE, 8);
        assert_eq!(ACCESS_QUERY_FLAG_BYPASSES_DISCRETIONARY_PERMISSIONS, 16);
    }

    #[test]
    fn file_stat_layout_matches_public_offsets() {
        let stat = FileStat::new(FILE_KIND_FILE, 42);
        assert_eq!(FILE_STAT_SIZE, core::mem::size_of::<FileStat>());
        assert_eq!(FILE_STAT_KIND_OFFSET, 0);
        assert_eq!(FILE_STAT_SIZE_OFFSET, core::mem::size_of::<usize>());
        assert_eq!(stat.kind, FILE_KIND_FILE);
        assert_eq!(stat.size, 42);
    }

    #[test]
    fn access_query_record_layout_matches_public_offsets() {
        let record = AccessQueryRecord::new(
            ACCESS_READ_BIT | ACCESS_WRITE_BIT,
            ACCESS_READ_BIT,
            ACCESS_QUERY_FLAG_ALLOWED | ACCESS_QUERY_FLAG_CAN_READ,
        );
        assert_eq!(
            ACCESS_QUERY_RECORD_SIZE,
            core::mem::size_of::<AccessQueryRecord>()
        );
        assert_eq!(ACCESS_QUERY_RECORD_REQUIRED_ACCESS_OFFSET, 0);
        assert_eq!(
            ACCESS_QUERY_RECORD_GRANTED_MODE_BITS_OFFSET,
            core::mem::size_of::<u16>()
        );
        assert_eq!(
            ACCESS_QUERY_RECORD_FLAGS_OFFSET,
            core::mem::size_of::<u16>() * 2
        );
        assert_eq!(record.required_access, ACCESS_READ_BIT | ACCESS_WRITE_BIT);
        assert_eq!(record.granted_mode_bits, ACCESS_READ_BIT);
        assert_eq!(
            record.flags,
            ACCESS_QUERY_FLAG_ALLOWED | ACCESS_QUERY_FLAG_CAN_READ
        );
    }

    #[test]
    fn permission_metadata_record_layout_matches_public_offsets() {
        let record = PermissionMetadataRecord::new(1000, 1001, 0o664);
        assert_eq!(
            PERMISSION_METADATA_RECORD_SIZE,
            core::mem::size_of::<PermissionMetadataRecord>()
        );
        assert_eq!(PERMISSION_METADATA_RECORD_OWNER_UID_OFFSET, 0);
        assert_eq!(
            PERMISSION_METADATA_RECORD_OWNER_GID_OFFSET,
            core::mem::size_of::<u32>()
        );
        assert_eq!(
            PERMISSION_METADATA_RECORD_MODE_OFFSET,
            core::mem::size_of::<u32>() * 2
        );
        assert_eq!(
            PERMISSION_METADATA_RECORD_RESERVED_OFFSET,
            PERMISSION_METADATA_RECORD_MODE_OFFSET + core::mem::size_of::<u16>()
        );
        assert_eq!(record.owner_uid, 1000);
        assert_eq!(record.owner_gid, 1001);
        assert_eq!(record.mode, 0o664);
        assert_eq!(record.reserved, 0);
    }

    #[test]
    fn fcntl_command_values_are_stable() {
        assert_eq!(F_DUPFD, 0);
        assert_eq!(F_GETFD, 1);
        assert_eq!(F_SETFD, 2);
        assert_eq!(F_GETFL, 3);
        assert_eq!(F_SETFL, 4);
        assert_eq!(F_SETPIPE_SZ, 1031);
        assert_eq!(F_GETPIPE_SZ, 1032);
        assert_eq!(FD_CLOEXEC, 1);
        assert_eq!(O_NONBLOCK, 0o4000);
    }

    #[test]
    fn directory_entry_record_defaults_name_payload_after_header() {
        let record = DirectoryEntryRecord::new(FILE_KIND_DIRECTORY, 3, 5);
        assert_eq!(
            DIRECTORY_ENTRY_RECORD_SIZE,
            core::mem::size_of::<DirectoryEntryRecord>()
        );
        assert_eq!(DIRECTORY_ENTRY_RECORD_KIND_OFFSET, 0);
        assert_eq!(
            DIRECTORY_ENTRY_RECORD_SIZE_OFFSET,
            core::mem::size_of::<usize>()
        );
        assert_eq!(
            DIRECTORY_ENTRY_RECORD_NAME_OFFSET_OFFSET,
            core::mem::size_of::<usize>() * 2
        );
        assert_eq!(
            DIRECTORY_ENTRY_RECORD_NAME_LEN_OFFSET,
            core::mem::size_of::<usize>() * 3
        );
        assert_eq!(record.name_offset, DIRECTORY_ENTRY_RECORD_SIZE);
        assert_eq!(record.name_len, 5);
        assert_eq!(record.size, 3);
    }
}
