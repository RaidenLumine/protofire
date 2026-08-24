//! src/kernel/fs/mod.rs
//!
//! Filesystem facade that mounts volumes, resolves paths, and exposes VFS operations.

pub mod block;
pub mod block_cache;
pub mod btrfs;
pub mod crypt_device;
pub mod fs_profiler;
pub mod luks2;
// ═══════════════════════════════════════════════════════════════════════
// Legacy demo disk builder — kept for the fs.init() boot path and
// kernel-side MBR tests.  New code that just needs a SimpleFs image
// should use `test_support::build_test_zone_image` or call
// `SimpleFs::build_image` directly.
// The canonical distribution copy lives in protofire-os/demo-disk.
// ═══════════════════════════════════════════════════════════════════════
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub mod demo;
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub use demo::build_demo_disk_image;
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub use demo::build_demo_disk_image_with_key;
// ── Test support ─────────────────────────────────────────────────────────
// Lightweight SimpleFs image builders for tests and demo-disk feature.
// Prefer these over the legacy `demo::build_zone_image` when you just
// need a valid SimpleFs image.
pub mod devfs;
pub mod erofs;
pub mod exfat;
pub mod ext4;
pub mod f2fs;
pub mod fat32;
pub(crate) mod fuse;
pub mod iso9660;
pub mod layout;
pub mod ntfs;
pub mod partition;
pub mod path;
pub mod pipe;
pub mod procfs;
pub mod simplefs;
pub mod squashfs;
#[cfg(any(test, feature = "demo-disk"))]
pub(crate) mod test_support;
pub mod tmpfs;
pub mod unicode;
pub mod vfs;
pub mod xfs;

// ── FileSystem implementation modules ──
pub(crate) mod filesystem;
pub(crate) mod handle;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::kernel::sync::Mutex;
use crate::Result;

use block::BlockDevice;
use vfs::FileSystem as VfsTrait;
use vfs::VNode;

pub use vfs::{DirectoryEntry, Metadata as FileMetadata, NodeKind};

// ── Re-exports from submodules ──
pub use filesystem::types::MountInfo;
pub use handle::FileHandle;

pub(crate) use filesystem::types::StorageInitReport;

use filesystem::types::MountPoint;

// ── Global filesystem singleton ──
static GLOBAL_FS: AtomicPtr<Mutex<FileSystem>> = AtomicPtr::new(ptr::null_mut());

// ── Public constants ──
pub const SEEK_SET: usize = 0;
pub const SEEK_CUR: usize = 1;
pub const SEEK_END: usize = 2;
pub const OPEN_EXISTING: u32 = 0;
pub const CREATE_NEW: u32 = 1;
pub const OPEN_ALWAYS: u32 = 2;

// ── Internal constants (used across submodules) ──
pub(crate) const VIRTUAL_DEVICE_FS_NAME: &str = "virtual-devices";
pub(crate) const VIRTUAL_DEVICE_MOUNT_DEVICE: &str = "/dev/protofire-virtual-devices";
pub(crate) const VIRTUAL_DEVICE_MOUNT_PATH: &str = "/system/dev";
pub(crate) const KERNEL_LOGS_FS_NAME: &str = "kernel-logs";
pub(crate) const KERNEL_LOGS_MOUNT_DEVICE: &str = "/dev/protofire-kernel-logs";
pub(crate) const KERNEL_LOGS_MOUNT_PATH: &str = "/system/logs";
pub(crate) const PROCFS_MOUNT_PATH: &str = "/proc";
pub(crate) const DEVFS_MOUNT_PATH: &str = "/dev";
pub(crate) const TEMP_FS_NAME: &str = "simplefs-temp";
pub(crate) const TEMP_MOUNT_DEVICE: &str = "/dev/protofire-temp";
pub(crate) const TEMP_MOUNT_PATH: &str = "/tmp";
pub(crate) const TEMP_DIRECTORY_MODE: u16 = 0o777;
pub(crate) const TEMP_FILE_MODE: u16 = 0o666;
pub(crate) const DATA_ROOT_PATH: &str = "/data";
pub(crate) const DATA_USERS_ROOT_PATH: &str = "/data/users";
pub(crate) const SYSTEM_DIRECTORY_MODE: u16 = 0o755;
pub(crate) const SYSTEM_FILE_MODE: u16 = 0o644;
pub(crate) const SYSTEM_DEVICE_MODE: u16 = 0o660;
pub(crate) const PUBLIC_DEVICE_MODE: u16 = 0o666;
pub(crate) const DATA_DIRECTORY_MODE: u16 = 0o775;
pub(crate) const DATA_FILE_MODE: u16 = 0o664;
pub(crate) const ACCESS_READ_BIT: u16 = 0b100;
pub(crate) const ACCESS_WRITE_BIT: u16 = 0b010;
pub(crate) const ACCESS_EXECUTE_BIT: u16 = 0b001;

// ── Public struct ──
pub struct FileSystem {
    pub(crate) root: Arc<dyn VNode>,
    pub(crate) filesystems: BTreeMap<String, Arc<dyn VfsTrait>>,
    pub(crate) block_devices: BTreeMap<String, Arc<dyn BlockDevice>>,
    pub(crate) mounted_fs: BTreeMap<String, MountPoint>,
    pub(crate) current_working_dir: Mutex<String>,
    pub(crate) next_handle: Mutex<u64>,
    pub(crate) storage_init_report: Mutex<Option<StorageInitReport>>,
    /// Root filesystem type: `"simplefs"` (default) or `"ext4"`.
    pub(crate) rootfs_type: String,
}

impl Default for FileSystem {
    fn default() -> Self {
        Self::new()
    }
}

// ── Global singleton helpers ──
pub fn install_global(fs: &'static Mutex<FileSystem>) {
    GLOBAL_FS.store(fs as *const _ as *mut _, Ordering::SeqCst);
}

/// # Safety
///
/// The caller must guarantee `fs` outlives every future `global()` access.
/// Prefer `install_global` whenever a `'static` reference is available.
pub unsafe fn install_global_unchecked(fs: &Mutex<FileSystem>) {
    GLOBAL_FS.store(fs as *const _ as *mut _, Ordering::SeqCst);
}

pub fn uninstall_global(fs: &Mutex<FileSystem>) {
    let fs_ptr = fs as *const _ as *mut _;
    let _ = GLOBAL_FS.compare_exchange(fs_ptr, ptr::null_mut(), Ordering::SeqCst, Ordering::SeqCst);
}

pub fn global() -> Option<&'static Mutex<FileSystem>> {
    let fs = GLOBAL_FS.load(Ordering::SeqCst);
    unsafe { fs.as_ref() }
}

/// Flush every mounted filesystem's pending data and metadata to stable
/// storage (POSIX `sync(2)`).  Best-effort when no global filesystem is
/// installed (host test builds).
pub fn sync_global_all() -> Result<()> {
    let Some(fs) = global() else {
        return Ok(());
    };
    let fs = fs.lock();
    for mount in fs.mounted_fs.values() {
        mount.fs.sync()?;
    }
    Ok(())
}

/// Flush every mounted filesystem's pending file data (POSIX `syncfs`-style
/// data-only variant).  Best-effort when no global filesystem is installed.
pub fn sync_global_data() -> Result<()> {
    let Some(fs) = global() else {
        return Ok(());
    };
    let fs = fs.lock();
    for mount in fs.mounted_fs.values() {
        mount.fs.sync_data()?;
    }
    Ok(())
}

/// Write back dirty cached blocks that have aged past `age_ticks` across every
/// mounted filesystem (the persistent write-back cache durability path).
///
/// Returns the total number of blocks written.  Best-effort when no global
/// filesystem is installed (returns 0).
pub fn sync_global_caches_aged(age_ticks: u64) -> Result<usize> {
    let Some(fs) = global() else {
        return Ok(0);
    };
    let fs = fs.lock();
    let mut total = 0_usize;
    for mount in fs.mounted_fs.values() {
        total += mount.fs.flush_aged(age_ticks)?;
    }
    Ok(total)
}
