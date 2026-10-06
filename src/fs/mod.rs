//! src/fs/mod.rs
//!
//! Filesystem facade that mounts volumes, resolves paths, and exposes VFS
//! operations.

// The block layer itself lives at `src/kernel/block.rs`, below this module:
// `drivers` implements `BlockDevice` and must not have to name `fs` to do it.
// The re-export keeps the historical `fs::block` path working, and that path is
// one-way — the filesystem depends on the block layer, not the other way round.
pub use crate::kernel::block;
pub mod block_cache;
pub mod btrfs;
pub mod crypt_device;
pub mod fs_profiler;
pub mod luks2;
// ═══════════════════════════════════════════════════════════════════════
// Legacy demo disk builder — kept for the fs.init() boot path and
// kernel-side MBR tests.  New code that just needs a SimpleFs image
// should call `SimpleFs::build_image` directly.
// The canonical distribution copy lives in protofire-os/demo-disk.
// ═══════════════════════════════════════════════════════════════════════
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub mod demo;
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub use demo::build_demo_disk_image;
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub use demo::build_demo_disk_image_with_key;
pub mod devfs;
pub mod erofs;
pub mod exfat;
pub mod ext4;
pub mod f2fs;
pub mod fat32;
pub(crate) mod fuse;
pub mod iso9660;
pub mod layout;
pub mod lock_timing;
pub mod ntfs;
pub mod partition;
pub mod path;
pub mod servicefs;
pub mod simplefs;
pub mod squashfs;
/// The system volume's A/B pair: which slot a boot takes, and how it switches.
pub mod system_image;
#[cfg(any(test, feature = "demo-disk"))]
pub(crate) mod test_support;
pub mod tmpfs;
pub mod unicode;
pub mod vfs;
/// Where a running machine writes, and why each place is the right one.
pub mod write_locations;
pub mod xfs;

// ── FileSystem implementation modules ──
pub(crate) mod filesystem;
pub(crate) mod handle;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;

use crate::kernel::sync::Mutex;
use crate::Result;

use block::BlockDevice;
use vfs::FileSystem as VfsTrait;
use vfs::VNode;

pub use vfs::DirectoryEntry;
pub use vfs::Metadata as FileMetadata;
pub use vfs::NodeKind;

/// What a set of open rights requires of a node's permission bits.
///
/// Exported for the syscall layer's device-node open, which authorizes a
/// virtual node against *its own* descriptor rather than against the mounted
/// filesystem — the same question the stat syscall already answers from the
/// node.  Sharing the mapping keeps the two answers the same answer.
pub(crate) use filesystem::access_helpers::required_open_access;

// ── Re-exports from submodules ──
pub use filesystem::types::MountInfo;
pub use handle::FileHandle;

pub(crate) use filesystem::types::StorageInitReport;

use filesystem::types::MountPoint;

// ── Global filesystem singleton ──
static GLOBAL_FS: AtomicPtr<Mutex<FileSystem>> = AtomicPtr::new(ptr::null_mut());

/// Projection of the mount table, for readers that run *inside* the filesystem
/// lock.
///
/// `/proc/mounts` is produced while the VFS holds the filesystem lock: the
/// producer runs inside the very read that found the node, so a producer that
/// takes that lock again deadlocks the machine.  It did — `/proc` became
/// reachable and `cat /proc/mounts` stopped the shell dead.
///
/// The mount table stays the only source of truth: this is written from it, by
/// [`publish_mount_snapshot`], at the two points that change it (mount and
/// unmount), and readers take only this lock.  The lock order is always
/// filesystem → snapshot, never the other way round.
static MOUNT_SNAPSHOT: Mutex<Vec<MountInfo>> = Mutex::new(Vec::new());

/// The mount table as of the last mount or unmount.
pub fn mount_snapshot() -> Vec<MountInfo> {
    MOUNT_SNAPSHOT.lock().clone()
}

pub(crate) fn publish_mount_snapshot(entries: Vec<MountInfo>) {
    *MOUNT_SNAPSHOT.lock() = entries;
}

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
pub(crate) const SERVICEFS_MOUNT_PATH: &str = "/service";
pub(crate) const DEVFS_FS_NAME: &str = "devfs";
pub(crate) const DEVFS_MOUNT_DEVICE: &str = "/dev/adastra-devfs";
pub(crate) const SERVICEFS_FS_NAME: &str = "servicefs";
pub(crate) const SERVICEFS_MOUNT_DEVICE: &str = "/dev/protofire-servicefs";
pub(crate) const TEMP_FS_NAME: &str = "simplefs-temp";
pub(crate) const TEMP_MOUNT_DEVICE: &str = "/dev/protofire-temp";
pub(crate) const TEMP_MOUNT_PATH: &str = "/tmp";
pub(crate) const TEMP_DIRECTORY_MODE: u16 = 0o777;
pub(crate) const TEMP_FILE_MODE: u16 = 0o666;
pub(crate) const DATA_ROOT_PATH: &str = "/data";
pub(crate) const DATA_USERS_ROOT_PATH: &str = "/data/users";
pub(crate) const DATA_CREDENTIAL_ROOT_PATH: &str = "/data/etc";
/// Modes for the credential store, which is carved out of the guest-owned data
/// zone in [`filesystem::security_helpers::default_security_descriptor_for_path`]:
/// the directory is closed to everyone but root, and so are the records in it.
pub(crate) const CREDENTIAL_DIRECTORY_MODE: u16 = 0o700;
pub(crate) const CREDENTIAL_FILE_MODE: u16 = 0o600;
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
    // SAFETY: the pointer is either null or one published through that atomic by
    // `install_global`, which keeps it for the life of the kernel.
    unsafe { fs.as_ref() }
}

/// Snapshot the mounted filesystems so the caller can flush them without
/// holding the filesystem lock.
///
/// Flushing a mounted filesystem reaches its block device, and that can take
/// as long as the device takes.  Holding the global filesystem lock across all
/// of them serialises every other filesystem operation in the kernel behind
/// the slowest disk, with interrupts masked; on an SMP machine every other CPU
/// spins on the lock for that whole time.
///
/// Taking the `Arc`s first and releasing the lock fixes that without weakening
/// anything: an `Arc` keeps the filesystem alive even if it is unmounted while
/// the flush is in flight, and flushing a just-unmounted volume is harmless —
/// it is the same blocks on the same device, and flushing them is the point.
fn mounted_filesystems() -> Vec<Arc<dyn VfsTrait>> {
    let Some(fs) = global() else {
        return Vec::new();
    };

    fs.lock()
        .mounted_fs
        .values()
        .map(|mount| mount.fs.clone())
        .collect()
}

/// Flush every mounted filesystem's pending data and metadata to stable
/// storage (POSIX `sync(2)`).  Best-effort when no global filesystem is
/// installed (host test builds).
pub fn sync_global_all() -> Result<()> {
    for filesystem in mounted_filesystems() {
        filesystem.sync()?;
    }
    Ok(())
}

/// Flush every mounted filesystem's pending file data (POSIX `syncfs`-style
/// data-only variant).  Best-effort when no global filesystem is installed.
pub fn sync_global_data() -> Result<()> {
    for filesystem in mounted_filesystems() {
        filesystem.sync_data()?;
    }
    Ok(())
}

/// Write back dirty cached blocks that have aged past `age_ticks` across every
/// mounted filesystem (the persistent write-back cache durability path).
///
/// Returns the total number of blocks written.  Best-effort when no global
/// filesystem is installed (returns 0).
pub fn sync_global_caches_aged(age_ticks: u64) -> Result<usize> {
    let mut total = 0_usize;
    for filesystem in mounted_filesystems() {
        total += filesystem.flush_aged(age_ticks)?;
    }
    Ok(total)
}
