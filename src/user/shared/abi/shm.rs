//! src/abi/shm.rs
//! ABI types for SystV shared memory (shm) operations.
//!
//! These types are shared between the kernel (`adastra`) and user-space
//! (`ring3-common`) via the `#[repr(C)]` ABI layout contract.

/// Shared memory segment info returned by `shmctl(IPC_STAT)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ShmInfo {
    /// Creator user ID.
    pub shm_perm_uid: u32,
    /// Creator group ID.
    pub shm_perm_gid: u32,
    /// Segment size in bytes.
    pub shm_segsz: u32,
    /// Last attach time (kernel tick).
    pub shm_atime: u64,
    /// Last detach time (kernel tick).
    pub shm_dtime: u64,
    /// PID of creator.
    pub shm_cpid: u32,
    /// PID of last shmat/shmdt.
    pub shm_lpid: u32,
    /// Number of current attaches.
    pub shm_nattch: u32,
    /// Internal segment state flags.
    pub shm_flags: u32,
}

/// Shared memory control commands.
pub const IPC_RMID: usize = 0;
pub const IPC_STAT: usize = 1;
pub const IPC_SET: usize = 2;
pub const IPC_PRIVATE: usize = 0;
pub const IPC_CREAT: usize = 0o1000;
pub const IPC_EXCL: usize = 0o2000;
pub const SHM_RDONLY: usize = 0o10000;

/// Maximum size (in bytes) of a single shared-memory segment.
pub const SHM_MAX_SIZE: usize = 0x4000_0000; // 1 GiB

/// Maximum number of concurrently tracked shared-memory segments.
pub const SHM_SEG_COUNT_MAX: usize = 256;

/// SysV IPC permission structure (mirrors `struct ipc_perm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IpcPerm {
    /// System-V key that created the segment.
    pub key: usize,
    /// Effective user ID of the owner.
    pub uid: u32,
    /// Effective group ID of the owner.
    pub gid: u32,
    /// User ID of the creator.
    pub cuid: u32,
    /// Group ID of the creator.
    pub cgid: u32,
    /// Permission bits (mode & 0o777).
    pub mode: u16,
    /// Reserved / alignment padding.
    pub _pad: u16,
}

impl IpcPerm {
    /// Build a permission struct with creator and owner both set to `uid`/`gid`.
    pub const fn new(key: usize, uid: u32, gid: u32, mode: u16) -> Self {
        Self {
            key,
            uid,
            gid,
            cuid: uid,
            cgid: gid,
            mode,
            _pad: 0,
        }
    }
}

/// Shared-memory data structure returned by `shmctl(IPC_STAT)` /
/// updated by `shmctl(IPC_SET)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ShmidDs {
    /// Permission structure.
    pub shm_perm: IpcPerm,
    /// Segment size in bytes.
    pub shm_segsz: usize,
    /// Last attach time (kernel tick).
    pub shm_atime: u64,
    /// Last detach time (kernel tick).
    pub shm_dtime: u64,
    /// Last change time (kernel tick).
    pub shm_ctime: u64,
    /// PID of the creator process.
    pub shm_cpid: u32,
    /// PID of the last shmat / shmdt caller.
    pub shm_lpid: u32,
    /// Number of current attaches.
    pub shm_nattch: u32,
    /// Reserved / alignment padding.
    pub _pad: u32,
}
