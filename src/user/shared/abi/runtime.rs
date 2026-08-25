//! src/user/shared/abi/runtime.rs
//!
//! Shared runtime ABI identity record and feature flags exposed to user space
//! via the `abi_info` syscall (#39).
//!
//! Single source of truth: the kernel re-exports this module
//! (`src/abi/runtime.rs` is `pub use crate::user::shared::abi::runtime::*;`),
//! so the record user space parses is byte-identical to what the kernel writes.
//!
//! # Versioning
//!
//! - `RUNTIME_ABI_MAJOR` / `RUNTIME_ABI_MINOR` describe the runtime ABI record
//!   itself.  The layout of `RuntimeAbiInfo` changed when the syscall ABI
//!   version fields were added (major 1 → 2); this is the last pre-freeze
//!   breaking layout change, and `record_size` lets older user space detect it.
//! - `syscall_abi_major` / `syscall_abi_minor` carry the syscall-table ABI
//!   version (`crate::user::shared::abi::syscall::SYSCALL_ABI_VERSION_*`),
//!   which user space uses for runtime negotiation alongside `syscall_count`.

use core::mem::offset_of;
use core::mem::size_of;

// "XIAB" in little-endian form so user space can sanity-check the record.
pub const RUNTIME_ABI_MAGIC: u32 = 0x4241_4958;
pub const RUNTIME_ABI_MAJOR: u32 = 2;
pub const RUNTIME_ABI_MINOR: u32 = 0;

pub const RUNTIME_ABI_FEATURE_LAUNCH_METADATA: u64 = 1 << 0;
pub const RUNTIME_ABI_FEATURE_EXCEPTION_HANDLERS: u64 = 1 << 1;
pub const RUNTIME_ABI_FEATURE_WAIT_PROCESS: u64 = 1 << 2;
pub const RUNTIME_ABI_FEATURE_PROCESS_SIGNALS: u64 = 1 << 3;
pub const RUNTIME_ABI_FEATURE_TCP_CONNECT: u64 = 1 << 4;

/// Stable user-visible runtime ABI feature set.
///
/// Keep this limited to features that are intentionally promised through the
/// public `abi_info` syscall record. Internal architecture capability probes
/// and preparatory runtime hooks must stay outside this mask until they become
/// part of the supported user-space contract.
pub const fn stable_runtime_abi_feature_flags() -> u64 {
    RUNTIME_ABI_FEATURE_LAUNCH_METADATA
        | RUNTIME_ABI_FEATURE_EXCEPTION_HANDLERS
        | RUNTIME_ABI_FEATURE_WAIT_PROCESS
        | RUNTIME_ABI_FEATURE_PROCESS_SIGNALS
        | RUNTIME_ABI_FEATURE_TCP_CONNECT
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeAbiInfo {
    pub magic: u32,
    pub major: u32,
    pub minor: u32,
    /// Explicit alignment padding (was implicit before `PaddingFree` safety
    /// audit).  Always zero — fills the 4 bytes at offset 12 that `#[repr(C)]`
    /// would otherwise leave uninitialised so the struct is safe to reinterpret
    /// as a flat byte slice.
    pub _pad: u32,
    pub feature_flags: u64,
    pub syscall_count: u32,
    /// Syscall-table ABI major version (see
    /// `crate::user::shared::abi::syscall`).
    pub syscall_abi_major: u32,
    /// Syscall-table ABI minor version (see
    /// `crate::user::shared::abi::syscall`).
    pub syscall_abi_minor: u32,
    pub record_size: u32,
}

impl RuntimeAbiInfo {
    pub const fn new(
        feature_flags: u64,
        syscall_count: u32,
        syscall_abi_major: u32,
        syscall_abi_minor: u32,
    ) -> Self {
        Self {
            magic: RUNTIME_ABI_MAGIC,
            major: RUNTIME_ABI_MAJOR,
            minor: RUNTIME_ABI_MINOR,
            _pad: 0,
            feature_flags,
            syscall_count,
            syscall_abi_major,
            syscall_abi_minor,
            record_size: RUNTIME_ABI_INFO_SIZE as u32,
        }
    }
}

pub const RUNTIME_ABI_INFO_SIZE: usize = size_of::<RuntimeAbiInfo>();
pub const RUNTIME_ABI_INFO_MAGIC_OFFSET: usize = offset_of!(RuntimeAbiInfo, magic);
pub const RUNTIME_ABI_INFO_MAJOR_OFFSET: usize = offset_of!(RuntimeAbiInfo, major);
pub const RUNTIME_ABI_INFO_MINOR_OFFSET: usize = offset_of!(RuntimeAbiInfo, minor);
pub const RUNTIME_ABI_INFO_FEATURE_FLAGS_OFFSET: usize = offset_of!(RuntimeAbiInfo, feature_flags);
pub const RUNTIME_ABI_INFO_SYSCALL_COUNT_OFFSET: usize = offset_of!(RuntimeAbiInfo, syscall_count);
pub const RUNTIME_ABI_INFO_SYSCALL_ABI_MAJOR_OFFSET: usize =
    offset_of!(RuntimeAbiInfo, syscall_abi_major);
pub const RUNTIME_ABI_INFO_SYSCALL_ABI_MINOR_OFFSET: usize =
    offset_of!(RuntimeAbiInfo, syscall_abi_minor);
pub const RUNTIME_ABI_INFO_RECORD_SIZE_OFFSET: usize = offset_of!(RuntimeAbiInfo, record_size);

#[cfg(test)]
mod tests {
    use super::stable_runtime_abi_feature_flags;
    use super::RuntimeAbiInfo;
    use super::RUNTIME_ABI_FEATURE_EXCEPTION_HANDLERS;
    use super::RUNTIME_ABI_FEATURE_LAUNCH_METADATA;
    use super::RUNTIME_ABI_FEATURE_PROCESS_SIGNALS;
    use super::RUNTIME_ABI_FEATURE_TCP_CONNECT;
    use super::RUNTIME_ABI_FEATURE_WAIT_PROCESS;
    use super::RUNTIME_ABI_INFO_FEATURE_FLAGS_OFFSET;
    use super::RUNTIME_ABI_INFO_MAGIC_OFFSET;
    use super::RUNTIME_ABI_INFO_MAJOR_OFFSET;
    use super::RUNTIME_ABI_INFO_MINOR_OFFSET;
    use super::RUNTIME_ABI_INFO_RECORD_SIZE_OFFSET;
    use super::RUNTIME_ABI_INFO_SIZE;
    use super::RUNTIME_ABI_INFO_SYSCALL_ABI_MAJOR_OFFSET;
    use super::RUNTIME_ABI_INFO_SYSCALL_ABI_MINOR_OFFSET;
    use super::RUNTIME_ABI_INFO_SYSCALL_COUNT_OFFSET;
    use super::RUNTIME_ABI_MAGIC;
    use super::RUNTIME_ABI_MAJOR;
    use super::RUNTIME_ABI_MINOR;

    #[test]
    fn runtime_abi_feature_masks_are_stable() {
        assert_eq!(RUNTIME_ABI_FEATURE_LAUNCH_METADATA, 1);
        assert_eq!(RUNTIME_ABI_FEATURE_EXCEPTION_HANDLERS, 2);
        assert_eq!(RUNTIME_ABI_FEATURE_WAIT_PROCESS, 4);
        assert_eq!(RUNTIME_ABI_FEATURE_PROCESS_SIGNALS, 8);
        assert_eq!(RUNTIME_ABI_FEATURE_TCP_CONNECT, 16);
    }

    #[test]
    fn stable_runtime_abi_feature_set_is_explicit() {
        assert_eq!(
            stable_runtime_abi_feature_flags(),
            RUNTIME_ABI_FEATURE_LAUNCH_METADATA
                | RUNTIME_ABI_FEATURE_EXCEPTION_HANDLERS
                | RUNTIME_ABI_FEATURE_WAIT_PROCESS
                | RUNTIME_ABI_FEATURE_PROCESS_SIGNALS
                | RUNTIME_ABI_FEATURE_TCP_CONNECT
        );
    }

    #[test]
    fn runtime_abi_info_layout_matches_public_offsets() {
        let info = RuntimeAbiInfo::new(RUNTIME_ABI_FEATURE_PROCESS_SIGNALS, 42, 1, 0);
        assert_eq!(RUNTIME_ABI_INFO_SIZE, 40);
        assert_eq!(
            RUNTIME_ABI_INFO_SIZE,
            core::mem::size_of::<RuntimeAbiInfo>()
        );
        assert_eq!(RUNTIME_ABI_INFO_MAGIC_OFFSET, 0);
        assert_eq!(RUNTIME_ABI_INFO_MAJOR_OFFSET, core::mem::size_of::<u32>());
        assert_eq!(
            RUNTIME_ABI_INFO_MINOR_OFFSET,
            core::mem::size_of::<u32>() * 2
        );
        assert_eq!(
            RUNTIME_ABI_INFO_FEATURE_FLAGS_OFFSET,
            core::mem::size_of::<u32>() * 4
        );
        assert_eq!(info.magic, RUNTIME_ABI_MAGIC);
        assert_eq!(info.major, RUNTIME_ABI_MAJOR);
        assert_eq!(info.minor, RUNTIME_ABI_MINOR);
        assert_eq!(info.syscall_count, 42);
        assert_eq!(info.syscall_abi_major, 1);
        assert_eq!(info.syscall_abi_minor, 0);
        assert_eq!(info.record_size, RUNTIME_ABI_INFO_SIZE as u32);
        assert_eq!(
            RUNTIME_ABI_INFO_SYSCALL_COUNT_OFFSET,
            RUNTIME_ABI_INFO_FEATURE_FLAGS_OFFSET + core::mem::size_of::<u64>()
        );
        assert_eq!(
            RUNTIME_ABI_INFO_SYSCALL_ABI_MAJOR_OFFSET,
            RUNTIME_ABI_INFO_SYSCALL_COUNT_OFFSET + core::mem::size_of::<u32>()
        );
        assert_eq!(
            RUNTIME_ABI_INFO_SYSCALL_ABI_MINOR_OFFSET,
            RUNTIME_ABI_INFO_SYSCALL_ABI_MAJOR_OFFSET + core::mem::size_of::<u32>()
        );
        assert_eq!(
            RUNTIME_ABI_INFO_RECORD_SIZE_OFFSET,
            RUNTIME_ABI_INFO_SYSCALL_ABI_MINOR_OFFSET + core::mem::size_of::<u32>()
        );
    }

    #[test]
    fn runtime_abi_major_is_two_after_syscall_version_added() {
        assert_eq!(RUNTIME_ABI_MAJOR, 2);
        assert_eq!(RUNTIME_ABI_MINOR, 0);
    }
}
