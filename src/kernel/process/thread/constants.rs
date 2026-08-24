//! src/kernel/process/thread/constants.rs
//!
//! Thread module constants and type aliases.

pub type ThreadId = u32;

pub(crate) const DEFAULT_KERNEL_STACK_SIZE: usize = 32 * 1024;
/// Unmapped guard region placed immediately below the kernel stack to catch
/// stack overflows with a page fault instead of silent corruption.
///
/// On host tests the guard region is kept out of the software `PageTable`;
/// on bare metal the per-arch `unmap_page` routine additionally clears the
/// hardware page-table entries so that any access faults immediately.
pub(crate) const KERNEL_STACK_GUARD_SIZE: usize = 4096;
pub(crate) const USER_THREAD_STACK_ALIGNMENT: usize = 16;
