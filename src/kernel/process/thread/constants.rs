//! src/kernel/process/thread/constants.rs
//!
//! Thread module constants and type aliases.

pub type ThreadId = u32;

pub(crate) const DEFAULT_KERNEL_STACK_SIZE: usize = 32 * 1024;
/// Guard region placed immediately below the kernel stack to catch stack
/// overflows with a page fault instead of silent corruption.
///
/// Where the architecture gives kernel stacks a window of their own, the guard
/// is the slice of that window the allocator never hands out: no mapping and no
/// frame, so an access faults whenever it happens.  Elsewhere the guard is a
/// page kept out of the software `PageTable` whose hardware entry the per-arch
/// `unmap_page` routine clears — best effort, and reported when the walk does
/// not reach the leaf.
pub(crate) const KERNEL_STACK_GUARD_SIZE: usize = 4096;
pub(crate) const USER_THREAD_STACK_ALIGNMENT: usize = 16;
