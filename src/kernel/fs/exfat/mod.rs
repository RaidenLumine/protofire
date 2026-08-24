//! src/kernel/fs/exfat/mod.rs
//!
//! exFAT read-write filesystem implementation.
//!
//! ## Supported features
//!
//! - Boot region parsing and checksum validation (Main + Backup boot sectors)
//! - Directory entry set parsing: file (0x85), stream extension (0xC0),
//!   file name extension (0xC1), volume label (0x83), allocation bitmap (0x81),
//!   up-case table (0x82)
//! - FAT table reading and cluster chain walking (32-bit FAT entries)
//! - NoFatChain contiguous file optimisation
//! - Path resolution with case-insensitive filename matching
//! - File reading (both contiguous and FAT-chained files)
//! - Directory listing
//! - Write/create/remove/rename support
//!
//! ## Architecture
//!
//! [`ExfatVolume`] is the public entry point — it wraps an `Arc<Mutex<ExfatFs>>` so
//! that [`VNode`] handles created by `lookup()` can cheaply hold a reference
//! to the underlying filesystem state.

pub(crate) mod fs;
#[cfg(test)]
mod tests;
pub(crate) mod types;
pub(crate) mod vfs;

use alloc::string::String;
use alloc::sync::Arc;

use crate::kernel::fs::block::BLOCK_SIZE;
use crate::kernel::fs::block_cache::BlockCache;
use crate::kernel::fs::filesystem::profiler::FsProfiler;

use types::ExfatBootRegion;

// ─── re-exports ────────────────────────────────────────────────────────────

#[allow(unused_imports)]
pub(crate) use types::*;

// ─── public volume wrapper ─────────────────────────────────────────────────

/// A mounted exFAT volume that implements [`VfsFileSystem`].
///
/// Create via [`ExfatVolume::open`], then register with the kernel's
/// [`FileSystem`](super::FileSystem) and mount at a path.
pub struct ExfatVolume {
    name: String,
    fs: Arc<crate::kernel::sync::Mutex<ExfatFs>>,
}

// ─── internal filesystem state ─────────────────────────────────────────────

/// Internal exFAT filesystem state, shared between [`ExfatVolume`] and
/// every [`ExfatVNode`] it hands out.
pub(crate) struct ExfatFs {
    /// Block cache for the device.
    cache: BlockCache,
    /// Parsed boot region geometry.
    boot: ExfatBootRegion,
    /// Reusable block-sized buffer for reading.
    block_buf: [u8; BLOCK_SIZE],
    /// First cluster of the allocation bitmap (0x81 entry), or 0 if none.
    bitmap_first_cluster: u32,
    /// Size in bytes of the allocation bitmap.
    bitmap_byte_count: u64,
    /// Filesystem operation profiler.
    pub(crate) profiler: FsProfiler,
}
