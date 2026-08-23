//! src/kernel/fs/fat32/mod.rs
//! FAT12/16/32 read-write filesystem implementation.
//!
//! ## Supported features
//!
//! - BPB parsing and validation for FAT12, FAT16, and FAT32
//! - FAT table reading and cluster chain walking (12/16/32-bit entries)
//! - 8.3 short filename directory entries
//! - LFN (Long File Name) entries (full UCS-2 / UTF-16LE → Unicode)
//! - Path resolution and file reading
//! - Write/create/remove/rename support
//!
//! ## Architecture
//!
//! [`FatVolume`] is the public entry point — it wraps an `Arc<Mutex<FatFs>>` so
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
use crate::kernel::fs::unicode::OemCodePage;

use types::FatGeometry;

// ─── re-exports ────────────────────────────────────────────────────────────

// Re-export types, constants, and helpers needed by sibling modules
// (and tests via `use super::*`).
#[allow(unused_imports)]
pub(crate) use types::*;

// ─── public volume wrapper ─────────────────────────────────────────────────

/// A mounted FAT volume that implements [`VfsFileSystem`].
///
/// Create via [`FatVolume::open`], then register with the kernel's
/// [`FileSystem`](super::FileSystem) and mount at a path.
pub struct FatVolume {
    name: String,
    fs: Arc<crate::kernel::sync::Mutex<FatFs>>,
}

// ─── internal filesystem state ─────────────────────────────────────────────

/// Internal FAT filesystem state (FAT12/16/32), shared between
/// [`FatVolume`] and every [`FatVNode`] it hands out.
pub(crate) struct FatFs {
    /// Block cache for the device.
    cache: BlockCache,
    /// Parsed BPB geometry.
    geom: FatGeometry,
    /// OEM code page for 8.3 short filename decoding (default: CP437).
    code_page: OemCodePage,
    /// Reusable block-sized buffer for reading.
    block_buf: [u8; BLOCK_SIZE],
    /// Filesystem operation profiler.
    pub(crate) profiler: FsProfiler,
}
