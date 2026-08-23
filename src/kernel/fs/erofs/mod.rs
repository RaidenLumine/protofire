//! src/kernel/fs/erofs/mod.rs
//! EROFS (Enhanced Read-Only File System) read-only implementation.
//!
//! Implements the VFS [`FileSystem`] trait so EROFS-formatted volumes
//! can be mounted alongside other filesystems.
//!
//! ## Architecture
//!
//! [`EroFsVolume`] is the public entry point — it wraps an `Arc<EroFs>`
//! so that [`VNode`] handles created by `lookup()` can cheaply hold a
//! reference to the underlying filesystem state.
//!
//! ## Limitations
//!
//! - Read-only: all mutating operations return [`Error::PermissionDenied`].
//! - Compact (32-byte) inodes only (no extended 64-byte inodes).
//! - Flat block mapping only (no compression, no chunked files).
//! - Symlinks limited to 16-byte fast symlinks (inline in i_u).

mod fs;
pub(crate) mod types;
pub(crate) mod vfs;

#[cfg(test)]
mod tests;

pub use vfs::EroFsVolume;
