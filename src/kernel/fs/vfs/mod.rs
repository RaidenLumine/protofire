//! src/kernel/fs/vfs/mod.rs
//!
//! Virtual File System layer: traits and implementations.
pub mod checksum;
pub mod filesystem;
#[cfg(test)]
mod tests;
pub mod types;
pub mod vnode;

// Re-export everything for backward compatibility with downstream filesystem
// drivers
pub use checksum::*;
pub use filesystem::*;
pub use types::*;
pub use vnode::*;
