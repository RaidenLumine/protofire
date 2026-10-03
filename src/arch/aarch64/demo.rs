//! src/arch/aarch64/demo.rs
//!
//! The demo volume's contents for this architecture.
//!
//! See the x86_64 module for why the choice of content file lives here rather
//! than in `src/fs/demo/mod.rs`, and for why this module re-exports the names
//! the content file expects from its parent.  This machine ships the AArch64
//! demo payloads: a launcher, a fault demo, a Rust payload, and the ring-3
//! shell.

pub(crate) use crate::fs::demo::build_system_zone_from;
pub(crate) use crate::fs::layout::StorageZone;
pub(crate) use crate::fs::simplefs::ImageEntry;
pub(crate) use crate::fs::simplefs::SimpleFs;
pub(crate) use crate::Result;
pub(crate) use alloc::vec::Vec;

#[path = "../../fs/demo/aarch64.rs"]
pub(crate) mod content;
