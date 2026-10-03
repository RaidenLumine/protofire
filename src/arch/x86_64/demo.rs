//! src/arch/x86_64/demo.rs
//!
//! The demo volume's contents for this architecture.
//!
//! Which payloads a target ships and what its manifests say is a property of
//! the machine, so the choice lives here and `src/fs/demo/mod.rs` asks for it
//! by name.  The content itself is `src/fs/demo/x86_64.rs`, reached through
//! `#[path]` because the demo volume is not part of the architecture — this
//! module re-exports the names that file expects from its parent, and nothing
//! else.
//!
//! A machine with no demo payloads would write its own `demo.rs` and answer
//! with the entries `src/fs/demo/mod.rs` still requires; there is no
//! placeholder for an architecture this tree does not build for, because the
//! tree has no interrupt controller, page-table code or timer for one either.

pub(crate) use crate::fs::demo::build_system_zone_from;
pub(crate) use crate::fs::layout::StorageZone;
pub(crate) use crate::fs::simplefs::ImageEntry;
pub(crate) use crate::fs::simplefs::SimpleFs;
pub(crate) use crate::Result;
pub(crate) use alloc::vec::Vec;

#[path = "../../fs/demo/x86_64.rs"]
pub(crate) mod content;
