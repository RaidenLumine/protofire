//! src/arch/riscv64/demo.rs
//!
//! The demo volume's contents for this architecture.
//!
//! See the x86_64 module for why the choice of content file lives here rather
//! than in `src/fs/demo/mod.rs`, and for why this module re-exports the names
//! the content file expects from its parent.  This machine ships the RISC-V
//! demo payloads and the ring-3 shell.

pub(crate) use crate::fs::demo::build_system_zone_from;
pub(crate) use crate::fs::layout::StorageZone;
pub(crate) use crate::fs::simplefs::ImageEntry;
pub(crate) use crate::fs::simplefs::SimpleFs;
pub(crate) use crate::Result;
pub(crate) use alloc::vec::Vec;

#[path = "../../fs/demo/riscv64.rs"]
pub(crate) mod content;

/// This machine's init program: the ring-3 program the demo disk ships as
/// `/system/init.elf`.
///
/// The program lives in the user tree (`src/user/demo/init_payload_riscv64.rs`)
/// because it is a user program; it is declared here because *which* programs a
/// machine ships is its own list, and this module is where that list is.
///
/// The x86_64 and AArch64 copies answer with an absent payload on a host whose
/// object format has no ELF payload section — the two Apple targets.  No such
/// host exists for this architecture, so this is the program and nothing else.
#[path = "../../user/demo/init_payload_riscv64.rs"]
pub(crate) mod init_payload_riscv64;
