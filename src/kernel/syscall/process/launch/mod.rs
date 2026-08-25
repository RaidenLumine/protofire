//! src/kernel/syscall/process/launch/mod.rs
//!
//! Process spawn/exec syscall decode, validation, and launch installation
//! pipeline.

mod decode;
mod pipeline;

pub(crate) use pipeline::exec;
pub(crate) use pipeline::fork;
pub(crate) use pipeline::spawn;

// Spawn keeps broader limits for compatibility with existing app payloads.
pub(super) const MAX_ARGUMENT_OVERRIDE_ENTRIES: usize = 128;
pub(super) const MAX_ENVIRONMENT_OVERRIDE_ENTRIES: usize = 128;
pub(super) const MAX_OVERRIDE_STRING_BYTES: usize = 4096;
pub(super) const MAX_ARGUMENT_OVERRIDE_TOTAL_BYTES: usize = 32 * 1024;
pub(super) const MAX_ENVIRONMENT_OVERRIDE_TOTAL_BYTES: usize = 32 * 1024;
pub(super) const MAX_WORKING_DIR_BYTES: usize = 4096;
pub(super) const MAX_LAUNCH_REFERENCE_BYTES: usize = 4096;

// Exec is stricter because it replaces the current process image in place.
pub(super) const MAX_EXEC_ARGUMENT_OVERRIDE_ENTRIES: usize = 64;
pub(super) const MAX_EXEC_ENVIRONMENT_OVERRIDE_ENTRIES: usize = 64;
pub(super) const MAX_EXEC_ARGUMENT_OVERRIDE_TOTAL_BYTES: usize = 16 * 1024;
pub(super) const MAX_EXEC_ENVIRONMENT_OVERRIDE_TOTAL_BYTES: usize = 16 * 1024;
pub(super) const MAX_EXEC_WORKING_DIR_BYTES: usize = 2048;

pub(super) const MAX_OVERRIDE_BUDGET_BYTES: usize = 64 * 1024;
pub(super) const MAX_EXEC_OVERRIDE_BUDGET_BYTES: usize = 24 * 1024;
