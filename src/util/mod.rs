//! src/util/mod.rs
//!
//! Utility module entry for debug and logger helpers.

pub mod debug;
pub mod logger;
/// Signing a release artifact on the host; a machine that only verifies does
/// not carry it.
#[cfg(not(target_os = "none"))]
pub mod sign_tool;
pub mod sync_unsafe_cell;
