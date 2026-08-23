//! src/abi/runtime.rs
//! Runtime ABI identity record and feature flags exposed to user space.
//!
//! The canonical definitions live in `crate::user::shared::abi::runtime`
//! (single source of truth, vendored from ring3-common).  Re-exported here so
//! kernel-side consumers (`abi_info` syscall, `PaddingFree` impl) reference
//! the same type user space parses.

pub use crate::user::shared::abi::runtime::*;
