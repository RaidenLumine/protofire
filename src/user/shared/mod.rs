//! src/user/shared/mod.rs
//!
//! The ABI and shell logic kernel and userspace both compile against.
//!
//! This module is a **re-export**: the code lives in the `protofire-shared`
//! crate at the root of this tree, and every path here answers with that
//! crate's.  It moved out of the kernel for one reason — the payloads are
//! copied out and run in ring 3, where a stack-protected frame cannot reload
//! `__stack_chk_guard` from the kernel's `.data`, so they must be a
//! compilation unit the protector is not applied to, and they need this ABI
//! to be one too.  See `shared/Cargo.toml` for the measurement.
//!
//! Kept as a module rather than renamed at every call site: there are some
//! three hundred of them, and the ABI has one name, `user::shared::abi`,
//! wherever it is read from.

pub use protofire_shared::*;
