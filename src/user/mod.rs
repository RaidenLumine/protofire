//! src/user/mod.rs
//!
//! User-side module entry that re-exports loaders, syscalls, and demo payload
//! helpers.

// Demo payload modules (assembly ELF builders) are compiled only when the demo
// disk is actually buildable: on host (tests), under the `demo-disk` feature,
// or when a target_os != none build can consume them.  A bare-metal kernel
// build without `demo-disk` does not need them, so they are not compiled in.
// The in-repo demo-disk builder (`src/fs/demo.rs`) imports them via
// `protofire::user::demo::*` with the `demo-disk` feature enabled.
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub mod demo;
pub mod elf;
pub mod exception;
pub mod program;
pub mod shared;
pub mod syscall;

// The demo programs are reached through `protofire::user::demo::*`, which is
// what the `pub mod demo` above provides; nothing named them through the
// shorter `protofire::user::*` path.
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use self::demo::payload_test_support;
