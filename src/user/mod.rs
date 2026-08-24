//! src/user/mod.rs
//!
//! User-side module entry that re-exports loaders, syscalls, and demo payload helpers.

// Demo payload modules (assembly ELF builders) are compiled only when the demo
// disk is actually buildable: on host (tests), under the `demo-disk` feature,
// or when a target_os != none build can consume them.  A bare-metal kernel
// build without `demo-disk` does not need them, so they are not compiled in.
// The in-repo demo-disk builder (`src/kernel/fs/demo.rs`) imports them via
// `protofire::user::demo::*` with the `demo-disk` feature enabled.
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub mod demo;
pub mod elf;
pub mod exception;
pub mod program;
pub mod shared;
pub mod syscall;

// Re-export demo modules as `pub` so the in-repo demo-disk builder and tests
// can import them via `protofire::user::demo::*`.  Each re-export requires
// both the demo-disk module gate AND the arch/test gate of the underlying item.
#[cfg(all(
    any(feature = "demo-disk", test, not(target_os = "none")),
    any(target_arch = "aarch64", test)
))]
#[allow(unused_imports)]
pub use self::demo::demo_program_aarch64;
#[cfg(all(
    any(feature = "demo-disk", test, not(target_os = "none")),
    any(target_arch = "aarch64", test)
))]
#[allow(unused_imports)]
pub use self::demo::demo_program_aarch64_elf;
#[cfg(all(
    any(feature = "demo-disk", test, not(target_os = "none")),
    any(target_arch = "aarch64", test)
))]
#[allow(unused_imports)]
pub use self::demo::demo_program_aarch64_fault;
#[cfg(all(
    any(feature = "demo-disk", test, not(target_os = "none")),
    any(target_arch = "aarch64", test)
))]
#[allow(unused_imports)]
pub use self::demo::demo_program_aarch64_rust;
#[cfg(all(
    any(feature = "demo-disk", test, not(target_os = "none")),
    any(target_arch = "x86_64", test)
))]
#[allow(unused_imports)]
pub use self::demo::demo_program_x86_64;
#[cfg(all(
    any(feature = "demo-disk", test, not(target_os = "none")),
    any(target_arch = "x86_64", test)
))]
#[allow(unused_imports)]
pub use self::demo::demo_program_x86_64_elf;
#[cfg(all(
    any(feature = "demo-disk", test, not(target_os = "none")),
    any(target_arch = "x86_64", test)
))]
#[allow(unused_imports)]
pub use self::demo::demo_program_x86_64_rust;
#[cfg(all(
    any(feature = "demo-disk", test, not(target_os = "none")),
    any(target_arch = "x86_64", test)
))]
#[allow(unused_imports)]
pub use self::demo::demo_program_x86_64_rust_io;
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use self::demo::payload_test_support;
