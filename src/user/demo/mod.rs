//! src/user/demo/mod.rs
//! Module entry that registers per-architecture demo payload builders.

// These modules are `pub` so the in-repo demo-disk builder and tests can
// import the legacy assembly demo ELF builders via `protofire::user::demo::*`.
#[cfg(any(target_arch = "aarch64", test))]
pub mod demo_program_aarch64;
#[cfg(any(target_arch = "aarch64", test))]
pub mod demo_program_aarch64_elf;
#[cfg(any(target_arch = "aarch64", test))]
pub mod demo_program_aarch64_fault;
#[cfg(any(target_arch = "aarch64", test))]
pub mod demo_program_aarch64_rust;
#[cfg(any(target_arch = "riscv64", test))]
pub mod demo_program_riscv64;
#[cfg(any(target_arch = "riscv64", test))]
pub mod demo_program_riscv64_elf;
#[cfg(any(target_arch = "x86_64", test))]
pub mod demo_program_x86_64;
#[cfg(any(target_arch = "x86_64", test))]
pub mod demo_program_x86_64_elf;
#[cfg(any(target_arch = "x86_64", test))]
pub mod demo_program_x86_64_rust;
#[cfg(any(target_arch = "x86_64", test))]
pub mod demo_program_x86_64_rust_io;
#[cfg(test)]
pub(crate) mod payload_test_support;
#[cfg(any(target_arch = "x86_64", test))]
pub mod shell_payload_x86_64;

/// Shared ELF64 artifact construction.  See [`crate::user::demo::elf_builder`].
pub mod elf_builder;
