//! src/arch/tlb.rs
//!
//! Dropping this CPU's translations, per architecture.
//!
//! The kernel decides which ranges must go, keeps the log of requests the
//! other CPUs have to walk, and answers "has every CPU dropped it?".  What an
//! instruction to drop one looks like is the architecture's business, and so
//! is whether the edit has already reached everyone: that second answer is
//! what lets the kernel say nothing at all on the architectures that need
//! nothing said, instead of posting requests nobody will ever collect.
//!
//! A new architecture adds a module beside these and two lines here, rather
//! than another `#[cfg(target_arch = ...)]` in the middle of the kernel.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::tlb::drop_local_all;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::tlb::drop_local_range;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::tlb::other_cpus_need_telling;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::tlb::drop_local_all;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::tlb::drop_local_range;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::tlb::other_cpus_need_telling;

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::tlb::drop_local_all;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::tlb::drop_local_range;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::tlb::other_cpus_need_telling;

/// The host, and any target that declares no TLB of its own.
///
/// Nothing to drop and nobody else to tell: a host process has no hardware
/// TLB of the kind these functions name, and it runs on one CPU.
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
mod absent {
    /// Nothing to drop.
    pub fn drop_local_range(start: usize, end: usize) {
        let _ = (start, end);
    }

    /// Nothing to drop.
    pub fn drop_local_all() {}

    /// There is no other CPU to tell.
    pub const fn other_cpus_need_telling() -> bool {
        false
    }
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::drop_local_all;
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::drop_local_range;
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::other_cpus_need_telling;
