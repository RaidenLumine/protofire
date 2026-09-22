//! src/arch/percpu.rs
//!
//! Where this CPU's `PerCpuData` pointer lives, per architecture.
//!
//! Every architecture keeps that pointer somewhere the CPU can reach without
//! loading a global: `gs` on x86_64, `TPIDR_EL1` on aarch64, `tp` on riscv64.
//! The kernel names none of those registers.  It asks this module for the base
//! and for the scheduler fast path, and the architecture answers — a new
//! architecture adds a module beside the others and one line here, rather than
//! another `#[cfg(target_arch = ...)]` in the middle of the kernel.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::percpu::base;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::percpu::base;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::percpu::base;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::percpu::set_base;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::percpu::set_base;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::percpu::set_base;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::percpu::scheduler_ptr;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::percpu::scheduler_ptr;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::percpu::scheduler_ptr;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::percpu::expects_base_installed;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::percpu::expects_base_installed;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::percpu::expects_base_installed;

/// Host and other targets have no per-CPU register, so there is no per-CPU
/// base to find: `base()` answers 0 and the kernel falls back to its single
/// static block.
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
mod absent {
    use crate::kernel::process::Scheduler;

    pub fn base() -> u64 {
        0
    }

    /// # Safety
    ///
    /// Nothing to install on a target without per-CPU registers; the call is
    /// accepted and ignored so that kernel code needs no `cfg` of its own.
    pub unsafe fn set_base(_base: u64) {}

    pub fn scheduler_ptr() -> *mut Scheduler {
        core::ptr::null_mut()
    }

    pub fn expects_base_installed() -> bool {
        false
    }
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::base;
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::expects_base_installed;
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::scheduler_ptr;
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::set_base;
