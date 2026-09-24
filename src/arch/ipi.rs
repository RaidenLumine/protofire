//! src/arch/ipi.rs
//!
//! Reaching another CPU from this one, per architecture.
//!
//! One question so far — "look at your run queue again" — and one answer per
//! architecture: a LAPIC IPI, a software-generated interrupt, or, where the
//! secondary cores do not enter the scheduler at all, nothing yet.  The
//! kernel decides *when* a CPU has to be asked (see
//! `kernel::smp::send_reschedule_ipi`); how it is asked is here.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::smp::send_reschedule_ipi;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::smp::send_reschedule_ipi;

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::smp::send_reschedule_ipi;

/// The host, and any target that declares no way to reach another CPU.
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
mod absent {
    /// There is no other CPU to reach.
    pub fn send_reschedule_ipi(cpu_id: u32) {
        let _ = cpu_id;
    }
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::send_reschedule_ipi;
