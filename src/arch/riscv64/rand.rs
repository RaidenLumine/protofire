//! src/arch/riscv64/rand.rs
//!
//! Hardware random number generation on RISC-V.
//!
//! There is none to wrap: the `Zkr` entropy-source extension and the `seed`
//! CSR are not in the ISA this kernel targets, and the machines it boots on
//! do not offer them either.  The question still has to be answered here,
//! because the kernel's entropy pool asks every machine what it has — and an
//! architecture that stays silent would be the one thing it cannot tell apart
//! from an architecture whose answer was forgotten.

use alloc::vec::Vec;

/// This machine has no hardware entropy source.
///
/// The pool's own fallback — RTC time and monotonic ticks, mixed with
/// anything already collected — is what seeds the generator on this target.
#[must_use]
pub fn hardware_entropy() -> Vec<u8> {
    Vec::new()
}
