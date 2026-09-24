//! src/kernel/smp/mod.rs
//!
//! What every architecture has to agree on once more than one CPU is running:
//! which CPUs are online, and who has dropped which translation.
//!
//! Starting a CPU is the architecture's business — `arch/x86_64/smp.rs`
//! (ACPI MADT, a trampoline and INIT-SIPI-SIPI), `arch/aarch64/smp.rs` (the
//! device tree and PSCI), `arch/riscv64/smp.rs` (SBI HSM) — and so is
//! reaching one afterwards (`arch::ipi`) and reading the tables that name
//! them (`arch/x86_64/acpi.rs`).  What is here is the part that would be
//! written twice otherwise: [`bringup`] holds the registry a CPU joins when
//! it can be dispatched on, and [`tlb`] holds the log of invalidations the
//! other CPUs have to walk.

pub(crate) mod bringup;
pub(crate) mod tlb;

pub(crate) use bringup::*;
pub(crate) use tlb::*;
