//! src/arch/interrupt_controller.rs
//!
//! Architecture-neutral interrupt-controller trait and dispatch functions.
//!
//! Each architecture provides a concrete controller that implements
//! `InterruptController`.  The dispatch functions below delegate to the
//! architecture-specific singleton, keeping callers decoupled from the
//! underlying hardware (PIC, GICv2, future APIC/IOAPIC).
//!
//! ## Trait contract
//!
//! - `init()` — one-time hardware initialisation (remapping, masking, group
//!   assignment).  Must be idempotent.
//! - `end_of_interrupt(vector)` — signal completion to the controller so it can
//!   de-assert the interrupt line or priority drop.
//! - `enable_interrupt(id)` — unmask / enable a specific interrupt source.
//! - `set_priority(id, priority)` — assign a priority level.  Hardware that
//!   does not support per-IRQ priority (e.g. 8259 PIC) makes this a no-op.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use super::aarch64;

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
use super::riscv64;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::x86_64;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

pub trait InterruptController {
    /// One-time hardware initialisation.  Must be idempotent.
    fn init(&self);

    /// Signal end-of-interrupt for `vector`.
    ///
    /// On PIC this sends EOI; on GIC this writes to GICC_EOIR.
    fn end_of_interrupt(&self, vector: u32);

    /// Enable (unmask) the interrupt identified by `interrupt_id`.
    fn enable_interrupt(&self, interrupt_id: u32);

    /// Set the priority of `interrupt_id` to `priority`.
    ///
    /// Hardware that does not support per-IRQ priority makes this a no-op.
    fn set_priority(&self, interrupt_id: u32, priority: u8);
}

// ---------------------------------------------------------------------------
// Dispatch functions — delegate to the architecture-specific singleton
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn controller() -> &'static dyn InterruptController {
    // APIC/IOAPIC is active — the runtime page-table pool supports mapping
    // LAPIC (0xFEE0_0000) and IOAPIC (0xFEC0_0000) MMIO addresses.  MSI-X
    // for NVMe/VirtIO is deferred to a future phase (requires PCI MSI-X
    // capability programming).
    &x86_64::interrupt_controller::APIC_CONTROLLER
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn controller() -> &'static dyn InterruptController {
    aarch64::interrupt_controller::active_controller()
}

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
fn controller() -> &'static dyn InterruptController {
    &riscv64::interrupt_controller::PLIC_CONTROLLER
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
fn controller() -> &'static dyn InterruptController {
    &NopController
}

pub fn init() {
    controller().init();
}

pub fn end_of_interrupt(vector: u32) {
    controller().end_of_interrupt(vector);
}

pub fn enable_interrupt(interrupt_id: u32) {
    controller().enable_interrupt(interrupt_id);
}

pub fn set_priority(interrupt_id: u32, priority: u8) {
    controller().set_priority(interrupt_id, priority);
}

// ---------------------------------------------------------------------------
// NopController — fallback for non-bare-metal targets (e.g. host tests)
// ---------------------------------------------------------------------------

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
struct NopController;

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
impl InterruptController for NopController {
    fn init(&self) {}
    fn end_of_interrupt(&self, _vector: u32) {}
    fn enable_interrupt(&self, _interrupt_id: u32) {}
    fn set_priority(&self, _interrupt_id: u32, _priority: u8) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nop_controller_does_not_panic() {
        let ctrl = NopController;
        ctrl.init();
        ctrl.end_of_interrupt(32);
        ctrl.enable_interrupt(0);
        ctrl.set_priority(0, 0x80);
    }
}
