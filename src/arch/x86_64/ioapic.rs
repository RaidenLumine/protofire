//! src/arch/x86_64/ioapic.rs
//!
//! IOAPIC driver for x86_64.
//!
//! The I/O APIC routes external interrupts from device pins to the Local
//! APIC(s) via a redirection table.  Each entry in the table maps one
//! input pin to a destination vector, delivery mode, and destination CPU.
//!
//! On QEMU q35 (and most real hardware), the IOAPIC MMIO registers are
//! at physical address `IOAPIC_MMIO_BASE_DEFAULT` (0xFEC0_0000).
//!
//! Most functions and constants are only active on bare-metal x86_64;
//! dead-code warnings on host builds are expected and suppressed.

#![cfg_attr(
    not(all(target_arch = "x86_64", target_os = "none")),
    allow(dead_code, unused_imports, unused_variables)
)]

use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use crate::println;

// ---------------------------------------------------------------------------
// IOAPIC MMIO base and register layout
// ---------------------------------------------------------------------------

/// Default IOAPIC MMIO base address.
pub const IOAPIC_MMIO_BASE_DEFAULT: usize = 0xFEC0_0000;

/// I/O Register Selector (offset 0x00): write the register index here.
const IOREGSEL: usize = 0x00;
/// I/O Window (offset 0x10): read/write the selected register's data here.
const IOWIN: usize = 0x10;

// ---------------------------------------------------------------------------
// IOAPIC register indices (written to IOREGSEL)
// ---------------------------------------------------------------------------

/// IOAPIC ID register (index 0x00).
const IOAPIC_ID: u8 = 0x00;
/// IOAPIC Version register (index 0x01): bits 23:16 = max redirection entry.
const IOAPIC_VER: u8 = 0x01;
/// Arbitration ID register (index 0x02).
const _IOAPIC_ARB: u8 = 0x02;

/// First redirection table entry (low 32 bits).  Entry N is at
/// index (0x10 + 2*N), with the high 32 bits at (0x10 + 2*N + 1).
const REDIRECTION_TABLE_BASE: u8 = 0x10;

// ---------------------------------------------------------------------------
// Redirection table entry bit definitions
// ---------------------------------------------------------------------------

/// Delivery mode: Fixed.
pub const DELIVERY_FIXED: u32 = 0x000;
/// Delivery mode: Lowest Priority.
pub const DELIVERY_LOWEST: u32 = 0x100;
/// Delivery mode: SMI.
pub const DELIVERY_SMI: u32 = 0x200;
/// Delivery mode: NMI.
pub const DELIVERY_NMI: u32 = 0x400;
/// Delivery mode: INIT.
pub const DELIVERY_INIT: u32 = 0x500;
/// Delivery mode: ExtINT.
pub const DELIVERY_EXTINT: u32 = 0x700;

/// Destination mode: physical (bit 11).
pub const DESTINATION_PHYSICAL: u32 = 0x0000;
/// Destination mode: logical (bit 11).
pub const DESTINATION_LOGICAL: u32 = 1 << 11;
/// Delivery status: pending (bit 12, read-only).
pub const DELIVERY_STATUS_PENDING: u32 = 1 << 12;
/// Pin polarity: active low (bit 13).
pub const POLARITY_ACTIVE_LOW: u32 = 1 << 13;
/// Remote IRR (bit 14, read-only for level-triggered).
pub const REMOTE_IRR: u32 = 1 << 14;
/// Trigger mode: level (bit 15).
pub const TRIGGER_LEVEL: u32 = 1 << 15;
/// Interrupt mask (bit 16).
pub const INT_MASKED: u32 = 1 << 16;

// ---------------------------------------------------------------------------
// IOAPIC operations
// ---------------------------------------------------------------------------

static IOAPIC_INITIALIZED: AtomicBool = AtomicBool::new(false);
static IOAPIC_BASE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(IOAPIC_MMIO_BASE_DEFAULT);
static MAX_REDIRECTION_ENTRY: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Read the IOAPIC register currently selected by IOREGSEL.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe fn ioapic_read(reg: u8) -> u32 {
    let base = IOAPIC_BASE.load(Ordering::Relaxed);
    unsafe {
        ptr::write_volatile((base + IOREGSEL) as *mut u32, reg as u32);
        ptr::read_volatile((base + IOWIN) as *const u32)
    }
}

/// Write a value to an IOAPIC register.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe fn ioapic_write(reg: u8, value: u32) {
    let base = IOAPIC_BASE.load(Ordering::Relaxed);
    unsafe {
        ptr::write_volatile((base + IOREGSEL) as *mut u32, reg as u32);
        ptr::write_volatile((base + IOWIN) as *mut u32, value);
    }
}

/// Read a redirection table entry.
///
/// Returns (low_32, high_32).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn read_redirection_entry(index: u8) -> (u32, u32) {
    let lo_reg = REDIRECTION_TABLE_BASE + 2 * index;
    let hi_reg = lo_reg + 1;
    unsafe {
        let lo = ioapic_read(lo_reg);
        let hi = ioapic_read(hi_reg);
        (lo, hi)
    }
}

/// Write a redirection table entry.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn write_redirection_entry(index: u8, lo: u32, hi: u32) {
    let lo_reg = REDIRECTION_TABLE_BASE + 2 * index;
    let hi_reg = lo_reg + 1;
    unsafe {
        ioapic_write(lo_reg, lo);
        ioapic_write(hi_reg, hi);
    }
}

/// Initialize the IOAPIC.
///
/// - Maps the IOAPIC MMIO page into the active kernel page tables.
/// - Reads the IOAPIC version to determine the number of redirection entries.
/// - Masks all entries (sets bit 16).
/// - Sets the IOAPIC ID to 0 (BSP only for now).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn init_ioapic() {
    if IOAPIC_INITIALIZED.swap(true, Ordering::Acquire) {
        return;
    }

    // Map the IOAPIC MMIO page into the active kernel page tables.
    unsafe { super::apic::map_device_mmio_page(IOAPIC_MMIO_BASE_DEFAULT) };

    // Read version register.
    let version = unsafe { ioapic_read(IOAPIC_VER) };
    let max_entry = ((version >> 16) & 0xFF) as u8;
    MAX_REDIRECTION_ENTRY.store(max_entry, Ordering::Release);

    println!(
        "[ioapic] version=0x{:08X}  max_redirection_entry={}",
        version, max_entry
    );

    // Set IOAPIC ID to 0.
    unsafe { ioapic_write(IOAPIC_ID, 0) };

    // Mask all redirection entries.
    for i in 0..=max_entry {
        let (lo, _hi) = read_redirection_entry(i);
        write_redirection_entry(i, lo | INT_MASKED, 0);
    }
}

/// Number of redirection table entries.
pub fn redirection_entry_count() -> u8 {
    MAX_REDIRECTION_ENTRY.load(Ordering::Acquire) + 1
}

/// Route an ISA IRQ to a vector on the BSP (LAPIC ID 0).
///
/// The entry is configured as:
/// - Fixed delivery mode
/// - Physical destination mode
/// - Edge-triggered, active high
/// - Destination: LAPIC ID 0
///
/// Call `ioapic_unmask_irq()` after routing to enable the interrupt.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn ioapic_route_irq(irq: u8, vector: u8) {
    let max_entry = MAX_REDIRECTION_ENTRY.load(Ordering::Acquire);
    if irq > max_entry {
        return;
    }

    let lo = (vector as u32) | DELIVERY_FIXED | DESTINATION_PHYSICAL;
    // Destination field in bits 56–63 of the 64-bit entry (high 32 bits, bits
    // 24–31). LAPIC ID 0 → destination 0.
    let hi = 0u32; // LAPIC ID 0

    write_redirection_entry(irq, lo, hi);
}

/// Set the destination LAPIC ID of an IOAPIC redirection entry.
///
/// Rewrites bits 56–63 of the entry (the destination field) to `lapic_id`,
/// leaving the vector, delivery mode, polarity, and trigger settings
/// untouched.  Called by the IRQ load balancer to re-target a device
/// interrupt onto a different CPU.
///
/// Available on all targets; only bare-metal x86_64 actually invokes it
/// (dead-code allowed elsewhere).
#[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
pub fn ioapic_set_irq_destination(pin: u8, lapic_id: u8) {
    let max_entry = MAX_REDIRECTION_ENTRY.load(Ordering::Acquire);
    if pin > max_entry {
        return;
    }

    let hi_reg = REDIRECTION_TABLE_BASE + 2 * pin + 1;
    let base = IOAPIC_BASE.load(Ordering::Relaxed);

    unsafe {
        // Destination field is bits 56–63 of the 64-bit entry, i.e. bits
        // 24–31 of the high 32-bit half.  Preserve the reserved low bits.
        ptr::write_volatile((base + IOREGSEL) as *mut u32, hi_reg as u32);
        let hi = ptr::read_volatile((base + IOWIN) as *const u32);
        ptr::write_volatile((base + IOREGSEL) as *mut u32, hi_reg as u32);
        ptr::write_volatile(
            (base + IOWIN) as *mut u32,
            (hi & 0x00FF_FFFF) | ((lapic_id as u32) << 24),
        );
    }
}

/// Unmask (enable) an IOAPIC IRQ line.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn ioapic_unmask_irq(irq: u8) {
    let (lo, hi) = read_redirection_entry(irq);
    write_redirection_entry(irq, lo & !INT_MASKED, hi);
}

/// Mask (disable) an IOAPIC IRQ line.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn ioapic_mask_irq(irq: u8) {
    let (lo, hi) = read_redirection_entry(irq);
    write_redirection_entry(irq, lo | INT_MASKED, hi);
}

/// Set up ISA IRQ routing through the IOAPIC.
///
/// Routes:
/// - IRQ 0 (timer)  → vector 32
/// - IRQ 1 (keyboard) → vector 33
/// - IRQ 2 (cascade, typically unused on APIC systems)
///
/// After routing, the IOAPIC entries are unmasked so interrupts can
/// be delivered.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn ioapic_setup_isa_irqs() {
    // Route the PIT timer to vector 32.  The i8254 PIT output lands on a
    // different I/O APIC pin depending on the machine model: i440fx exposes
    // it as ISA IRQ 0 (pin 0), while QEMU's q35 routes it through the LPC
    // bridge onto pin 2 (GSI 2).  Route both pins to the timer vector so the
    // 100 Hz tick is delivered regardless of machine type; on i440fx pin 2 is
    // the (silent on APIC systems) legacy cascade, and on q35 pin 0 has no
    // attached device, so a single unmasked pin fires in practice.
    ioapic_route_irq(0, 32);
    ioapic_unmask_irq(0);
    ioapic_route_irq(2, 32);
    ioapic_unmask_irq(2);

    // Route IRQ 1 (keyboard) to vector 33.
    ioapic_route_irq(1, 33);
    ioapic_unmask_irq(1);

    // IRQ 2 is the cascade from the slave PIC; we don't route it.
    // Other IRQs remain masked until a driver explicitly enables them.
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioapic_redirection_constants() {
        assert_ne!(DELIVERY_FIXED, DELIVERY_SMI);
        assert_ne!(DELIVERY_FIXED, DELIVERY_NMI);
        assert_ne!(DESTINATION_PHYSICAL, DESTINATION_LOGICAL);
        assert_ne!(TRIGGER_LEVEL, 0);
        assert_ne!(INT_MASKED, 0);
    }

    #[test]
    fn ioapic_redirection_entry_register_indices() {
        // Entry 0: low at REDIRECTION_TABLE_BASE, high at REDIRECTION_TABLE_BASE + 1.
        assert_eq!(REDIRECTION_TABLE_BASE, 0x10);
        assert_eq!(REDIRECTION_TABLE_BASE + 1, 0x11);
        // Entry 23: low at 0x10 + 46 = 0x3E, high at 0x3F.
        assert_eq!(REDIRECTION_TABLE_BASE + 2 * 23, 0x3E);
        assert_eq!(REDIRECTION_TABLE_BASE + 2 * 23 + 1, 0x3F);
    }
}
