//! src/arch/x86_64/interrupt_controller.rs
//! x86_64 interrupt controller drivers — 8259A PIC and APIC/IOAPIC.
//!
//! Implements the architecture-neutral `InterruptController` trait so
//! callers can use the dispatch functions in `crate::arch::interrupt_controller`
//! instead of coupling directly to the hardware.
//!
//! ## Controller selection
//!
//! When the APIC is available (which is the case on all modern x86_64 CPUs
//! and QEMU), the `APIC_CONTROLLER` is used.  The legacy `PIC_CONTROLLER`
//! is kept as a fallback for environments without APIC support.

use core::sync::atomic::{AtomicBool, Ordering};

use super::port::Port;
use crate::arch::interrupt_controller::InterruptController;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;
const PIC_EOI: u8 = 0x20;

const ICW1_ICW4: u8 = 0x01;
const ICW1_INIT: u8 = 0x10;
const ICW4_8086: u8 = 0x01;

pub const MASTER_VECTOR_OFFSET: u8 = 32;
pub const SLAVE_VECTOR_OFFSET: u8 = 40;
pub const LAST_VECTOR: u8 = SLAVE_VECTOR_OFFSET + 7;
pub const TIMER_VECTOR: u8 = MASTER_VECTOR_OFFSET;
pub const KEYBOARD_VECTOR: u8 = MASTER_VECTOR_OFFSET + 1;

/// Singleton PIC controller used by the arch-level dispatch.
pub static PIC_CONTROLLER: PicController = PicController;

/// 8259A Programmable Interrupt Controller.
pub struct PicController;

impl InterruptController for PicController {
    fn init(&self) {
        if INITIALIZED.swap(true, Ordering::Acquire) {
            return;
        }

        super::interrupts::disable();
        super::idt::init();
        remap_pic(MASTER_VECTOR_OFFSET, SLAVE_VECTOR_OFFSET);
        mask_irqs(0xFC, 0xFF);
    }

    fn end_of_interrupt(&self, vector: u32) {
        let mut pic1_command = Port::<u8>::new(PIC1_COMMAND);
        let mut pic2_command = Port::<u8>::new(PIC2_COMMAND);

        unsafe {
            if vector as u8 >= SLAVE_VECTOR_OFFSET {
                pic2_command.write(PIC_EOI);
            }
            pic1_command.write(PIC_EOI);
        }
    }

    fn enable_interrupt(&self, _interrupt_id: u32) {
        // The 8259 PIC uses a fixed mask set at init time.
        // Individual IRQ enable/disable is not supported through
        // this interface; the mask is configured once in init().
    }

    fn set_priority(&self, _interrupt_id: u32, _priority: u8) {
        // The 8259 PIC has a fixed priority scheme (IRQ0 > IRQ1 > ... >
        // IRQ7 > IRQ8 > ... > IRQ15).  Per-IRQ priority is not supported.
    }
}

/// Legacy: send EOI to the PIC(s) servicing `vector`.
///
/// Prefer `InterruptController::end_of_interrupt` through the dispatch
/// layer.  This function remains for callers that need a bare function
/// pointer and for backward compatibility with existing vector-typed paths.
#[allow(dead_code)]
pub(crate) fn acknowledge(vector: u8) {
    PIC_CONTROLLER.end_of_interrupt(vector as u32);
}

fn remap_pic(master_offset: u8, slave_offset: u8) {
    let mut pic1_command = Port::<u8>::new(PIC1_COMMAND);
    let mut pic1_data = Port::<u8>::new(PIC1_DATA);
    let mut pic2_command = Port::<u8>::new(PIC2_COMMAND);
    let mut pic2_data = Port::<u8>::new(PIC2_DATA);

    let master_mask = unsafe { pic1_data.read() };
    let slave_mask = unsafe { pic2_data.read() };

    unsafe {
        pic1_command.write(ICW1_INIT | ICW1_ICW4);
        io_wait();
        pic2_command.write(ICW1_INIT | ICW1_ICW4);
        io_wait();

        pic1_data.write(master_offset);
        io_wait();
        pic2_data.write(slave_offset);
        io_wait();

        pic1_data.write(4);
        io_wait();
        pic2_data.write(2);
        io_wait();

        pic1_data.write(ICW4_8086);
        io_wait();
        pic2_data.write(ICW4_8086);
        io_wait();

        pic1_data.write(master_mask);
        pic2_data.write(slave_mask);
    }
}

fn mask_irqs(master_mask: u8, slave_mask: u8) {
    let mut pic1_data = Port::<u8>::new(PIC1_DATA);
    let mut pic2_data = Port::<u8>::new(PIC2_DATA);

    unsafe {
        pic1_data.write(master_mask);
        pic2_data.write(slave_mask);
    }
}

unsafe fn io_wait() {
    let mut port = Port::<u8>::new(0x80);
    port.write(0);
}

// ---------------------------------------------------------------------------
// APIC/IOAPIC interrupt controller (bare-metal only)
// ---------------------------------------------------------------------------

/// Singleton APIC-based interrupt controller used by the arch-level dispatch
/// on modern x86_64 systems (QEMU q35 and real hardware with LAPIC/IOAPIC).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub static APIC_CONTROLLER: ApicInterruptController = ApicInterruptController;

/// Interrupt controller that uses the Local APIC and IOAPIC instead of the
/// legacy 8259 PIC.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub struct ApicInterruptController;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl InterruptController for ApicInterruptController {
    fn init(&self) {
        if INITIALIZED.swap(true, Ordering::Acquire) {
            return;
        }

        super::interrupts::disable();

        // The legacy 8259 PIC must be brought into a known state (ICW1-ICW4)
        // before its mask register functions correctly.  On some hardware
        // (including QEMU), writing the IMR without prior ICW initialisation
        // has no effect, leaving the PIC with its power-on vector mapping.
        // Since the PIC's default master IRQ0 (timer) aliases vector 8
        // (the #DF exception), an unmasked PIC would deliver an interrupt
        // through ISR_ERR which expects a CPU-pushed error code that the PIC
        // INTR cycle does not provide — corrupting the interrupt stack frame.
        //
        // Remap the PIC to a safe vector range (32-47), mask every IRQ, then
        // hand control to the APIC.
        remap_pic(MASTER_VECTOR_OFFSET, SLAVE_VECTOR_OFFSET);
        mask_irqs(0xFF, 0xFF);
        crate::println!("[apic  ] legacy PIC remapped to vectors 32-47 and fully masked");

        // The LAPIC MMIO registers at 0xFEE0_0000 lie above the 1 GiB
        // bootstrap identity map and are not statically pre-mapped, so the
        // first lapic_read/write would #PF before init_ioapic() installs the
        // device MMIO identity map.  map_device_mmio_page() identity-maps both
        // the LAPIC and IOAPIC pages and is idempotent (the later call inside
        // init_ioapic() is a no-op).
        unsafe { super::apic::map_device_mmio_page(super::apic::LAPIC_MMIO_BASE_DEFAULT) };

        // Initialize the Local APIC.
        super::apic::init_lapic();
        crate::println!(
            "[apic  ] LAPIC initialized (id={})",
            super::apic::lapic_id()
        );

        // Initialize the IOAPIC.
        super::ioapic::init_ioapic();
        crate::println!(
            "[apic  ] IOAPIC initialized ({} redirection entries)",
            super::ioapic::redirection_entry_count()
        );

        // Set up ISA IRQ routing through the IOAPIC.
        super::ioapic::ioapic_setup_isa_irqs();
        crate::println!("[apic  ] ISA IRQs routed through IOAPIC (IRQ0→vec32, IRQ1→vec33)");
    }

    fn end_of_interrupt(&self, _vector: u32) {
        super::apic::lapic_eoi();
    }

    fn enable_interrupt(&self, interrupt_id: u32) {
        super::ioapic::ioapic_unmask_irq(interrupt_id as u8);
    }

    fn set_priority(&self, _interrupt_id: u32, priority: u8) {
        let tpr_val = priority as u32 & 0xF0;
        let base = super::apic::LAPIC_MMIO_BASE_DEFAULT;
        unsafe {
            core::ptr::write_volatile((base + super::apic::LAPIC_TPR) as *mut u32, tpr_val);
        }
    }
}
