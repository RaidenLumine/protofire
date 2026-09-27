//! src/arch/x86_64/interrupts.rs
//!
//! x86_64 interrupt enable/disable helpers and common IRQ dispatch glue.

use core::arch::asm;

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use super::port::Port;
use crate::arch::interrupt_controller;
use crate::drivers::keyboard;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::drivers::nvme;
use crate::kernel::process;

// IRQ vector assignments.  When the APIC is active these are routed
// through the IOAPIC; when using the legacy PIC they correspond to
// the master/slave PIC offsets.
pub const TIMER_VECTOR: u8 = 32;
pub const KEYBOARD_VECTOR: u8 = 33;

// ─── MSI-X vectors for device drivers ────────────────────────────
// These are allocated from the free range 34-127 (non-exception,
// non-IPI, non-syscall).  NVMe uses 44-45; VirtIO uses 46-47.

/// MSI-X vector for VirtIO config-space change notifications.
pub const VIRTIO_CONFIG_VECTOR: u8 = 46;
/// MSI-X vector for VirtIO virtqueue notifications.
pub const VIRTIO_QUEUE_VECTOR: u8 = 47;

/// Global IRQ-fired flag for VirtIO MSI-X.
///
/// Set by the ISR when any VirtIO MSI-X vector fires; consumed (cleared)
/// by the VirtIO virtqueue polling code.  Using a single flag for all
/// VirtIO devices is acceptable: the polling loop syncs the device's own
/// used-ring index, so a spurious wake-up (flag set by a different
/// device) just results in one extra iteration that finds nothing.
#[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
pub(crate) static VIRTIO_IRQ_FIRED: AtomicBool = AtomicBool::new(false);

pub fn enable() {
    // SAFETY: setting the interrupt flag is a privileged, memory-free
    // instruction; the caller is responsible for being in a state where taking
    // an interrupt is correct.
    unsafe {
        asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

pub fn disable() {
    // SAFETY: as `enable` — clearing the flag, which the caller pairs with a
    // later enable.
    unsafe {
        asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

/// Enable interrupts and halt in a single instruction window.
/// This ensures a pending interrupt is serviced immediately rather than
/// just waking the CPU from HLT with IF still clear.
pub fn enable_and_halt() {
    // SAFETY: a single instruction window that sets the interrupt flag and
    // halts, so a pending interrupt is taken rather than merely waking the CPU;
    // neither instruction touches memory.
    unsafe {
        asm!("sti; hlt", options(nomem, nostack, preserves_flags));
    }
}

pub fn are_enabled() -> bool {
    let rflags: u64;
    // SAFETY: `pushfq`/`pop` move the flags register through the stack without
    // reading or writing any memory the kernel cares about, and `nostack` is
    // not claimed because the sequence does use the stack it is already on.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags));
    }

    rflags & (1 << 9) != 0
}

pub(crate) fn handle_irq(vector: u8, _allow_preemption: bool) {
    match vector {
        TIMER_VECTOR => {
            let ticks = super::timer::acknowledge_tick();
            interrupt_controller::end_of_interrupt(vector as u32);
            process::on_timer_tick_with_preemption(ticks, _allow_preemption);
            return;
        }
        KEYBOARD_VECTOR => {
            let scancode = read_keyboard_scancode();
            keyboard::handle_scancode(scancode);
        }
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        v if v == nvme::NVME_ADMIN_VECTOR || v == nvme::NVME_IO_VECTOR => {
            nvme::nvme_irq_handler();
        }
        VIRTIO_CONFIG_VECTOR | VIRTIO_QUEUE_VECTOR => {
            VIRTIO_IRQ_FIRED.store(true, Ordering::Release);
        }
        _ => {}
    }

    // Send EOI through the dispatch layer (PIC or LAPIC, depending on
    // which controller is active).
    interrupt_controller::end_of_interrupt(vector as u32);
}

fn read_keyboard_scancode() -> u8 {
    let mut data = Port::<u8>::new(0x60);
    // SAFETY: port 0x60 is the PS/2 data port on this machine, read inside the
    // keyboard handler that the PIC vector dispatched.
    unsafe { data.read() }
}
