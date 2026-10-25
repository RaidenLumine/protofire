//! src/arch/x86_64/interrupts.rs
//!
//! x86_64 interrupt enable/disable helpers and common IRQ dispatch glue.

use core::arch::asm;

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use super::port::Port;
use crate::arch::interrupt_controller;
use crate::drivers::keyboard;
use crate::kernel::process;

// IRQ vector assignments.  When the APIC is active these are routed
// through the IOAPIC; when using the legacy PIC they correspond to
// the master/slave PIC offsets.
pub const TIMER_VECTOR: u8 = 32;
pub const KEYBOARD_VECTOR: u8 = 33;
/// The console UART's received-data interrupt: ISA IRQ 4, whose vector is the
/// PIC's mapping (32 + 4) so the legacy and APIC paths name it the same.  The
/// IOAPIC routes pin 4 here and the UART is armed for it once that route
/// exists (`super::ioapic::ioapic_setup_isa_irqs`).
pub const COM1_VECTOR: u8 = 36;

// ─── MSI-X vectors for device drivers ────────────────────────────
// These are allocated from the free range 34-127 (non-exception,
// non-IPI, non-syscall).  VirtIO uses 46-47; NVMe's completions are
// message-signalled like the other PCIe devices' now, so its driver
// claims a vector out of the MSI-X window instead of naming a constant
// here (the 44-45 pair the class used before the claim existed).

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
    // SAFETY: `pushfq`/`pop` move the flags register through the stack and give
    // back every byte they take: the flags come out unchanged, which is what
    // `preserves_flags` claims.
    //
    // Neither `nostack` nor `nomem` is claimed, because the sequence does use
    // the stack it is already on — it writes there.  Claiming `nomem` would let
    // the compiler move other accesses across a block that touches memory.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
    }

    rflags & (1 << 9) != 0
}

pub(crate) fn handle_irq(vector: u8, _allow_preemption: bool) {
    match vector {
        TIMER_VECTOR => {
            // Only the boot CPU owns the machine's clock.  Every CPU now takes
            // this vector — the boot CPU from the PIT through the I/O APIC,
            // each AP from its own LAPIC timer — and the tick counter is one
            // number the scheduler reads everywhere.  Letting each of them
            // advance it would make a tick pass four times as fast on a
            // four-CPU machine, and every timeout, sleep and retransmission
            // measured in ticks would be a quarter of what it says.
            //
            // So an AP's timer is a *preemption clock*, not a second source of
            // time: it asks the scheduler to look at the CPU it interrupted and
            // keeps the boot CPU's tick as the answer to "what time is it".
            let boot_cpu = crate::kernel::percpu::get().cpu_id == 0;
            let ticks = if boot_cpu {
                super::timer::acknowledge_tick()
            } else {
                super::timer::ticks()
            };
            interrupt_controller::end_of_interrupt(vector as u32);
            if boot_cpu {
                process::on_timer_tick_with_preemption(ticks, _allow_preemption);
            } else {
                // The per-CPU half only: sweep this CPU's own sleepers and
                // preempt its current thread.  The machine-wide work a tick
                // carries — the network clock, the device polls, the deferred
                // maintenance — belongs to the one clock, which is the branch
                // above.
                process::on_local_timer_tick_with_preemption(ticks, _allow_preemption);
                // One line, the first time: an AP that programs its LAPIC
                // timer and never takes the interrupt looks identical to one
                // with no timer from every other angle — the entry can be
                // masked, the vector mis-routed, the counter never started.
                // This is the only place that can tell them apart, and it is
                // what `check-smp-runtime` reads to know the timer works
                // rather than merely exists.
                crate::arch::x86_64::timer::note_ap_timer_tick(crate::kernel::percpu::get().cpu_id);
            }
            return;
        }
        KEYBOARD_VECTOR => {
            let scancode = read_keyboard_scancode();
            keyboard::handle_scancode(scancode);
        }
        COM1_VECTOR => {
            // The console UART's received-data interrupt: drain what arrived
            // and bridge it to the console, which is what input used to depend
            // on the timer tick to do.
            crate::drivers::serial::handle_rx_interrupt();
        }
        VIRTIO_CONFIG_VECTOR | VIRTIO_QUEUE_VECTOR => {
            VIRTIO_IRQ_FIRED.store(true, Ordering::Release);
        }
        // A device's own MSI-X vectors: the identity is the vector, and the
        // handler is whoever claimed it (see `src/arch/x86_64/msi.rs`).  A
        // vector in the window that nobody claimed is counted as spurious, the
        // same answer the device-tree machines give an unclaimed identity.
        v if super::msi::is_msix_vector(v) && !super::msi::dispatch_vector(v) => {
            crate::kernel::irq_stats::record_spurious();
        }
        // A claimed vector: its handler has already run.
        v if super::msi::is_msix_vector(v) => {}
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
