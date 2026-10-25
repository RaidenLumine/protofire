//! src/arch/x86_64/apic.rs
//!
//! Local APIC (LAPIC) driver: MMIO identity mapping, register access,
//! initialisation, EOI, APIC ID, and inter-processor interrupt (IPI) ICR
//! helpers.  Bare-metal x86_64 only.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::AtomicBool;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::AtomicU32;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::Ordering;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::paging::PAGE_ENTRY_ADDRESS_MASK;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::paging::PAGE_ENTRY_PRESENT;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::paging::PAGE_ENTRY_WRITABLE;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PAGE_TABLE_ENTRY_COUNT: usize = 512;

/// Page-sized, 4 KiB-aligned array usable as an x86_64 intermediate page
/// table (PDPT, PD, or PT).  The `align(4096)` is mandatory — the CPU
/// masks the low 12 bits of every table entry to locate the next level,
/// so the array must reside at a page boundary.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[repr(align(4096))]
struct PageTablePage([u64; PAGE_TABLE_ENTRY_COUNT]);

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl PageTablePage {
    const ZEROED: Self = Self([0u64; PAGE_TABLE_ENTRY_COUNT]);
}

/// Statically-allocated PD for the LAPIC identity mapping (PDPT entry 3,
/// covering the 3–4 GiB region where 0xFEE0_0000 lives).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static mut HIGH_PD: PageTablePage = PageTablePage::ZEROED;
/// A statically-allocated PT for the LAPIC (PDPT[3] PD index 503): the MMIO
/// physical address 0xFEE0_0000 is used directly as a virtual address.  The
/// I/O APIC is *not* mapped here — its address is the machine's, read from the
/// MADT, and it is mapped by `init_ioapic` through the general device mapper.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static mut HIGH_PTS: [PageTablePage; 1] = [PageTablePage::ZEROED; 1];

/// Identity-map the LAPIC MMIO page into the active kernel page tables using
/// statically-allocated intermediate tables.
///
/// The LAPIC register window lives at the architectural address 0xFEE0_0000,
/// in the 3–4 GiB range (PDPT[3]).  Rather than blindly replacing the PDPT
/// entry — which would destroy any existing device mappings in that range
/// (framebuffer BAR0, ECAM, etc.) — this function checks whether PDPT[3] is
/// already present:
///
/// * If **present**, it adds the LAPIC PD entry into the **existing** PD page
///   so that both the prior mappings and the new identity mapping co-exist.
/// * If **not present**, it installs the statically-allocated `HIGH_PD` as the
///   PDPT entry, which contains the one entry.
///
/// In both cases the raw MMIO pointers used by `lapic_read` / `lapic_write`
/// become valid identity mappings.  The I/O APIC is mapped separately, at the
/// address the machine declares, by `ioapic::init_ioapic`.
///
/// # Safety
///
/// Must be called with the active PML4 valid (runtime page tables active),
/// interrupts disabled, and before any other CPU exists.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn map_device_mmio_page(_phys_addr: usize) {
    // SAFETY: the contract above — the active PML4, interrupts off, one CPU —
    // is what makes editing the live page tables sound; the guard below keeps
    // the edit from happening twice.
    unsafe {
        static MAPPED: AtomicBool = AtomicBool::new(false);
        if MAPPED.swap(true, Ordering::Acquire) {
            return; // already set up
        }

        // Read the active PML4 address from CR3.
        let pml4_addr: u64;
        {
            core::arch::asm!(
                "mov {}, cr3",
                out(reg) pml4_addr,
                options(nostack, preserves_flags)
            );
        }
        let pml4 = (pml4_addr as usize & PAGE_ENTRY_ADDRESS_MASK as usize)
            as *mut [u64; PAGE_TABLE_ENTRY_COUNT];

        // LAPIC (0xFEE0_0000) and IOAPIC (0xFEC0_0000) are in PML4[0],
        // PDPT[3] (covers 3 GiB – 4 GiB).  Read KERNEL_PDPT from PML4[0].
        let pdpt = ((*pml4)[0] as usize & PAGE_ENTRY_ADDRESS_MASK as usize)
            as *mut [u64; PAGE_TABLE_ENTRY_COUNT];

        // PD index within PDPT[3] (PDPT base = 0xC000_0000):
        //   LAPIC  0xFEE0_0000 → PD[503] (0x1F7)
        // Its PT index is 0x000 (page offset within the 2 MiB PD entry).
        const LAPIC_PD_IDX: usize = 503;

        {
            // Wire up the statically-allocated PT regardless.
            HIGH_PD.0[LAPIC_PD_IDX] = (core::ptr::addr_of!(HIGH_PTS[0]) as u64)
                | PAGE_ENTRY_PRESENT
                | PAGE_ENTRY_WRITABLE;
            HIGH_PTS[0].0[0] = (0xFEE0_0000u64) | PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;

            let existing_pdpt_entry = (*pdpt)[3];

            if existing_pdpt_entry & PAGE_ENTRY_PRESENT != 0 {
                // PDPT[3] already has a valid PD — likely created by
                // `map_device_mmio` for a PCI BAR (e.g. framebuffer) that sits in
                // the 3–4 GiB range.  Add the LAPIC entry to the existing PD
                // instead of replacing the PDPT entry.
                let existing_pd = (existing_pdpt_entry as usize & PAGE_ENTRY_ADDRESS_MASK as usize)
                    as *mut [u64; PAGE_TABLE_ENTRY_COUNT];

                // Only write if the target entry is currently empty, avoiding
                // overwriting an existing mapping for the same physical page.
                if (*existing_pd)[LAPIC_PD_IDX] & PAGE_ENTRY_PRESENT == 0 {
                    (*existing_pd)[LAPIC_PD_IDX] = HIGH_PD.0[LAPIC_PD_IDX];
                }
            } else {
                // No existing mapping for the 3–4 GiB region — install HIGH_PD
                // directly as the PDPT entry.
                (*pdpt)[3] = (core::ptr::addr_of!(HIGH_PD) as u64)
                    | PAGE_ENTRY_PRESENT
                    | PAGE_ENTRY_WRITABLE;
            }
        }

        // Flush all TLB entries so the new LAPIC/IOAPIC mappings take effect.
        // A plain CR3 reload would not flush once CR4.PCIDE is set, so go through
        // the PCID-aware path (INVPCID when active, CR3 reload otherwise).
        crate::arch::x86_64::paging::pcid::flush_all_tlb();
    }
}

// ---------------------------------------------------------------------------
// LAPIC MMIO base
// ---------------------------------------------------------------------------

/// Default LAPIC MMIO base address (architectural).
#[allow(dead_code)]
pub const LAPIC_MMIO_BASE_DEFAULT: usize = 0xFEE0_0000;

// ---------------------------------------------------------------------------
// LAPIC register offsets (from MMIO base, in bytes)
// ---------------------------------------------------------------------------

/// Local APIC ID register.
#[allow(dead_code)]
pub const LAPIC_ID: usize = 0x0020;
/// Task Priority Register.
pub const LAPIC_TPR: usize = 0x0080;
/// End Of Interrupt register.
pub const LAPIC_EOI: usize = 0x00B0;
/// Spurious Interrupt Vector Register.
pub const LAPIC_SVR: usize = 0x00F0;
/// Local Vector Table entry for the APIC timer.
pub const LAPIC_LVT_TIMER: usize = 0x0320;
/// Timer divide configuration register.
pub const LAPIC_TIMER_DCR: usize = 0x03E0;
/// Timer initial-count register (writing starts the countdown).
pub const LAPIC_TIMER_ICR: usize = 0x0380;
/// Timer current-count register (reads the countdown).
pub const LAPIC_TIMER_CCR: usize = 0x0390;
/// Interrupt Command Register — low DWORD (triggers the send).
pub const LAPIC_ICR_LOW: usize = 0x0300;
/// Interrupt Command Register — high DWORD (destination APIC ID).
pub const LAPIC_ICR_HIGH: usize = 0x0310;

/// SVR bit that enables the LAPIC.
pub const SVR_APIC_ENABLE: u32 = 1 << 8;
/// Spurious-interrupt vector number (bit 8 set → 0xFF | 0x100).
pub const SPURIOUS_VECTOR: u32 = 0xFF;

// ─── ICR low-DWORD field constants ────────────────────────────────────

/// Delivery mode: FIXED.
pub const ICR_DELIVERY_FIXED: u32 = 0x000;
/// Delivery mode: INIT (0x5 << 8).
pub const ICR_DELIVERY_INIT: u32 = 0x500;
/// Delivery mode: STARTUP (0x6 << 8).
pub const ICR_DELIVERY_STARTUP: u32 = 0x600;
/// Delivery status bit (1 while an IPI is still pending delivery).
pub const ICR_STATUS_PENDING: u32 = 1 << 12;
/// Level field: assert (used with trigger mode level for INIT).
pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;
/// Trigger mode: level (used for INIT).
pub const ICR_TRIGGER_LEVEL: u32 = 1 << 15;

// ─── LAPIC register access ─────────────────────────────────────────────

/// Read a 32-bit LAPIC register at `offset` (bytes from the MMIO base).
///
/// # Safety
///
/// The LAPIC MMIO pages must be identity-mapped (see
/// [`map_device_mmio_page`]) and `offset` must be within the LAPIC register
/// window.
pub unsafe fn lapic_read(offset: u32) -> u32 {
    // SAFETY: the contract above: the LAPIC pages are mapped and `offset` names
    // a register inside them.
    unsafe { core::ptr::read_volatile((LAPIC_MMIO_BASE_DEFAULT + offset as usize) as *const u32) }
}

/// Write a 32-bit value to the LAPIC register at `offset`.
///
/// # Safety
///
/// Same requirements as [`lapic_read`].
pub unsafe fn lapic_write(offset: u32, value: u32) {
    // SAFETY: as `lapic_read` — the same mapped window, on the write side.
    unsafe {
        core::ptr::write_volatile(
            (LAPIC_MMIO_BASE_DEFAULT + offset as usize) as *mut u32,
            value,
        );
    }
}

/// Acknowledge the current interrupt by writing the LAPIC EOI register.
pub fn lapic_eoi() {
    // SAFETY: the EOI register is a LAPIC register and the LAPIC page is mapped
    // by the time any interrupt handler runs.
    unsafe {
        lapic_write(LAPIC_EOI as u32, 0);
    }
}

/// Read this CPU's LAPIC ID (upper 8 bits of the LAPIC ID register).
pub fn lapic_id() -> u32 {
    // SAFETY: as `lapic_eoi` — the ID register of the mapped LAPIC.
    unsafe { lapic_read(LAPIC_ID as u32) >> 24 }
}

// ─── LAPIC initialisation ──────────────────────────────────────────────

/// Initialise the local APIC on the BSP: enable it via SVR, clear the TPR,
/// and mask the LVT entries that are not otherwise configured.
pub fn init_lapic() {
    // Enable the LAPIC and point the spurious vector at a valid vector.
    // SAFETY: the BSP's own LAPIC page, mapped by `map_device_mmio_page` before
    // this runs; these are its SVR and TPR registers.
    unsafe {
        let svr = lapic_read(LAPIC_SVR as u32);
        lapic_write(LAPIC_SVR as u32, (svr | SVR_APIC_ENABLE) | SPURIOUS_VECTOR);
        // Clear the task priority so all interrupts are accepted.
        lapic_write(LAPIC_TPR as u32, 0);
    }
    crate::println!(
        "[apic  ] LAPIC enabled (spurious vector 0x{:02x})",
        SPURIOUS_VECTOR,
    );
}

/// Initialise the local APIC on an application processor (AP).
///
/// Called from the AP trampoline before entering the scheduler.  Less work
/// than the BSP path: the LAPIC MMIO mapping is already in place and the
/// timer/interrupt vectors are shared system-wide.
pub fn init_lapic_ap() {
    // SAFETY: as `init_lapic` — the mapping is in place before an AP runs this,
    // which is what the note above records.
    unsafe {
        let svr = lapic_read(LAPIC_SVR as u32);
        lapic_write(LAPIC_SVR as u32, (svr | SVR_APIC_ENABLE) | SPURIOUS_VECTOR);
        lapic_write(LAPIC_TPR as u32, 0);
    }
}

/// The LAPIC timer's countdown value for one tick, in this CPU's bus clock.
///
/// Calibrated once and shared: every CPU's LAPIC runs at the same bus
/// frequency, and calibrating per CPU would spend a whole PIT tick on each of
/// them during a bring-up that already has one.  `AtomicU32` rather than a
/// lock because the value is a plain number written once by the first AP and
/// read by the rest.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static TIMER_COUNT_PER_TICK: AtomicU32 = AtomicU32::new(0);

/// The countdown this machine's LAPIC timer uses for one tick, or 0 when it
/// was never calibrated.
///
/// Read by the AP bring-up line, which is what a gate asserts: a CPU that says
/// it is online without a timer would be a CPU whose threads are never
/// preempted, and the number being non-zero is the difference.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn lapic_timer_count_per_tick() -> u32 {
    TIMER_COUNT_PER_TICK.load(Ordering::Acquire)
}

/// Program this CPU's LAPIC timer to interrupt at the PIT's rate.
///
/// The PIT is wired to one LAPIC (see `timer.rs` and the ioapic route), so an
/// AP that is given work has no tick of its own: a thread it runs cannot be
/// preempted by time slice, and a thread that sleeps there is woken only by
/// the boot CPU's sweep.  The LAPIC's own timer is per-CPU and needs no wire,
/// which is what makes it the right clock for an AP.
///
/// The rate has to match the PIT's, because the tick counter is one number the
/// scheduler reads on every CPU; a second rate would make "a tick" mean two
/// different lengths of time.  So the countdown is calibrated against the PIT
/// once and every CPU uses it.
///
/// Called after the LAPIC is enabled and before interrupts are unmasked.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn start_lapic_timer_ap() {
    let per_tick = TIMER_COUNT_PER_TICK.load(Ordering::Acquire);
    let per_tick = if per_tick == 0 {
        let counted = calibrate_timer_against_pit();
        if counted == 0 {
            // The PIT did not tick inside the window: programming a zero
            // countdown would leave this CPU with no timer at all, and
            // guessing one would give it a rate that disagrees with the tick
            // counter.  Leaving it unarmed is the honest answer — the CPU runs
            // until the boot CPU's sweep serves it, which is what it did
            // before this existed.
            crate::println!(
                "[apic  ] LAPIC timer not calibrated: this CPU keeps the boot CPU's tick"
            );
            return;
        }
        TIMER_COUNT_PER_TICK.store(counted, Ordering::Release);
        counted
    } else {
        per_tick
    };

    // SAFETY: this CPU's own LAPIC page, mapped before bring-up, and the three
    // registers are the timer's own: the divide configuration, the LVT entry
    // (periodic mode, unmasked, vector = the timer's), and the initial count
    // that starts it.
    unsafe {
        // Divide by 16: a countdown large enough to calibrate, small enough
        // that the initial count fits the register at 100 Hz.
        lapic_write(LAPIC_TIMER_DCR as u32, 0x3);
        lapic_write(
            LAPIC_LVT_TIMER as u32,
            (crate::arch::x86_64::interrupts::TIMER_VECTOR as u32) | LVT_TIMER_PERIODIC,
        );
        lapic_write(LAPIC_TIMER_ICR as u32, per_tick);
    }
}

/// Bits of the LVT timer entry this module sets.
///
/// Bit 17 is the mode: clear is one-shot, set is periodic.  Bit 16 masks the
/// entry; it stays clear so the timer actually interrupts.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const LVT_TIMER_PERIODIC: u32 = 1 << 17;

/// Count how fast this CPU's LAPIC timer runs, by timing it with the PIT.
///
/// The PIT is the machine's known-good clock here: it is programmed at 100 Hz
/// before any AP is started, and `timer::ticks()` advances when its interrupt
/// is acknowledged.  Starting the LAPIC timer at full count and reading what
/// is left after one PIT tick gives the countdown for one tick directly —
/// subtraction rather than a frequency, so the answer is in the units the
/// register takes.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn calibrate_timer_against_pit() -> u32 {
    use crate::arch::x86_64::timer as pit;

    // SAFETY: as above — this CPU's own LAPIC timer registers.  Divide by 16
    // for the calibration too, so the number measured is the number used.
    unsafe {
        lapic_write(LAPIC_TIMER_DCR as u32, 0x3);
        // Masked while it counts: this is a measurement, not a tick.
        lapic_write(LAPIC_LVT_TIMER as u32, LVT_TIMER_MASKED);
        lapic_write(LAPIC_TIMER_ICR as u32, u32::MAX);
    }

    // Wait for exactly one PIT tick.  The wait is bounded: a machine whose PIT
    // is not ticking must not hang an AP's bring-up, so this gives up after
    // twice the tick period in spin-loop iterations — an upper bound no
    // emulator on this tree's gates approaches, and one a broken PIT stops at
    // instead of holding the CPU.
    let start = pit::ticks();
    let mut spins = 0u64;
    while pit::ticks() == start {
        core::hint::spin_loop();
        spins += 1;
        if spins > CALIBRATION_SPIN_LIMIT {
            // SAFETY: stopping the timer this function started.
            unsafe { lapic_write(LAPIC_TIMER_ICR as u32, 0) };
            return 0;
        }
    }

    // SAFETY: reading this CPU's timer countdown.
    let remaining = unsafe { lapic_read(LAPIC_TIMER_CCR as u32) };
    // SAFETY: stopping it again — the caller restarts it in periodic mode.
    unsafe { lapic_write(LAPIC_TIMER_ICR as u32, 0) };

    u32::MAX.saturating_sub(remaining)
}

/// Bit 16 of the LVT timer entry: masked.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const LVT_TIMER_MASKED: u32 = 1 << 16;

/// Spin-loop bound for one calibration window.
///
/// A PIT tick is 10 ms.  This is far more iterations than that takes on any
/// machine the tree boots, and its purpose is only to keep a machine whose
/// PIT is silent from hanging where it used to run.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CALIBRATION_SPIN_LIMIT: u64 = 200_000_000;
