//! src/arch/x86_64/apic.rs
//!
//! Local APIC (LAPIC) driver: MMIO identity mapping, register access,
//! initialisation, EOI, APIC ID, and inter-processor interrupt (IPI) ICR
//! helpers.  Bare-metal x86_64 only.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::AtomicBool;
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

/// Statically-allocated PD for LAPIC/IOAPIC identity mapping (PDPT entry 3,
/// covering the 3–4 GiB region where 0xFEE0_0000 and 0xFEC0_0000 live).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static mut HIGH_PD: PageTablePage = PageTablePage::ZEROED;
/// Statically-allocated PTs for LAPIC (PDPT[3] PD index 503) and IOAPIC
/// (PDPT[3] PD index 502).  Both pages are identity-mapped: the MMIO
/// physical addresses 0xFEE0_0000 / 0xFEC0_0000 are used directly as
/// virtual addresses.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static mut HIGH_PTS: [PageTablePage; 2] = [PageTablePage::ZEROED; 2];

/// Identity-map the LAPIC and IOAPIC MMIO pages into the active kernel page
/// tables using statically-allocated intermediate tables.
///
/// Both registers live in the 3–4 GiB physical-address range (PDPT[3]).
/// Rather than blindly replacing the PDPT entry — which would destroy any
/// existing device mappings in that range (framebuffer BAR0, ECAM, etc.) —
/// this function checks whether PDPT[3] is already present:
///
/// * If **present**, it adds the LAPIC/IOAPIC PD entries into the **existing**
///   PD page so that both the prior mappings and the new identity mappings
///   co-exist.
/// * If **not present**, it installs the statically-allocated `HIGH_PD` as the
///   PDPT entry, which only contains the two entries.
///
/// In both cases the raw MMIO pointers used by `lapic_read` / `lapic_write`
/// and `ioapic_read` / `ioapic_write` become valid identity mappings.
///
/// # Safety
///
/// Must be called with the active PML4 valid (runtime page tables active),
/// interrupts disabled, and before any other CPU exists.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn map_device_mmio_page(_phys_addr: usize) {
    static MAPPED: AtomicBool = AtomicBool::new(false);
    if MAPPED.swap(true, Ordering::Acquire) {
        return; // already set up
    }

    // Read the active PML4 address from CR3.
    let pml4_addr: u64;
    unsafe {
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

    // PD indices within PDPT[3] (PDPT base = 0xC000_0000):
    //   LAPIC  0xFEE0_0000 → PD[503] (0x1F7)
    //   IOAPIC 0xFEC0_0000 → PD[502] (0x1F6)
    // Both PT indices are 0x000 (page offset within the 2 MiB PD entry).
    const LAPIC_PD_IDX: usize = 503;
    const IOAPIC_PD_IDX: usize = 502;

    unsafe {
        // Wire up the statically-allocated PTs regardless.
        HIGH_PD.0[LAPIC_PD_IDX] =
            (core::ptr::addr_of!(HIGH_PTS[0]) as u64) | PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;
        HIGH_PTS[0].0[0] = (0xFEE0_0000u64) | PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;

        HIGH_PD.0[IOAPIC_PD_IDX] =
            (core::ptr::addr_of!(HIGH_PTS[1]) as u64) | PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;
        HIGH_PTS[1].0[0] = (0xFEC0_0000u64) | PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;

        let existing_pdpt_entry = (*pdpt)[3];

        if existing_pdpt_entry & PAGE_ENTRY_PRESENT != 0 {
            // PDPT[3] already has a valid PD — likely created by
            // `map_device_mmio` for a PCI BAR (e.g. framebuffer) that sits in
            // the 3–4 GiB range.  Add LAPIC/IOAPIC entries to the existing PD
            // instead of replacing the PDPT entry.
            let existing_pd = (existing_pdpt_entry as usize & PAGE_ENTRY_ADDRESS_MASK as usize)
                as *mut [u64; PAGE_TABLE_ENTRY_COUNT];

            // Only write if the target entries are currently empty, avoiding
            // overwriting an existing mapping for the same physical pages.
            if (*existing_pd)[LAPIC_PD_IDX] & PAGE_ENTRY_PRESENT == 0 {
                (*existing_pd)[LAPIC_PD_IDX] = HIGH_PD.0[LAPIC_PD_IDX];
            }
            if (*existing_pd)[IOAPIC_PD_IDX] & PAGE_ENTRY_PRESENT == 0 {
                (*existing_pd)[IOAPIC_PD_IDX] = HIGH_PD.0[IOAPIC_PD_IDX];
            }
        } else {
            // No existing mapping for the 3–4 GiB region — install HIGH_PD
            // directly as the PDPT entry.
            (*pdpt)[3] =
                (core::ptr::addr_of!(HIGH_PD) as u64) | PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;
        }
    }

    // Flush all TLB entries so the new LAPIC/IOAPIC mappings take effect.
    // A plain CR3 reload would not flush once CR4.PCIDE is set, so go through
    // the PCID-aware path (INVPCID when active, CR3 reload otherwise).
    crate::arch::x86_64::paging::pcid::flush_all_tlb();
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
    core::ptr::read_volatile((LAPIC_MMIO_BASE_DEFAULT + offset as usize) as *const u32)
}

/// Write a 32-bit value to the LAPIC register at `offset`.
///
/// # Safety
///
/// Same requirements as [`lapic_read`].
pub unsafe fn lapic_write(offset: u32, value: u32) {
    core::ptr::write_volatile(
        (LAPIC_MMIO_BASE_DEFAULT + offset as usize) as *mut u32,
        value,
    );
}

/// Acknowledge the current interrupt by writing the LAPIC EOI register.
pub fn lapic_eoi() {
    unsafe {
        lapic_write(LAPIC_EOI as u32, 0);
    }
}

/// Read this CPU's LAPIC ID (upper 8 bits of the LAPIC ID register).
pub fn lapic_id() -> u32 {
    unsafe { lapic_read(LAPIC_ID as u32) >> 24 }
}

// ─── LAPIC initialisation ──────────────────────────────────────────────

/// Initialise the local APIC on the BSP: enable it via SVR, clear the TPR,
/// and mask the LVT entries that are not otherwise configured.
pub fn init_lapic() {
    // Enable the LAPIC and point the spurious vector at a valid vector.
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
    unsafe {
        let svr = lapic_read(LAPIC_SVR as u32);
        lapic_write(LAPIC_SVR as u32, (svr | SVR_APIC_ENABLE) | SPURIOUS_VECTOR);
        lapic_write(LAPIC_TPR as u32, 0);
    }
}
