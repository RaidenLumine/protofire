//! src/arch/riscv64/aia_imsic.rs
//!
//! RISC-V AIA IMSIC (Incoming Message-Signalled Interrupt Controller)
//! driver for MSI / MSI-X delivery.
//!
//! The IMSIC is the AIA interrupt file that receives MSIs: a device delivers
//! an MSI by storing `(1 << 31) | irq` to the target hart's IMSIC file MMIO
//! address, which sets the pending bit for `irq` in that file's `eip`
//! register.  The hart claims the highest-priority pending interrupt by
//! reading the file's `ih` register and completes it (EOI) by writing the
//! claimed id back.
//!
//! This driver:
//! - manages one IMSIC file per hart ([`init_aia_imsic`] /
//!   [`imsic_file_base`]),
//! - implements [`InterruptController`] so EOI writes `ih`, enabling an
//!   interrupt sets its `eie` bit, and per-IRQ priority is a no-op (the IMSIC
//!   has a single per-file threshold),
//! - dispatches claimed interrupts through a per-IRQ handler table
//!   ([`register_irq_handler`] / [`handle_pending_external`]),
//! - programmes real 16-byte MSI-X table entries against a device BAR
//!   ([`configure_msix`]), replacing the previous software-only table.
//!
//! Reference: RISC-V Advanced Interrupt Architecture (AIA) v1.0, chapter 3.

use alloc::format;
use core::arch::asm;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use super::read_volatile;
use super::write_volatile;
use crate::arch::interrupt_controller::InterruptController;
use crate::kernel::percpu;
use crate::kernel::sync::SpinLock;
use crate::util::logger::log;
use crate::util::logger::LogLevel;
use crate::Error;

// ── Platform geometry ──────────────────────────────────────────────────
//
// With `-machine virt,aia=aplic-imsic` QEMU places the first IMSIC group at
// 0x2400_0000 with one 16 KiB file per hart.  These are the boot defaults;
// the FDT `riscv,imsic` node (parsed by [`crate::arch::fdt`]) overrides the
// base once the boot path calls `parse_fdt`.

/// Default IMSIC group base on QEMU `virt` with AIA.
const IMSIC_QEMU_VIRT_BASE: usize = 0x2400_0000;
/// MMIO stride between consecutive harts' IMSIC files on QEMU `virt`.
const IMSIC_QEMU_VIRT_STRIDE: usize = 0x4000;
/// Highest interrupt identity an IMSIC file can hold (2048 interrupts).
const IMSIC_MAX_IRQ: u32 = 2047;
/// Number of entries in the per-IRQ handler table.
const IRQ_TABLE_LEN: usize = 256;

// ── IMSIC file register offsets (AIA v1.0 §3.2) ─────────────────────────

/// Interrupt-pending registers (`eip`), one 64-bit word per 64 interrupts.
///
/// Claimed via `ih` rather than polled, so the pending bitmap is never read
/// directly; kept for the register map.
#[allow(dead_code)]
const IMSIC_EIP_BASE: usize = 0x0000;
/// Interrupt-enable registers (`eie`), one 64-bit word per 64 interrupts.
const IMSIC_EIE_BASE: usize = 0x0080;
/// Interrupt-threshold register (`ith`), 32-bit.
const IMSIC_ITH_OFFSET: usize = 0x0020;
/// Interrupt-claim/complete register (`ih`), 32-bit.
const IMSIC_IH_OFFSET: usize = 0x0030;

/// An MSI is a 32-bit store of `(1 << 31) | irq` to the file address.
const IMSIC_MSI_PENDING_BIT: u32 = 1 << 31;

/// `sie` bit 9 — Supervisor External Interrupt Enable.
const SIE_SEIE: u64 = 1 << 9;

/// Registered device-interrupt handler signature.
pub type IrqHandler = fn(irq: u32);

// ── Per-hart IMSIC geometry ────────────────────────────────────────────

/// IMSIC file geometry captured at init.
#[derive(Clone, Copy)]
struct ImsicLayout {
    /// MMIO base of hart 0's IMSIC file.
    base: usize,
    /// Stride between consecutive harts' files.
    stride: usize,
    /// Number of harts in this IMSIC group.
    hart_count: u32,
}

/// The MMIO address of `cpu_id`'s IMSIC file.
fn imsic_file_base(layout: &ImsicLayout, cpu_id: u32) -> usize {
    layout.base + (cpu_id % layout.hart_count) as usize * layout.stride
}

/// The IMSIC file base belonging to the current hart.
fn current_file_base(layout: &ImsicLayout) -> usize {
    imsic_file_base(layout, percpu::get().cpu_id)
}

/// Read the `eip`/`eie` 64-bit word covering `irq` on the current hart.
fn read_bitset(layout: &ImsicLayout, base_offset: usize, irq: u32) -> u64 {
    let addr = current_file_base(layout) + base_offset + (irq as usize / 64) * 8;
    unsafe { read_volatile(addr as *const u64) }
}

/// Write the `eip`/`eie` 64-bit word covering `irq` on the current hart.
fn write_bitset(layout: &ImsicLayout, base_offset: usize, irq: u32, value: u64) {
    let addr = current_file_base(layout) + base_offset + (irq as usize / 64) * 8;
    unsafe { write_volatile(addr as *mut u64, value) }
}

// ── Global state ───────────────────────────────────────────────────────

static IMSIC_LAYOUT: SpinLock<Option<ImsicLayout>> = SpinLock::new(None);
static GLOBAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// The per-IRQ device handler table.  Indexed by the claimed interrupt
/// identity; entries are registered at device-probe time.
static IRQ_HANDLERS: SpinLock<[Option<IrqHandler>; IRQ_TABLE_LEN]> =
    SpinLock::new([None; IRQ_TABLE_LEN]);

/// Initialise the IMSIC for this platform.
///
/// `base` is the MMIO address of hart 0's IMSIC file; each hart's file is
/// `stride` bytes after the previous.  Idempotent: re-initialising with the
/// same geometry is harmless.
pub fn init_aia_imsic(base: usize) {
    let hart_count = crate::arch::fdt::cpu_count().max(1);
    *IMSIC_LAYOUT.lock() = Some(ImsicLayout {
        base,
        stride: IMSIC_QEMU_VIRT_STRIDE,
        hart_count,
    });
    log(
        LogLevel::Info,
        &format!(
            "AIA IMSIC: {} hart file(s), base={:#x} stride={:#x}",
            hart_count, base, IMSIC_QEMU_VIRT_STRIDE
        ),
    );
}

/// Initialise the IMSIC from the platform's device tree, when the AIA node
/// has been parsed.
///
/// The boot path does not yet feed the device-tree blob to `parse_fdt`, so
/// on current builds `platform_info().imsic_base` is `None` and this is a
/// no-op — the PLIC remains the active controller and AIA delivery is armed
/// but dormant.  Wiring FDT parsing (a boot-time fix) activates it.
pub fn init_from_fdt() {
    if let Some(base) = crate::arch::fdt::platform_info().imsic_base {
        init_aia_imsic(base);
    }
}

/// Whether the IMSIC is the active external-interrupt source.
pub fn has_aia_imsic() -> bool {
    IMSIC_LAYOUT.lock().is_some()
}

/// Register `handler` for `irq`.  Subsequent claims of `irq` are dispatched
/// to `handler` by [`handle_pending_external`].
pub fn register_irq_handler(irq: u32, handler: IrqHandler) -> Result<(), Error> {
    if irq as usize >= IRQ_TABLE_LEN {
        return Err(Error::InvalidArgument);
    }
    IRQ_HANDLERS.lock()[irq as usize] = Some(handler);
    Ok(())
}

// ── External-interrupt dispatch ────────────────────────────────────────

/// Claim and dispatch the highest-priority pending external interrupt.
///
/// Returns the claimed interrupt identity (0 when nothing was pending).
/// The EOI is performed before returning, so handlers must copy any state
/// they need before this returns.
pub fn handle_pending_external() -> u32 {
    let layout = match IMSIC_LAYOUT.lock().as_ref().copied() {
        Some(layout) => layout,
        None => return 0,
    };
    let ih_addr = current_file_base(&layout) + IMSIC_IH_OFFSET;
    let claimed = unsafe { read_volatile(ih_addr as *const u32) };
    if claimed == 0 || claimed > IMSIC_MAX_IRQ {
        // No pending interrupt (or an identity outside the table): nothing
        // to dispatch.  Do not complete the (non-)claim.
        return 0;
    }

    crate::kernel::irq_stats::record_irq(claimed);
    let handler = IRQ_HANDLERS.lock()[claimed as usize % IRQ_TABLE_LEN];
    if let Some(handler) = handler {
        handler(claimed);
    } else {
        crate::kernel::irq_stats::record_spurious();
        log(
            LogLevel::Debug,
            &format!("AIA IMSIC: no handler for irq {}", claimed),
        );
    }

    // Complete the interrupt (EOI).
    unsafe { write_volatile(ih_addr as *mut u32, claimed) };
    claimed
}

// ── MSI-X table programming ────────────────────────────────────────────

/// A single 16-byte MSI-X table entry (PCI 3.0 §6.8.2.4).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MsixTableEntry {
    /// Message Address — low 32 bits (the target IMSIC file's MMIO address).
    pub msg_addr_low: u32,
    /// Message Address — high 32 bits.
    pub msg_addr_high: u32,
    /// Message Data — `(1 << 31) | irq` for the IMSIC.
    pub msg_data: u32,
    /// Vector Control (bit 0 = masked).
    pub vector_control: u32,
}

/// Compose an MSI-X table entry delivering `irq` to `target_cpu`'s IMSIC
/// file.  The entry is created unmasked (Vector Control 0) so it fires as
/// soon as the device writes it.
pub fn compose_msix_entry(target_cpu: u32, irq: u32) -> MsixTableEntry {
    let layout = IMSIC_LAYOUT.lock();
    let base = layout
        .as_ref()
        .map(|l| imsic_file_base(l, target_cpu) as u64)
        .unwrap_or(IMSIC_QEMU_VIRT_BASE as u64);
    MsixTableEntry {
        msg_addr_low: base as u32,
        msg_addr_high: (base >> 32) as u32,
        msg_data: IMSIC_MSI_PENDING_BIT | (irq & IMSIC_MAX_IRQ),
        vector_control: 0,
    }
}

/// Programme `count` MSI-X table entries starting at `table_phys`, mapping
/// `base_irq..base_irq + count` to `target_cpu`'s IMSIC file.
///
/// `table_phys` is the physical address of the device's MSI-X table within
/// its BAR (the riscv64 identity-mapped device window, so the address is
/// directly writable).  Returns the first interrupt identity on success.
///
/// MSI-X must additionally be enabled via the device's Message Control
/// register (PCI config space); that is the PCI MSI-X manager's job, not
/// this file's.
pub fn configure_msix(
    table_phys: u64,
    count: u32,
    target_cpu: u32,
    base_irq: u32,
) -> Result<u32, Error> {
    if !has_aia_imsic() {
        return Err(Error::NotImplemented);
    }
    if count == 0 || base_irq + count > IRQ_TABLE_LEN as u32 {
        return Err(Error::InvalidArgument);
    }
    // The riscv64 device MMIO window (Sv39 identity map) covers
    // 0x0000_0000..DEVICE_MMIO_END; a table address outside it cannot be
    // reached without a dedicated mapping.  QEMU `virt` places the PCIe MMIO
    // window at 0x4000_0000..0x8000_0000, inside this range.
    if table_phys >= crate::arch::riscv64::mmu::DEVICE_MMIO_END as u64 {
        return Err(Error::InvalidArgument);
    }

    let table = table_phys as usize as *mut u8;
    for i in 0..count {
        let entry = compose_msix_entry(target_cpu, base_irq + i);
        let p = unsafe { table.add(i as usize * core::mem::size_of::<MsixTableEntry>()) };
        // SAFETY: the table is identity-mapped device MMIO and each entry is
        // written as four 32-bit stores to keep the volatile accesses word
        // aligned on any target.
        unsafe {
            p.cast::<u32>().write_volatile(entry.msg_addr_low);
            p.add(4).cast::<u32>().write_volatile(entry.msg_addr_high);
            p.add(8).cast::<u32>().write_volatile(entry.msg_data);
            p.add(12).cast::<u32>().write_volatile(entry.vector_control);
        }
    }

    log(
        LogLevel::Info,
        &format!(
            "AIA IMSIC: programmed {} MSI-X entr(y/ies) @{:#x} -> cpu{} irq {}..={}",
            count,
            table_phys,
            target_cpu,
            base_irq,
            base_irq + count - 1
        ),
    );
    Ok(base_irq)
}

// ── InterruptController implementation ─────────────────────────────────

/// The IMSIC as the architecture's interrupt controller.
pub struct AiaImsicController;

/// Singleton used by `arch::interrupt_controller` when the IMSIC is active.
pub static IMSIC_CONTROLLER: AiaImsicController = AiaImsicController;

impl InterruptController for AiaImsicController {
    fn init(&self) {
        let layout = match IMSIC_LAYOUT.lock().as_ref().copied() {
            Some(layout) => layout,
            None => return,
        };

        if !GLOBAL_INITIALIZED.swap(true, Ordering::Acquire) {
            super::interrupts::disable();
        }

        // Per-CPU: accept every priority (threshold 0) and enable supervisor
        // external interrupts in `sie` so the IMSIC can interrupt us.
        let file = current_file_base(&layout);
        // SAFETY: MMIO write to the current hart's IMSIC threshold register.
        unsafe { write_volatile((file + IMSIC_ITH_OFFSET) as *mut u32, 0) };
        // SAFETY: `sie` is a supervisor CSR; SEIE is bit 9.  `csrs` is the
        // register form (the 512-bit set mask exceeds `csrsi`'s 5-bit
        // immediate).
        unsafe {
            asm!("csrs sie, {seie}", seie = in(reg) SIE_SEIE, options(nomem, nostack, preserves_flags));
        }
    }

    fn end_of_interrupt(&self, vector: u32) {
        let layout = match IMSIC_LAYOUT.lock().as_ref().copied() {
            Some(layout) => layout,
            None => return,
        };
        let ih_addr = current_file_base(&layout) + IMSIC_IH_OFFSET;
        // SAFETY: writing the claimed id to `ih` completes it (EOI).
        unsafe { write_volatile(ih_addr as *mut u32, vector) };
    }

    fn enable_interrupt(&self, interrupt_id: u32) {
        let layout = match IMSIC_LAYOUT.lock().as_ref().copied() {
            Some(layout) => layout,
            None => return,
        };
        if interrupt_id > IMSIC_MAX_IRQ {
            return;
        }
        let word = read_bitset(&layout, IMSIC_EIE_BASE, interrupt_id);
        write_bitset(
            &layout,
            IMSIC_EIE_BASE,
            interrupt_id,
            word | (1 << (interrupt_id % 64)),
        );
    }

    fn set_priority(&self, _interrupt_id: u32, _priority: u8) {
        // The IMSIC has no per-IRQ priority — only a per-file threshold —
        // so this is a no-op, matching the trait contract.
    }
}
