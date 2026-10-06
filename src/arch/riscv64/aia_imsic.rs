//! src/arch/riscv64/aia_imsic.rs
//!
//! RISC-V AIA IMSIC (Incoming Message-Signalled Interrupt Controller)
//! driver for MSI / MSI-X delivery.
//!
//! The IMSIC is the AIA interrupt file that receives MSIs.  Only its first
//! page is memory — the MSI-write page, where a four-byte store of the **bare
//! identity** sets that interrupt pending — and the register file
//! (`eidelivery`, `eithreshold`, `eip`, `eie`) is reached *indirectly*,
//! through the `siselect`/`sireg` CSRs that supervisor mode gains with Smaia.
//! Claiming is `stopei`: reading it answers with the identity on top and
//! writing zero claims it, which for an MSI is what clears the pending bit.
//!
//! This driver used to speak a different interface — registers at fixed MMIO
//! offsets inside the page, an MSI data word of `(1 << 31) | irq`, and a claim
//! through a register at `+0x30` that the device does not have.  On QEMU
//! `virt` (8.2, `-machine virt,aia=aplic-imsic`) that was not dormant but
//! broken: the boot took an access fault at `base + 0x20`
//! (`scause = 7, stval = 0x2400_0020`), and a message it did send would have
//! carried bit 31 and been dropped as out of range.  Both halves are the
//! interface the machine actually implements now, which is what
//! `scripts/check-riscv64-aia-runtime.sh` boots and checks.
//!
//! The default machine (no IMSIC in the device tree) never reaches any of
//! this: [`init_from_fdt`] is a no-op there and the PLIC remains the external
//! interrupt controller.
//!
//! This driver:
//! - manages one IMSIC file per hart ([`init_aia_imsic`] /
//!   [`imsic_file_base`]),
//! - implements [`InterruptController`] so EOI writes `ih`, enabling an
//!   interrupt sets its `eie` bit, and per-IRQ priority is a no-op (the IMSIC
//!   has a single per-file threshold),
//! - dispatches claimed interrupts through a per-IRQ handler table
//!   ([`claim_device_irqs_each`] registers an owner per identity;
//!   [`handle_pending_external`] hands the message to it),
//! - programmes real 16-byte MSI-X table entries against a device BAR
//!   ([`configure_msix`]), replacing the previous software-only table.
//! - walks its own message path once at boot ([`self_test`]), because a machine
//!   that describes an IMSIC would otherwise carry an untested delivery path
//!   until a device happened to send something.
//!
//! Reference: RISC-V Advanced Interrupt Architecture (AIA) v1.0, chapter 3.

use alloc::format;
use core::arch::asm;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use super::write_volatile;
use crate::arch::interrupt_controller::InterruptController;
use crate::kernel::percpu;
use crate::kernel::sync::SpinLock;
use crate::util::logger::log;
use crate::util::logger::LogLevel;
use crate::Error;

// ── Platform geometry ──────────────────────────────────────────────────
//
// With `-machine virt,aia=aplic-imsic` QEMU places two IMSIC groups: the
// machine-mode file at 0x2400_0000 and the supervisor-mode one at
// 0x2800_0000, each hart's file 16 KiB after the previous.  Only the
// supervisor group is this kernel's to use, so that is the fallback here; the
// device tree's own node overrides it (see [`init_from_fdt`]).

/// Default supervisor IMSIC group base on QEMU `virt` with AIA.
const IMSIC_QEMU_VIRT_BASE: usize = 0x2800_0000;
/// MMIO stride between consecutive harts' IMSIC files on QEMU `virt`.
const IMSIC_QEMU_VIRT_STRIDE: usize = 0x4000;
/// Highest interrupt identity an IMSIC file can hold (2048 interrupts).
const IMSIC_MAX_IRQ: u32 = 2047;
use crate::arch::irq_handlers::IRQ_TABLE_LEN;

/// The identity the boot's self-test uses, and which device allocation must
/// leave alone.
///
/// It has to be an identity the machine's file can hold — QEMU `virt` gives
/// its guest IMSIC 256 of them, 0 through 255 — and one no device will be
/// given, so a message this test leaves pending can never be mistaken for a
/// device's.  Device identities therefore stop one below the table's end.
const IMSIC_SELF_TEST_IRQ: u32 = (IRQ_TABLE_LEN - 1) as u32;
/// Highest identity a device may be assigned.
pub const IMSIC_MAX_DEVICE_IRQ: u32 = IMSIC_SELF_TEST_IRQ - 1;

// ── The interrupt file's registers, reached indirectly (AIA v1.0 §5) ───
//
// The file's registers are *not* at fixed offsets in its page.  Supervisor
// mode reaches them through the Smaia pair: write the register's number to
// `siselect`, then read or write `sireg`.  The page itself is only the
// MSI-write page, which is where a device's message goes.
//
// The CSR numbers are written numerically because the assembler only knows
// their names with an extension directive, and the kernel should not have to
// teach it one to touch a register the machine advertised.

/// Selects the interrupt-file register that `sireg` then reads or writes.
const CSR_SISELECT: u64 = 0x150;
/// The register `siselect` selected.
const CSR_SIREG: u64 = 0x151;
/// Top external interrupt: read it for the identity, write it to claim.
const CSR_STOPEI: u64 = 0x15C;
/// Bits the identity sits above in a `stopei` value — the same shift Linux
/// applies to `CSR_TOPEI`'s answer.
const CSR_TOPEI_ID_SHIFT: u32 = 16;

/// Select number of `eidelivery`.
const IMSIC_EIDELIVERY: u64 = 0x70;
/// Select number of `eithreshold`.
const IMSIC_EITHRESHOLD: u64 = 0x72;
/// First select number of the `eip` words (read-only; the claim is `stopei`).
const IMSIC_EIP0: u64 = 0x80;
/// First select number of the `eie` words.
const IMSIC_EIE0: u64 = 0xC0;
/// Delivery enabled (`eidelivery`).
const IMSIC_EIDELIVERY_ENABLE: u64 = 1;
/// A threshold of zero delivers every priority the file can hold.
const IMSIC_EITHRESHOLD_ALL: u64 = 0;
/// Select numbers step by two per 64-bit word: the specification gives each
/// register an even/odd pair of 32-bit slots, and on RV64 the even one
/// addresses the whole 64-bit register.  Linux does the same arithmetic
/// (`isel = (id / BITS_PER_LONG) * (BITS_PER_LONG / 32)`).
const IMSIC_SELECT_STRIDE: u64 = 2;

/// The `siselect` value whose word holds `irq`, for the register starting at
/// `base` (`IMSIC_EIE0` or `IMSIC_EIP0`).
fn select_for(base: u64, irq: u32) -> u64 {
    base + (irq as u64 / 64) * IMSIC_SELECT_STRIDE
}

/// Select a register, then write it.
fn imsic_csr_write(reg: u64, value: u64) {
    // SAFETY: `siselect` and `sireg` are the supervisor indirect-access CSRs
    // this extension defines; the number is one of the file's registers, and
    // the file belongs to the running hart.  Neither access touches memory.
    unsafe {
        asm!("csrw {select}, {reg}", select = const CSR_SISELECT, reg = in(reg) reg,
             options(nomem, nostack));
        asm!("csrw {data}, {value}", data = const CSR_SIREG, value = in(reg) value,
             options(nomem, nostack));
    }
}

/// Select a register, then read it.
fn imsic_csr_read(reg: u64) -> u64 {
    let value: u64;
    // SAFETY: as `imsic_csr_write` — the same register pair, read instead.
    unsafe {
        asm!("csrw {select}, {reg}", select = const CSR_SISELECT, reg = in(reg) reg,
             options(nomem, nostack));
        asm!("csrr {value}, {data}", value = out(reg) value, data = const CSR_SIREG,
             options(nomem, nostack));
    }
    value
}

/// Select a register, then set the bits in `mask` and return the old value.
fn imsic_csr_set(reg: u64, mask: u64) -> u64 {
    let old: u64;
    // SAFETY: as `imsic_csr_write` — a read-modify-write of one indirect
    // register, performed by the CSR instruction itself.
    unsafe {
        asm!("csrw {select}, {reg}", select = const CSR_SISELECT, reg = in(reg) reg,
             options(nomem, nostack));
        asm!("csrrs {old}, {data}, {mask}", old = out(reg) old, data = const CSR_SIREG,
             mask = in(reg) mask, options(nomem, nostack));
    }
    old
}

/// Claim the highest-priority pending external interrupt, if any.
///
/// Reading `stopei` answers with the identity; *writing* it claims that
/// interrupt, which for an MSI is what clears its pending bit.  A write of
/// zero claims whichever one is on top, so the read and the claim are one
/// instruction pair here (`csrrw` with zero), which is what Linux does:
/// `while ((local_id = csr_swap(CSR_TOPEI, 0)))`.
///
/// The value it answers with is not the identity itself: the identity sits
/// sixteen bits up (`TOPEI_ID_SHIFT` in Linux, which shifts by the same
/// amount), so a message for identity 255 reads back as 0x00ff00ff.
fn claim_top_external() -> u32 {
    let claimed: u64;
    // SAFETY: `stopei` is the supervisor top-external-interrupt CSR; reading it
    // reports the pending identity and writing zero claims that interrupt.  No
    // memory is touched.
    unsafe {
        asm!("csrrw {claimed}, {topei}, {zero}", claimed = out(reg) claimed,
             topei = const CSR_STOPEI, zero = in(reg) 0u64, options(nomem, nostack));
    }
    (claimed >> CSR_TOPEI_ID_SHIFT) as u32
}

/// `sie` bit 9 — Supervisor External Interrupt Enable.
const SIE_SEIE: u64 = 1 << 9;

/// Registered device-interrupt handler.
///
/// A handler carries state: the device it belongs to, the wait queue its
/// completions are parked on, the counters its driver reports.  It is called
/// from the external-interrupt path and must not block.
pub use crate::arch::irq_handlers::IrqHandler;

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

/// Read the `eip`/`eie` word covering `irq` on the *current* hart.
///
/// The CSRs address the running hart's own file, so the layout is not needed
/// here; it is what the MSI address in [`compose_msix_entry`] is built from.
fn read_bitset(base: u64, irq: u32) -> u64 {
    imsic_csr_read(select_for(base, irq))
}

/// Set the bit for `irq` in the `eip`/`eie` word covering it, and answer with
/// the word as it was.
fn set_bitset_bit(base: u64, irq: u32) -> u64 {
    imsic_csr_set(select_for(base, irq), 1 << (irq % 64))
}

// ── Global state ───────────────────────────────────────────────────────

static IMSIC_LAYOUT: SpinLock<Option<ImsicLayout>> = SpinLock::new(None);
static GLOBAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

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
/// The boot path does feed the blob to `parse_fdt`, and QEMU `virt` with
/// `aia=aplic-imsic` does describe the node: booting that machine prints
/// `AIA IMSIC: 1 hart file(s), base=0x24000000`.  What fails is the first
/// register access — see the module note.  On the default machine (no IMSIC
/// in the tree) this stays a no-op and the PLIC remains the controller.
pub fn init_from_fdt() {
    if let Some(base) = crate::arch::fdt::platform_info().imsic_base {
        init_aia_imsic(base);
        // A machine that describes an IMSIC delivers every device's messages
        // through it, and nothing boots a device that would prove the path
        // works — so the boot walks it once itself.  See [`self_test`].
        match self_test() {
            Some(irq) => log(
                LogLevel::Info,
                &format!(
                    "AIA IMSIC: self-test delivered and claimed identity {}",
                    irq
                ),
            ),
            None => log(LogLevel::Warn, "AIA IMSIC: self-test delivered nothing"),
        }
    }
}

/// Whether the IMSIC is the active external-interrupt source.
pub fn has_aia_imsic() -> bool {
    IMSIC_LAYOUT.lock().is_some()
}

/// How many harts can receive a message-signalled interrupt right now.
///
/// A hart counts when it is running and this platform has an IMSIC for it: a
/// message delivered to a hart that has not switched its IMSIC on is dropped
/// rather than queued, so a placement must not name one.
pub fn msix_capable_count() -> u32 {
    let hart_count = match IMSIC_LAYOUT.lock().as_ref() {
        Some(layout) => layout.hart_count,
        None => return 0,
    };
    let mut capable = 0;
    for cpu in 0..crate::kernel::smp::MAX_CPUS as u32 {
        if cpu < hart_count && crate::kernel::smp::cpu_is_online(cpu) {
            capable += 1;
        }
    }
    capable
}

/// The `slot`-th hart that can receive a message-signalled interrupt.
fn msix_capable_at(slot: u32) -> Option<u32> {
    let layout = IMSIC_LAYOUT.lock();
    let hart_count = layout.as_ref()?.hart_count;
    let mut remaining = slot;
    for cpu in 0..crate::kernel::smp::MAX_CPUS as u32 {
        if cpu >= hart_count || !crate::kernel::smp::cpu_is_online(cpu) {
            continue;
        }
        if remaining == 0 {
            return Some(cpu);
        }
        remaining -= 1;
    }
    None
}

/// The hart that entry `index` of a device's MSI-X table is delivered to.
///
/// Round-robin over the harts that can receive, which is what puts a
/// multi-queue device's queues on different harts — see
/// [`crate::arch::irq_placement`] for why the policy is round-robin.
pub fn msix_cpu_for_entry(index: u32) -> Option<u32> {
    let slot = crate::arch::irq_placement::place_entry(index, msix_capable_count())?;
    msix_capable_at(slot)
}

/// The identity RISC-V indexes [`crate::arch::irq_handlers`] from: its
/// identities start at zero, so an identity is its own slot.
const IRQ_WINDOW_BASE: u32 = 0;

/// Whether any handler is registered for `irq`.
pub fn irq_has_handler(irq: u32) -> bool {
    crate::arch::irq_handlers::is_registered(IRQ_WINDOW_BASE, irq)
}

/// The first identity a device may be given.
///
/// Identity 0 is not an interrupt — [`handle_pending_external`] answers 0 for
/// "nothing pending" — so a device's identities start here and stop at
/// [`IMSIC_MAX_DEVICE_IRQ`], which leaves the boot self-test's identity alone.
pub const FIRST_DEVICE_IRQ: u32 = 1;

/// Claim `handlers.len()` device identities, one handler each.
///
/// The range is allocated first-fit from [`FIRST_DEVICE_IRQ`], with the
/// registry in [`crate::arch::irq_handlers`] holding the table and the
/// all-or-nothing rule.
///
/// See [`crate::arch::irq_handlers::claim_each`] for why a device wants them:
/// one identity per queue is what lets a completion wake its own queue's
/// waiter rather than the whole device's.
pub fn claim_device_irqs_each(handlers: &[IrqHandler]) -> Result<u32, Error> {
    crate::arch::irq_handlers::claim_each(
        IRQ_WINDOW_BASE,
        FIRST_DEVICE_IRQ,
        IMSIC_MAX_DEVICE_IRQ,
        handlers,
    )
}

// ── External-interrupt dispatch ────────────────────────────────────────

/// Claim and dispatch the highest-priority pending external interrupt.
///
/// Returns the claimed interrupt identity (0 when nothing was pending).
/// The EOI is performed before returning, so handlers must copy any state
/// they need before this returns.
pub fn handle_pending_external() -> u32 {
    if IMSIC_LAYOUT.lock().is_none() {
        return 0;
    }

    // The claim is the read: `csrrw` of `stopei` with zero answers with the
    // identity on top and claims it in the same instruction, which is what
    // clears an MSI's pending bit.
    let claimed = claim_top_external();
    if claimed == 0 || claimed > IMSIC_MAX_IRQ {
        // No pending interrupt (or an identity outside the table): nothing
        // to dispatch.  Do not complete the (non-)claim.
        return 0;
    }

    crate::kernel::irq_stats::record_irq(claimed);
    if !crate::arch::irq_handlers::dispatch(IRQ_WINDOW_BASE, claimed) {
        crate::kernel::irq_stats::record_spurious();
        log(
            LogLevel::Debug,
            &format!("AIA IMSIC: no handler for irq {}", claimed),
        );
    }

    claimed
}

// ── MSI-X table programming ────────────────────────────────────────────

/// Walk the message path once, on this machine, at boot.
///
/// Nothing QEMU `virt` attaches sends an MSI, so the path a device would take
/// is walked by the kernel itself: enable an identity, write the message a
/// device would write into this hart's own MSI page, and read the identity
/// back out of `stopei`.  That covers the page address, the bare-identity data
/// word, the pending and enable bits, and the claim — everything between a
/// device's MSI-X table entry and the trap the kernel would take for it.
///
/// The identity is one past the range device handlers use, so a message this
/// test leaves behind can never be mistaken for a device's.
pub fn self_test() -> Option<u32> {
    let layout = IMSIC_LAYOUT.lock().as_ref().copied()?;

    // Delivery on, nothing filtered: the same two writes `init` makes, because
    // this runs before the controller is installed.
    imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_EITHRESHOLD_ALL);
    imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_EIDELIVERY_ENABLE);

    let irq = IMSIC_SELF_TEST_IRQ;
    let _ = set_bitset_bit(IMSIC_EIE0, irq);

    // The message: four bytes at the hart's MSI page, carrying the identity.
    let msi_page = current_file_base(&layout);
    // SAFETY: `msi_page` is the base of this hart's MSI-write page, which the
    // platform mapped for the kernel's lifetime; a four-byte store there is
    // exactly what a device's MSI-X table entry performs.
    unsafe { write_volatile(msi_page as *mut u32, irq) };

    let pending = read_bitset(IMSIC_EIP0, irq);
    let claimed = claim_top_external();
    if claimed != irq {
        log(
            LogLevel::Warn,
            &format!(
                "AIA IMSIC: self-test wrote identity {} (pending word {:#x}) and claimed {}",
                irq, pending, claimed
            ),
        );
        return None;
    }
    Some(irq)
}

/// Write the message a device's MSI-X table entry would write for `irq`.
///
/// The delivery half of the path, without the claim: the pending bit is set
/// and left for whoever claims it — the external-interrupt trap in a running
/// kernel, or [`handle_pending_external`] in a check that wants the dispatch
/// itself rather than a claim.
pub fn deliver_message(irq: u32) -> bool {
    let Some(layout) = IMSIC_LAYOUT.lock().as_ref().copied() else {
        return false;
    };
    if irq > IMSIC_MAX_IRQ {
        return false;
    }

    // The identity must be enabled, or the file holds the message and never
    // makes it pending.  `ie` is per-identity, so this is the enable a device's
    // owner would have asked for.
    let _ = set_bitset_bit(IMSIC_EIE0, irq);

    let msi_page = current_file_base(&layout);
    // SAFETY: `msi_page` is the base of this hart's MSI-write page, which the
    // platform mapped for the kernel's lifetime; a four-byte store there is
    // exactly what a device's MSI-X table entry performs.
    unsafe { write_volatile(msi_page as *mut u32, irq) };
    read_bitset(IMSIC_EIP0, irq) != 0
}

/// A single 16-byte MSI-X table entry (PCI 3.0 §6.8.2.4).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
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

/// Read one entry back from a programmed MSI-X table.
///
/// The twin of [`compose_msix_entry`], and the reason both exist: what a probe
/// writes into a device's table is only known to have reached device MMIO if
/// it can be read back from there.  The four words are read as four volatile
/// loads, the way they are written.
pub fn read_msix_entry(table_entry: usize) -> MsixTableEntry {
    let base = table_entry as *const u32;
    // SAFETY: `table_entry` names one 16-byte table entry in the identity-mapped
    // device window, and the four loads cover exactly that entry.
    unsafe {
        MsixTableEntry {
            msg_addr_low: core::ptr::read_volatile(base),
            msg_addr_high: core::ptr::read_volatile(base.add(1)),
            msg_data: core::ptr::read_volatile(base.add(2)),
            vector_control: core::ptr::read_volatile(base.add(3)),
        }
    }
}

/// Compose an MSI-X table entry delivering `irq` to `target_cpu`'s IMSIC
/// file.  The entry is created unmasked (Vector Control 0) so it fires as
/// soon as the device writes it.
pub fn compose_msix_entry(target_cpu: u32, irq: u32) -> MsixTableEntry {
    let layout = IMSIC_LAYOUT.lock();
    // Before `init_aia_imsic` the platform's layout is unknown; the QEMU
    // `virt` one is the fallback, and it names the *target hart's* file rather
    // than hart 0's — a message addressed to the wrong file is delivered to a
    // hart that has no handler for it, silently.
    let base = match layout.as_ref() {
        Some(l) => imsic_file_base(l, target_cpu) as u64,
        None => (IMSIC_QEMU_VIRT_BASE + target_cpu as usize * IMSIC_QEMU_VIRT_STRIDE) as u64,
    };
    MsixTableEntry {
        msg_addr_low: base as u32,
        msg_addr_high: (base >> 32) as u32,
        // The identity, bare.  The MSI-write page takes the identity as the
        // whole data word: an address selects the file, and the word selects
        // the interrupt in it.  The specification's older `setip` form put a
        // bit above the identity to say "set pending", and this machine reads
        // that bit as an identity outside its range and drops the message.
        msg_data: irq & IMSIC_MAX_IRQ,
        vector_control: 0,
    }
}

/// Programme the MSI-X table at `table_phys`, mapping the claimed identities
/// to the IMSIC files `targets` names.
///
/// `table_phys` is the physical address of the device's MSI-X table within
/// its BAR (the riscv64 identity-mapped device window, so the address is
/// directly writable), `table_size` is how many entries that table has,
/// `entries[i]` is the table entry that delivers `base_irq + i`, and
/// `targets[i]` is the hart it is delivered to — the placement, which is what
/// lets a multi-queue device's queues be completed by different harts.  Every
/// entry not named in `entries` is written masked.  Returns the first
/// interrupt identity on success.
///
/// MSI-X must additionally be enabled via the device's Message Control
/// register (PCI config space); that is the PCI MSI-X manager's job, not
/// this file's.
pub fn configure_msix(
    table_phys: u64,
    table_size: u32,
    base_irq: u32,
    entries: &[u16],
    targets: &[u32],
) -> Result<u32, Error> {
    if !has_aia_imsic() {
        return Err(Error::NotImplemented);
    }
    let count = entries.len() as u32;
    if targets.len() != count as usize || count == 0 {
        return Err(Error::InvalidArgument);
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
    // Every entry of the device's table is written, and each ends this step
    // either programmed or masked: an entry this claim does not own is written
    // with its mask bit set rather than left as whatever a previous user put
    // there, so the device cannot deliver an identity nobody registered.
    for i in 0..table_size {
        let entry = match entries.iter().position(|entry| *entry as u32 == i) {
            Some(offset) => compose_msix_entry(targets[offset], base_irq + offset as u32),
            None => MsixTableEntry {
                msg_addr_low: 0,
                msg_addr_high: 0,
                msg_data: 0,
                vector_control: 1,
            },
        };
        // SAFETY: `table` is the identity-mapped MSI-X table the caller reserved and
        // `i` is bounded by the table size it read from the capability, so the
        // pointer names one entry.
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
            "AIA IMSIC: programmed {} MSI-X entr(y/ies) @{:#x} -> harts {:?} irq {}..={}",
            count,
            table_phys,
            targets,
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
        if IMSIC_LAYOUT.lock().is_none() {
            return;
        }

        if !GLOBAL_INITIALIZED.swap(true, Ordering::Acquire) {
            super::interrupts::disable();
        }

        // Per-CPU, and in this order: take the threshold down to zero so no
        // identity is filtered, then switch delivery on, then let supervisor
        // external interrupts reach the hart at all.
        imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_EITHRESHOLD_ALL);
        imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_EIDELIVERY_ENABLE);
        // SAFETY: `sie` is a supervisor CSR; SEIE is bit 9.  `csrs` is the
        // register form (the 512-bit set mask exceeds `csrsi`'s 5-bit
        // immediate).
        unsafe {
            asm!("csrs sie, {seie}", seie = in(reg) SIE_SEIE, options(nomem, nostack, preserves_flags));
        }
    }

    fn end_of_interrupt(&self, vector: u32) {
        // Nothing to do: an IMSIC interrupt is claimed by the `stopei` read in
        // [`handle_pending_external`], and claiming it *is* completing it.  The
        // trait's EOI exists for controllers that acknowledge in two steps.
        let _ = vector;
    }

    fn enable_interrupt(&self, interrupt_id: u32) {
        if IMSIC_LAYOUT.lock().is_none() {
            return;
        }
        if interrupt_id > IMSIC_MAX_IRQ {
            return;
        }
        let _ = set_bitset_bit(IMSIC_EIE0, interrupt_id);
    }

    fn set_priority(&self, _interrupt_id: u32, _priority: u8) {
        // The IMSIC has no per-IRQ priority — only a per-file threshold —
        // so this is a no-op, matching the trait contract.
    }
}
