//! src/arch/aarch64/gicv3.rs
//!
//! ARM Generic Interrupt Controller v3: the distributor, the per-CPU
//! redistributors, and the `ICC_*` system-register CPU interface.
//!
//! This is the second half of the platform's interrupt controller, beside the
//! GICv2 one in [`super::interrupt_controller`].  Which of the two runs is not
//! a build choice: `GICD_PIDR2` reports the architecture revision on the
//! machine in front of the kernel, and programming the v2 register layout onto
//! a v3 machine writes registers that mean something else — measured as a data
//! abort at the GICv2 CPU interface's address.  The revision is read once at
//! bring-up and the controller that matches it is the one the rest of the
//! kernel talks to.
//!
//! Scope, and why it stops where it does:
//!
//! - **Group 1, non-secure, only.**  The kernel runs at EL1 with no EL3 of its
//!   own, so Group 0 and secure Group 1 belong to a monitor that is not here.
//!   Interrupts are assigned to Group 1 as they are enabled, `ICC_IGRPEN1_EL1`
//!   is the only group enable the CPU interface sets, and EOI is the
//!   `ICC_EOIR1_EL1` write that both drops priority and deactivates.
//! - **No LPIs and no ITS.**  A message-signalled interrupt is a device writing
//!   an interrupt id into memory; on this architecture the id is a translation
//!   the ITS performs, and the ids it delivers are LPIs.  Neither is
//!   implemented yet, so a PCIe device on this platform still completes by
//!   polling.  The redistributor's LPI machinery (`GICR_PROPBASER`,
//!   `GICR_PENDBASER`, `GICR_CTLR.EnableLPIs`) is therefore left untouched, and
//!   so is the ITS register block the device tree already describes.
//!
//! References:
//!
//! - ARM IHI 0069, *Architecture Specification: GICv3 and GICv4* — GICD_CTLR,
//!   GICR_TYPER, GICR_WAKER, the SGI/PPI frame, and `ICC_SGI1R_EL1`.
//! - Linux `drivers/irqchip/irq-gic-v3.c` and
//!   `include/linux/irqchip/arm-gic-v3.h` — the bring-up order this follows.

use core::arch::asm;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

use super::interrupt_controller::gicd_base;
use super::interrupt_controller::gicr_base;
use super::mmio::dsb_sy;
use super::mmio::isb;
use super::mmio::read_u32;
use super::mmio::read_u64;
use super::mmio::write_u32;
use super::mmio::write_u64;
use super::mmio::write_u8;
use crate::arch::interrupt_controller::InterruptController;
use crate::kernel::sync::SpinLock;
use crate::memory::dma::DmaBuffer;

// -- Distributor ----------------------------------------------------------

const GICD_CTLR: usize = 0x0000;
const GICD_IGROUPR: usize = 0x0080;
const GICD_ISENABLER: usize = 0x0100;
const GICD_IPRIORITYR: usize = 0x0400;
const GICD_IROUTER: usize = 0x6000;

/// `GICD_CTLR` group enables for a kernel that drives Group 1 only.
///
/// The two bits are the pair Linux writes for the same configuration, and they
/// are not a mistake or a spare: the non-secure view of the register puts
/// Group 1's enable at bit 1 once affinity routing is on, while a controller
/// with a single security state (no EL3 in the picture — QEMU `virt` without
/// `secure=on`) reads its only Group 1 enable from bit 0 instead.  Writing
/// both is what makes one bring-up sequence work on either machine.
const GICD_CTLR_ENABLE_G1: u32 = 1 << 0;
const GICD_CTLR_ENABLE_G1A: u32 = 1 << 1;
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
const GICD_CTLR_RWP: u32 = 1 << 31;

// -- Redistributor --------------------------------------------------------

const GICR_TYPER: usize = 0x0008;
const GICR_WAKER: usize = 0x0014;
const GICR_CTLR: usize = 0x0000;
const GICR_PROPBASER: usize = 0x0070;
const GICR_PENDBASER: usize = 0x0078;

/// A redistributor is two 64 KiB frames: the RD frame at its base and the
/// SGI/PPI frame `0x10000` above it.  Consecutive redistributors are one frame
/// pair apart, which is the stride the chain is walked with.
const GICR_FRAME_SIZE: usize = 0x2_0000;
const GICR_SGI_FRAME: usize = 0x1_0000;
const GICR_IGROUPR0: usize = GICR_SGI_FRAME + 0x0080;
const GICR_ISENABLER0: usize = GICR_SGI_FRAME + 0x0100;
const GICR_IPRIORITYR: usize = GICR_SGI_FRAME + 0x0400;

const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
const GICR_TYPER_LAST: u64 = 1 << 4;
const GICR_CTLR_ENABLE_LPIS: u32 = 1 << 0;

/// The first LPI, and the window of them this kernel hands out.
///
/// An LPI's number is this base plus an ID of [`LPI_ID_BITS`] bits, and eight
/// bits is exactly the 256 identities [`crate::arch::irq_handlers`] can hold —
/// so the LPI space enabled here is 8192..=8447, and every number in it has a
/// slot in the registry.
pub(crate) const LPI_BASE: u32 = 8192;
/// LPIs this kernel hands out, which is what
/// [`crate::arch::irq_handlers`] can hold — not the whole LPI space the
/// machine implements, which is what the tables below are sized for.
const LPI_WINDOW: usize = 256;

/// The last LPI the tables this controller allocates cover.
pub(crate) const LPI_LAST: u32 = LPI_BASE + LPI_WINDOW as u32 - 1;

/// What an enabled LPI's configuration-table byte holds.
///
/// The byte is a priority in bits [7:2] with two flags under it: Group 1,
/// which is the only group this kernel drives, and the enable bit the
/// redistributor checks before it will deliver the interrupt at all.  The
/// priority value is the one Linux gives an LPI by default.
const LPI_CONFIG_ENABLED: u8 = 0xA0 | 0b11;

/// The alignment `GICR_PENDBASER` can name.
///
/// Its address field starts at bit 16 — the low fifteen bits are not
/// implemented — so a pending table that does not start on a 64 KiB boundary
/// is not one the redistributor can be pointed at.
const LPI_PENDING_ALIGNMENT: usize = 0x1_0000;

/// Shareability and cacheability for the LPI tables, as the architecture
/// encodes them: inner shareable, inner read/write-allocate.  The
/// redistributor reads these tables, so they carry the attributes a shared
/// table needs rather than the ones a private buffer would.
const TABLE_INNER_SHAREABLE: u64 = 3 << 10;
const TABLE_INNER_CACHEABLE: u64 = 7 << 59;

/// Redistributor frames this controller will enumerate.
///
/// The bound is the kernel's own CPU ceiling — [`super::smp::MAX_APS`] plus the
/// BSP — not a property of the architecture: a machine with more PEs than the
/// scheduler can hold is one where the extra frames are of no use here.
const MAX_REDISTRIBUTORS: usize = super::smp::MAX_APS + 1;

static REDISTRIBUTOR_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Where each redistributor frame is, by the order the chain was walked in.
static REDISTRIBUTOR_BASE: [AtomicUsize; MAX_REDISTRIBUTORS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicUsize = AtomicUsize::new(0);
    [ZERO; MAX_REDISTRIBUTORS]
};

/// The PE each of those frames belongs to, as an MPIDR-shaped affinity.
static REDISTRIBUTOR_AFFINITY: [AtomicU64; MAX_REDISTRIBUTORS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; MAX_REDISTRIBUTORS]
};

// -- Interrupt ids --------------------------------------------------------

/// Ids at and above this one are the architecture's special returns
/// (spurious, and the two "no pending interrupt" answers), not interrupts.
const SPURIOUS_INTERRUPT_ID_START: u32 = 1020;

const ICC_SRE_EL1_SRE: u64 = 1 << 0;
const ICC_SRE_EL1_DIB: u64 = 1 << 2;

/// `ICC_SGI1R_EL1` field positions, from the same specification.
const ICC_SGI1R_AFFINITY_1_SHIFT: u64 = 16;
const ICC_SGI1R_INTID_SHIFT: u64 = 24;
const ICC_SGI1R_AFFINITY_2_SHIFT: u64 = 32;
const ICC_SGI1R_RS_SHIFT: u64 = 44;
const ICC_SGI1R_AFFINITY_3_SHIFT: u64 = 48;

// -- System-register CPU interface ----------------------------------------

fn read_mpidr() -> u64 {
    let mpidr: u64;

    // SAFETY: MPIDR_EL1 is the core's own identity register and is readable
    // from EL1 at any time; the instruction touches no memory.
    unsafe {
        asm!(
            "mrs {mpidr}, MPIDR_EL1",
            mpidr = out(reg) mpidr,
            options(nomem, nostack, preserves_flags)
        );
    }

    mpidr
}

fn read_icc_sre() -> u64 {
    let value: u64;

    // SAFETY: ICC_SRE_EL1 is the EL1 system-register interface control,
    // readable whenever the interface is in use; no memory operand.
    unsafe {
        asm!(
            "mrs {value}, ICC_SRE_EL1",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }

    value
}

fn write_icc_sre(value: u64) {
    // SAFETY: the write side of the same register.  The caller pairs it with
    // an `isb` because its effect is the visibility of every later `ICC_*`
    // access.
    unsafe {
        asm!(
            "msr ICC_SRE_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn read_icc_ctlr() -> u64 {
    let value: u64;

    // SAFETY: ICC_CTLR_EL1 reports the CPU interface's implemented width; an
    // EL1 read with no memory operand.
    unsafe {
        asm!(
            "mrs {value}, ICC_CTLR_EL1",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }

    value
}

fn write_icc_pmr(value: u64) {
    // SAFETY: ICC_PMR_EL1 masks which priorities may be signalled; an EL1
    // write with no memory operand.
    unsafe {
        asm!(
            "msr ICC_PMR_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn write_icc_bpr1(value: u64) {
    // SAFETY: ICC_BPR1_EL1 splits preemption, not routing; an EL1 write with
    // no memory operand.
    unsafe {
        asm!(
            "msr ICC_BPR1_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn write_icc_ctlr(value: u64) {
    // SAFETY: the write side of the register `read_icc_ctlr` reads.
    unsafe {
        asm!(
            "msr ICC_CTLR_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn write_icc_ap1r0(value: u64) {
    // SAFETY: ICC_AP1R0_EL1 is the active-priority bank Group 1 always
    // implements (the architecture's floor is four priority bits); an EL1
    // write with no memory operand.
    unsafe {
        asm!(
            "msr ICC_AP1R0_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn write_icc_ap1r1(value: u64) {
    // SAFETY: as `write_icc_ap1r0` — the second bank, which implementations
    // with more than five priority bits have.  The caller checks the width
    // before reaching here; below it the register does not exist and the
    // access would be an undefined instruction.
    unsafe {
        asm!(
            "msr ICC_AP1R1_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn write_icc_ap1r2(value: u64) {
    // SAFETY: as `write_icc_ap1r1` — the third bank, from seven bits up.
    unsafe {
        asm!(
            "msr ICC_AP1R2_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn write_icc_ap1r3(value: u64) {
    // SAFETY: as `write_icc_ap1r1` — the fourth bank, from eight bits up.
    unsafe {
        asm!(
            "msr ICC_AP1R3_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn write_icc_igrpen1(value: u64) {
    // SAFETY: ICC_IGRPEN1_EL1 is the Group 1 enable this module sets once the
    // per-CPU configuration below it is in place.
    unsafe {
        asm!(
            "msr ICC_IGRPEN1_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn read_icc_iar1() -> u64 {
    let value: u64;

    // SAFETY: the acknowledge read of the Group 1 CPU interface; it does not
    // touch memory, and its effect — claiming the interrupt — is the point.
    unsafe {
        asm!(
            "mrs {value}, ICC_IAR1_EL1",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }

    value
}

fn write_icc_eoir1(value: u64) {
    // SAFETY: the end-of-interrupt write paired with `read_icc_iar1`; with
    // EOImode 0 it both drops the priority and deactivates the interrupt.
    unsafe {
        asm!(
            "msr ICC_EOIR1_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn write_icc_sgi1r(value: u64) {
    // SAFETY: the software-generated-interrupt register; the caller builds the
    // value from a redistributor's own affinity, so it names a PE this
    // controller enumerated.
    unsafe {
        asm!(
            "msr ICC_SGI1R_EL1, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

// -- Affinity -------------------------------------------------------------

/// Turn `GICR_TYPER`'s affinity fields into an MPIDR-shaped value.
///
/// The register holds the redistributor's PE in four bytes at the top of the
/// word — Aff0 in bits [39:32] up to Aff3 in bits [63:56] — and this kernel
/// keeps an MPIDR-shaped value everywhere it names a PE, so the four bytes are
/// packed the way MPIDR_EL1 packs them (one byte per affinity level).
fn affinity_from_typer(typer: u64) -> u64 {
    let aff0 = (typer >> 32) & 0xff;
    let aff1 = (typer >> 40) & 0xff;
    let aff2 = (typer >> 48) & 0xff;
    let aff3 = (typer >> 56) & 0xff;
    aff0 | (aff1 << 8) | (aff2 << 16) | (aff3 << 24)
}

/// The same packing for a core reading its own `MPIDR_EL1`.
fn affinity_from_mpidr(mpidr: u64) -> u64 {
    let aff0 = mpidr & 0xff;
    let aff1 = (mpidr >> 8) & 0xff;
    let aff2 = (mpidr >> 16) & 0xff;
    let aff3 = (mpidr >> 32) & 0xff;
    aff0 | (aff1 << 8) | (aff2 << 16) | (aff3 << 24)
}

fn current_cpu_id() -> u32 {
    (affinity_from_mpidr(read_mpidr()) & 0xff) as u32
}

/// How many PEs this controller has a redistributor for.
pub(crate) fn redistributor_count() -> usize {
    REDISTRIBUTOR_COUNT.load(Ordering::Acquire)
}

/// The redistributor frame of the PE the kernel calls `cpu_id`.
///
/// A PE's identity here is its Aff0 — the byte `MPIDR_EL1` puts at the bottom
/// and the one the AP entry point reads — and a GICv3 controller has one
/// redistributor frame per PE, so the frame whose `GICR_TYPER` carries that
/// Aff0 is the one that belongs to it.
fn redistributor_for_cpu(cpu_id: u32) -> Option<usize> {
    for index in 0..redistributor_count() {
        let affinity = REDISTRIBUTOR_AFFINITY[index].load(Ordering::Acquire);
        if (affinity & 0xff) as u32 == cpu_id {
            return Some(REDISTRIBUTOR_BASE[index].load(Ordering::Acquire));
        }
    }
    None
}

fn redistributor_for_current_cpu() -> Option<usize> {
    redistributor_for_cpu(current_cpu_id())
}

/// The redistributor frame of `cpu_id`, for a caller that has to name it.
///
/// An ITS collection is the caller this exists for: a collection is where a
/// message is sent, and the address it holds is a redistributor's.
pub(crate) fn rd_base_for_cpu(cpu_id: u32) -> Option<usize> {
    redistributor_for_cpu(cpu_id)
}

/// The linear processor number this redistributor reports.
///
/// `GICR_TYPER` carries it in bits [23:8].  An ITS whose `GITS_TYPER.PTA` is
/// clear wants this number rather than the redistributor's address in a
/// collection, and the controller's own report is the only place it comes
/// from.
pub(crate) fn processor_number(rd_base: usize) -> u32 {
    ((read_u64(rd_base + GICR_TYPER) >> 8) & 0xffff) as u32
}

/// The affinity an SGI to `cpu_id` must name, or `None` when this controller
/// never found a redistributor for that PE.
fn affinity_for_cpu(cpu_id: u32) -> Option<u64> {
    for slot in REDISTRIBUTOR_AFFINITY.iter().take(redistributor_count()) {
        let affinity = slot.load(Ordering::Acquire);
        if (affinity & 0xff) as u32 == cpu_id {
            return Some(affinity);
        }
    }
    None
}

/// Walk the redistributor chain and remember every frame in it.
///
/// The chain is a stride, not a list: each frame's `GICR_TYPER` says whether it
/// is the last one, and its affinity says which PE it belongs to.  Both are
/// read here once, before any secondary core is started, so the SGI path and
/// the per-CPU bring-up have a table to consult rather than an assumption that
/// a PE's identity is its frame index.
fn discover_redistributors(base: usize) -> usize {
    let mut count = 0;

    for index in 0..MAX_REDISTRIBUTORS {
        let frame = base + index * GICR_FRAME_SIZE;
        let typer = read_u64(frame + GICR_TYPER);

        // An address past the end of the mapped region reads as all ones on
        // most buses; a redistributor never reports that, so it ends the walk
        // rather than being recorded as one.
        if typer == u64::MAX {
            break;
        }

        REDISTRIBUTOR_BASE[index].store(frame, Ordering::Relaxed);
        REDISTRIBUTOR_AFFINITY[index].store(affinity_from_typer(typer), Ordering::Relaxed);
        count = index + 1;

        if typer & GICR_TYPER_LAST != 0 {
            break;
        }
    }

    REDISTRIBUTOR_COUNT.store(count, Ordering::Release);
    count
}

// -- Bring-up -------------------------------------------------------------

/// Wait for the distributor's pending register writes to land.
///
/// `GICD_CTLR.RWP` is the only answer to "has the last write arrived", and it
/// is set while one is in flight.  The poll is bounded: a controller that never
/// clears the bit is broken, and a boot that hangs inside the interrupt
/// controller is worse than one that says so and carries on.
fn wait_for_rwp(base: usize) -> bool {
    for _ in 0..1_000_000 {
        if read_u32(base + GICD_CTLR) & GICD_CTLR_RWP == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Put the distributor into affinity-routed, Group-1-enabled operation.
fn init_distributor(base: usize) {
    write_u32(base + GICD_CTLR, 0);
    let _ = wait_for_rwp(base);

    // Group 1, affinity routing on.  The order matters: ARE is what turns the
    // routing registers (`GICD_IROUTER`) into the ones an SPI's target is
    // written to, and it cannot be changed while a group is enabled, which is
    // why the write above disabled the distributor first.
    let ctlr = GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_G1A | GICD_CTLR_ENABLE_G1;
    write_u32(base + GICD_CTLR, ctlr);
    if !wait_for_rwp(base) {
        crate::println!("[irq   ] GICv3: distributor never finished its enable sequence");
    }
}

/// Wake one CPU's redistributor so its frames answer.
///
/// A redistributor boots asleep: `GICR_WAKER.ProcessorSleep` is set until
/// software clears it, and until `ChildrenAsleep` follows, its frame answers
/// nothing useful.  This is per-CPU state, so every core runs it for itself.
fn wake_redistributor(frame: usize) -> bool {
    let waker = read_u32(frame + GICR_WAKER);

    if waker & GICR_WAKER_CHILDREN_ASLEEP == 0 {
        return true;
    }

    write_u32(frame + GICR_WAKER, waker & !GICR_WAKER_PROCESSOR_SLEEP);
    dsb_sy();

    for _ in 0..1_000_000 {
        if read_u32(frame + GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP == 0 {
            return true;
        }
        core::hint::spin_loop();
    }

    false
}

/// Turn on the system-register CPU interface.
///
/// `ICC_SRE_EL1.SRE` selects between the system-register interface and the
/// memory-mapped one the architecture dropped; every other `ICC_*` access is
/// undefined until it reads back set.  Firmware may already have set it, so
/// the bit is only written when it is clear.
fn enable_system_register_interface() -> bool {
    let mut sre = read_icc_sre();

    if sre & ICC_SRE_EL1_SRE == 0 {
        // DIB additionally makes a priority drop unable to mask interrupts,
        // which is the behaviour this kernel's one-write EOI model assumes.
        write_icc_sre(sre | ICC_SRE_EL1_SRE | ICC_SRE_EL1_DIB);
        isb();
        sre = read_icc_sre();
    }

    sre & ICC_SRE_EL1_SRE != 0
}

/// The CPU-interface half of GICv3 bring-up, run on every core.
///
/// Returns whether this core's redistributor was found and woken.  A core
/// without one cannot be interrupted at all, and the caller is the core
/// itself, so the answer is what lets it stop with a message instead of
/// running as a CPU that never takes a tick.
pub(crate) fn init_cpu() -> bool {
    let Some(frame) = redistributor_for_current_cpu() else {
        return false;
    };

    if !wake_redistributor(frame) {
        return false;
    }

    // SGIs and PPIs are per-CPU and live in this frame, not in the
    // distributor.  Group 1 is what the CPU interface below enables, so the
    // whole bank is assigned to it here; enabling the individual interrupts
    // stays with whoever owns them (the timer, for the tick).
    //
    // SGIs have no enable bit to set either: the architecture makes ids 0-15
    // always enabled, which is why nothing here writes GICR_ISENABLER0 for
    // them.
    write_u32(frame + GICR_IGROUPR0, u32::MAX);
    dsb_sy();

    if !enable_system_register_interface() {
        return false;
    }

    write_icc_pmr(0xFF);
    write_icc_bpr1(0);
    // EOImode 0: the EOI write both drops the priority and deactivates the
    // interrupt, which is the one-write model the trap path already has.
    write_icc_ctlr(0);

    // A bootloader can hand over with active priorities left behind, and an
    // active priority at or above a pending interrupt's blocks it forever.
    // The banks above the first only exist when the interface has the priority
    // bits for them, so the width decides which are written.
    let priority_bits = ((read_icc_ctlr() >> 8) & 0x7) + 1;
    write_icc_ap1r0(0);
    if priority_bits > 5 {
        write_icc_ap1r1(0);
    }
    if priority_bits > 6 {
        write_icc_ap1r2(0);
    }
    if priority_bits > 7 {
        write_icc_ap1r3(0);
    }
    isb();

    write_icc_igrpen1(1);
    true
}

// -- LPIs -----------------------------------------------------------------

/// The tables a redistributor needs before it can deliver an LPI.
struct LpiState {
    /// One byte per LPI the machine implements, shared by every CPU that
    /// delivers them: bit 0 enables the LPI, bit 1 puts it in Group 1, and
    /// bits [7:2] are its priority.
    config: DmaBuffer,
    /// The boot CPU's pending table, a bit per LPI.  The redistributor sets
    /// one when a message arrives.
    pending: DmaBuffer,
    /// The LPI bits the machine implements, as `GICR_PROPBASER` wants them:
    /// one less than the number of bits in an LPI id, which is what sizes
    /// both tables.
    id_bits: u32,
}

static LPI_STATE: SpinLock<Option<LpiState>> = SpinLock::new(None);

/// Wait for `GICD_TYPER` to report how many bits of LPI id this machine has.
///
/// The answer is in bits [23:19], one less than the count, and it is what
/// sizes the configuration and pending tables: an LPI's number is the base
/// plus an id of that many bits, so a machine with sixteen bits of id has an
/// LPI space of 65536 and its tables are sized for all of it.
fn lpi_id_bits() -> u32 {
    let typer = read_u32(gicd_base() + 0x004);
    (typer >> 19) & 0x1f
}

/// Allocate the LPI tables and enable LPIs on the CPU that runs this.
///
/// One CPU is the whole configuration on purpose: every ITS collection this
/// kernel programs targets the boot CPU's redistributor (an MSI-X device's
/// messages are delivered where its collection points, and the collection is
/// chosen here), so there is exactly one pending table to keep alive and no
/// per-CPU LPI state for a secondary core to bring up.  A machine whose
/// interrupts should be spread across CPUs is a later problem, and it will
/// need one pending table per CPU when it arrives.
///
/// Returns whether LPIs are enabled; a machine whose frame allocator is
/// already empty leaves them off and the callers stay on the polling path.
pub(crate) fn init_lpis() -> bool {
    let id_bits = lpi_id_bits();
    // One byte per LPI, and one bit per LPI in the pending table.
    let lpi_count = 1_usize << (id_bits + 1);
    let Some(config) = DmaBuffer::allocate(lpi_count.div_ceil(crate::memory::frame::FRAME_SIZE))
    else {
        return false;
    };
    let pending_bytes = lpi_count / 8;
    let Some(pending) = DmaBuffer::allocate_aligned(
        pending_bytes.div_ceil(crate::memory::frame::FRAME_SIZE),
        LPI_PENDING_ALIGNMENT,
    ) else {
        return false;
    };

    *LPI_STATE.lock() = Some(LpiState {
        config,
        pending,
        id_bits,
    });

    // The state and the hardware go together: until this CPU's redistributor
    // is actually pointed at the tables, a claim that thinks an LPI is
    // deliverable would arm a device that could never signal.  Leaving the
    // state in place would be exactly that, so a failure takes it back out.
    if !enable_lpis_for_current_cpu() {
        *LPI_STATE.lock() = None;
        return false;
    }
    true
}

/// Point this core's redistributor at the LPI tables and turn LPIs on.
///
/// `GICR_PROPBASER` names the shared configuration table and how many LPI bits
/// it holds; `GICR_PENDBASER` names this core's pending table.  Both are
/// written before `GICR_CTLR.EnableLPIs`, because the redistributor is not
/// allowed to be using them while they move.
fn enable_lpis_for_current_cpu() -> bool {
    let Some(frame) = redistributor_for_current_cpu() else {
        return false;
    };

    let state = LPI_STATE.lock();
    let Some(state) = state.as_ref() else {
        return false;
    };

    let prop = state.config.phys_addr() as u64
        | TABLE_INNER_CACHEABLE
        | TABLE_INNER_SHAREABLE
        | state.id_bits as u64;
    write_u64(frame + GICR_PROPBASER, prop);

    let pend = state.pending.phys_addr() as u64 | TABLE_INNER_CACHEABLE | TABLE_INNER_SHAREABLE;
    write_u64(frame + GICR_PENDBASER, pend);
    dsb_sy();

    let ctlr = read_u32(frame + GICR_CTLR) | GICR_CTLR_ENABLE_LPIS;
    write_u32(frame + GICR_CTLR, ctlr);
    dsb_sy();
    true
}

/// Enable or disable one LPI in the configuration table.
///
/// The redistributor reads this byte before it will deliver the interrupt, so
/// a device's LPI is enabled here before its MSI-X table is allowed to signal.
/// Answers whether the LPI is one this controller's tables cover.
pub(crate) fn set_lpi_enabled(lpi: u32, enabled: bool) -> bool {
    let Some(index) = lpi.checked_sub(LPI_BASE).map(|offset| offset as usize) else {
        return false;
    };

    let state = LPI_STATE.lock();
    let Some(state) = state.as_ref() else {
        return false;
    };

    // Two bounds, and both matter: the window is what this kernel hands out,
    // and the table is what the byte is written into.  They agree today —
    // the machine's LPI space is far larger than the window — and checking
    // both is what keeps a machine that reports a smaller space from turning
    // a claim into an out-of-bounds write.
    if index >= LPI_WINDOW || index >= state.config.len() {
        return false;
    }

    let value = if enabled { LPI_CONFIG_ENABLED } else { 0 };
    // The byte is inside the configuration table `state` owns, whose
    // allocation is a page and whose length is the LPI space it was sized for.
    write_u8(state.config.as_ptr() as usize + index, value);
    // The redistributor reads the table behind the kernel's caches; the
    // barrier is what makes the byte visible before the device is let go.
    dsb_sy();
    true
}

// -- Interrupt routing ----------------------------------------------------

/// Assign one interrupt to Group 1.
///
/// Ids below 32 are per-CPU and live in this core's redistributor; the rest
/// live in the distributor and are shared.  A core whose redistributor was
/// never found has no register to write here, and `init_cpu` has already
/// failed its bring-up with a message.
pub(crate) fn set_group1(interrupt_id: u32) {
    if interrupt_id < 32 {
        let Some(frame) = redistributor_for_current_cpu() else {
            return;
        };
        let register = frame + GICR_IGROUPR0;
        write_u32(register, read_u32(register) | (1 << interrupt_id));
    } else {
        let register = gicd_base() + GICD_IGROUPR + (interrupt_id as usize / 32) * 4;
        write_u32(register, read_u32(register) | (1 << (interrupt_id % 32)));
    }
}

/// Enable one interrupt.
///
/// The enable registers are write-1-to-set, so the bit is written rather than
/// read, set and written back — a difference that matters when another core is
/// enabling a neighbour in the same word.
pub(crate) fn enable_interrupt(interrupt_id: u32) {
    if interrupt_id < 32 {
        let Some(frame) = redistributor_for_current_cpu() else {
            return;
        };
        write_u32(frame + GICR_ISENABLER0, 1 << interrupt_id);
    } else {
        let register = gicd_base() + GICD_ISENABLER + (interrupt_id as usize / 32) * 4;
        write_u32(register, 1 << (interrupt_id % 32));
    }
}

/// Set one interrupt's priority.
///
/// The priority array is a byte per interrupt in both register blocks; the
/// unimplemented low bits read as zero and are ignored on write.
pub(crate) fn set_priority(interrupt_id: u32, priority: u8) {
    let address = if interrupt_id < 32 {
        let Some(frame) = redistributor_for_current_cpu() else {
            return;
        };
        frame + GICR_IPRIORITYR + interrupt_id as usize
    } else {
        gicd_base() + GICD_IPRIORITYR + interrupt_id as usize
    };
    write_u8(address, priority);
}

/// Route an SPI to one CPU.
///
/// `GICD_IROUTER<n>` holds the target PE's affinity rather than a bit in a
/// list, so the target's own `GICR_TYPER` affinity is what is written.  SGIs
/// and PPIs are per-CPU by construction and cannot be re-targeted, which is
/// why the id check comes first.
pub(crate) fn set_affinity(interrupt_id: u32, cpu_id: u32) {
    if interrupt_id < 32 {
        return;
    }

    // A CPU the controller never enumerated has no affinity to write; its own
    // id, read as Aff0 in cluster 0, is the only description of it there is.
    let affinity = affinity_for_cpu(cpu_id).unwrap_or(cpu_id as u64);
    write_u64(
        gicd_base() + GICD_IROUTER + (interrupt_id as usize - 32) * 8,
        affinity,
    );
}

// -- Acknowledge, EOI and SGIs --------------------------------------------

/// The interrupt id inside an acknowledge value.
///
/// GICv3's field is 24 bits wide — LPIs, when they arrive, are ids far above
/// the 10-bit range GICv2 could name — so the mask is the full field rather
/// than the older one.
pub(crate) fn interrupt_id(acknowledge: u32) -> u32 {
    acknowledge & 0x00ff_ffff
}

pub(crate) fn claim() -> Option<u32> {
    let acknowledge = read_icc_iar1() as u32;
    let interrupt_id = interrupt_id(acknowledge);

    // The ids between the last SPI and the first LPI are the architecture's
    // special returns, and an LPI is a valid answer above them — the wire
    // range is not the whole range any more.
    (!(SPURIOUS_INTERRUPT_ID_START..LPI_BASE).contains(&interrupt_id)).then_some(acknowledge)
}

pub(crate) fn end_of_interrupt(vector: u32) {
    let interrupt_id = interrupt_id(vector);
    if (SPURIOUS_INTERRUPT_ID_START..LPI_BASE).contains(&interrupt_id) {
        return;
    }
    write_icc_eoir1(interrupt_id as u64);
}

/// Build the `ICC_SGI1R_EL1` value that targets one affinity.
///
/// TargetList names the low nibble of Aff0 as a one-hot list and RS carries
/// the rest of Aff0, which is why a PE whose Aff0 is 16 or more is still one
/// register write rather than a special case.
fn sgi_value(interrupt_id: u8, affinity: u64) -> u64 {
    let aff0 = affinity & 0xff;
    let aff1 = (affinity >> 8) & 0xff;
    let aff2 = (affinity >> 16) & 0xff;
    let aff3 = (affinity >> 24) & 0xff;
    let range_selector = (aff0 >> 4) & 0xf;

    (aff3 << ICC_SGI1R_AFFINITY_3_SHIFT)
        | (range_selector << ICC_SGI1R_RS_SHIFT)
        | (aff2 << ICC_SGI1R_AFFINITY_2_SHIFT)
        | ((interrupt_id as u64) << ICC_SGI1R_INTID_SHIFT)
        | (aff1 << ICC_SGI1R_AFFINITY_1_SHIFT)
        | (1_u64 << (aff0 & 0xf))
}

/// Send one SGI to one CPU.
///
/// A CPU this controller has no redistributor for is a PE it cannot address;
/// signalling nothing is the honest answer, and inventing an affinity would
/// wake a different core instead.
pub(crate) fn send_sgi(interrupt_id: u8, cpu_id: u32) {
    if interrupt_id >= 16 {
        return;
    }
    let Some(affinity) = affinity_for_cpu(cpu_id) else {
        return;
    };
    write_icc_sgi1r(sgi_value(interrupt_id, affinity));
}

/// Broadcast one SGI to every other CPU this controller enumerated.
///
/// GICv3 has an "all except self" mode, but it stops at one affinity group;
/// the frames walked at bring-up are the list that makes "all" mean the whole
/// machine, and walking it is what this does.
pub(crate) fn send_sgi_all_except_self(interrupt_id: u8) {
    if interrupt_id >= 16 {
        return;
    }
    let self_affinity = affinity_from_mpidr(read_mpidr());
    for slot in REDISTRIBUTOR_AFFINITY.iter().take(redistributor_count()) {
        let affinity = slot.load(Ordering::Acquire);
        if affinity != self_affinity {
            write_icc_sgi1r(sgi_value(interrupt_id, affinity));
        }
    }
}

// -- The controller -------------------------------------------------------

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Singleton GICv3 controller used by the arch-level dispatch.
pub(crate) static GICV3_CONTROLLER: GicV3Controller = GicV3Controller;

/// ARM Generic Interrupt Controller v3.
pub(crate) struct GicV3Controller;

impl InterruptController for GicV3Controller {
    fn init(&self) {
        if INITIALIZED.swap(true, Ordering::Acquire) {
            return;
        }

        let redistributors = discover_redistributors(gicr_base());
        crate::println!(
            "[irq   ] GICv3 at {:#x}: {} redistributor frame(s), distributor at {:#x}",
            gicr_base(),
            redistributors,
            gicd_base()
        );

        init_distributor(gicd_base());
        if !init_cpu() {
            crate::println!("[irq   ] GICv3: the boot CPU has no redistributor of its own");
        }
        if init_lpis() {
            crate::println!(
                "[irq   ] GICv3: LPIs {}..{} enabled on the boot CPU",
                LPI_BASE,
                LPI_LAST
            );
        } else {
            crate::println!("[irq   ] GICv3: no LPI tables; message-signalled interrupts stay off");
        }
    }

    fn end_of_interrupt(&self, vector: u32) {
        end_of_interrupt(vector);
    }

    fn enable_interrupt(&self, interrupt_id: u32) {
        enable_interrupt(interrupt_id);
    }

    fn set_priority(&self, interrupt_id: u32, priority: u8) {
        set_priority(interrupt_id, priority);
    }
}
