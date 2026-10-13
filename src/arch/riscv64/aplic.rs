//! src/arch/riscv64/aplic.rs
//!
//! RISC-V AIA APLIC driver — the wired half of an AIA machine.
//!
//! An APLIC domain watches a source's *line* and, in MSI mode, delivers it as
//! a message: the domain's `target` register for that source names the hart
//! whose IMSIC file receives it and the identity the message carries
//! (`EIID`), and the domain writes that identity into that file's MSI page —
//! the same write a device's MSI-X table entry makes.  So a wire ends up
//! exactly where a PCIe device's message does: an identity in the IMSIC's
//! space, claimed in the handler registry
//! ([`crate::arch::irq_handlers`]) and dispatched by the external-interrupt
//! trap, which is why the UART costs no second delivery path.
//!
//! What this kernel programs is the **supervisor-level** domain — the one
//! that delivers.  QEMU `virt` describes two APLIC nodes: a machine-level
//! domain that holds the wires and delegates each source to a child
//! (`riscv,children`), and the child that turns a delegated source into a
//! message.  Only the child is this kernel's; the machine-level domain's own
//! state, including the `SMSICFGADDR` base the child's messages are addressed
//! through, belongs to firmware.  Measured on QEMU 10.2.1 (its bundled
//! OpenSBI): the delegating domain comes up with the sources already
//! delegated and `SMSICFGADDR` pointing at the supervisor IMSIC, while the
//! child's sources are all inactive — so what this driver does is exactly
//! what is missing.
//!
//! Register layout: AIA v1.0 §4.  Only the MSI-mode registers are touched:
//! `domaincfg` (the domain's delivery enable), `sourcecfg[n]` (level-high),
//! `target[n]` (hart index and EIID) and `setienum`.
//!
//! A machine whose APLIC is in **direct** mode — `-machine virt,aia=aplic`,
//! where no IMSIC receives messages — is driven here too, through a different
//! half of the specification: the domain raises the receiving hart's
//! supervisor external interrupt and the hart claims the source by *reading*
//! its own `claimi` register.  [`arm_source_direct`] and [`claim_direct`] are
//! that path, and `docs/kernel/interrupts.md` says how the two modes share
//! one registry (`make check-riscv64-aplic-direct-runtime` is the gate).

use super::read_volatile;
use super::write_volatile;
use crate::Error;

// ── The supervisor domain's registers (AIA v1.0 §4.8, "MSI configuration
// registers" and the source registers before them) ──────────────────────

/// `domaincfg`: bit 8 is `IE`, the domain's delivery enable; bits 2 (`DM`)
/// and 31 are read-only, and a read reports the mode the domain is in.
const DOMAINCFG: usize = 0x0000;
/// `sourcecfg[n]` for source `n` sits at `SOURCECFG_BASE + (n - 1) * 4`.
const SOURCECFG_BASE: usize = 0x0004;
/// Write a source number here to enable it.
const SETIENUM: usize = 0x1EDC;
/// `target[n]` for source `n`, the MSI-mode form: hart index, guest index and
/// `EIID`.
const TARGET_BASE: usize = 0x3004;

/// `domaincfg.IE` — the domain delivers its enabled sources.
const DOMAINCFG_IE: u32 = 1 << 8;
/// `sourcecfg.SM` value for a level-sensitive, active-high source: the UART's
/// received-data line is high while a byte sits in its FIFO, and the handler
/// drains the FIFO low, which is the transition the domain watches.
const SOURCECFG_SM_LEVEL_HIGH: u32 = 6;
/// `sourcecfg.SM` mask — the field the read-back check compares.
const SOURCECFG_SM_MASK: u32 = 0x7;
/// `target.HART_IDX` — which hart of the domain's set receives the message.
const TARGET_HART_IDX_SHIFT: u32 = 18;
/// `target.EIID` — the identity the delivered message carries in its data
/// word, and the bound on the field.
const TARGET_EIID_MASK: u32 = 0x7ff;
/// `target.IPRIO` — the source's priority in the domain's own scale, which is
/// what direct-mode delivery arbitrates by and what a threshold is compared
/// against.
const TARGET_IPRIO_MASK: u32 = 0xff;

// ── The priority policy ─────────────────────────────────────────────────
//
// Direct-mode delivery arbitrates by one number per source, and the
// specification is explicit about its direction: "Smaller priority numbers
// convey higher priority", "Only values 1 through 2^IPRIOLEN - 1 are allowed
// for IPRIO, not zero", and a threshold of P holds back "priority numbers P
// and higher".  So a source's IPRIO *is* the order it is served in — the
// claim register answers with the highest-priority pending source — and a
// policy is a choice from `1..=TARGET_IPRIO_MASK`, made once here rather
// than at each call site.

/// The console's priority, and the policy's answer to "what must never
/// wait": input was moved off the timer tick on every machine so a person's
/// keystroke does not ride on a stall, and it must not wait behind a device's
/// wire either.  It is the scale's most urgent value, so no source can
/// outrank the console while both are pending.
pub const PRIORITY_CONSOLE: u32 = 1;

/// Every other wired source.  Below the console and above nothing: a device's
/// completion may be slower than a keystroke, and no machine here arms one
/// yet — the constant is where such a driver's number comes from, so the
/// order between roles is decided in this block rather than in a driver.
pub const PRIORITY_DEVICE: u32 = 2;

/// The hart's `ithreshold`.  Zero is the value that makes the ordering above
/// the whole policy: any nonzero threshold P would mute every source whose
/// priority is P or higher — a threshold of `PRIORITY_CONSOLE` would mute the
/// console itself — so a machine that wanted to hold device wires back while
/// the console is pending would have to raise this deliberately, and the
/// raised value is what would say so.
pub const THRESHOLD_ACCEPT_ALL: u32 = 0;

// The policy's relations as build-time facts, so a later edit that flips the
// scale's direction or lets a role be zero fails the build rather than the
// machine: the specification's "smaller conveys higher priority", its "only
// values 1 through the field's maximum", and this file's own "the console
// outranks a device".
const _: () = assert!(PRIORITY_CONSOLE < PRIORITY_DEVICE);
const _: () = assert!(PRIORITY_CONSOLE >= 1);
const _: () = assert!(PRIORITY_DEVICE <= TARGET_IPRIO_MASK);

// ── Direct mode (`domaincfg.DM == 0`, `-machine virt,aia=aplic`) ────────
//
// A direct-mode domain does not compose messages at all: it raises the
// receiving hart's supervisor external interrupt, and the hart claims the
// source by **reading** its own `claimi` register.  The registers below are
// the per-hart delivery window ("IDC") the specification gives each hart of a
// direct-mode domain, and the semantics measured on QEMU 10.2.1's
// `riscv_aplic.c` are the ones written down here:
//
//   * `target[i]` is `HART_IDX` in bits 31:18 and `IPRIO` in bits 7:0, and the
//     domain rewrites a zero priority to 1 on the write;
//   * a hart's delivery is `domaincfg.IE && idelivery[hart] && (topi or
//     iforce)`, where `topi` is nonzero only when a pending source's target
//     names this hart and its priority is below `ithreshold`;
//   * reading `claimi` claims the top source — no separate completion register
//     — and a level-high source whose input is still asserted is re-pended by
//     the domain, so it is the handler's drain that lowers the line.

/// The per-hart delivery window's base inside the domain.
const IDC_BASE: usize = 0x4000;
/// The stride from one hart's window to the next.
const IDC_SIZE: usize = 32;
/// `idelivery[hart]`: this hart accepts interrupts from the domain.
const IDC_IDELIVERY: usize = 0x00;
/// `ithreshold[hart]`: priorities at or above it are held back; zero passes
/// every priority.
const IDC_ITHRESHOLD: usize = 0x08;
/// `claimi[hart]`: *reading* it claims the top pending source for this hart.
const IDC_CLAIMI: usize = 0x1c;
/// The source number's position in a `topi`/`claimi` word — the index sits at
/// the top, a priority at the bottom, and the two together are not an
/// identity any registry indexes by.
const IDC_TOPI_ID_SHIFT: u32 = 16;
/// The widest source number those words carry.
const IDC_TOPI_ID_MASK: u32 = 0x3ff;

/// One of a hart's delivery registers.
pub(crate) fn idc_register(base: usize, hart_index: u32, offset: usize) -> usize {
    base + IDC_BASE + hart_index as usize * IDC_SIZE + offset
}

/// The `target` word that names `hart_index` and priority `priority` for a
/// source in direct mode.
pub(crate) fn direct_target(hart_index: u32, priority: u32) -> u32 {
    (hart_index << TARGET_HART_IDX_SHIFT) | (priority & TARGET_IPRIO_MASK)
}

/// Read one domain register.
fn read(register: usize) -> u32 {
    // SAFETY: `register` is an address inside the supervisor APLIC window the
    // platform described, which the machine's device mapping covers; a
    // four-byte load is the access width the specification gives its
    // registers.
    unsafe { read_volatile(register as *const u32) }
}

/// Write one domain register.
fn write(register: usize, value: u32) {
    // SAFETY: as `read` — the same window, on the write side.
    unsafe { write_volatile(register as *mut u32, value) }
}

/// Order the writes above before anything can observe them.
///
/// The domain's registers are device memory: without a fence the stores are
/// only ordered against each other by accident of the bus, and a source must
/// not be able to deliver through a `target` that has not arrived.
fn fence_iorw() {
    // SAFETY: an ordering fence over the hart's own I/O and memory accesses;
    // it touches no memory and cannot fault.
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags));
    }
}

/// The supervisor APLIC window the machine described, if it described one.
pub fn aplic_base() -> Option<usize> {
    crate::arch::fdt::platform_info().aplic_base
}

/// Whether this machine's wires are an APLIC with **no IMSIC behind it**
/// (`-machine virt,aia=aplic`): the direct-delivery mode.
///
/// Direct mode is a different delivery path — a source is claimed through the
/// domain's own `topi`/`claimi` registers, not "turned into a message" — and
/// this driver does not implement it.  What it must not do is let the machine
/// fall back onto PLIC addresses on a board that has no PLIC: measured on
/// QEMU 10.2.1 with `aia=aplic`, the boot reached the PLIC controller anyway,
/// wrote its per-context threshold at `0xc201000` (the fallback base
/// `0xc000_0000` plus the PLIC's own offsets, an address no device answers
/// on this machine), and died in a store access fault before the console had
/// done anything but start.  The machines are told apart here, once.
pub fn is_direct_mode() -> bool {
    aplic_base().is_some() && !super::aia_imsic::has_aia_imsic()
}

/// Arm `source` so its line is delivered as an MSI carrying identity
/// `source`, received by hart `hart_index`'s IMSIC file.
///
/// The identity is the source number, which keeps the two RISC-V machines'
/// registries the same shape: a PLIC machine's source *is* its identity, and
/// this domain is told to send that same number as the message.
///
/// The order matters, and `sourcecfg` goes first because the specification
/// makes `target` read-only zero while the source is inactive: "If interrupt
/// source i is inactive in this domain, register target[i] is read-only
/// zero" (the AIA specification's `target[1]-target[1023]` section), so a
/// `target` written before its `sourcecfg` is a write the domain drops —
/// QEMU implements the drop from commit `7c96dbdd` (2026-01-09), and the
/// 10.2.1 this was measured on does not, which is why writing `target` first
/// used to pass.  Then `setienum` after the source is configured (the domain
/// ignores an enable for an inactive source), and the domain's `IE` last — a
/// source that went pending while `IE` was clear is delivered by the write
/// that sets it, through the `target` written first.  Every write is read
/// back: a domain that took none of them would otherwise surface as an
/// interrupt that never arrives.
pub fn arm_source(source: u32, hart_index: u32) -> Result<(), Error> {
    let base = aplic_base().ok_or(Error::NotImplemented)?;
    if source == 0 || source > TARGET_EIID_MASK {
        return Err(Error::InvalidArgument);
    }

    let target = (hart_index << TARGET_HART_IDX_SHIFT) | source;
    let target_register = base + TARGET_BASE + (source as usize - 1) * 4;
    let sourcecfg_register = base + SOURCECFG_BASE + (source as usize - 1) * 4;
    write(sourcecfg_register, SOURCECFG_SM_LEVEL_HIGH);
    write(target_register, target);
    write(base + SETIENUM, source);
    write(base + DOMAINCFG, DOMAINCFG_IE);
    fence_iorw();

    let sourcecfg = read(sourcecfg_register);
    let read_back = read(target_register);
    let domaincfg = read(base + DOMAINCFG);
    if sourcecfg & SOURCECFG_SM_MASK != SOURCECFG_SM_LEVEL_HIGH
        || read_back != target
        || domaincfg & DOMAINCFG_IE == 0
    {
        crate::println!(
            "[aplic ] source {} did not take its configuration (sourcecfg {:#x}, target {:#x}, domaincfg {:#x})",
            source,
            sourcecfg,
            read_back,
            domaincfg
        );
        return Err(Error::DeviceError);
    }

    crate::println!(
        "[aplic ] source {} armed at {:#x}: level-high, MSI identity {} to hart {}",
        source,
        base,
        source & TARGET_EIID_MASK,
        hart_index
    );
    Ok(())
}

/// Arm `source` in **direct mode**: its line raises hart `hart_index`'s
/// supervisor external interrupt, and the hart claims it by reading its own
/// `claimi` register.
///
/// The configuration is the same shape as [`arm_source`]'s — `sourcecfg`
/// first, because `target` is read-only zero while the source is inactive —
/// and then the three switches the domain delivers through, in the order the
/// specification gives them: this hart's `idelivery`, its `ithreshold` (the
/// policy's, [`THRESHOLD_ACCEPT_ALL`] by default), and the domain's own `IE`
/// last, so a source that went pending meanwhile is delivered by the write
/// that sets it.  Every write is read back for the same reason
/// [`arm_source`]'s are: a domain that took none of them would otherwise
/// surface as an interrupt that never arrives.
///
/// `priority` is the caller's choice from the scale the policy block above
/// describes — [`PRIORITY_CONSOLE`] for the console, [`PRIORITY_DEVICE`] for
/// a device's wire — and zero is refused rather than substituted, because the
/// domain's own substitution ("a write of zero is set to 1 instead", the
/// specification) would turn a caller's missing answer into the most urgent
/// priority there is.
pub fn arm_source_direct(source: u32, hart_index: u32, priority: u32) -> Result<(), Error> {
    let base = aplic_base().ok_or(Error::NotImplemented)?;
    if source == 0 || source > TARGET_EIID_MASK {
        return Err(Error::InvalidArgument);
    }
    if priority == 0 || priority > TARGET_IPRIO_MASK {
        return Err(Error::InvalidArgument);
    }

    let target = direct_target(hart_index, priority);
    let target_register = base + TARGET_BASE + (source as usize - 1) * 4;
    let sourcecfg_register = base + SOURCECFG_BASE + (source as usize - 1) * 4;
    let idelivery_register = idc_register(base, hart_index, IDC_IDELIVERY);
    let ithreshold_register = idc_register(base, hart_index, IDC_ITHRESHOLD);

    write(sourcecfg_register, SOURCECFG_SM_LEVEL_HIGH);
    write(target_register, target);
    write(base + SETIENUM, source);
    write(idelivery_register, 1);
    write(ithreshold_register, THRESHOLD_ACCEPT_ALL);
    write(base + DOMAINCFG, DOMAINCFG_IE);
    fence_iorw();

    let sourcecfg = read(sourcecfg_register);
    let read_back = read(target_register);
    let idelivery = read(idelivery_register);
    let domaincfg = read(base + DOMAINCFG);
    if sourcecfg & SOURCECFG_SM_MASK != SOURCECFG_SM_LEVEL_HIGH
        || read_back != target
        || idelivery & 1 == 0
        || domaincfg & DOMAINCFG_IE == 0
    {
        crate::println!(
            "[aplic ] source {} did not take its direct-mode configuration (sourcecfg {:#x}, target {:#x}, idelivery {:#x}, domaincfg {:#x})",
            source,
            sourcecfg,
            read_back,
            idelivery,
            domaincfg
        );
        return Err(Error::DeviceError);
    }

    crate::println!(
        "[aplic ] source {} armed at {:#x}: level-high, direct delivery to hart {} (priority {} of {})",
        source,
        base,
        hart_index,
        priority,
        TARGET_IPRIO_MASK
    );
    Ok(())
}

/// Claim the highest-priority pending source for `hart_index` in direct mode.
///
/// *Reading* `claimi` is the claim — the direct-mode path has no separate
/// completion register — and the register answers with the domain's `topi`
/// word, which is **not** the identity the handler registry indexes by:
/// measured, a boot that passed the raw word along looked for a handler for
/// `0x000a0001` (source 10, priority 1, in one 32-bit register) and found
/// none, so the byte was never drained, the line stayed high, and the domain
/// re-pended the source forever — a claim loop that starved even the timer
/// tick, because this interrupt outranks it.  The source number is what this
/// returns, so every path dispatches by the same identity the PLIC and IMSIC
/// paths use.
///
/// A level-high source whose input is still asserted is re-pended by the
/// domain itself, so the handler's drain is what lowers the line; a source
/// nobody armed is not claimable and answers zero, which the caller counts as
/// spurious the way every other path does.
pub fn claim_direct(hart_index: u32) -> u32 {
    let Some(base) = aplic_base() else {
        return 0;
    };
    let topi = read(idc_register(base, hart_index, IDC_CLAIMI));
    (topi >> IDC_TOPI_ID_SHIFT) & IDC_TOPI_ID_MASK
}

#[cfg(test)]
mod tests {
    use super::direct_target;
    use super::idc_register;
    use super::IDC_TOPI_ID_MASK;
    use super::IDC_TOPI_ID_SHIFT;
    use super::PRIORITY_CONSOLE;
    use super::PRIORITY_DEVICE;
    use super::TARGET_IPRIO_MASK;
    use super::THRESHOLD_ACCEPT_ALL;

    /// The defect this pins: `claimi` answers with `topi`, which packs the
    /// source number and a priority into one word.  Passing that word along
    /// as an identity found no handler for `0x000a0001`, so nothing drained
    /// the FIFO and the domain re-pended source 10 forever (measured on the
    /// direct-mode machine, where the resulting claim loop starved the timer
    /// tick).
    #[test]
    fn a_topi_word_decodes_to_its_source_number() {
        let word = (10u32 << IDC_TOPI_ID_SHIFT) | 1;
        assert_eq!((word >> IDC_TOPI_ID_SHIFT) & IDC_TOPI_ID_MASK, 10);
        assert_ne!(word, 10, "the raw word is not an identity");
        assert_eq!((0u32 >> IDC_TOPI_ID_SHIFT) & IDC_TOPI_ID_MASK, 0);
        assert_eq!(
            ((0x3ffu32 << IDC_TOPI_ID_SHIFT) >> IDC_TOPI_ID_SHIFT) & IDC_TOPI_ID_MASK,
            0x3ff,
            "the field's own bound survives the round trip"
        );
    }

    #[test]
    fn direct_target_names_the_hart_and_carries_the_priority_it_was_given() {
        let target = direct_target(3, PRIORITY_DEVICE);
        assert_eq!(target >> 18, 3, "the hart index rides bits 31:18");
        assert_eq!(
            target & 0xff,
            PRIORITY_DEVICE,
            "the priority is stored as written, not substituted"
        );
        assert_ne!(
            direct_target(3, PRIORITY_CONSOLE) & 0xff,
            direct_target(3, PRIORITY_DEVICE) & 0xff,
            "the two roles are told apart in the word the domain arbitrates by"
        );
    }

    /// The policy's own relations, which the arbitration leans on: smaller is
    /// more urgent (the specification: "Smaller priority numbers convey
    /// higher priority"), the console is the most urgent value the scale has,
    /// a device sits below it, and zero — "not zero" in the specification — is
    /// never a role's value.
    #[test]
    fn the_priority_policy_is_ordered_and_nonzero() {
        assert!(
            PRIORITY_CONSOLE < PRIORITY_DEVICE,
            "the console must outrank a device"
        );
        assert!(
            PRIORITY_CONSOLE >= 1 && PRIORITY_DEVICE >= 1,
            "zero is not a priority: the domain substitutes the most urgent one, which would silently promote a role"
        );
        assert!(
            PRIORITY_DEVICE <= TARGET_IPRIO_MASK,
            "the field is IPRIOLEN bits wide"
        );
        assert_eq!(
            THRESHOLD_ACCEPT_ALL, 0,
            "a nonzero threshold mutes every source at or above it, which is a different policy than this one"
        );
    }

    #[test]
    fn idc_windows_are_one_stride_apart_per_hart() {
        let base = 0xd00_0000;
        assert_eq!(idc_register(base, 0, super::IDC_CLAIMI), base + 0x401c);
        assert_eq!(idc_register(base, 1, super::IDC_CLAIMI), base + 0x403c);
        assert_eq!(idc_register(base, 2, super::IDC_IDELIVERY), base + 0x4040);
        assert_eq!(idc_register(base, 3, super::IDC_ITHRESHOLD), base + 0x4068);
    }
}
