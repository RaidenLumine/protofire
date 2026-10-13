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
//! where no IMSIC receives messages — is not driven here: direct mode claims
//! through the domain's own `topi`/`claimi` registers, a different delivery
//! path, and the console UART keeps the tick's poll there
//! ([`super::serial::enable_rx_interrupt`] reports and returns).

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
