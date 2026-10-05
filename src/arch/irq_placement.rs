//! src/arch/irq_placement.rs
//!
//! Which CPU a message-signalled interrupt's entry is delivered to.
//!
//! Every architecture answers the same question with different words for
//! "which CPU" — an AArch64 LPI names a collection, a RISC-V message names a
//! hart's IMSIC file, an x86_64 message names a local APIC — and the policy
//! that picks the answer is not architecture-specific at all.  It is one line,
//! and it lives beside [`crate::arch::irq_handlers`] because the interesting
//! part is what it must *not* do: hand every entry of a device to the boot CPU.
//!
//! The policy is round-robin over the CPUs that can receive an interrupt.  For
//! a device with several queues that is the property worth buying: its queues
//! are placed on different cores instead of all on the one that also runs the
//! scheduler tick.  "Least loaded" was the alternative and loses because
//! placement happens when a driver claims a device — before it has any load to
//! read — and because a placement that depends on a moving number makes the
//! boot's work depend on the boot's timing.

/// The slot, among `capable` CPUs that can receive an interrupt, that the
/// device entry at `index` is delivered to.
///
/// `None` when nothing can receive one, which is the honest answer on a
/// machine whose interrupt controller never came up: the caller keeps the
/// device on its polling path rather than naming a reader that is not there.
///
/// The function is pure so that the policy can be tested without a machine;
/// turning a slot into a CPU id is the architecture's half.
// Only the two architectures whose MSI-X tables this kernel programs place
// entries through this: AArch64 through the ITS and RISC-V through the IMSIC.
// x86_64 composes its destination into the device's own message and does not
// program a table yet, so the item is unused there rather than dead — see
// RFC 0001, which leaves that architecture out on purpose.
#[cfg_attr(
    not(any(target_arch = "aarch64", target_arch = "riscv64")),
    allow(dead_code)
)]
pub(crate) fn place_entry(index: u32, capable: u32) -> Option<u32> {
    if capable == 0 {
        None
    } else {
        Some(index % capable)
    }
}

#[cfg(test)]
mod tests {
    use super::place_entry;

    #[test]
    fn no_capable_cpu_has_no_placement() {
        assert_eq!(place_entry(0, 0), None);
        assert_eq!(place_entry(7, 0), None);
    }

    #[test]
    fn one_capable_cpu_takes_every_entry() {
        assert_eq!(place_entry(0, 1), Some(0));
        assert_eq!(place_entry(1, 1), Some(0));
        assert_eq!(place_entry(9, 1), Some(0));
    }

    #[test]
    fn entries_spread_over_the_capable_cpus_in_order() {
        assert_eq!(place_entry(0, 4), Some(0));
        assert_eq!(place_entry(1, 4), Some(1));
        assert_eq!(place_entry(2, 4), Some(2));
        assert_eq!(place_entry(3, 4), Some(3));
        // The fifth entry wraps: a device with more queues than CPUs reuses
        // them in the same order.
        assert_eq!(place_entry(4, 4), Some(0));
    }

    #[test]
    fn a_device_with_fewer_entries_than_cpus_uses_the_first_ones() {
        // Two queues, four CPUs: the queues land on the first two cores and
        // the others keep whatever they were doing.
        assert_eq!(place_entry(0, 4), Some(0));
        assert_eq!(place_entry(1, 4), Some(1));
    }
}
