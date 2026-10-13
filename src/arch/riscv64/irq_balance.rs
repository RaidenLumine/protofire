//! src/arch/riscv64/irq_balance.rs
//!
//! RISC-V interrupt load-balancing: PLIC source re-targeting.
//!
//! PLIC external sources can be routed to any hart by programming the
//! per-context enable bits — the PLIC only forwards an interrupt to a
//! context that has it enabled.  Timer and software (IPI) interrupts are
//! per-hart and never migratable.
//!
//! An AIA machine has nothing this can move, and there are two kinds.  One
//! delivers through an IMSIC: its wire interrupts arrive as *messages*, the
//! destination is written where the message is composed — a device's MSI-X
//! table entry, or the APLIC's target register — and this machine's firmware
//! leaves the APLIC's message-address fields with no hart index bits at all,
//! so every message lands in hart 0's IMSIC file whatever a target says.
//! Answering "routable" there would send the balancer into the PLIC's
//! register addresses, which on an AIA machine are the **machine-level**
//! APLIC's window — firmware's domain, not this kernel's, and one whose
//! registers do not mean what a PLIC's do.  The other kind is an APLIC in
//! **direct mode**, which has no PLIC either and no IMSIC to receive a
//! message: the PLIC addresses there are backed by no device at all
//! (measured: a store access fault at `0xc201000`), so the answer is the
//! same.

/// Highest PLIC interrupt id considered routable (matches the controller's
/// `PLIC_MAX_INTERRUPT_ID` cap of 128).
const PLIC_MAX_INTERRUPT_ID: u32 = 128;

/// PLIC external sources (1..=127) can be routed to any hart.
pub fn is_routable(vector: u32) -> bool {
    if super::aia_imsic::has_aia_imsic() || super::aplic::is_direct_mode() {
        return false;
    }
    (1..PLIC_MAX_INTERRUPT_ID).contains(&vector)
}

/// Re-target `vector` (a PLIC source id) to `cpu_id`.
pub fn set_destination(vector: u32, cpu_id: u32) -> crate::Result<()> {
    if !is_routable(vector) {
        return Err(crate::Error::NotFound);
    }
    super::interrupt_controller::set_irq_affinity(vector, cpu_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plic_sources_are_routable_but_reserved_ids_are_not() {
        assert!(is_routable(1));
        assert!(is_routable(33));
        assert!(is_routable(127));
        assert!(!is_routable(0)); // no interrupt
        assert!(!is_routable(128));
    }

    #[test]
    fn set_destination_rejects_non_plic_source() {
        assert_eq!(set_destination(0, 1), Err(crate::Error::NotFound));
        assert_eq!(set_destination(128, 1), Err(crate::Error::NotFound));
    }
}
