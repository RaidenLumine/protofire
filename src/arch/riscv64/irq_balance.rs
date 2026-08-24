//! src/arch/riscv64/irq_balance.rs
//!
//! RISC-V interrupt load-balancing: PLIC source re-targeting.
//!
//! PLIC external sources can be routed to any hart by programming the
//! per-context enable bits — the PLIC only forwards an interrupt to a
//! context that has it enabled.  Timer and software (IPI) interrupts are
//! per-hart and never migratable.

/// Highest PLIC interrupt id considered routable (matches the controller's
/// `PLIC_MAX_INTERRUPT_ID` cap of 128).
const PLIC_MAX_INTERRUPT_ID: u32 = 128;

/// PLIC external sources (1..=127) can be routed to any hart.
pub fn is_routable(vector: u32) -> bool {
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
