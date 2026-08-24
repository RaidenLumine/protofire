//! src/arch/aarch64/irq_balance.rs
//!
//! AArch64 interrupt load-balancing: GIC SPI re-targeting.
//!
//! Shared peripheral interrupts (SPIs, interrupt ids 32..1020) can be
//! re-routed between CPUs via GICD_IROUTER (GICv3) or GICD_ITARGETSR
//! (GICv2).  SGIs, PPIs (per-CPU, e.g. the generic timer), and LPIs
//! (MSI, routed through the ITS) are not migratable this way.

/// SPIs (interrupt ids 32..1020) can be re-routed between CPUs.  SGIs and
/// PPIs (< 32) are per-CPU by design and LPIs (>= 8192) use ITS routing.
pub fn is_routable(vector: u32) -> bool {
    (32..1020).contains(&vector)
}

/// Re-target `vector` (a GIC SPI id) to `cpu_id`.
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
    fn spis_are_routable_but_sgis_ppis_are_not() {
        assert!(is_routable(32));
        assert!(is_routable(33));
        assert!(is_routable(1019));
        assert!(!is_routable(0)); // SGI
        assert!(!is_routable(16)); // PPI
        assert!(!is_routable(30)); // generic timer PPI
        assert!(!is_routable(1020));
    }

    #[test]
    fn set_destination_rejects_non_spi() {
        assert_eq!(set_destination(30, 1), Err(crate::Error::NotFound));
    }
}
