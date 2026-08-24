//! src/arch/x86_64/irq_balance.rs
//!
//! x86_64 interrupt load-balancing: IOAPIC redirection re-targeting.
//!
//! Only interrupts that flow through an IOAPIC redirection entry are
//! migratable — the LAPIC timer, IPIs, and MSI-X vectors are not.  The PIT
//! timer (IOAPIC pin 0) is deliberately excluded: it is the sole x86_64
//! scheduler-tick source and must stay on the BSP.

use core::sync::atomic::{AtomicI8, Ordering};

use crate::util::sync_unsafe_cell::SyncUnsafeCell;

/// Maximum number of logical CPUs (matches the scheduler's 16-CPU cap).
pub const MAX_CPUS: usize = 16;

/// Maps an interrupt vector to its IOAPIC redirection pin, or -1 when the
/// vector is not IOAPIC-routed (and therefore not migratable).
static VECTOR_TO_PIN: [AtomicI8; 256] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const UNMAPPED: AtomicI8 = AtomicI8::new(-1);
    [UNMAPPED; 256]
};

/// Logical CPU ID → LAPIC ID, used to rewrite IOAPIC destination fields.
static CPU_LAPIC_IDS: SyncUnsafeCell<[u8; MAX_CPUS]> = SyncUnsafeCell::new([0; MAX_CPUS]);

/// Record the LAPIC ID for a logical CPU so IOAPIC pins can be re-targeted
/// to it.
///
/// Only bare-metal x86_64 smp bring-up calls this; on other targets it is
/// intentionally unused (dead-code allowed).
#[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
pub(crate) fn register_cpu(cpu_id: u32, lapic_id: u8) {
    if let Some(slot) = (unsafe { &mut *CPU_LAPIC_IDS.get() }).get_mut(cpu_id as usize) {
        *slot = lapic_id;
    }
}

/// Remember that `vector` is delivered through IOAPIC redirection pin `pin`.
///
/// Called from [`super::ioapic::ioapic_route_irq`].  Pin 0 (the PIT timer)
/// is deliberately not recorded so the timer is never migrated.
///
/// Not yet wired into the IRQ delivery path on any target, so it is
/// intentionally unused (dead-code allowed).
#[allow(dead_code)]
pub(crate) fn register_vector_pin(vector: u8, pin: u8) {
    if pin == 0 {
        return;
    }
    if let Some(slot) = VECTOR_TO_PIN.get(vector as usize) {
        slot.store(pin as i8, Ordering::Release);
    }
}

/// Whether `vector` is an IOAPIC-routed interrupt eligible for migration.
pub fn is_routable(vector: u32) -> bool {
    VECTOR_TO_PIN
        .get(vector as usize)
        .is_some_and(|slot| slot.load(Ordering::Acquire) >= 0)
}

/// Re-target `vector` to `cpu_id` by rewriting its IOAPIC redirection entry.
pub fn set_destination(vector: u32, cpu_id: u32) -> crate::Result<()> {
    let pin = match VECTOR_TO_PIN.get(vector as usize) {
        Some(slot) if slot.load(Ordering::Acquire) >= 0 => slot.load(Ordering::Acquire) as u8,
        _ => return Err(crate::Error::NotFound),
    };
    let lapic_id = match (unsafe { &*CPU_LAPIC_IDS.get() }).get(cpu_id as usize) {
        Some(id) => *id,
        None => return Err(crate::Error::InvalidArgument),
    };
    super::ioapic::ioapic_set_irq_destination(pin, lapic_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests mutate the process-global `VECTOR_TO_PIN` table, so they
    /// serialise on the shared counter test lock.
    fn test_lock() -> crate::kernel::sync::MutexGuard<'static, ()> {
        crate::kernel::irq_stats::test_lock()
    }

    #[test]
    fn unmapped_vector_is_not_routable() {
        let _guard = test_lock();
        VECTOR_TO_PIN
            .iter()
            .for_each(|slot| slot.store(-1, Ordering::Release));
        assert!(!is_routable(32));
        assert!(!is_routable(33));
    }

    #[test]
    fn registered_pin_is_routable_but_pin_zero_is_not() {
        let _guard = test_lock();
        VECTOR_TO_PIN
            .iter()
            .for_each(|slot| slot.store(-1, Ordering::Release));
        register_vector_pin(33, 1);
        assert!(is_routable(33));
        // Pin 0 (PIT timer) is never registered.
        register_vector_pin(32, 0);
        assert!(!is_routable(32));
    }

    #[test]
    fn set_destination_rejects_unmapped_vector() {
        let _guard = test_lock();
        VECTOR_TO_PIN
            .iter()
            .for_each(|slot| slot.store(-1, Ordering::Release));
        assert_eq!(set_destination(40, 0), Err(crate::Error::NotFound));
    }

    #[test]
    fn set_destination_rejects_unknown_cpu() {
        let _guard = test_lock();
        VECTOR_TO_PIN
            .iter()
            .for_each(|slot| slot.store(-1, Ordering::Release));
        register_vector_pin(33, 1);
        assert_eq!(set_destination(33, 200), Err(crate::Error::InvalidArgument));
    }
}
