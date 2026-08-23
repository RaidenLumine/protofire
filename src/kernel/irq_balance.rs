//! src/kernel/irq_balance.rs
//! SMP interrupt load balancing.
//!
//! Periodically migrates the highest-volume migratable IRQ from the busiest
//! CPU to the idlest CPU.  Migration is performed by the architecture's
//! interrupt controller (IOAPIC redirection re-target, GIC SPI affinity,
//! PLIC per-context enable bits) through the [`crate::arch::irq_balance`]
//! dispatchers.
//!
//! The policy is deliberately conservative: it only acts on a clear
//! imbalance (busiest > idlest + a margin), only migrates IRQs the
//! architecture reports as re-routable, and honours software pins.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::irq_stats;
use super::irq_stats::MAX_IRQ_VECTORS;

/// How often `maybe_rebalance` runs, in scheduler ticks (200 ticks at 100 Hz
/// = every 2 seconds).
pub const REBALANCE_INTERVAL_TICKS: u64 = 200;

/// A busiest CPU must exceed the idlest CPU's IRQ count by at least this
/// many deliveries before a migration is attempted.
const MIN_IMBALANCE: u64 = 8;

static ENABLED: AtomicBool = AtomicBool::new(true);
static MIGRATIONS: AtomicU64 = AtomicU64::new(0);
static LAST_TARGET: AtomicU32 = AtomicU32::new(0);

/// Current destination CPU for each vector.  Most controllers default to
/// targeting CPU 0 (or broadcast), so the initial value mirrors that.
static DESTINATION: [AtomicU8; MAX_IRQ_VECTORS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const CPU0: AtomicU8 = AtomicU8::new(0);
    [CPU0; MAX_IRQ_VECTORS]
};

/// Vectors the policy refuses to migrate regardless of architecture
/// constraints (a software pin, e.g. keep a device on the BSP).
static PINNED: [AtomicBool; MAX_IRQ_VECTORS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const FALSE: AtomicBool = AtomicBool::new(false);
    [FALSE; MAX_IRQ_VECTORS]
};

/// Whether the load balancer is active.
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Enable or disable the load balancer.
pub fn set_enabled(value: bool) {
    ENABLED.store(value, Ordering::Release);
}

/// Number of IRQ migrations performed so far.
pub fn migrations() -> u64 {
    MIGRATIONS.load(Ordering::Relaxed)
}

/// CPU id of the most recent migration target.
pub fn last_target_cpu() -> u32 {
    LAST_TARGET.load(Ordering::Relaxed)
}

/// Mark `vector` as non-migratable by policy.
pub fn pin_irq(vector: u32) {
    if let Some(slot) = PINNED.get(vector as usize) {
        slot.store(true, Ordering::Release);
    }
}

/// Pure decision core — testable without hardware.
///
/// Returns `(vector, target_cpu)` to migrate, or `None` when the system is
/// single-CPU, balanced, or has no migratable IRQ on the busiest CPU.
fn choose_migration(
    cpu_count: u32,
    irq_total: impl Fn(u32) -> u64,
    irq_count: impl Fn(u32, u32) -> u64,
    is_candidate: impl Fn(u32) -> bool,
) -> Option<(u32, u32)> {
    if cpu_count <= 1 {
        return None;
    }

    let mut busiest = 0u32;
    let mut busiest_load = 0u64;
    let mut idlest = 0u32;
    let mut idlest_load = u64::MAX;
    for cpu in 0..cpu_count {
        let load = irq_total(cpu);
        if load > busiest_load {
            busiest = cpu;
            busiest_load = load;
        }
        if load < idlest_load {
            idlest = cpu;
            idlest_load = load;
        }
    }

    if busiest == idlest || busiest_load < idlest_load.saturating_add(MIN_IMBALANCE) {
        return None;
    }

    let mut best: Option<(u32, u64)> = None;
    for vector in 0..MAX_IRQ_VECTORS as u32 {
        if PINNED[vector as usize].load(Ordering::Acquire) || !is_candidate(vector) {
            continue;
        }
        let count = irq_count(busiest, vector);
        if count > 0 && best.is_none_or(|(_, best_count)| count > best_count) {
            best = Some((vector, count));
        }
    }

    best.map(|(vector, _)| (vector, idlest))
}

/// Attempt one IRQ migration if the per-CPU IRQ load is imbalanced.
///
/// Called periodically from the scheduler tick.
pub fn maybe_rebalance() {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }

    let Some((vector, target)) = choose_migration(
        crate::arch::cpu_count(),
        irq_stats::irq_total_for_cpu,
        irq_stats::irq_count_for_cpu,
        crate::arch::irq_balance::is_routable,
    ) else {
        return;
    };

    // Skip if the vector is already recorded as targeting the idlest CPU.
    if DESTINATION[vector as usize].load(Ordering::Acquire) as u32 == target {
        return;
    }

    if crate::arch::irq_balance::set_destination(vector, target).is_ok() {
        DESTINATION[vector as usize].store(target as u8, Ordering::Release);
        MIGRATIONS.fetch_add(1, Ordering::Relaxed);
        LAST_TARGET.store(target, Ordering::Relaxed);
        crate::println!(
            "[irqbal] irq {} -> cpu{} ({} migrations)",
            vector,
            target,
            MIGRATIONS.load(Ordering::Relaxed)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::irq_stats::MAX_CPUS;
    use super::*;

    /// Synthetic per-CPU / per-vector table for the pure decision core.
    struct Table {
        totals: [u64; MAX_CPUS],
        counts: [[u64; MAX_IRQ_VECTORS]; MAX_CPUS],
    }

    impl Table {
        fn total(&self, cpu: u32) -> u64 {
            self.totals[cpu as usize]
        }
        fn count(&self, cpu: u32, vector: u32) -> u64 {
            self.counts[cpu as usize][vector as usize]
        }
    }

    fn table_with_busy_cpu0() -> Table {
        let mut totals = [0u64; MAX_CPUS];
        totals[0] = 100;
        totals[1] = 10;
        let mut counts = [[0u64; MAX_IRQ_VECTORS]; MAX_CPUS];
        counts[0][33] = 90; // keyboard storm on CPU 0
        counts[1][33] = 0;
        Table { totals, counts }
    }

    #[test]
    fn single_cpu_never_migrates() {
        let _guard = irq_stats::test_lock();
        let t = table_with_busy_cpu0();
        assert!(choose_migration(1, |c| t.total(c), |c, v| t.count(c, v), |_| true).is_none());
    }

    #[test]
    fn balanced_system_never_migrates() {
        let _guard = irq_stats::test_lock();
        let t = Table {
            totals: [50, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            counts: [[0u64; MAX_IRQ_VECTORS]; MAX_CPUS],
        };
        assert!(choose_migration(2, |c| t.total(c), |c, v| t.count(c, v), |_| true).is_none());
    }

    #[test]
    fn imbalance_migrates_hottest_irq_to_idlest_cpu() {
        let _guard = irq_stats::test_lock();
        let t = table_with_busy_cpu0();
        let (vector, target) = choose_migration(2, |c| t.total(c), |c, v| t.count(c, v), |_| true)
            .expect("imbalance should yield a migration");
        assert_eq!(vector, 33);
        assert_eq!(target, 1);
    }

    #[test]
    fn non_routable_irq_is_skipped() {
        let _guard = irq_stats::test_lock();
        let t = table_with_busy_cpu0();
        // Vector 33 is the only hot IRQ; if it is not routable, nothing moves.
        assert!(choose_migration(2, |c| t.total(c), |c, v| t.count(c, v), |v| v != 33).is_none());
    }

    #[test]
    fn small_imbalance_is_ignored() {
        let _guard = irq_stats::test_lock();
        let t = Table {
            totals: [20, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            counts: [[0u64; MAX_IRQ_VECTORS]; MAX_CPUS],
        };
        // 20 vs 15 is below MIN_IMBALANCE=8 → no migration.
        assert!(choose_migration(2, |c| t.total(c), |c, v| t.count(c, v), |_| true).is_none());
    }
}
