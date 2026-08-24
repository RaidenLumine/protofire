//! src/kernel/irq_stats.rs
//!
//! Per-CPU, per-vector interrupt accounting and the IRQ profiler snapshot.
//!
//! Every architecture's IRQ entry path records deliveries here:
//! - normal interrupts (`record_irq`, keyed by the vector / controller id)
//! - inter-processor interrupts (`record_ipi`)
//! - NMI-class entries (`record_nmi` — x86_64 NMI, AArch64 SError/FIQ)
//! - spurious / unmatched vectors (`record_spurious`)
//!
//! The same counters feed both the userspace profiler snapshot
//! ([`snapshot`]) and the SMP IRQ load balancer's per-CPU load estimates.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi::diagnostic::IrqProfilerRecord;

/// Maximum number of CPUs the stats tables cover (matches the scheduler's
/// 16-CPU cap).
pub const MAX_CPUS: usize = 16;
/// Number of interrupt vectors tracked per CPU.
pub const MAX_IRQ_VECTORS: usize = 256;

#[allow(clippy::declare_interior_mutable_const)]
const ZERO_U64: AtomicU64 = AtomicU64::new(0);

/// Interrupt deliveries per CPU per vector.
///
/// Each cell is written by the owning CPU's IRQ entry path and read by the
/// diagnostic and load-balance paths.  `Relaxed` atomics are sufficient:
/// no ordering guarantee is required for counters.
static IRQ_COUNTS: [[AtomicU64; MAX_IRQ_VECTORS]; MAX_CPUS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ROW: [AtomicU64; MAX_IRQ_VECTORS] = [ZERO_U64; MAX_IRQ_VECTORS];
    [ROW; MAX_CPUS]
};

/// IPI deliveries per CPU (reschedule + TLB shootdown combined).
static IPI_COUNTS: [AtomicU64; MAX_CPUS] = [ZERO_U64; MAX_CPUS];
/// NMI / SError / FIQ deliveries per CPU.
static NMI_COUNTS: [AtomicU64; MAX_CPUS] = [ZERO_U64; MAX_CPUS];
/// Spurious (unmatched-vector) interrupts per CPU.
static SPURIOUS_COUNTS: [AtomicU64; MAX_CPUS] = [ZERO_U64; MAX_CPUS];

#[inline]
fn current_cpu() -> u32 {
    crate::kernel::percpu::get().cpu_id
}

/// Record that `vector` was delivered on the current CPU.
#[inline]
pub fn record_irq(vector: u32) {
    let cpu = current_cpu() as usize;
    if let Some(row) = IRQ_COUNTS.get(cpu) {
        if let Some(cell) = row.get(vector as usize) {
            cell.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Record an inter-processor interrupt on the current CPU.
#[inline]
pub fn record_ipi() {
    let cpu = current_cpu() as usize;
    if let Some(cell) = IPI_COUNTS.get(cpu) {
        cell.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a non-maskable interrupt (NMI / SError / FIQ) on the current CPU.
#[inline]
pub fn record_nmi() {
    let cpu = current_cpu() as usize;
    if let Some(cell) = NMI_COUNTS.get(cpu) {
        cell.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a spurious (unmatched) interrupt on the current CPU.
#[inline]
pub fn record_spurious() {
    let cpu = current_cpu() as usize;
    if let Some(cell) = SPURIOUS_COUNTS.get(cpu) {
        cell.fetch_add(1, Ordering::Relaxed);
    }
}

// ── Queries (used by the load balancer and the profiler snapshot) ────────

/// Total IRQ deliveries on `cpu` (sum over all vectors).
pub fn irq_total_for_cpu(cpu: u32) -> u64 {
    let mut total: u64 = 0;
    if let Some(row) = IRQ_COUNTS.get(cpu as usize) {
        for cell in row {
            total = total.saturating_add(cell.load(Ordering::Relaxed));
        }
    }
    total
}

/// Deliveries of `vector` on `cpu`.
pub fn irq_count_for_cpu(cpu: u32, vector: u32) -> u64 {
    IRQ_COUNTS
        .get(cpu as usize)
        .and_then(|row| row.get(vector as usize))
        .map_or(0, |cell| cell.load(Ordering::Relaxed))
}

/// Deliveries of `vector` across all CPUs.
pub fn irq_count_total(vector: u32) -> u64 {
    let mut total: u64 = 0;
    for cpu in 0..MAX_CPUS {
        total = total.saturating_add(irq_count_for_cpu(cpu as u32, vector));
    }
    total
}

/// Total IRQ deliveries across all CPUs.
pub fn total_irqs() -> u64 {
    let mut total: u64 = 0;
    for cpu in 0..MAX_CPUS as u32 {
        total = total.saturating_add(irq_total_for_cpu(cpu));
    }
    total
}

/// IPI deliveries on `cpu`.
pub fn ipi_total_for_cpu(cpu: u32) -> u64 {
    IPI_COUNTS
        .get(cpu as usize)
        .map_or(0, |cell| cell.load(Ordering::Relaxed))
}

/// NMI-class deliveries on `cpu`.
pub fn nmi_total_for_cpu(cpu: u32) -> u64 {
    NMI_COUNTS
        .get(cpu as usize)
        .map_or(0, |cell| cell.load(Ordering::Relaxed))
}

/// Spurious deliveries on `cpu`.
pub fn spurious_total_for_cpu(cpu: u32) -> u64 {
    SPURIOUS_COUNTS
        .get(cpu as usize)
        .map_or(0, |cell| cell.load(Ordering::Relaxed))
}

/// Total IPI deliveries across all CPUs.
pub fn total_ipis() -> u64 {
    let mut total: u64 = 0;
    for cell in &IPI_COUNTS {
        total = total.saturating_add(cell.load(Ordering::Relaxed));
    }
    total
}

/// Total NMI-class deliveries across all CPUs.
pub fn total_nmis() -> u64 {
    let mut total: u64 = 0;
    for cell in &NMI_COUNTS {
        total = total.saturating_add(cell.load(Ordering::Relaxed));
    }
    total
}

/// Total spurious deliveries across all CPUs.
pub fn total_spurious() -> u64 {
    let mut total: u64 = 0;
    for cell in &SPURIOUS_COUNTS {
        total = total.saturating_add(cell.load(Ordering::Relaxed));
    }
    total
}

/// Build a full ABI snapshot of the interrupt counters.
///
/// The load-balancer fields (enabled / migrations / last target) and the
/// online-CPU count are filled in by the caller (the diagnostic handler),
/// keeping this module free of a dependency on [`super::irq_balance`].
pub fn snapshot() -> IrqProfilerRecord {
    let mut record = IrqProfilerRecord {
        total_irqs: total_irqs(),
        total_ipis: total_ipis(),
        total_nmis: total_nmis(),
        spurious_interrupts: total_spurious(),
        ..IrqProfilerRecord::default()
    };

    for (cpu, row) in IRQ_COUNTS.iter().enumerate() {
        let mut cpu_total = 0u64;
        for (vector, cell) in row.iter().enumerate() {
            let count = cell.load(Ordering::Relaxed);
            if let Some(slot) = record.irq_counts.get_mut(vector) {
                *slot = slot.saturating_add(count);
            }
            cpu_total = cpu_total.saturating_add(count);
        }
        if let Some(slot) = record.per_cpu_irqs.get_mut(cpu) {
            *slot = cpu_total;
        }
        if let Some(slot) = record.per_cpu_ipis.get_mut(cpu) {
            *slot = IPI_COUNTS[cpu].load(Ordering::Relaxed);
        }
        if let Some(slot) = record.per_cpu_nmis.get_mut(cpu) {
            *slot = NMI_COUNTS[cpu].load(Ordering::Relaxed);
        }
    }
    record
}

// ── Tests ────────────────────────────────────────────────────────────────

/// Serialise counter-mutating tests: the counters are process-global, so
/// parallel test threads would otherwise race on the shared cells.
#[cfg(test)]
pub(crate) fn test_lock() -> crate::kernel::sync::MutexGuard<'static, ()> {
    static LOCK: crate::kernel::sync::Mutex<()> = crate::kernel::sync::Mutex::new(());
    LOCK.lock()
}

/// Zero every counter (test-only, under [`test_lock`]).
#[cfg(test)]
pub(crate) fn reset_for_test() {
    for row in IRQ_COUNTS.iter() {
        for cell in row {
            cell.store(0, Ordering::Relaxed);
        }
    }
    for cell in &IPI_COUNTS {
        cell.store(0, Ordering::Relaxed);
    }
    for cell in &NMI_COUNTS {
        cell.store(0, Ordering::Relaxed);
    }
    for cell in &SPURIOUS_COUNTS {
        cell.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_query_irq_counters() {
        let _guard = test_lock();
        reset_for_test();
        record_irq(32);
        record_irq(32);
        record_irq(33);
        assert_eq!(irq_count_for_cpu(0, 32), 2);
        assert_eq!(irq_count_for_cpu(0, 33), 1);
        assert_eq!(irq_total_for_cpu(0), 3);
        assert_eq!(irq_count_total(32), 2);
        assert_eq!(total_irqs(), 3);
    }

    #[test]
    fn record_ipi_nmi_and_spurious() {
        let _guard = test_lock();
        reset_for_test();
        record_ipi();
        record_nmi();
        record_spurious();
        assert_eq!(ipi_total_for_cpu(0), 1);
        assert_eq!(nmi_total_for_cpu(0), 1);
        assert_eq!(spurious_total_for_cpu(0), 1);
        assert_eq!(total_ipis(), 1);
        assert_eq!(total_nmis(), 1);
        assert_eq!(total_spurious(), 1);
    }

    #[test]
    fn snapshot_aggregates_per_cpu_and_per_vector_counts() {
        let _guard = test_lock();
        reset_for_test();
        record_irq(30);
        record_irq(30);
        record_irq(9);
        record_ipi();
        record_nmi();

        let snap = snapshot();
        assert_eq!(snap.irq_counts[30], 2);
        assert_eq!(snap.irq_counts[9], 1);
        assert_eq!(snap.per_cpu_irqs[0], 3);
        assert_eq!(snap.per_cpu_ipis[0], 1);
        assert_eq!(snap.per_cpu_nmis[0], 1);
        assert_eq!(snap.total_irqs, 3);
        assert_eq!(snap.total_ipis, 1);
        assert_eq!(snap.total_nmis, 1);
        // Load-balancer fields are filled by the caller.
        assert_eq!(snap.irq_balance_enabled, 0);
        assert_eq!(snap.online_cpus, 0);
    }
}
