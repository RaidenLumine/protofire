//! src/kernel/perf_baseline.rs
//!
//! One line of measured work from a boot, behind the `perf_baseline` feature.
//!
//! **Counters, not seconds.**  A wall-clock number from a shared machine is
//! noise, and a gate that fails on noise is a gate someone switches off.  Every
//! number here counts something the kernel *did* — frames taken, pages mapped,
//! blocks read, packets received — so the same boot produces the same line, and
//! a change to it is a change in work rather than in how busy the host was.
//! That is the measurement a performance change should be judged against: the
//! question "did this do less work" has an answer here, and "was this faster on
//! someone's laptop" does not.
//!
//! It is printed once, at a fixed tick, by the maintenance thread — late enough
//! that the demo's services and network stack have run, early enough that a
//! check does not wait for them to stop.  `make check-perf-baseline` boots with
//! the profiler features on and compares the line against
//! `scripts/perf-baseline.txt`.
//!
//! Without the feature this module costs a function call that returns: the
//! counters the profilers keep are no-ops in a default build, so there is
//! nothing to read and nothing to print.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

/// The tick the summary is taken at: five seconds into a hundred-hertz boot.
pub const PERF_BASELINE_TICK: u64 = 500;

static LOGGED: AtomicBool = AtomicBool::new(false);

/// Print the boot's work once, if the boot has reached [`PERF_BASELINE_TICK`].
///
/// Called from the maintenance thread, which is ordinary thread context: every
/// snapshot below takes a lock, and taking one from an interrupt handler would
/// be the mistake this module's caller exists to avoid elsewhere.
pub(crate) fn log_once(ticks: u64) {
    if ticks < PERF_BASELINE_TICK || LOGGED.swap(true, Ordering::AcqRel) {
        return;
    }

    let alloc = crate::memory::global_mut()
        .map(|memory| memory.alloc_profiler_snapshot())
        .unwrap_or_default();
    let faults = crate::memory::global_mut()
        .map(|memory| memory.fault_profiler_snapshot())
        .unwrap_or_default();
    let fs = crate::fs::global()
        .map(|fs| fs.lock().fs_profiler_snapshot())
        .unwrap_or_default();
    let net = crate::network::stack::NetworkStack::global()
        .map(|stack| stack.profiler_snapshot())
        .unwrap_or_default();

    crate::println!(
        "[perf  ] boot work: ticks={} frames={} frame-frees={} frame-zero-bytes={} \
         heap-allocs={} heap-bytes={} pt-maps={} pt-lookups={} faults={} \
         fs-lookups={} fs-reads={} fs-read-bytes={} fs-writes={} fs-write-bytes={} \
         fs-transactions={} \
         ip4-rx={} ip4-tx={} ip6-rx={} ip6-tx={} \
         irqs={} ipis={} spurious={}",
        ticks,
        alloc.frame_allocs,
        alloc.frame_frees,
        alloc.frame_zero_bytes,
        alloc.heap_allocs,
        alloc.heap_bytes_allocated,
        alloc.page_table_maps,
        alloc.page_table_lookups,
        faults.faults_total,
        fs.lookups,
        fs.reads,
        fs.read_bytes,
        fs.writes,
        fs.write_bytes,
        fs.transactions,
        net.ipv4_packets_rx,
        net.ipv4_packets_tx,
        net.ipv6_packets_rx,
        net.ipv6_packets_tx,
        crate::kernel::irq_stats::total_irqs(),
        crate::kernel::irq_stats::total_ipis(),
        crate::kernel::irq_stats::total_spurious(),
    );
}
