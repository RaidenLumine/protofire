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

/// The tick the cycle counter is first sampled at, so the sample tick has an
/// interval to calibrate with.  It is a fraction of the way up on purpose:
/// late enough that the early boot's one-off work is behind it, early enough
/// that the interval is hundreds of ticks long.
const CALIBRATION_TICK: u64 = PERF_BASELINE_TICK / 8;

static EARLY_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static EARLY_TICK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Watch the tick: sample the cycle counter once early, then calibrate it
/// across the interval to the sample tick.
///
/// The workload reports a duration, and a duration needs a rate; the rate is
/// measured across ticks rather than assumed, and this is the measurement.
/// The first calibration wins (see
/// [`crate::arch::timer::record_cycles_per_tick`]), so a boot that also
/// measures lock timing keeps whichever interval was longest rather than
/// whichever ran last.
pub(crate) fn observe_tick(ticks: u64) {
    if ticks < CALIBRATION_TICK {
        return;
    }
    if EARLY_TICK.load(Ordering::Relaxed) == 0 {
        EARLY_CYCLES.store(crate::arch::timer::monotonic_cycles(), Ordering::Relaxed);
        EARLY_TICK.store(ticks, Ordering::Relaxed);
        return;
    }
    if ticks < PERF_BASELINE_TICK {
        return;
    }
    let early = EARLY_TICK.load(Ordering::Relaxed);
    let cycles =
        crate::arch::timer::monotonic_cycles().wrapping_sub(EARLY_CYCLES.load(Ordering::Relaxed));
    crate::arch::timer::record_cycles_per_tick(cycles, ticks - early);
}

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
    let cache = crate::fs::global()
        .map(|fs| fs.lock().cache_stats())
        .unwrap_or_default();
    let device = crate::kernel::block::device_io_snapshot();
    let workload = crate::kernel::workload::last();

    crate::println!(
        "[perf  ] boot work: ticks={} frames={} frame-frees={} frame-zero-bytes={} \
         heap-allocs={} heap-bytes={} pt-maps={} pt-lookups={} faults={} \
         fs-lookups={} fs-reads={} fs-read-bytes={} fs-writes={} fs-write-bytes={} \
         fs-transactions={} \
         cache-hits={} cache-misses={} cache-prefetches={} cache-sequential-hits={} \
         cache-evictions={} \
         blk-reads={} blk-read-bytes={} blk-writes={} blk-write-bytes={} \
         blk-in-flight-high-water={} \
         wl-files={} wl-bytes={} wl-fs-reads={} wl-fs-read-bytes={} \
         wl-fs-writes={} wl-fs-write-bytes={} wl-fs-transactions={} \
         wl-cache-hits={} wl-cache-misses={} \
         wl-blk-reads={} wl-blk-read-bytes={} wl-blk-writes={} wl-blk-write-bytes={} \
         wl-device-bytes-per-asked-byte={} \
         nw-datagrams-tx={} nw-datagrams-rx={} nw-bytes={} nw-polls={} \
         nw-completed={} \
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
        cache.hits,
        cache.misses,
        cache.prefetches_issued,
        cache.sequential_hits,
        cache.evictions,
        device.read_ops,
        device.read_bytes,
        device.write_ops,
        device.write_bytes,
        device.in_flight_high_water,
        workload.files,
        workload.bytes,
        workload.fs_reads,
        workload.fs_read_bytes,
        workload.fs_writes,
        workload.fs_write_bytes,
        workload.fs_transactions,
        workload.cache_hits,
        workload.cache_misses,
        workload.blk_reads,
        workload.blk_read_bytes,
        workload.blk_writes,
        workload.blk_write_bytes,
        workload.device_bytes_per_asked_byte(),
        workload.net_datagrams_tx,
        workload.net_datagrams_rx,
        workload.net_bytes,
        workload.net_polls,
        workload.net_completed,
        net.ipv4_packets_rx,
        net.ipv4_packets_tx,
        net.ipv6_packets_rx,
        net.ipv6_packets_tx,
        crate::kernel::irq_stats::total_irqs(),
        crate::kernel::irq_stats::total_ipis(),
        crate::kernel::irq_stats::total_spurious(),
    );

    // The workload's own duration, on a line no gate compares: a gate that
    // measures a duration measures the machine it ran on, and every gate in
    // this tree compares counters instead.  What this is for is the question a
    // counter raises and cannot answer — "why is this number what it is?" —
    // and the rate it converts with is measured rather than assumed, so a
    // machine that could not calibrate one gets cycles alone.
    if workload.ran() {
        let ops = workload.ops.max(1);
        let cycles_per_op = workload.cycles / ops;
        match crate::arch::timer::cycles_per_second().filter(|rate| *rate > 0) {
            Some(rate) => {
                let nanoseconds_per_op =
                    (workload.cycles as u128 * 1_000_000_000) / (rate as u128 * ops as u128);
                crate::println!(
                    "[perf  ] workload time: cycles={} ops={} cycles-per-op={} ns-per-op={}",
                    workload.cycles,
                    workload.ops,
                    cycles_per_op,
                    nanoseconds_per_op,
                );
            }
            None => {
                crate::println!(
                    "[perf  ] workload time: cycles={} ops={} cycles-per-op={}",
                    workload.cycles,
                    workload.ops,
                    cycles_per_op,
                );
            }
        }
    }
}
