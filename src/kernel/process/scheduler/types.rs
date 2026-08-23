//! src/kernel/process/scheduler/types.rs
//! Scheduler auxiliary types: hotspot statistics and timed-waiter entries.
use alloc::sync::Arc;

use crate::kernel::sync::WaitTimeoutCleanupRef;

use super::super::Thread;

// Baseline counters intentionally stay coarse-grained so performance work can
// compare scheduler behavior across targets without paying for heavy tracing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SchedulerHotspotStats {
    pub dispatch_count: u64,
    pub block_count: u64,
    pub timed_wait_registration_count: u64,
    pub signal_wake_count: u64,
    pub timeout_wake_count: u64,
    pub preempt_count: u64,
}

impl SchedulerHotspotStats {
    pub(crate) fn observe_dispatch(&mut self) {
        self.dispatch_count = self.dispatch_count.saturating_add(1);
    }

    pub(crate) fn observe_block(&mut self) {
        self.block_count = self.block_count.saturating_add(1);
    }

    pub(crate) fn observe_timed_wait_registration(&mut self) {
        self.timed_wait_registration_count = self.timed_wait_registration_count.saturating_add(1);
    }

    pub(crate) fn observe_signal_wake(&mut self) {
        self.signal_wake_count = self.signal_wake_count.saturating_add(1);
    }

    pub(crate) fn observe_timeout_wake(&mut self, woke: usize) {
        self.timeout_wake_count = self.timeout_wake_count.saturating_add(woke as u64);
    }

    pub(crate) fn observe_preempt(&mut self) {
        self.preempt_count = self.preempt_count.saturating_add(1);
    }
}

/// Aggregate scheduler statistics for monitoring and load averaging.
///
/// - `total_ticks` and `idle_ticks` are used to derive CPU utilisation.
/// - `total_context_switches` tracks overall scheduling overhead.
/// - `load_history` holds a 5-minute sliding window of CPU-busy samples
///   (0–1000, representing 0.0 % – 100.0 %) collected at 1 s resolution.
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    /// Total scheduler ticks since boot.
    pub total_ticks: u64,
    /// Total context switches since boot.
    pub total_context_switches: u64,
    /// Per-CPU idle ticks (max 16 CPUs).
    pub idle_ticks: [u64; 16],
    /// 5-minute load history at 1-second resolution: values 0–1000
    /// representing 0.0 % – 100.0 % CPU busy.
    pub load_history: [u16; 300],
    /// Number of valid entries in load_history (wraps at 300).
    load_history_entries: usize,
    /// Next slot to write in the load_history ring buffer.
    load_history_cursor: usize,
    /// Snapshot of `total_ticks` taken during the last load-average update.
    last_snapshot_total_ticks: u64,
    /// Snapshot of `sum(idle_ticks)` taken during the last load-average update.
    last_snapshot_idle_sum: u64,
}

impl Default for SchedulerStats {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerStats {
    /// Create a new `SchedulerStats` with all counters initialised to zero.
    pub fn new() -> Self {
        Self {
            total_ticks: 0,
            total_context_switches: 0,
            idle_ticks: [0; 16],
            load_history: [0; 300],
            load_history_entries: 0,
            load_history_cursor: 0,
            last_snapshot_total_ticks: 0,
            last_snapshot_idle_sum: 0,
        }
    }

    /// Record that the given CPU was idle during the current tick.
    ///
    /// # Parameters
    ///
    /// * `cpu_id` — the CPU index (0..15).  Indexes >= 16 are silently
    ///   ignored.
    pub fn record_idle_tick(&mut self, cpu_id: u32) {
        if let Some(slot) = self.idle_ticks.get_mut(cpu_id as usize) {
            *slot = slot.saturating_add(1);
        }
    }

    /// Record a context switch event (increments the counter by one).
    pub fn record_context_switch(&mut self) {
        self.total_context_switches = self.total_context_switches.saturating_add(1);
    }

    /// Compute the CPU-busy ratio since the last call and push it into the
    /// load-history ring buffer.  Must be called at 1 s intervals (100 ticks).
    pub fn compute_and_push_load(&mut self) {
        let total_idle: u64 = self.idle_ticks.iter().copied().sum();
        let delta_total = self.total_ticks - self.last_snapshot_total_ticks;
        let delta_idle = total_idle - self.last_snapshot_idle_sum;

        let load = if delta_total > 0 {
            let busy_ticks = delta_total.saturating_sub(delta_idle);
            // Scale busy ratio to 0–1000 (0.0 % – 100.0 %).
            (busy_ticks * 1000 / delta_total) as u16
        } else {
            0
        };

        self.load_history[self.load_history_cursor] = load.min(1000);
        self.load_history_cursor = (self.load_history_cursor + 1) % 300;
        if self.load_history_entries < 300 {
            self.load_history_entries += 1;
        }
        self.last_snapshot_total_ticks = self.total_ticks;
        self.last_snapshot_idle_sum = total_idle;
    }

    /// Number of valid entries in the load history (1..=300).
    fn load_history_len(&self) -> usize {
        self.load_history_entries
    }

    /// 1-minute load average (0–1000).  Returns 0 if no history yet.
    /// Return the 1-minute load average scaled to 0–1000
    /// (0.0 % – 100.0 % busy).
    ///
    /// Returns 0 if no history has been collected yet.
    pub fn load_average_1m(&self) -> u16 {
        let count = self.load_history_len();
        let entries = count.min(60);
        if entries == 0 {
            return 0;
        }
        let mut sum = 0u64;
        for i in 0..entries {
            let idx = (self.load_history_cursor + 300 - 1 - i) % 300;
            sum += self.load_history[idx] as u64;
        }
        (sum / entries as u64) as u16
    }

    /// 5-minute load average (0–1000).  Returns 0 if no history yet.
    /// Return the 5-minute load average scaled to 0–1000
    /// (0.0 % – 100.0 % busy).
    ///
    /// Returns 0 if no history has been collected yet.
    pub fn load_average_5m(&self) -> u16 {
        let count = self.load_history_len();
        if count == 0 {
            return 0;
        }
        let mut sum = 0u64;
        for i in 0..count {
            let idx = (self.load_history_cursor + 300 - 1 - i) % 300;
            sum += self.load_history[idx] as u64;
        }
        (sum / count as u64) as u16
    }

    /// Most recently recorded CPU-busy sample (0–1000, 0.0% – 100.0%).
    ///
    /// Unlike the 1-minute / 5-minute averages this returns the raw last
    /// sample, which is what the CPU-frequency governor wants for fast load
    /// tracking.  Returns 0 until the first sample has been collected.
    pub fn last_load_sample(&self) -> u16 {
        if self.load_history_entries == 0 {
            return 0;
        }
        let idx = (self.load_history_cursor + 300 - 1) % 300;
        self.load_history[idx]
    }
}

pub(crate) struct TimedWaiter {
    pub thread: Arc<Thread>,
    pub cleanup: Option<WaitTimeoutCleanupRef>,
}

/// Result of a [`Scheduler::terminate_threads_of_process`] scan: whether a
/// thread of the process is currently running on the scanned scheduler's CPU.
pub(crate) struct ProcessTerminateScan {
    pub(crate) running_present: bool,
}
