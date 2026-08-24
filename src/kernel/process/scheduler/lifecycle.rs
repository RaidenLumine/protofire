//! src/kernel/process/scheduler/lifecycle.rs
//!
//! Scheduler construction, PID allocation, and CPU-spread setup.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU32;
#[cfg(not(test))]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use super::super::{Context, ContextCell, THREAD_PRIORITY_COUNT};
use super::clear_current_scheduler_ptr_if_matches;
use super::types::{SchedulerHotspotStats, SchedulerStats};
use super::Scheduler;
use crate::kernel::sync::Mutex;

// ── Construction ──

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    /// Create a new scheduler.
    ///
    /// PIDs are allocated starting at 2 (`1` is reserved for the idle
    /// process).  Call [`Scheduler::install_global`] before the first
    /// scheduling pass so interrupt handlers can find this instance.
    pub fn new() -> Self {
        Self {
            ready_queues: Mutex::new([const { VecDeque::new() }; THREAD_PRIORITY_COUNT]),
            waiting_queue: Mutex::new(Vec::new()),
            current: Mutex::new(None),
            processes: Mutex::new(Vec::new()),
            next_pid: Mutex::new(2),
            freed_pids: Mutex::new(Vec::new()),
            need_resched: AtomicBool::new(false),
            next_cpu: AtomicU32::new(0),
            dispatch_context: ContextCell::new(Context::empty()),
            dying_thread: Mutex::new(None),
            deferred_dying: Mutex::new(None),
            simulated_ticks: Mutex::new(0),
            hotspot_stats: Mutex::new(SchedulerHotspotStats::default()),
            stats: Mutex::new(SchedulerStats::default()),
        }
    }

    /// Initialise the per-CPU thread-spread counter to `cpu_id`.
    ///
    /// Each CPU's scheduler keeps a round-robin counter that determines
    /// which CPU a newly spawned thread is assigned to.
    pub fn init_next_cpu(&self, cpu_id: u32) {
        self.next_cpu.store(cpu_id, Ordering::Release);
    }

    /// Allocate a fresh PID.
    ///
    /// Reuses freed PIDs before allocating fresh ones so long-running
    /// systems don't exhaust the u32 PID space.  PID `1` is reserved for
    /// the idle process, so allocation starts at `2`.
    pub(crate) fn allocate_pid(&self) -> u32 {
        // Reuse freed PIDs before allocating fresh ones so long-running
        // systems don't exhaust the u32 PID space.
        if let Some(pid) = self.freed_pids.lock().pop() {
            return pid;
        }

        let mut next = self.next_pid.lock();
        let pid = *next;
        match pid.checked_add(1) {
            Some(next_pid) => *next = next_pid,
            None => {
                // PID counter wrapped after 2³² allocations.
                // Re-check freed_pids (another thread may have freed one
                // since our first check), then reset the counter to 2
                // (1 is reserved for init).
                drop(next);
                if let Some(pid) = self.freed_pids.lock().pop() {
                    return pid;
                }
                *self.next_pid.lock() = 2;
                return 2;
            }
        }
        pid
    }
}

// ── Drop ──

impl Drop for Scheduler {
    fn drop(&mut self) {
        let self_ptr = self as *mut Self;
        clear_current_scheduler_ptr_if_matches(self_ptr);
    }
}
