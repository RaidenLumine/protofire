//! src/kernel/process/scheduler/lifecycle.rs
//!
//! Scheduler construction, PID allocation, and CPU-spread setup.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
#[cfg(not(test))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
#[cfg(not(test))]
use core::sync::atomic::Ordering;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
#[cfg(test)]
use std::sync::atomic::Ordering;

use super::super::Context;
use super::super::ContextCell;
use super::super::THREAD_PRIORITY_COUNT;
use super::clear_current_scheduler_ptr_if_matches;
use super::types::SchedulerHotspotStats;
use super::types::SchedulerStats;
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
            home_cpu: AtomicU32::new(0),
            next_cpu: AtomicU32::new(0),
            dispatch_context: ContextCell::new(Context::empty()),
            dying_thread: Mutex::new(None),
            deferred_dying: Mutex::new(None),
            simulated_ticks: Mutex::new(0),
            hotspot_stats: Mutex::new(SchedulerHotspotStats::default()),
            stats: Mutex::new(SchedulerStats::default()),
            unplaced_suspects: Mutex::new([(0, 0); Self::PLACEMENT_WATCHDOG_CAPACITY]),
        }
    }

    /// Say which CPU this scheduler belongs to.
    ///
    /// Two things follow from it: the CPU's idle thread is pinned here, and
    /// the round-robin that assigns new threads starts from here — so work
    /// spawned on this CPU spreads outwards instead of landing on CPU 0.
    ///
    /// Called before anything is spawned on the scheduler, which is why it can
    /// be a plain store.
    pub fn bind_to_cpu(&self, cpu_id: u32) {
        self.home_cpu.store(cpu_id, Ordering::Release);
        self.next_cpu.store(cpu_id, Ordering::Release);
    }

    /// The CPU this scheduler belongs to.
    pub(crate) fn home_cpu(&self) -> u32 {
        self.home_cpu.load(Ordering::Acquire)
    }

    /// Allocate a fresh PID.
    ///
    /// Reuses freed PIDs before allocating fresh ones so long-running
    /// systems don't exhaust the u32 PID space.  PID `1` is reserved for
    /// the idle process, so allocation starts at `2`.
    ///
    /// The pool is the primary scheduler's, whichever CPU asks.  A pid names a
    /// process in the process registry, and the registry — like the children
    /// lists and the reaped-pid pool — belongs to the primary scheduler.  With
    /// a counter per CPU, two CPUs hand the same pid to two different
    /// processes, and every lookup by pid (wait, reap, signal delivery,
    /// `/proc/<pid>`) then has two answers and picks one.
    pub(crate) fn allocate_pid(&self) -> u32 {
        self.primary_scheduler().allocate_pid_from_pool()
    }

    /// Take the next pid out of the primary scheduler's pool.
    fn allocate_pid_from_pool(&self) -> u32 {
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
