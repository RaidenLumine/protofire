//! src/kernel/process/posix_timer.rs
//!
//! POSIX per-process timer
//! (timer_create/timer_settime/timer_gettime/timer_delete).
//!
//! Each timer delivers a signal on expiry.  Timers are tracked in a global
//! list and checked on every scheduler tick (100 Hz granularity).

use crate::kernel::sync::Mutex;
use crate::Result;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

/// Timer ID type (opaque handle returned to userspace).
pub type TimerId = u32;

/// Clock identifiers.
pub const CLOCK_REALTIME: u32 = 0;
pub const CLOCK_MONOTONIC: u32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: u32 = 2;
pub const CLOCK_THREAD_CPUTIME_ID: u32 = 3;

/// Signal notification type.
pub const SIGEV_SIGNAL: i32 = 0;
pub const SIGEV_NONE: i32 = 1;

/// A single POSIX timer.
pub struct PosixTimer {
    /// Timer ID.
    pub id: TimerId,
    /// Owning process PID.
    pub owner_pid: u32,
    /// Clock source.
    pub clock_id: u32,
    /// Expiry tick (scheduler ticks); 0 = not armed.
    pub expiry_tick: AtomicU64,
    /// Interval in ticks (0 = one-shot).
    pub interval_ticks: AtomicU64,
    /// Signal to deliver on expiry.
    pub signo: i32,
    /// Sigval value to deliver.
    pub sigval_value: usize,
    /// Whether the timer is still active.
    pub active: AtomicBool,
}

/// Global timer manager.
struct PosixTimerManager {
    /// Map from timer ID to timer.
    timers: BTreeMap<TimerId, Arc<PosixTimer>>,
    /// Next timer ID.
    next_id: TimerId,
}

impl PosixTimerManager {
    const fn new() -> Self {
        Self {
            timers: BTreeMap::new(),
            next_id: 1,
        }
    }

    fn alloc(&mut self, owner_pid: u32, clock_id: u32) -> Arc<PosixTimer> {
        let id = self.next_id;
        self.next_id += 1;
        let timer = Arc::new(PosixTimer {
            id,
            owner_pid,
            clock_id,
            expiry_tick: AtomicU64::new(0),
            interval_ticks: AtomicU64::new(0),
            signo: 0,
            sigval_value: 0,
            active: AtomicBool::new(true),
        });
        self.timers.insert(id, timer.clone());
        timer
    }

    fn get(&self, id: TimerId) -> Option<&Arc<PosixTimer>> {
        self.timers.get(&id)
    }

    fn remove(&mut self, id: TimerId) -> Option<Arc<PosixTimer>> {
        let timer = self.timers.remove(&id)?;
        timer.active.store(false, Ordering::Release);
        Some(timer)
    }
}

static TIMER_MANAGER: Mutex<PosixTimerManager> = Mutex::new(PosixTimerManager::new());

/// Convert nanoseconds to scheduler ticks (100 Hz → 10 ms per tick).
pub fn ns_to_ticks(ns: u64) -> u64 {
    // 1 tick = 10_000_000 ns (10 ms)
    ns.div_ceil(10_000_000)
}

/// Convert ticks to nanoseconds.
pub fn ticks_to_ns(ticks: u64) -> u64 {
    ticks.saturating_mul(10_000_000)
}

/// Create a new POSIX timer.
pub fn timer_create(owner_pid: u32, clock_id: u32) -> Result<TimerId> {
    if clock_id > CLOCK_THREAD_CPUTIME_ID {
        return Err(crate::Error::InvalidArgument);
    }
    let mut mgr = TIMER_MANAGER.lock();
    let timer = mgr.alloc(owner_pid, clock_id);
    Ok(timer.id)
}

/// Arm or disarm a timer.
pub fn timer_settime(
    timer_id: TimerId,
    flags: u32,
    value_sec: i64,
    value_nsec: i64,
    interval_sec: i64,
    interval_nsec: i64,
) -> Result<()> {
    let mgr = TIMER_MANAGER.lock();
    let timer = mgr.get(timer_id).ok_or(crate::Error::InvalidArgument)?;
    if !timer.active.load(Ordering::Acquire) {
        return Err(crate::Error::InvalidArgument);
    }

    let current_ticks = crate::arch::timer::ticks();
    let interval_ticks = ns_to_ticks(
        (interval_sec.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(interval_nsec.max(0) as u64),
    );
    timer
        .interval_ticks
        .store(interval_ticks, Ordering::Release);

    if value_sec == 0 && value_nsec == 0 {
        // Disarm.
        timer.expiry_tick.store(0, Ordering::Release);
        return Ok(());
    }

    let value_ns = (value_sec.max(0) as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(value_nsec.max(0) as u64);
    let value_ticks = ns_to_ticks(value_ns);

    let expiry = if (flags & 0x01) != 0 {
        // TIMER_ABSTIME: value is absolute
        value_ticks
    } else {
        current_ticks.saturating_add(value_ticks.max(1))
    };

    timer.expiry_tick.store(expiry, Ordering::Release);
    Ok(())
}

/// Get remaining time for a timer.
pub fn timer_gettime(timer_id: TimerId) -> Result<(i64, i64, i64, i64)> {
    let mgr = TIMER_MANAGER.lock();
    let timer = mgr.get(timer_id).ok_or(crate::Error::InvalidArgument)?;
    if !timer.active.load(Ordering::Acquire) {
        return Err(crate::Error::InvalidArgument);
    }

    let expiry = timer.expiry_tick.load(Ordering::Acquire);
    let interval = timer.interval_ticks.load(Ordering::Acquire);
    let current = crate::arch::timer::ticks();

    let remaining = if expiry > current && expiry > 0 {
        ticks_to_ns(expiry - current)
    } else {
        0
    };

    let int_ns = ticks_to_ns(interval);

    Ok((
        (remaining / 1_000_000_000) as i64,
        (remaining % 1_000_000_000) as i64,
        (int_ns / 1_000_000_000) as i64,
        (int_ns % 1_000_000_000) as i64,
    ))
}

/// Delete a timer.
pub fn timer_delete(timer_id: TimerId) -> Result<()> {
    let mut mgr = TIMER_MANAGER.lock();
    mgr.remove(timer_id).ok_or(crate::Error::InvalidArgument)?;
    Ok(())
}

/// Called from the scheduler tick to check expired timers.
/// Delivers signals for any expired timer and re-arms interval timers.
pub fn check_expired_timers(ticks: u64) {
    let mut timers_to_fire: Vec<TimerId> = Vec::new();
    {
        let mgr = TIMER_MANAGER.lock();
        for (&id, timer) in mgr.timers.iter() {
            if !timer.active.load(Ordering::Acquire) {
                continue;
            }
            let expiry = timer.expiry_tick.load(Ordering::Acquire);
            if expiry > 0 && ticks >= expiry {
                timers_to_fire.push(id);
            }
        }
    }

    for id in timers_to_fire {
        let mgr = TIMER_MANAGER.lock();
        if let Some(timer) = mgr.get(id) {
            if !timer.active.load(Ordering::Acquire) {
                continue;
            }
            let interval = timer.interval_ticks.load(Ordering::Acquire);
            if interval > 0 {
                // Re-arm interval timer.
                let next = ticks.saturating_add(interval);
                timer.expiry_tick.store(next, Ordering::Release);
            } else {
                // One-shot: disarm.
                timer.expiry_tick.store(0, Ordering::Release);
            }

            // Deliver signal via the global scheduler.
            if timer.signo > 0 {
                if let Some(sched) =
                    unsafe { crate::kernel::percpu::current_scheduler_ptr().as_ref() }
                {
                    // Use pid 0 as sender (kernel).
                    let _ = sched.send_signal(
                        0,
                        timer.owner_pid,
                        timer.signo as usize,
                        timer.sigval_value,
                    );
                }
            }
        }
    }
}
