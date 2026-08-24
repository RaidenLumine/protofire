//! src/kernel/process/scheduler/queue.rs
//!
//! Ready-queue and waiting-queue utility functions.
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::sync::wait::WaiterIdentity;

use super::super::thread::ThreadSchedPolicy;
use super::super::{ProcessState, Thread, ThreadState, THREAD_PRIORITY_COUNT};
use super::types::TimedWaiter;
use super::TIME_SLICE_TICKS;

pub(crate) fn should_requeue_simulated_preempted_thread(state: ThreadState) -> bool {
    !matches!(
        state,
        ThreadState::Terminated | ThreadState::Waiting | ThreadState::Stopped
    )
}

pub(crate) fn should_dispatch_ready_thread(state: ThreadState) -> bool {
    state == ThreadState::Ready
}

pub(crate) fn thread_has_dispatch_address_space(thread: &Thread) -> bool {
    thread.user_start().is_none() || thread.process().has_user_address_space()
}

pub(crate) fn should_preempt_for_time_slice(ticks: u64) -> bool {
    ticks.is_multiple_of(TIME_SLICE_TICKS)
}

pub(crate) fn has_timed_wait_elapsed(deadline: Option<u64>, ticks: u64) -> bool {
    deadline.is_some_and(|wake_tick| wake_tick <= ticks)
}

pub(crate) fn timed_waiter_is_active(waiter: &TimedWaiter) -> bool {
    waiter.thread.state() == ThreadState::Waiting
        && waiter.thread.process().state() != ProcessState::Terminated
        && waiter.thread.wake_deadline().is_some()
}

pub(crate) fn remove_timed_waiter_from_wait_queue(timed_waiter: TimedWaiter) {
    let identity = WaiterIdentity::from_thread(&timed_waiter.thread);
    if let Some(cleanup) = &timed_waiter.cleanup {
        cleanup.remove_waiter(identity);
    }
}

pub(crate) fn remove_timed_waiters_from_wait_queues(timed_waiters: Vec<TimedWaiter>) {
    for timed_waiter in timed_waiters {
        remove_timed_waiter_from_wait_queue(timed_waiter);
    }
}

pub(crate) fn process_elapsed_timed_waiter(
    timed_waiter: TimedWaiter,
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
) -> bool {
    let identity = WaiterIdentity::from_thread(&timed_waiter.thread);
    if let Some(cleanup) = &timed_waiter.cleanup {
        cleanup.remove_waiter(identity);
    }

    if timed_waiter.thread.wake_by_timeout() {
        if let Some(cleanup) = &timed_waiter.cleanup {
            cleanup.on_timeout(identity);
        }
        enqueue_ready_thread(ready_queues, timed_waiter.thread)
    } else {
        false
    }
}

pub(crate) fn remove_timed_waiters_by_identity(
    waiting_queue: &mut Vec<TimedWaiter>,
    identity: WaiterIdentity,
) -> usize {
    let original_len = waiting_queue.len();
    waiting_queue.retain(|waiter| WaiterIdentity::from_thread(&waiter.thread) != identity);
    original_len - waiting_queue.len()
}

pub(crate) fn take_stale_timed_waiters(waiting_queue: &mut Vec<TimedWaiter>) -> Vec<TimedWaiter> {
    let mut stale = Vec::new();
    let mut index = 0;
    while index < waiting_queue.len() {
        if timed_waiter_is_active(&waiting_queue[index]) {
            index += 1;
        } else {
            stale.push(waiting_queue.swap_remove(index));
        }
    }

    stale
}

pub(crate) fn prune_nondispatchable_ready_threads(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
) -> usize {
    let mut pruned = 0;
    for queue in ready_queues.iter_mut() {
        let original_len = queue.len();
        queue.retain(|thread| should_dispatch_ready_thread(thread.state()));
        pruned += original_len - queue.len();
    }
    pruned
}

pub(crate) fn has_dispatchable_ready_thread(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
) -> bool {
    let _ = prune_nondispatchable_ready_threads(ready_queues);
    ready_queues.iter().any(|queue| !queue.is_empty())
}

pub(crate) fn enqueue_ready_thread(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
    thread: Arc<Thread>,
) -> bool {
    if !should_dispatch_ready_thread(thread.state()) {
        return false;
    }

    let priority = thread.priority() as usize;
    let pid = thread.pid();
    let tid = thread.tid();
    let ready_queue = &mut ready_queues[priority];
    if ready_queue
        .iter()
        .any(|queued| queued.pid() == pid && queued.tid() == tid)
    {
        return false;
    }

    ready_queue.push_back(thread);
    true
}

/// Requeue a preempted thread.  FIFO threads go to the front of their
/// queue to preserve run-to-completion ordering; round-robin threads
/// go to the back.
pub(crate) fn requeue_preempted_thread(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
    thread: Arc<Thread>,
) {
    if !should_dispatch_ready_thread(thread.state()) {
        return;
    }
    let priority = thread.priority() as usize;
    let pid = thread.pid();
    let tid = thread.tid();
    let ready_queue = &mut ready_queues[priority];
    if ready_queue
        .iter()
        .any(|queued| queued.pid() == pid && queued.tid() == tid)
    {
        return;
    }

    if thread.sched_policy() == ThreadSchedPolicy::SchedFifo {
        ready_queue.push_front(thread);
    } else {
        ready_queue.push_back(thread);
    }
}

pub(crate) fn take_next_dispatchable_thread(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
) -> Option<Arc<Thread>> {
    // Scan from highest priority (Realtime) to lowest (Idle).
    for priority in (0..THREAD_PRIORITY_COUNT).rev() {
        let queue = &mut ready_queues[priority];
        while let Some(thread) = queue.pop_front() {
            if should_dispatch_ready_thread(thread.state()) {
                return Some(thread);
            }
        }
    }

    None
}

/// Count the total number of ready threads across all priority levels.
pub(crate) fn ready_queue_len(
    ready_queues: &[VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
) -> usize {
    ready_queues.iter().map(|q| q.len()).sum()
}

/// Remove up to `count` threads from the highest-priority ready queues.
///
/// Threads are taken from the front of each queue so the remote CPU's
/// scheduling order is preserved as much as possible.
pub(crate) fn steal_ready_threads(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
    count: usize,
    target_cpu: Option<u32>,
) -> Vec<Arc<Thread>> {
    let mut stolen = Vec::with_capacity(count);
    let mut remaining = count;

    // Steal from highest priority down.
    for priority in (0..THREAD_PRIORITY_COUNT).rev() {
        let queue = &mut ready_queues[priority];
        let mut skipped = Vec::new(); // threads with incompatible affinity
        while remaining > 0 {
            match queue.pop_front() {
                Some(thread) => {
                    let affinity = thread.cpu_affinity();
                    // Thread with affinity to a specific CPU: only steal if
                    // target_cpu matches or isn't specified, or affinity is 0 (any).
                    let can_steal = target_cpu.is_none_or(|tcpu| affinity == 0 || affinity == tcpu);

                    if !can_steal {
                        // Leave it in the victim's queue (save and re-enqueue).
                        skipped.push(thread);
                        continue;
                    }

                    if should_dispatch_ready_thread(thread.state()) {
                        stolen.push(thread);
                        remaining -= 1;
                    }
                    // Non-dispatchable threads are discarded (pruned).
                }
                None => break,
            }
        }
        // Re-enqueue any skipped threads at the back of their priority queue.
        for thread in skipped.drain(..) {
            queue.push_back(thread);
        }
        if remaining == 0 {
            break;
        }
    }

    stolen
}

pub(crate) fn take_elapsed_timed_waiters(
    waiting_queue: &mut Vec<TimedWaiter>,
    ticks: u64,
) -> Vec<TimedWaiter> {
    let mut woke = Vec::new();
    let mut index = 0;
    // swap_remove keeps this pass O(n) while filtering by wake deadline.
    while index < waiting_queue.len() {
        let deadline = waiting_queue[index].thread.wake_deadline();
        if has_timed_wait_elapsed(deadline, ticks) {
            woke.push(waiting_queue.swap_remove(index));
        } else {
            index += 1;
        }
    }

    woke
}
