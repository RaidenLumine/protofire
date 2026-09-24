//! src/kernel/process/scheduler/queue.rs
//!
//! Ready-queue and waiting-queue utility functions.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::sync::wait::WaiterIdentity;

use super::super::thread::ThreadSchedPolicy;
use super::super::ProcessState;
use super::super::Thread;
use super::super::ThreadState;
use super::super::THREAD_PRIORITY_COUNT;
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

/// Is this thread still parked by the scheduler?
///
/// The queue is the scheduler's list of the threads it has taken out of the
/// running set, and it holds every one of them: a thread blocked with a
/// deadline, and a thread blocked on a wait queue that will be woken by
/// whoever signals it.  A registration whose thread is no longer waiting is
/// what a wake leaves behind, and this is what drops it.
///
/// The deadline is not part of the question.  It used to be, which is why a
/// thread blocked without one was invisible here — and a thread the scheduler
/// cannot see is one it reports as lost.
pub(crate) fn parked_waiter_is_active(waiter: &TimedWaiter) -> bool {
    waiter.thread.state() == ThreadState::Waiting
        && waiter.thread.process().state() != ProcessState::Terminated
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
) -> EnqueueOutcome {
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
        // The thread was not waiting: somebody else woke it first, so it is
        // already where it belongs.
        EnqueueOutcome::NotReady
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

/// The same removal, but handing back what was taken.
///
/// The caller that takes a registration away has to be able to ask what it
/// just did to the thread: a registration removed while the thread is still
/// waiting for it is a thread nothing will wake.
pub(crate) fn take_timed_waiters_by_identity(
    waiting_queue: &mut Vec<TimedWaiter>,
    identity: WaiterIdentity,
) -> Vec<TimedWaiter> {
    let mut taken = Vec::new();
    let mut index = 0;
    while index < waiting_queue.len() {
        if WaiterIdentity::from_thread(&waiting_queue[index].thread) == identity {
            taken.push(waiting_queue.swap_remove(index));
        } else {
            index += 1;
        }
    }
    taken
}

pub(crate) fn take_stale_timed_waiters(waiting_queue: &mut Vec<TimedWaiter>) -> Vec<TimedWaiter> {
    let mut stale = Vec::new();
    let mut index = 0;
    while index < waiting_queue.len() {
        if parked_waiter_is_active(&waiting_queue[index]) {
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

/// Remove every queued copy of `thread`, wherever it is queued.
///
/// The ready queues are indexed by priority, and a thread's priority can
/// change while it sits in one — the starvation boost does exactly that.  So
/// "is this thread queued?" is a question about the *thread*, not about the
/// queue for the priority it happens to have now.  Asking only that one queue
/// is how the same thread ends up queued twice, and a thread queued twice can
/// be dispatched twice.
fn remove_queued_thread(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
    thread: &Thread,
) -> bool {
    let pid = thread.pid();
    let tid = thread.tid();
    let mut removed = false;
    for queue in ready_queues.iter_mut() {
        let before = queue.len();
        queue.retain(|queued| !(queued.pid() == pid && queued.tid() == tid));
        removed |= queue.len() != before;
    }
    removed
}

/// What an enqueue did with a thread.
///
/// A bare `bool` cannot say *why* nothing was queued, and "nothing was
/// queued" is the only answer that matters: the caller has already made the
/// thread runnable, so a thread that is not queued here is in no queue at all
/// and the scheduler will never look at it again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EnqueueOutcome {
    /// The thread is in exactly one ready queue, for its current priority.
    Enqueued,
    /// The thread is not `Ready`, so it must not be queued: it is running,
    /// blocked, stopped or gone.  A *runnable* thread refused here is a bug.
    NotReady,
}

impl EnqueueOutcome {
    pub(crate) fn enqueued(self) -> bool {
        matches!(self, Self::Enqueued)
    }
}

pub(crate) fn enqueue_ready_thread(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
    thread: Arc<Thread>,
) -> EnqueueOutcome {
    if !should_dispatch_ready_thread(thread.state()) {
        return EnqueueOutcome::NotReady;
    }

    // Exactly one copy, in the queue for the priority it has now.
    let _ = remove_queued_thread(ready_queues, &thread);
    ready_queues[thread.priority() as usize].push_back(thread);
    EnqueueOutcome::Enqueued
}

/// Requeue a preempted thread.  FIFO threads go to the front of their
/// queue to preserve run-to-completion ordering; round-robin threads
/// go to the back.
///
/// Answers whether the thread went back into a queue.  A preempted thread
/// that was not runnable does not, and it has just left the CPU — so the
/// caller is the only place that can notice a thread going nowhere, and it
/// is what [`Scheduler::record_dropped_current`] counts.
pub(crate) fn requeue_preempted_thread(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
    thread: Arc<Thread>,
) -> bool {
    if !should_dispatch_ready_thread(thread.state()) {
        return false;
    }

    let _ = remove_queued_thread(ready_queues, &thread);
    let ready_queue = &mut ready_queues[thread.priority() as usize];
    if thread.sched_policy() == ThreadSchedPolicy::SchedFifo {
        ready_queue.push_front(thread);
    } else {
        ready_queue.push_back(thread);
    }
    true
}

/// Walk the ready queues and answer with the next thread to run.
///
/// The same walk as [`take_next_dispatchable_thread_with_dropped`], for
/// callers that are not in a position to record what it discards.
pub(crate) fn take_next_dispatchable_thread(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
) -> Option<Arc<Thread>> {
    take_next_dispatchable_thread_with_dropped(ready_queues).0
}

/// Walk the ready queues, answering with the next thread to run and with how
/// many entries were not dispatchable.
///
/// The count is not decoration.  A ready queue is supposed to hold only
/// `Ready` threads, so an entry that is not one is a thread that has just left
/// the scheduler's view — popped out of the queue and put nowhere — and this
/// is the only place that sees it happen.
/// [`super::Scheduler::record_dropped_ready`] says so the first time.
pub(crate) fn take_next_dispatchable_thread_with_dropped(
    ready_queues: &mut [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT],
) -> (Option<Arc<Thread>>, usize) {
    let mut dropped = 0usize;
    // Scan from highest priority (Realtime) to lowest (Idle).
    for priority in (0..THREAD_PRIORITY_COUNT).rev() {
        let queue = &mut ready_queues[priority];
        while let Some(thread) = queue.pop_front() {
            if should_dispatch_ready_thread(thread.state()) {
                return (Some(thread), dropped);
            }
            // Not `Ready`: the dispatch rules do not allow it to run, and it
            // goes nowhere.  Counted by the caller.
            dropped += 1;
        }
    }

    (None, dropped)
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
