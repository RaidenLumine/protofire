//! src/kernel/sync/wait.rs
//! Wait-queue core utilities for parking, waking, and timeout cleanup integration.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::process::{ProcessId, ProcessState, Scheduler, Thread, ThreadId, ThreadState};

use super::SpinLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimedWaitPlan {
    Unavailable,
    ZeroTimeout,
    Deadline(u64),
}

fn is_active_waiter(thread: &Thread) -> bool {
    thread.state() == ThreadState::Waiting && thread.process().state() != ProcessState::Terminated
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WaiterIdentity {
    pub pid: ProcessId,
    pub tid: ThreadId,
}

impl WaiterIdentity {
    pub(crate) fn from_thread(thread: &Thread) -> Self {
        Self {
            pid: thread.pid(),
            tid: thread.tid(),
        }
    }

    fn matches(self, thread: &Thread) -> bool {
        self.pid == thread.pid() && self.tid == thread.tid()
    }
}

pub(crate) fn plan_timed_wait(timeout_ticks: u64) -> TimedWaitPlan {
    if timeout_ticks == 0 {
        return TimedWaitPlan::ZeroTimeout;
    }

    let Some(scheduler) = Scheduler::global() else {
        return TimedWaitPlan::Unavailable;
    };

    TimedWaitPlan::Deadline(scheduler.current_tick().saturating_add(timeout_ticks))
}

fn remove_waiters_by_identity(
    waiters: &mut VecDeque<Arc<Thread>>,
    identity: WaiterIdentity,
) -> usize {
    let original_len = waiters.len();
    waiters.retain(|thread| !identity.matches(thread));
    original_len - waiters.len()
}

pub(crate) trait WaitTimeoutCleanup: Send + Sync {
    fn remove_waiter(&self, identity: WaiterIdentity);

    fn on_timeout(&self, _identity: WaiterIdentity) {}
}

pub(crate) type WaitTimeoutCleanupRef = Arc<dyn WaitTimeoutCleanup>;

struct CompositeWaitTimeoutCleanup {
    queue_cleanup: WaitTimeoutCleanupRef,
    timeout_observer: WaitTimeoutCleanupRef,
}

fn compose_timeout_cleanup(
    queue_cleanup: WaitTimeoutCleanupRef,
    timeout_observer: WaitTimeoutCleanupRef,
) -> WaitTimeoutCleanupRef {
    Arc::new(CompositeWaitTimeoutCleanup {
        queue_cleanup,
        timeout_observer,
    })
}

impl WaitTimeoutCleanup for CompositeWaitTimeoutCleanup {
    fn remove_waiter(&self, identity: WaiterIdentity) {
        self.queue_cleanup.remove_waiter(identity);
        self.timeout_observer.remove_waiter(identity);
    }

    fn on_timeout(&self, identity: WaiterIdentity) {
        self.queue_cleanup.on_timeout(identity);
        self.timeout_observer.on_timeout(identity);
    }
}

struct WaitQueueState<T> {
    state: T,
    waiters: VecDeque<Arc<Thread>>,
}

struct WaitQueueInner<T> {
    state: SpinLock<WaitQueueState<T>>,
}

impl<T: Send + 'static> WaitTimeoutCleanup for WaitQueueInner<T> {
    fn remove_waiter(&self, identity: WaiterIdentity) {
        let mut inner = self.state.lock();
        let _ = remove_waiters_by_identity(&mut inner.waiters, identity);
    }
}

pub struct WaitQueue<T = ()> {
    inner: Arc<WaitQueueInner<T>>,
}

impl WaitQueue<()> {
    pub fn new() -> Self {
        Self::with_state(())
    }
}

impl Default for WaitQueue<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> WaitQueue<T> {
    pub fn with_state(state: T) -> Self {
        Self {
            inner: Arc::new(WaitQueueInner {
                state: SpinLock::new(WaitQueueState {
                    state,
                    waiters: VecDeque::new(),
                }),
            }),
        }
    }

    pub fn waiter_count(&self) -> usize {
        self.with_lock(|_, waiters| {
            Self::prune_stale_waiters(waiters);
            waiters.len()
        })
    }

    pub fn block_current(&self) -> bool {
        self.block_current_if(|_, waiters, thread| {
            waiters.push_back(thread.clone());
            true
        })
    }

    pub fn block_current_if<F>(&self, prepare: F) -> bool
    where
        F: FnOnce(&mut T, &mut VecDeque<Arc<Thread>>, &Arc<Thread>) -> bool,
    {
        let Some(scheduler) = Scheduler::global() else {
            return false;
        };

        scheduler.block_current_thread_if(|thread| {
            let mut inner = self.inner.state.lock();
            let WaitQueueState { state, waiters } = &mut *inner;
            // Drop stale waiter entries before evaluating the new block condition.
            Self::prune_stale_waiters(waiters);
            if !prepare(state, waiters, thread) {
                return false;
            }

            thread.block();
            true
        })
    }

    pub fn block_current_until_if<F>(&self, deadline: u64, prepare: F) -> bool
    where
        T: Send + 'static,
        F: FnOnce(&mut T, &mut VecDeque<Arc<Thread>>, &Arc<Thread>) -> bool,
    {
        self.block_current_until_if_with_timeout_cleanup(deadline, None, prepare)
    }

    pub(crate) fn block_current_until_if_with_timeout_cleanup<F>(
        &self,
        deadline: u64,
        timeout_observer: Option<WaitTimeoutCleanupRef>,
        prepare: F,
    ) -> bool
    where
        T: Send + 'static,
        F: FnOnce(&mut T, &mut VecDeque<Arc<Thread>>, &Arc<Thread>) -> bool,
    {
        let Some(scheduler) = Scheduler::global() else {
            return false;
        };

        let queue_cleanup = self.timeout_cleanup();
        let cleanup = timeout_observer
            .map(|observer| compose_timeout_cleanup(queue_cleanup.clone(), observer))
            .unwrap_or(queue_cleanup);

        scheduler.block_current_thread_if(|thread| {
            let mut inner = self.inner.state.lock();
            let WaitQueueState { state, waiters } = &mut *inner;
            Self::prune_stale_waiters(waiters);
            if !prepare(state, waiters, thread) {
                return false;
            }

            thread.block_until(deadline);
            // Register cleanup so timeout can remove stale queue links by tid.
            scheduler.register_timed_waiter(thread.clone(), Some(cleanup.clone()));
            true
        })
    }

    pub fn wake_one(&self) -> bool {
        self.wake_with(|_, waiters, waking| {
            if let Some(thread) = Self::take_next_waiter(waiters) {
                waking.push(thread);
            }
        }) != 0
    }

    pub fn wake_all(&self) -> usize {
        self.wake_with(|_, waiters, waking| {
            Self::prune_stale_waiters(waiters);
            waking.extend(waiters.drain(..));
        })
    }

    pub fn wake_with<F>(&self, select: F) -> usize
    where
        F: FnOnce(&mut T, &mut VecDeque<Arc<Thread>>, &mut Vec<Arc<Thread>>),
    {
        let mut waking = Vec::new();
        {
            let mut inner = self.inner.state.lock();
            let WaitQueueState { state, waiters } = &mut *inner;
            Self::prune_stale_waiters(waiters);
            select(state, waiters, &mut waking);
        }

        let Some(scheduler) = Scheduler::global() else {
            return 0;
        };

        // Wake outside the queue lock to avoid lock coupling with scheduler internals.
        let mut woke = 0;
        for thread in waking {
            if scheduler.wake_thread(thread) {
                woke += 1;
            }
        }

        woke
    }

    pub(crate) fn with_lock<R>(
        &self,
        update: impl FnOnce(&mut T, &mut VecDeque<Arc<Thread>>) -> R,
    ) -> R {
        let mut inner = self.inner.state.lock();
        let WaitQueueState { state, waiters } = &mut *inner;
        update(state, waiters)
    }

    pub(crate) fn set_current_wait_outcome(
        &self,
        outcome: crate::kernel::process::ThreadWaitOutcome,
    ) {
        if let Some(thread) = Scheduler::global().and_then(|scheduler| scheduler.current_thread()) {
            thread.set_wait_outcome(outcome);
        }
    }

    pub(crate) fn take_next_waiter(waiters: &mut VecDeque<Arc<Thread>>) -> Option<Arc<Thread>> {
        // Skip stale entries and return the first waiter whose process can still run.
        while let Some(thread) = waiters.pop_front() {
            if is_active_waiter(&thread) {
                return Some(thread);
            }
        }

        None
    }

    fn prune_stale_waiters(waiters: &mut VecDeque<Arc<Thread>>) {
        waiters.retain(|thread| is_active_waiter(thread));
    }

    fn timeout_cleanup(&self) -> WaitTimeoutCleanupRef
    where
        T: Send + 'static,
    {
        self.inner.clone()
    }
}
