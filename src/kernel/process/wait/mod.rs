//! src/kernel/process/wait/mod.rs
//!
//! Blocking wait primitives: the wait queue that every parking facility is
//! built on, and the event, semaphore, and condition-variable wrappers over
//! it.
//!
//! These sit beside the scheduler rather than in `kernel::sync` because
//! parking a thread *is* a scheduler act: a queue holds `Arc<Thread>`s and
//! wakes them through the [`Scheduler`](super::scheduler::Scheduler).  Keeping
//! them here leaves one dependency direction — this module knows the
//! scheduler, the scheduler does not know this module — and lets `kernel::sync`
//! stay a leaf that names no thread at all.

pub mod condvar;
pub mod event;
pub(crate) mod input_wait;
mod queue;
pub mod semaphore;

pub use condvar::Condvar;
pub use condvar::CondvarWait;
pub use event::Event;
pub use event::EventMode;
pub(crate) use queue::plan_timed_wait;
pub(crate) use queue::TimedWaitPlan;
pub use queue::WaitQueue;
pub(crate) use queue::WaitTimeoutCleanupRef;
pub(crate) use queue::WaiterIdentity;
pub use semaphore::Semaphore;
