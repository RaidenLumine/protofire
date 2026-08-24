//! src/kernel/sync/mod.rs
//!
//! Synchronization primitive exports for mutexes, events, semaphores, and waits.

pub mod condvar;
pub mod event;
pub(crate) mod input_wait;
pub mod mutex;
pub mod semaphore;
pub mod spinlock;
pub mod wait;

pub use condvar::{Condvar, CondvarWait};
pub use event::{Event, EventMode};
pub use mutex::{Mutex, MutexGuard};
pub use semaphore::Semaphore;
pub use spinlock::{SpinLock, SpinLockGuard};
pub use wait::WaitQueue;
pub(crate) use wait::WaitTimeoutCleanupRef;
