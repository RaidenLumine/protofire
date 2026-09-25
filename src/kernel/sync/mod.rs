//! src/kernel/sync/mod.rs
//!
//! The leaf synchronisation layer: a spinlock and the RAII mutex wrapper over
//! it.  Neither names a thread, so anything — the heap, the filesystem, a
//! driver — may use them.
//!
//! The primitives that *block a thread* live one layer up, in
//! [`kernel::process::wait`](crate::kernel::process::wait): parking is a
//! scheduler act, and a queue that parks threads has no business in the layer
//! a mutex is built on.

pub mod mutex;
pub mod spinlock;

pub use mutex::Mutex;
pub use mutex::MutexGuard;
pub use spinlock::SpinLock;
pub use spinlock::SpinLockGuard;
