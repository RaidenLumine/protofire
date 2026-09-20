//! src/kernel/sync/mutex.rs
//!
//! Mutex abstraction built on spinlock with RAII guard-based exclusive access.

use core::fmt;
use core::ops::Deref;
use core::ops::DerefMut;

use super::SpinLock;
use super::SpinLockGuard;

pub struct Mutex<T> {
    inner: SpinLock<T>,
}

impl<T: fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.try_lock() {
            Some(guard) => f.debug_struct("Mutex").field("value", &*guard).finish(),
            None => f.debug_struct("Mutex").field("value", &"<locked>").finish(),
        }
    }
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: SpinLock::new(value),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        // Keep all locking policy inside SpinLock; Mutex only wraps the RAII surface.
        MutexGuard {
            mutex: self,
            inner: self.inner.lock(),
        }
    }

    /// Try to acquire the mutex without waiting for it.
    ///
    /// Returns `None` when another thread holds the lock.  The interesting use
    /// is asserting lock discipline: a test can check that a lock is *not* held
    /// at a point where holding it would serialise unrelated work behind a slow
    /// operation.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        Some(MutexGuard {
            mutex: self,
            inner: self.inner.try_lock()?,
        })
    }

    /// Acquire the mutex without masking interrupts.
    ///
    /// This is a different lock discipline from [`lock`](Self::lock), and the
    /// two cannot be mixed freely on one lock: a holder here is preemptible,
    /// while a waiter using [`lock`](Self::lock) spins with interrupts masked
    /// and can therefore wait forever on a uniprocessor.  See
    /// [`SpinLock::lock_without_irq_disable`] for the full statement of the
    /// hazard and the conditions under which this is acceptable.
    pub fn lock_without_irq_disable(&self) -> MutexGuard<'_, T> {
        MutexGuard {
            mutex: self,
            inner: self.inner.lock_without_irq_disable(),
        }
    }
}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
    inner: SpinLockGuard<'a, T>,
}

impl<'a, T> MutexGuard<'a, T> {
    pub(crate) fn unlock_without_restore(self) -> (&'a Mutex<T>, bool) {
        // Split unlock and interrupt-restore so Condvar can atomically park/relock.
        let mutex = self.mutex;
        let interrupts_were_enabled = self.inner.unlock_without_restore();
        (mutex, interrupts_were_enabled)
    }

    pub(crate) fn set_interrupt_restore_state(&mut self, enabled: bool) {
        self.inner.set_interrupt_restore_state(enabled);
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
