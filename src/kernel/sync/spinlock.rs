//! src/kernel/sync/spinlock.rs
//!
//! Interrupt-aware spinlock primitive and guard semantics for low-level
//! locking.

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch;

pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        // Disable interrupts while spinning to avoid local re-entrancy deadlocks.
        let interrupts_were_enabled = arch::interrupts::save_and_disable();

        // Exponential backoff: start with a short spin, double up to a cap.
        let mut backoff: u32 = 1;
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Wait until observed unlocked, then retry atomic acquisition.
            while self.locked.load(Ordering::Relaxed) {
                for _ in 0..backoff.min(64) {
                    spin_loop();
                }
                backoff = backoff.saturating_mul(2).min(1024);
            }
            // Lock just became free — reset backoff for fairness.
            backoff = 1;
        }

        SpinLockGuard {
            lock: self,
            interrupts_were_enabled,
        }
    }

    /// Acquire the lock without disabling interrupts.
    ///
    /// Use only when the caller guarantees:
    /// 1. No interrupt handler tries to lock this same lock (else deadlock on
    ///    the same CPU).
    /// 2. The critical section is short enough that preemption while holding
    ///    the lock is unlikely.
    ///
    /// This is necessary for SMP correctness when the critical section may
    /// overlap with a cross-CPU TLB shootdown: the other CPU sends an IPI and
    /// waits for acknowledgment, which requires local interrupts to be enabled.
    pub fn lock_without_irq_disable(&self) -> SpinLockGuard<'_, T> {
        // Note: interrupts are NOT saved/disabled — the caller must ensure
        // it is safe to receive interrupts while holding this lock.
        let saved = arch::interrupts::save_and_disable();
        arch::interrupts::restore(saved);

        let mut backoff: u32 = 1;
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                for _ in 0..backoff.min(64) {
                    spin_loop();
                }
                backoff = backoff.saturating_mul(2).min(1024);
            }
            backoff = 1;
        }

        SpinLockGuard {
            lock: self,
            interrupts_were_enabled: saved, // original state, may be enabled
        }
    }

    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let interrupts_were_enabled = arch::interrupts::save_and_disable();
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinLockGuard {
                lock: self,
                interrupts_were_enabled,
            })
            .or_else(|| {
                // Acquisition failed: restore interrupt state immediately.
                arch::interrupts::restore(interrupts_were_enabled);
                None
            })
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    interrupts_were_enabled: bool,
}

impl<T> SpinLockGuard<'_, T> {
    pub(crate) fn unlock_without_restore(self) -> bool {
        let guard = ManuallyDrop::new(self);
        guard.lock.locked.store(false, Ordering::Release);
        guard.interrupts_were_enabled
    }

    pub(crate) fn set_interrupt_restore_state(&mut self, enabled: bool) {
        self.interrupts_were_enabled = enabled;
    }
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        // Release lock first, then restore caller interrupt state.
        self.lock.locked.store(false, Ordering::Release);
        arch::interrupts::restore(self.interrupts_were_enabled);
    }
}
