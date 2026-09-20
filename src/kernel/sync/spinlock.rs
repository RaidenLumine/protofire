//! src/kernel/sync/spinlock.rs
//!
//! Interrupt-aware spinlock primitive and guard semantics for low-level
//! locking.

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::mem::ManuallyDrop;
use core::ops::Deref;
use core::ops::DerefMut;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

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

    /// Acquire the lock without masking interrupts.
    ///
    /// # This is a second lock discipline, and it is in tension with the first
    ///
    /// [`lock`](Self::lock) masks interrupts for the whole critical section, so
    /// its holder cannot be preempted.  This one does not, so its holder can.
    /// Mixing the two on one lock gives you a failure mode either way:
    ///
    /// - **A holder here is preemptible.**  If another thread acquires the same
    ///   lock with [`lock`](Self::lock), that thread spins with interrupts
    ///   masked.  On a single CPU the preempted holder then needs the timer to
    ///   be rescheduled, and the timer needs interrupts — so neither side ever
    ///   moves again.  This is a permanent wedge, not a slow path.
    /// - **Masking interrupts here instead is not free either.**  Some callers
    ///   hold a lock across `memory::global_mut()`.  If another CPU holds the
    ///   memory-manager lock and is waiting for a TLB-shootdown acknowledgement
    ///   from this one, masking interrupts here is exactly what stops the
    ///   acknowledgement.
    ///
    /// # When this is justified
    ///
    /// The second hazard needs the critical section to acquire the
    /// memory-manager lock, because that is the lock a TLB shootdown runs
    /// under.  So the precise criterion is: **use this only if the critical
    /// section calls `memory::global_mut()`.**
    ///
    /// Nothing else justifies it.  Allocating does not: the kernel heap is a
    /// pre-sized static array with its own lock and never reaches the memory
    /// manager, so a critical section that only allocates is fully covered by
    /// the ordinary [`lock`](Self::lock).
    ///
    /// Prefer removing the reason over choosing a discipline.  Restructure the
    /// caller to release this lock before touching the memory manager — the
    /// two-phase load in `user/program/launch_reference.rs` is the worked
    /// example — and then [`lock`](Self::lock) is correct and the wedge above
    /// cannot happen at all.
    ///
    /// # Current status
    ///
    /// **Nothing calls this.**  Every former caller held a lock across
    /// `memory::global_mut()` and has been restructured to release it first, so
    /// the criterion above is met by nothing.  The method is kept as a
    /// documented capability rather than deleted, because the TLB-shootdown
    /// reason it exists for is real; reintroducing a caller means re-checking
    /// that its critical section acquires the memory-manager lock, and on SMP
    /// hardware, not just under emulation.
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
