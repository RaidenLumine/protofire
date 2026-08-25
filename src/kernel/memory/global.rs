//! src/kernel/memory/global.rs
//!
//! Global memory-manager singleton, exponential-backoff lock, and accessors.

use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;

use super::manager::MemoryManager;

pub(crate) static GLOBAL_MEMORY_MANAGER: AtomicPtr<MemoryManager> = AtomicPtr::new(ptr::null_mut());

/// SMP spinlock serialising [`global_mut`] access.  Uses the same
/// exponential-backoff pattern as [`SpinLock`](crate::kernel::sync::SpinLock)
/// but without interrupt save/restore — the callerʼs interrupt state is
/// preserved across the critical section.
static MEMORY_MANAGER_LOCK: AtomicBool = AtomicBool::new(false);

/// RAII guard returned by [`global_mut`].
///
/// Holds the memory-manager lock and dereferences to `&mut MemoryManager`.
/// Dropping the guard releases the lock so the other CPU can proceed.
///
/// Uses [`UnsafeCell`] internally so that [`DerefMut`](core::ops::DerefMut)
/// works through `&self` — callers do not need to declare the guard `mut`.
pub(crate) struct MemoryManagerGuard {
    manager: UnsafeCell<&'static mut MemoryManager>,
    locked: bool,
}

impl core::ops::Deref for MemoryManagerGuard {
    type Target = MemoryManager;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.manager.get() }
    }
}

impl core::ops::DerefMut for MemoryManagerGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.manager.get() }
    }
}

impl Drop for MemoryManagerGuard {
    fn drop(&mut self) {
        if self.locked {
            MEMORY_MANAGER_LOCK.store(false, Ordering::Release);
            self.locked = false;
        }
    }
}

// SAFETY: the guard is safe to send across CPU boundaries because the
// underlying lock serialises all access — only one CPU holds the guard at
// any time.  MemoryManager itself is !Send (contains raw pointers), but the
// guard only hands out &mut references that are valid on the owning CPU.
unsafe impl Send for MemoryManagerGuard {}

/// # Safety
///
/// The caller must guarantee `memory` outlives every future `global()` or
/// `global_mut()` access.
pub(crate) unsafe fn install_global_unchecked(memory: &MemoryManager) {
    GLOBAL_MEMORY_MANAGER.store(memory as *const _ as *mut _, Ordering::SeqCst);
}

/// Install a global memory-manager reference for integration tests.
///
/// The provided `MemoryManager` must be leaked or otherwise live for the
/// remainder of the process.
///
/// # Safety
///
/// Same lifetime constraints as [`install_global_unchecked`].
pub unsafe fn install_global_for_tests(memory: &MemoryManager) {
    GLOBAL_MEMORY_MANAGER.store(memory as *const _ as *mut _, Ordering::SeqCst);
}

pub(crate) fn global() -> Option<&'static MemoryManager> {
    let memory = GLOBAL_MEMORY_MANAGER.load(Ordering::SeqCst);
    unsafe { memory.as_ref() }
}

/// SMP-safe mutable accessor for the global memory manager.
///
/// On SMP systems both CPUs may call this concurrently (e.g. the BSP
/// spawning kernel threads while the AP creates its idle thread).  The
/// returned [`MemoryManagerGuard`] holds an exponential-backoff spinlock
/// so only one CPU executes inside the memory manager at a time.
pub(crate) fn global_mut() -> Option<MemoryManagerGuard> {
    // Acquire the memory-manager spinlock with exponential backoff.
    let mut backoff: u32 = 1;
    while MEMORY_MANAGER_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        while MEMORY_MANAGER_LOCK.load(Ordering::Relaxed) {
            for _ in 0..backoff.min(64) {
                core::hint::spin_loop();
            }
            backoff = backoff.saturating_mul(2).min(1024);
        }
        // Lock just became free — reset backoff for fairness.
        backoff = 1;
    }
    let memory = GLOBAL_MEMORY_MANAGER.load(Ordering::SeqCst);
    if memory.is_null() {
        MEMORY_MANAGER_LOCK.store(false, Ordering::Release);
        None
    } else {
        Some(MemoryManagerGuard {
            manager: UnsafeCell::new(unsafe { &mut *memory }),
            locked: true,
        })
    }
}

/// Public accessor for integration tests (single-threaded, no locking).
pub fn global_mut_for_tests() -> Option<&'static mut MemoryManager> {
    let memory = GLOBAL_MEMORY_MANAGER.load(Ordering::SeqCst);
    unsafe { memory.as_mut() }
}
