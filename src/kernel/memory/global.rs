//! src/kernel/memory/global.rs
//!
//! Global memory-manager singleton, exponential-backoff lock, and accessors.

use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use super::manager::MemoryManager;

pub(crate) static GLOBAL_MEMORY_MANAGER: AtomicPtr<MemoryManager> = AtomicPtr::new(ptr::null_mut());

/// Spinlock serialising [`global_mut`] access, with the same
/// exponential-backoff pattern as [`SpinLock`](crate::kernel::sync::SpinLock).
///
/// Interrupts are disabled for the duration, exactly as `SpinLock` does, and
/// that is load-bearing rather than tidiness.  Holding this lock with
/// interrupts enabled makes the holder preemptible, and on a single CPU that
/// wedges the machine:
///
/// 1. A thread takes this lock and is then preempted by the timer, which is
///    allowed because nothing masked interrupts.  The thread goes back on the
///    ready queue still holding the lock.
/// 2. Another thread takes a `sync::Mutex` — which *does* disable interrupts —
///    and calls [`global_mut`] from inside it.  `Vec::push` growing a buffer,
///    or any other path into the frame allocator, is enough to get here.
/// 3. That thread now spins on this lock with interrupts disabled.  The holder
///    can never be rescheduled, because rescheduling needs the timer, and the
///    timer needs interrupts.  The spin is permanent and the machine goes
///    silent.
///
/// Keeping the two lock families on the same discipline — interrupts off for
/// the whole critical section — removes step 1 and with it the wedge.
static MEMORY_MANAGER_LOCK: AtomicBool = AtomicBool::new(false);

/// Id recorded in [`MEMORY_MANAGER_LOCK_OWNER`] while no CPU holds the lock.
const NO_CPU: u32 = u32::MAX;

/// Id of the CPU executing this code.
///
/// Reads the per-CPU data, which [`crate::util::debug`] already reads on every
/// printed line, so it is safe wherever the console is.
fn current_cpu() -> u32 {
    crate::kernel::percpu::get().cpu_id
}

/// Which CPU holds a lock, or [`NO_CPU`] while it is free.
///
/// A plain `AtomicBool` cannot answer the one question a fault handler has to
/// ask: whether the lock it cannot take is *this* CPU's own.  Waiting for a
/// lock another CPU holds is ordinary contention that ends; waiting for one
/// this CPU holds is a deadlock that never does, because the guard that would
/// release it is below the frame doing the waiting.
pub(crate) struct LockOwner {
    owner: AtomicU32,
}

impl LockOwner {
    pub(crate) const fn new() -> Self {
        Self {
            owner: AtomicU32::new(NO_CPU),
        }
    }

    /// Record that this CPU has taken the lock.
    pub(crate) fn acquired(&self) {
        self.owner.store(current_cpu(), Ordering::Relaxed);
    }

    /// Record that the lock is free again.
    pub(crate) fn released(&self) {
        // Release rather than Relaxed: the next acquirer must not be able to
        // read the owner as still naming the previous holder after it has
        // taken the lock.
        self.owner.store(NO_CPU, Ordering::Release);
    }

    /// Whether the lock is held by the CPU running this code.
    pub(crate) fn held_by_current_cpu(&self) -> bool {
        self.owner.load(Ordering::Relaxed) == current_cpu()
    }

    /// The raw recorded owner, for tests that need to name a *different* CPU.
    #[cfg(test)]
    pub(crate) fn owner_for_tests(&self) -> u32 {
        self.owner.load(Ordering::Relaxed)
    }

    /// Set the recorded owner directly, for tests that need to name a
    /// *different* CPU — something [`acquired`](Self::acquired) cannot do,
    /// since it always records the CPU it runs on.
    #[cfg(test)]
    pub(crate) fn set_owner_for_tests(&self, cpu: u32) {
        self.owner.store(cpu, Ordering::Relaxed);
    }

    /// The value meaning "no CPU holds this".
    #[cfg(test)]
    pub(crate) const FREE: u32 = NO_CPU;
}

/// CPU currently inside the memory-manager critical section.
static MEMORY_MANAGER_LOCK_OWNER: LockOwner = LockOwner::new();

/// Whether *this* CPU is already inside a [`global_mut`] critical section.
///
/// A caller that can observe this must not try to take the lock.  The guard
/// that would release it lives on this CPU's stack, below the current frame,
/// so it cannot run until this frame returns — and this frame would be waiting
/// for exactly that.  With interrupts masked, as [`global_mut`] now leaves
/// them, nothing can break the cycle either.
///
/// The one caller that needs this is the x86_64 page-fault handler: it cannot
/// resolve a fault until it holds the memory manager, and the fault may well
/// have been raised *by* the critical section it would have to wait for.
pub(crate) fn held_by_current_cpu() -> bool {
    MEMORY_MANAGER_LOCK_OWNER.held_by_current_cpu()
}

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
    /// Whether interrupts were enabled when the lock was taken, so that
    /// dropping the guard restores the caller's state rather than
    /// unconditionally enabling them.
    interrupts_were_enabled: bool,
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
            // Clear the owner before releasing, so the next acquirer never
            // sees the lock free while it still names the previous holder.
            MEMORY_MANAGER_LOCK_OWNER.released();
            MEMORY_MANAGER_LOCK.store(false, Ordering::Release);
            self.locked = false;
            // Release before restoring: the next acquirer must not observe the
            // lock as held while this CPU still has interrupts masked.
            crate::arch::interrupts::restore(self.interrupts_were_enabled);
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

/// Return the global slot to its "no memory manager" state.
///
/// Only for tests that install one to exercise the accessors: the library's
/// unit tests share a process, so a test that installs a manager must put the
/// slot back rather than leave it pointing at its own stack frame.
#[cfg(test)]
pub(crate) fn uninstall_global_for_tests() {
    GLOBAL_MEMORY_MANAGER.store(ptr::null_mut(), Ordering::SeqCst);
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
    // Mask interrupts before spinning, so a holder on this CPU cannot be
    // preempted and can always finish.  See `MEMORY_MANAGER_LOCK`.
    let interrupts_were_enabled = crate::arch::interrupts::save_and_disable();

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
        crate::arch::interrupts::restore(interrupts_were_enabled);
        None
    } else {
        MEMORY_MANAGER_LOCK_OWNER.acquired();
        Some(MemoryManagerGuard {
            manager: UnsafeCell::new(unsafe { &mut *memory }),
            locked: true,
            interrupts_were_enabled,
        })
    }
}

/// Take the lock only if it is free, never waiting for it.
///
/// Used by diagnostics that must not be able to stall the path reporting them
/// — the fault profiler counters in the exception handlers.  A missed
/// increment costs a number in a report; waiting there can cost the machine.
///
/// Returns `None` when the lock is held, by this CPU or another, and when no
/// memory manager is installed.
pub(crate) fn try_global_mut() -> Option<MemoryManagerGuard> {
    // Mask first, then make the one attempt, so a holder here is never
    // preemptible — the same discipline as `global_mut`, just without a loop.
    let interrupts_were_enabled = crate::arch::interrupts::save_and_disable();

    if MEMORY_MANAGER_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        crate::arch::interrupts::restore(interrupts_were_enabled);
        return None;
    }

    let memory = GLOBAL_MEMORY_MANAGER.load(Ordering::SeqCst);
    if memory.is_null() {
        MEMORY_MANAGER_LOCK.store(false, Ordering::Release);
        crate::arch::interrupts::restore(interrupts_were_enabled);
        return None;
    }

    MEMORY_MANAGER_LOCK_OWNER.acquired();
    Some(MemoryManagerGuard {
        manager: UnsafeCell::new(unsafe { &mut *memory }),
        locked: true,
        interrupts_were_enabled,
    })
}

/// Public accessor for integration tests (single-threaded, no locking).
pub fn global_mut_for_tests() -> Option<&'static mut MemoryManager> {
    let memory = GLOBAL_MEMORY_MANAGER.load(Ordering::SeqCst);
    unsafe { memory.as_mut() }
}
