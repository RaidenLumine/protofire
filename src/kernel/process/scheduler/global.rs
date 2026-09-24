//! src/kernel/process/scheduler/global.rs
//!
//! Global scheduler installation and lookup.

use alloc::sync::Arc;

use super::super::Thread;

#[cfg(test)]
use super::clear_thread_local_scheduler_slot;
use super::load_current_scheduler_ptr;
#[cfg(not(target_os = "none"))]
use super::store_current_scheduler_ptr;
use super::Scheduler;

impl Scheduler {
    pub fn current_thread(&self) -> Option<Arc<Thread>> {
        self.current.lock().clone()
    }

    pub fn install_global(&'static self) {
        // SAFETY: a `'static` scheduler outlives every future `global()` call,
        // which is exactly the guarantee the unchecked form asks for.
        unsafe { self.install_global_unchecked() };
    }

    /// # Safety
    ///
    /// The caller must guarantee that the scheduler outlives every future
    /// [`global()`] access — the pointer is stashed without a lifetime guard.
    /// Prefer [`install_global`] whenever a `'static` reference is available.
    pub unsafe fn install_global_unchecked(&self) {
        let ptr = self as *const Self as *mut Self;
        // The per-CPU slot is the one `global()` reads on bare metal: which
        // scheduler is running is a property of the CPU, and a machine with
        // several of them must not have them overwrite each other.
        crate::kernel::percpu::set_current_scheduler(ptr);
        // A target with no per-CPU register has nowhere else to put it; there
        // the shared slot is what `global()` falls back to.
        #[cfg(not(target_os = "none"))]
        store_current_scheduler_ptr(ptr);
    }

    pub fn global() -> Option<&'static Self> {
        let percpu_ptr = crate::kernel::percpu::current_scheduler_ptr();
        if !percpu_ptr.is_null() {
            // SAFETY: the pointer was installed by this CPU with itself as a
            // `'static` scheduler, and is cleared only when that scheduler is
            // dropped — which a CPU does not do to itself mid-schedule.
            return unsafe { percpu_ptr.as_ref() };
        }
        // No per-CPU slot to read: either the target has no per-CPU register,
        // or this CPU has not entered the scheduler yet.
        let scheduler = load_current_scheduler_ptr();
        // SAFETY: as above, through the single shared slot.
        unsafe { scheduler.as_ref() }
    }

    #[cfg(test)]
    pub fn clear_thread_local_scheduler() {
        clear_thread_local_scheduler_slot();
    }
}
