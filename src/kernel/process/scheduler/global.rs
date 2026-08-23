//! src/kernel/process/scheduler/global.rs
//! Global scheduler installation and lookup.
use alloc::sync::Arc;

use super::super::Thread;

#[cfg(test)]
use super::clear_thread_local_scheduler_slot;
use super::Scheduler;
use super::{load_current_scheduler_ptr, store_current_scheduler_ptr};

impl Scheduler {
    pub fn current_thread(&self) -> Option<Arc<Thread>> {
        self.current.lock().clone()
    }

    pub fn install_global(&'static self) {
        store_current_scheduler_ptr(self as *const Self as *mut Self);
    }

    /// # Safety
    ///
    /// The caller must guarantee that the scheduler outlives every future
    /// [`global()`] access — the pointer is stashed without a lifetime guard.
    /// Prefer [`install_global`] whenever a `'static` reference is available.
    pub unsafe fn install_global_unchecked(&self) {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            crate::kernel::percpu::set_current_scheduler(self as *const Self as *mut Self);
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
        {
            store_current_scheduler_ptr(self as *const Self as *mut Self);
            crate::kernel::percpu::set_current_scheduler(self as *const Self as *mut Self);
        }
    }

    pub fn global() -> Option<&'static Self> {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            let percpu_ptr = crate::kernel::percpu::current_scheduler_ptr();
            if !percpu_ptr.is_null() {
                return unsafe { percpu_ptr.as_ref() };
            }
        }
        let scheduler = load_current_scheduler_ptr();
        unsafe { scheduler.as_ref() }
    }

    #[cfg(test)]
    pub fn clear_thread_local_scheduler() {
        clear_thread_local_scheduler_slot();
    }
}
