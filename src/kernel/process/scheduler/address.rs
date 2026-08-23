//! src/kernel/process/scheduler/address.rs
//! Address space management for dispatch.

use alloc::sync::Arc;

use super::super::Thread;
use super::queue::thread_has_dispatch_address_space;
use super::Scheduler;

impl Scheduler {
    pub(crate) fn prepare_thread_address_space_for_dispatch(&self, thread: &Arc<Thread>) -> bool {
        if !thread_has_dispatch_address_space(thread) {
            return false;
        }

        self.activate_thread_address_space(thread)
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    ))]
    pub(crate) fn activate_thread_address_space(&self, thread: &Arc<Thread>) -> bool {
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::gdt::set_kernel_stack_top(thread.kernel_stack_top());
        let activated = thread.process().activate_address_space_for_thread();
        let current_gen = thread.process().current_address_space_generation();
        if activated {
            thread.set_active_address_space_generation(current_gen);
        }
        activated
    }

    #[cfg(not(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    )))]
    pub(crate) fn activate_thread_address_space(&self, _thread: &Arc<Thread>) -> bool {
        true
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    ))]
    pub(crate) fn restore_kernel_address_space(&self) {
        let _ = crate::arch::mmu::activate_prepared_runtime_kernel_page_tables();
    }

    #[cfg(not(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    )))]
    pub(crate) fn restore_kernel_address_space(&self) {}
}
