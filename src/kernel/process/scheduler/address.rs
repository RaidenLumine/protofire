//! src/kernel/process/scheduler/address.rs
//!
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

    pub(crate) fn activate_thread_address_space(&self, thread: &Arc<Thread>) -> bool {
        crate::arch::dispatch::entering_thread(thread);

        // A bare-metal machine has page tables to switch; a host has none, and
        // the caller only asks whether the switch happened.
        #[cfg(target_os = "none")]
        {
            let activated = thread.process().activate_address_space_for_thread();
            // A user thread that ends up on the kernel root is about to `sret`
            // into a page it cannot execute: the kernel root maps the demo
            // slots as supervisor blocks, so the first fetch faults, and the
            // trap reports an instruction page fault in the payload rather than
            // the dispatch failure that caused it. Say so at the dispatch that
            // did it, where the thread and its state are still known.
            if thread.user_start().is_some() && !thread.process().has_user_address_space() {
                crate::println!(
                    "[sched ] dispatching a user thread with no address space pid={} tid={}",
                    thread.pid(),
                    thread.tid()
                );
            }
            activated
        }
        #[cfg(not(target_os = "none"))]
        {
            true
        }
    }

    pub(crate) fn restore_kernel_address_space(&self) {
        #[cfg(target_os = "none")]
        let _ = crate::arch::mmu::activate_prepared_runtime_kernel_page_tables();
    }
}
