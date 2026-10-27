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
            thread.process().activate_address_space_for_thread()
        }
        #[cfg(not(target_os = "none"))]
        {
            true
        }
    }

    pub(crate) fn restore_kernel_address_space(&self) {
        #[cfg(target_os = "none")]
        {
            // Record who asked, so a later trap can say which path replaced a
            // user thread's root.  The seven call sites all look alike from a
            // trap frame; the return address does not.
            let caller = riscv64_caller_address();
            crate::arch::mmu::note_kernel_restore_caller(caller);
            let _ = crate::arch::mmu::activate_prepared_runtime_kernel_page_tables();
        }
    }
}

/// The address this function was called from, as the architecture can see it.
#[cfg(target_os = "none")]
fn riscv64_caller_address() -> usize {
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        let ra: usize;
        // SAFETY: reading the return-address register the ABI reserves for it;
        // no memory is touched.
        unsafe {
            core::arch::asm!("mv {ra}, ra", ra = out(reg) ra, options(nomem, nostack, preserves_flags));
        }
        ra
    }
    #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
    {
        0
    }
}
