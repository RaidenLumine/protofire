//! src/arch/dispatch.rs
//!
//! What the CPU needs told before it runs a thread.
//!
//! Switching between threads is the scheduler's, and so is deciding which
//! address space a thread should run in.  What is *not* the scheduler's is the
//! register or descriptor an architecture keeps outside the page-table
//! switch: x86_64 has to be handed the kernel stack top through the TSS
//! before the switch happens, and a machine with no such thing has nothing to
//! say.  The scheduler asks here rather than naming an architecture.

use crate::kernel::process::Thread;

/// Tell this CPU about the thread it is about to run, where it needs telling.
///
/// x86_64 records the thread's kernel stack top in the TSS, so the first
/// interrupt or exception that lands after the switch pushes onto the right
/// stack.  The other architectures carry that in a register or a descriptor
/// the switch itself updates, so there is nothing to do here.
pub(crate) fn entering_thread(thread: &Thread) {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    crate::arch::x86_64::gdt::set_kernel_stack_top(thread.kernel_stack_top());

    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    let _ = thread;
}
