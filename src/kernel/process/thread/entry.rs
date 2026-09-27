//! src/kernel/process/thread/entry.rs
//!
//! Thread entry-point helpers: instruction pointer selection, kernel-stack
//! frame initialization, and the unsupported-user-mode fallback.

use super::types::UserThreadStart;

pub(crate) fn initial_instruction_pointer(
    _entry_point: usize,
    _user_start: Option<UserThreadStart>,
) -> usize {
    // Every bare-metal target starts a thread at the trampoline that builds
    // the first frame; the list of architectures here was the list of targets
    // this crate has, written out.  What the code means is "bare metal".
    #[cfg(target_os = "none")]
    {
        super::super::scheduler::thread_trampoline as *const () as usize
    }

    #[cfg(not(target_os = "none"))]
    {
        // Host / non-bare-metal builds cannot run user-mode threads, so there
        // is no unsupported-start redirect anymore: a thread just begins at its
        // requested entry point like any other host thread.
        _entry_point
    }
}

/// Where the first kernel frame starts, for this machine.
pub(crate) fn initial_kernel_stack_pointer(stack_top: usize) -> usize {
    crate::arch::thread::initial_kernel_stack_pointer(stack_top)
}
