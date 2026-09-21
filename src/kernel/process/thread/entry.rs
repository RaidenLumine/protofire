//! src/kernel/process/thread/entry.rs
//!
//! Thread entry-point helpers: instruction pointer selection, kernel-stack
//! frame initialization, and the unsupported-user-mode fallback.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use ::core::mem::size_of;

use super::types::UserThreadStart;

pub(crate) fn initial_instruction_pointer(
    _entry_point: usize,
    _user_start: Option<UserThreadStart>,
) -> usize {
    #[cfg(all(
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ),
        target_os = "none"
    ))]
    {
        super::super::scheduler::thread_trampoline as *const () as usize
    }

    #[cfg(not(all(
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ),
        target_os = "none"
    )))]
    {
        // Host / non-bare-metal builds cannot run user-mode threads, so there
        // is no unsupported-start redirect anymore: a thread just begins at its
        // requested entry point like any other host thread.
        _entry_point
    }
}

pub(crate) fn initialize_frame_kernel_stack(
    _stack_ptr: *mut u8,
    _stack_len: usize,
    stack_top: usize,
) -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        let initial_stack_pointer = (stack_top & !0xF).saturating_sub(size_of::<usize>());
        unsafe {
            *(initial_stack_pointer as *mut usize) = 0;
        }
        initial_stack_pointer
    }

    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    {
        let _ = _stack_ptr;
        let _ = _stack_len;
        // Leave room for the deepest frame the exception entry can save.
        //
        // `stack_top` is exclusive: the first address past the usable stack.
        // Returning it as the initial SP leaves the vector stub nowhere to
        // put its 304-byte frame — it subtracts that much and stores at
        // `sp + offset`, and the upper slots land past the mapped end.  A
        // margin of exactly one frame means the entry always fits, and it
        // stays inside the mapped region because the region ends at
        // `stack_top`.
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            (stack_top & !0xF).saturating_sub(crate::arch::aarch64::trap::EXCEPTION_FRAME_BYTES)
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        {
            stack_top & !0xF
        }
    }
}
