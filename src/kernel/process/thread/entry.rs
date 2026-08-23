//! src/kernel/process/thread/entry.rs
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
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    ))]
    {
        super::super::scheduler::thread_trampoline as *const () as usize
    }

    #[cfg(not(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    )))]
    {
        if _user_start.is_some() {
            unsupported_user_thread_entry as *const () as usize
        } else {
            _entry_point
        }
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
        stack_top & !0xF
    }
}

#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_os = "none"
)))]
pub(crate) fn unsupported_user_thread_entry() {
    crate::println!("[user  ] user-mode threads are only executable on bare-metal targets");
}
