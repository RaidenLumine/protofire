//! src/kernel/syscall/memory/brk.rs
//! Brk syscall handler — program break for userspace heap.

use crate::kernel::process::Process;
use crate::user::program::USER_PAGE_SIZE;
use crate::Result;

/// Userspace heap is placed between the loaded image (typically ending
/// around 0x40_2000) and the stack guard page.  We use conservative bounds
/// that leave room for the stack and its guard.
const HEAP_MAX: usize = 0x7F00_0000_0000;

pub(super) fn brk(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 1)?;
    let new_break = context.arg(0);

    super::runtime::with_current_process(|process: &Process| {
        let current_break = process.program_break();
        let break_val = if new_break == 0 {
            // brk(0) — query current break.  If unset, default to a
            // reasonable starting break just past the typical image.
            if current_break == 0 {
                let default_break = 0x40_2000;
                process.set_program_break(default_break);
                default_break
            } else {
                current_break
            }
        } else {
            // Validate: must be page-aligned.
            if new_break & (USER_PAGE_SIZE - 1) != 0 {
                return Err(crate::Error::InvalidArgument);
            }
            // Validate: must be at or above the current break (no shrink).
            if new_break < current_break {
                return Err(crate::Error::InvalidArgument);
            }
            // Validate: must fit within the userspace heap region.
            if new_break > HEAP_MAX {
                return Err(crate::Error::OutOfMemory);
            }
            process.set_program_break(new_break);
            new_break
        };
        Ok(super::SyscallDispatch::complete(break_val))
    })
}
