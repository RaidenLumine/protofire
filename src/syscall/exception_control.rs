//! src/syscall/exception_control.rs
//!
//! Exception-handler install/return syscalls and frame-pointer safety checks.

use crate::Error;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UserExceptionFrameLayout {
    len: usize,
    align: usize,
}

pub(super) fn install_handler(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 4)?;

    let vector = context.arg(0) as u8;
    let handler = context.arg(1);
    let stack_pointer = context.arg(2);
    let flags = context.arg(3);

    super::runtime::with_current_thread(|thread| {
        thread.install_user_exception_handler(vector, handler, stack_pointer, flags)
    })?;
    Ok(super::SyscallDispatch::complete(0))
}

pub(super) fn return_from_exception(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 1)?;

    let frame_pointer = context.arg(0);
    validate_return_from_exception_frame_pointer(frame_pointer)?;

    Ok(super::SyscallDispatch::return_from_exception(frame_pointer))
}

fn validate_return_from_exception_frame_pointer(frame_pointer: usize) -> Result<()> {
    super::runtime::current_thread()?;
    let frame_layout = current_arch_user_exception_frame_layout()?;
    validate_return_from_exception_frame_pointer_shape(frame_pointer, frame_layout)?;

    super::user_memory::validate_current_process_user_input_buffer(
        frame_pointer as *const u8,
        frame_layout.len,
        frame_layout.len,
    )
}

fn validate_return_from_exception_frame_pointer_shape(
    frame_pointer: usize,
    frame_layout: UserExceptionFrameLayout,
) -> Result<()> {
    if frame_pointer == 0 {
        return Err(Error::InvalidArgument);
    }

    // Require ABI alignment so frame decoding is stable across architectures.
    if !frame_pointer.is_multiple_of(frame_layout.align) {
        return Err(Error::InvalidArgument);
    }

    // Reject pointer arithmetic overflow before user-memory probing.
    frame_pointer
        .checked_add(frame_layout.len)
        .ok_or(Error::InvalidArgument)?;

    Ok(())
}

/// The frame this machine delivers, as the syscall layer needs it: the size
/// and alignment a user pointer to one is validated against.
///
/// Which frame that is — and whether there is one at all — is the machine's
/// answer, from `crate::arch::thread`.
fn current_arch_user_exception_frame_layout() -> Result<UserExceptionFrameLayout> {
    let (len, align) =
        crate::arch::thread::user_exception_frame_layout().ok_or(Error::Unsupported)?;
    Ok(UserExceptionFrameLayout { len, align })
}

#[cfg(test)]
mod tests {
    use super::validate_return_from_exception_frame_pointer_shape;
    use super::UserExceptionFrameLayout;
    use crate::Error;
    use crate::Result;

    #[test]
    fn return_frame_pointer_shape_rejects_zero_pointer() {
        assert_shape(0, sample_layout(), Err(Error::InvalidArgument));
    }

    #[test]
    fn return_frame_pointer_shape_rejects_misaligned_pointer() {
        assert_shape(0x1008, sample_layout(), Err(Error::InvalidArgument));
    }

    #[test]
    fn return_frame_pointer_shape_rejects_pointer_overflow() {
        assert_shape(
            usize::MAX - 7,
            UserExceptionFrameLayout { len: 16, align: 1 },
            Err(Error::InvalidArgument),
        );
    }

    #[test]
    fn return_frame_pointer_shape_accepts_aligned_in_range_pointer() {
        assert_shape(0x1000, sample_layout(), Ok(()));
    }

    fn sample_layout() -> UserExceptionFrameLayout {
        UserExceptionFrameLayout { len: 64, align: 16 }
    }

    fn assert_shape(
        frame_pointer: usize,
        frame_layout: UserExceptionFrameLayout,
        expected: Result<()>,
    ) {
        assert_eq!(
            validate_return_from_exception_frame_pointer_shape(frame_pointer, frame_layout),
            expected
        );
    }
}
