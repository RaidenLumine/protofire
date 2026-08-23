//! src/arch/syscall_trap.rs
//! Post-syscall user-context capture policy shared by every architecture's
//! syscall trap path.
//!
//! Each trap handler dispatches the syscall, then needs to decide *when* the
//! saved user context must be captured back into the thread.  Most actions are
//! side effects on kernel state and the capture can happen immediately
//! (`BeforePostAction`); `ExecProcess` rewrites the user image, so the capture
//! must be deferred until after the new image has been applied.

use crate::kernel::syscall::SyscallAction;
use crate::{Error, Result};

/// Whether the user context should be captured before the post-action is
/// applied, or only after `ExecProcess` has replaced the user image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserContextCapturePoint {
    BeforePostAction,
    AfterExecProcessApply,
}

/// Where the user context must be captured for a given post-syscall action.
pub const fn user_context_capture_point(post_action: SyscallAction) -> UserContextCapturePoint {
    match post_action {
        SyscallAction::ExecProcess => UserContextCapturePoint::AfterExecProcessApply,
        SyscallAction::None
        | SyscallAction::Yield
        | SyscallAction::Exit { .. }
        | SyscallAction::ReturnFromException { .. } => UserContextCapturePoint::BeforePostAction,
        SyscallAction::SigReturn => UserContextCapturePoint::BeforePostAction,
    }
}

/// Outcome of trying to resume a suspended user exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnFromExceptionResolution {
    ReturnToUser,
    SetError(Error),
}

/// Translate the result of `Thread::resume_*_user_exception` into the trap
/// path's action: resume directly to user mode, or surface an error.
pub fn resolve_return_from_exception_resume(
    resume_result: Result<bool>,
) -> ReturnFromExceptionResolution {
    match resume_result {
        Ok(true) => ReturnFromExceptionResolution::ReturnToUser,
        Ok(false) => ReturnFromExceptionResolution::SetError(Error::InternalError),
        Err(error) => ReturnFromExceptionResolution::SetError(error),
    }
}

/// Outcome of applying the new image for `ExecProcess` before returning to
/// user mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecProcessApplyResolution {
    CaptureUserContext,
    SetErrorAndCaptureUserContext(Error),
}

/// Translate the result of `Thread::write_*_user_context_to_*` for the
/// `ExecProcess` path.  On success the caller captures the context; on error
/// it still captures (the frame holds the pre-exec user state) but records the
/// error in the return register.
pub fn resolve_exec_process_apply_result(apply_result: Result<()>) -> ExecProcessApplyResolution {
    match apply_result {
        Ok(()) => ExecProcessApplyResolution::CaptureUserContext,
        Err(error) => ExecProcessApplyResolution::SetErrorAndCaptureUserContext(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        resolve_exec_process_apply_result, resolve_return_from_exception_resume,
        user_context_capture_point, ExecProcessApplyResolution, ReturnFromExceptionResolution,
        UserContextCapturePoint,
    };
    use crate::kernel::syscall::SyscallAction;
    use crate::Error;

    #[test]
    fn user_context_capture_point_keeps_side_effect_actions_before_post_action() {
        assert_eq!(
            user_context_capture_point(SyscallAction::None),
            UserContextCapturePoint::BeforePostAction
        );
        assert_eq!(
            user_context_capture_point(SyscallAction::Yield),
            UserContextCapturePoint::BeforePostAction
        );
        assert_eq!(
            user_context_capture_point(SyscallAction::Exit { status: 7 }),
            UserContextCapturePoint::BeforePostAction
        );
        assert_eq!(
            user_context_capture_point(SyscallAction::ReturnFromException {
                frame_pointer: 0x7000,
            }),
            UserContextCapturePoint::BeforePostAction
        );
    }

    #[test]
    fn user_context_capture_point_defers_exec_process_until_context_apply() {
        assert_eq!(
            user_context_capture_point(SyscallAction::ExecProcess),
            UserContextCapturePoint::AfterExecProcessApply
        );
    }

    #[test]
    fn resolve_return_from_exception_maps_ok_true_to_return_to_user() {
        assert_eq!(
            resolve_return_from_exception_resume(Ok(true)),
            ReturnFromExceptionResolution::ReturnToUser
        );
    }

    #[test]
    fn resolve_return_from_exception_maps_missing_frame_to_internal_error() {
        assert_eq!(
            resolve_return_from_exception_resume(Ok(false)),
            ReturnFromExceptionResolution::SetError(Error::InternalError)
        );
    }

    #[test]
    fn resolve_return_from_exception_maps_error_verbatim() {
        assert_eq!(
            resolve_return_from_exception_resume(Err(Error::InvalidArgument)),
            ReturnFromExceptionResolution::SetError(Error::InvalidArgument)
        );
    }

    #[test]
    fn resolve_exec_process_apply_ok_captures_user_context() {
        assert_eq!(
            resolve_exec_process_apply_result(Ok(())),
            ExecProcessApplyResolution::CaptureUserContext
        );
    }

    #[test]
    fn resolve_exec_process_apply_error_sets_error_and_captures() {
        assert_eq!(
            resolve_exec_process_apply_result(Err(Error::InternalError)),
            ExecProcessApplyResolution::SetErrorAndCaptureUserContext(Error::InternalError)
        );
    }
}
