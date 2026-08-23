//! src/kernel/process/thread/exception.rs
//! Architecture-generic user-exception delivery: frame layout, stack-pointer
//! selection, nested-delivery policies, and per-arch delivery builders.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
use crate::{Error, Result};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
use ::core::mem::size_of;

#[cfg(target_arch = "aarch64")]
use super::arch_aarch64::{
    AArch64UserExceptionFrame, AArch64UserThreadContext, AARCH64_EXCEPTION_DATA_ABORT_VECTOR,
    AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR, AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};
#[cfg(target_arch = "x86_64")]
use super::arch_x86_64::{
    X86_64UserExceptionFrame, X86_64UserThreadContext, X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR,
    X86_64_EXCEPTION_INVALID_OPCODE_VECTOR, X86_64_EXCEPTION_PAGE_FAULT_VECTOR,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED, X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
use super::types::is_canonical_user_address;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
use super::types::{PendingExceptionFrameStack, UserPendingExceptionFrame};

// ── Arch-specific delivery builders ─────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub(crate) fn build_x86_64_exception_delivery(
    resume_context: X86_64UserThreadContext,
    exception_stack_pointer: Option<usize>,
    require_exception_stack: bool,
    vector: u8,
    error_code: u64,
    fault_address: Option<usize>,
    handler: usize,
) -> Result<(usize, X86_64UserExceptionFrame, X86_64UserThreadContext)> {
    build_user_exception_delivery(
        UserExceptionDeliveryBuildSpec {
            resume_stack_pointer: resume_context.stack_pointer as usize,
            exception_stack_pointer,
            require_exception_stack,
            frame_size: size_of::<X86_64UserExceptionFrame>(),
            handler,
        },
        resume_context,
        |resume_context| {
            X86_64UserExceptionFrame::from_user_context(
                resume_context,
                vector,
                error_code,
                fault_address.unwrap_or(0),
            )
        },
        |handler_context, handler, frame_pointer| {
            // The handler starts with the synthetic exception frame as both
            // its stack top and first argument, matching the public user
            // exception ABI.
            handler_context.instruction_pointer = handler as u64;
            handler_context.stack_pointer = frame_pointer as u64;
            handler_context.rdi = frame_pointer as u64;
        },
    )
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn build_aarch64_exception_delivery(
    resume_context: AArch64UserThreadContext,
    exception_stack_pointer: Option<usize>,
    require_exception_stack: bool,
    vector: u8,
    error_code: u64,
    fault_address: Option<usize>,
    handler: usize,
) -> Result<(usize, AArch64UserExceptionFrame, AArch64UserThreadContext)> {
    build_user_exception_delivery(
        UserExceptionDeliveryBuildSpec {
            resume_stack_pointer: resume_context.stack_pointer as usize,
            exception_stack_pointer,
            require_exception_stack,
            frame_size: size_of::<AArch64UserExceptionFrame>(),
            handler,
        },
        resume_context,
        |resume_context| {
            AArch64UserExceptionFrame::from_user_context(
                resume_context,
                vector,
                error_code,
                fault_address.unwrap_or(0),
            )
        },
        |handler_context, handler, frame_pointer| {
            // The handler starts with the synthetic exception frame as both
            // its stack top and first argument, matching the public user
            // exception ABI.
            handler_context.instruction_pointer = handler as u64;
            handler_context.stack_pointer = frame_pointer as u64;
            handler_context.x0 = frame_pointer as u64;
        },
    )
}

// ── Generic delivery helpers ────────────────────────────────────────────

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
pub(crate) const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UserExceptionDeliveryBuildSpec {
    resume_stack_pointer: usize,
    exception_stack_pointer: Option<usize>,
    require_exception_stack: bool,
    frame_size: usize,
    handler: usize,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn build_user_exception_delivery<Context: Copy, Frame>(
    spec: UserExceptionDeliveryBuildSpec,
    resume_context: Context,
    build_frame: impl FnOnce(Context) -> Frame,
    configure_handler_context: impl FnOnce(&mut Context, usize, usize),
) -> Result<(usize, Frame, Context)> {
    let frame_pointer = compute_user_exception_frame_pointer(
        spec.resume_stack_pointer,
        spec.exception_stack_pointer,
        spec.require_exception_stack,
        spec.frame_size,
    )?;

    let frame = build_frame(resume_context);
    let mut handler_context = resume_context;
    configure_handler_context(&mut handler_context, spec.handler, frame_pointer);
    Ok((frame_pointer, frame, handler_context))
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn compute_user_exception_frame_pointer(
    resume_stack_pointer: usize,
    exception_stack_pointer: Option<usize>,
    require_exception_stack: bool,
    frame_size: usize,
) -> Result<usize> {
    let delivery_stack_top = match exception_stack_pointer {
        Some(stack_pointer) => stack_pointer,
        None if require_exception_stack => return Err(Error::InvalidArgument),
        None => resume_stack_pointer,
    };
    let frame_pointer = align_down(
        delivery_stack_top
            .checked_sub(frame_size)
            .ok_or(Error::OutOfMemory)?,
        16,
    );

    if frame_pointer == 0 || !is_canonical_user_address(frame_pointer) {
        return Err(Error::InvalidArgument);
    }

    Ok(frame_pointer)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn validate_user_exception_handler_registration(
    handler: usize,
    stack_pointer: usize,
    flags: usize,
    supported_flags: usize,
    allows_nested: bool,
    requires_exception_stack: bool,
    has_thread_exception_stack: bool,
) -> Result<Option<usize>> {
    if flags & !supported_flags != 0 {
        return Err(Error::InvalidArgument);
    }

    if !is_canonical_user_address(handler) {
        return Err(Error::InvalidArgument);
    }

    let stack_pointer = normalize_optional_user_exception_stack_pointer(stack_pointer)?;
    if allows_nested && !requires_exception_stack {
        // Nested delivery is only allowed when the handler has a dedicated
        // exception stack contract; otherwise inner faults could trample the
        // interrupted program stack.
        return Err(Error::InvalidArgument);
    }

    if requires_exception_stack && stack_pointer.is_none() && !has_thread_exception_stack {
        return Err(Error::InvalidArgument);
    }

    Ok(stack_pointer)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserExceptionHandlerInstallProfile {
    pub(crate) supported_flags: usize,
    pub(crate) allows_nested: bool,
    pub(crate) requires_exception_stack: bool,
    pub(crate) has_thread_exception_stack: bool,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
pub(crate) fn install_user_exception_handler_registration<R>(
    slot: &mut Option<R>,
    handler: usize,
    stack_pointer: usize,
    flags: usize,
    profile: UserExceptionHandlerInstallProfile,
    reset_delivery_state: impl FnOnce(),
    build_registration: impl FnOnce(usize, Option<usize>, usize) -> R,
) -> Result<()> {
    if handler == 0 {
        *slot = None;
        reset_delivery_state();
        return Ok(());
    }

    let stack_pointer = validate_user_exception_handler_registration(
        handler,
        stack_pointer,
        flags,
        profile.supported_flags,
        profile.allows_nested,
        profile.requires_exception_stack,
        profile.has_thread_exception_stack,
    )?;

    *slot = Some(build_registration(handler, stack_pointer, flags));
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn normalize_optional_user_exception_stack_pointer(stack_pointer: usize) -> Result<Option<usize>> {
    let stack_pointer = (stack_pointer != 0).then_some(stack_pointer);
    if let Some(address) = stack_pointer {
        if !is_canonical_user_address(address) {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(stack_pointer)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
const fn user_exception_nested_delivery_allowed(
    active_allows_nested: bool,
    registration_allows_nested: bool,
) -> bool {
    active_allows_nested && registration_allows_nested
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserExceptionDeliverySelection {
    Blocked,
    Deliver { stack_pointer: Option<usize> },
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn select_user_exception_delivery_stack_pointer(
    nested: bool,
    resume_stack_pointer: usize,
    registration_stack_pointer: Option<usize>,
    thread_exception_stack_pointer: Option<usize>,
) -> Option<usize> {
    if nested {
        // Nested exceptions stay on the active handler stack so inner
        // deliveries unwind in strict LIFO order.
        return Some(resume_stack_pointer);
    }

    registration_stack_pointer.or(thread_exception_stack_pointer)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
pub(crate) fn plan_user_exception_delivery<const CAPACITY: usize>(
    pending: &PendingExceptionFrameStack<CAPACITY>,
    registration_stack_pointer: Option<usize>,
    resume_stack_pointer: usize,
    thread_exception_stack_pointer: Option<usize>,
    registration_allows_nested: bool,
    active_allows_nested: fn(usize) -> bool,
) -> Result<UserExceptionDeliverySelection> {
    let nested = !pending.is_empty();
    if nested {
        let Some(active) = pending.top() else {
            return Err(Error::InternalError);
        };

        if !user_exception_nested_delivery_allowed(
            active_allows_nested(active.flags),
            registration_allows_nested,
        ) {
            return Ok(UserExceptionDeliverySelection::Blocked);
        }
    }

    Ok(UserExceptionDeliverySelection::Deliver {
        stack_pointer: select_user_exception_delivery_stack_pointer(
            nested,
            resume_stack_pointer,
            registration_stack_pointer,
            thread_exception_stack_pointer,
        ),
    })
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
pub(crate) fn finish_user_exception_delivery<R, const CAPACITY: usize>(
    slot: &mut Option<R>,
    pending: &mut PendingExceptionFrameStack<CAPACITY>,
    frame_pointer: usize,
    flags: usize,
    one_shot: bool,
) -> Result<()> {
    pending.push(UserPendingExceptionFrame {
        frame_pointer,
        flags,
    })?;

    if one_shot {
        // Clear only after queueing the frame so the current delivery still
        // reaches the handler that was just matched.
        *slot = None;
    }

    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
pub(crate) fn pop_pending_user_exception_frame<const CAPACITY: usize>(
    pending: &mut PendingExceptionFrameStack<CAPACITY>,
    frame_pointer: usize,
) -> Result<Option<bool>> {
    let Some(_entry) = pending.pop_expected(frame_pointer)? else {
        return Ok(None);
    };

    Ok(Some(pending.is_empty()))
}

// ── Arch vector / flag helper const fns ─────────────────────────────────

#[cfg(target_arch = "aarch64")]
pub(crate) const fn is_supported_aarch64_user_exception_vector(vector: u8) -> bool {
    matches!(
        vector,
        AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR | AARCH64_EXCEPTION_DATA_ABORT_VECTOR
    )
}

#[cfg(target_arch = "aarch64")]
pub(crate) const fn aarch64_user_exception_handler_is_one_shot(flags: usize) -> bool {
    flags & AARCH64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT != 0
}

#[cfg(target_arch = "aarch64")]
pub(crate) const fn aarch64_user_exception_handler_requires_exception_stack(flags: usize) -> bool {
    flags & AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK != 0
}

#[cfg(target_arch = "aarch64")]
pub(crate) const fn aarch64_user_exception_handler_allows_nested(flags: usize) -> bool {
    flags & AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED != 0
}

#[cfg(target_arch = "x86_64")]
pub(crate) const fn is_supported_x86_64_user_exception_vector(vector: u8) -> bool {
    matches!(
        vector,
        X86_64_EXCEPTION_INVALID_OPCODE_VECTOR
            | X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR
            | X86_64_EXCEPTION_PAGE_FAULT_VECTOR
    )
}

#[cfg(target_arch = "x86_64")]
pub(crate) const fn x86_64_user_exception_handler_is_one_shot(flags: usize) -> bool {
    flags & X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT != 0
}

#[cfg(target_arch = "x86_64")]
pub(crate) const fn x86_64_user_exception_handler_requires_exception_stack(flags: usize) -> bool {
    flags & X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK != 0
}

#[cfg(target_arch = "x86_64")]
pub(crate) const fn x86_64_user_exception_handler_allows_nested(flags: usize) -> bool {
    flags & X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED != 0
}
