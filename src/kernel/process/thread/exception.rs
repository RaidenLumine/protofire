//! src/kernel/process/thread/exception.rs
//!
//! Architecture-generic user-exception delivery: frame layout, stack-pointer
//! selection, nested-delivery policies, and per-arch delivery builders.

// One import for every architecture's names: the facade in `arch.rs` has
// already chosen which of them exist on this target, so the gate that used to
// sit on each of these lines lives there instead.
use super::types::is_canonical_user_address;
use crate::arch::thread::*;
use crate::Error;
use crate::Result;

// ── Shared exception-frame stack (aarch64 + x86_64) ─────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserPendingExceptionFrame {
    pub(crate) frame_pointer: usize,
    pub(crate) flags: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingExceptionFrameStack<const CAPACITY: usize> {
    len: usize,
    entries: [UserPendingExceptionFrame; CAPACITY],
}

#[cfg_attr(test, allow(dead_code))]
impl<const CAPACITY: usize> PendingExceptionFrameStack<CAPACITY> {
    const EMPTY_ENTRY: UserPendingExceptionFrame = UserPendingExceptionFrame {
        frame_pointer: 0,
        flags: 0,
    };

    pub(crate) const fn new() -> Self {
        Self {
            len: 0,
            entries: [Self::EMPTY_ENTRY; CAPACITY],
        }
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn top(&self) -> Option<UserPendingExceptionFrame> {
        if self.len == 0 {
            None
        } else {
            Some(self.entries[self.len - 1])
        }
    }

    pub(crate) fn push(&mut self, entry: UserPendingExceptionFrame) -> Result<()> {
        if self.len == CAPACITY {
            return Err(Error::Busy);
        }

        self.entries[self.len] = entry;
        self.len += 1;
        Ok(())
    }

    pub(crate) fn pop_expected(
        &mut self,
        frame_pointer: usize,
    ) -> Result<Option<UserPendingExceptionFrame>> {
        let Some(entry) = self.top() else {
            return Ok(None);
        };

        if entry.frame_pointer != frame_pointer {
            return Err(Error::InvalidArgument);
        }

        self.len -= 1;
        Ok(Some(entry))
    }
}

// ── Arch-specific delivery builders ─────────────────────────────────────

// ── Generic delivery helpers ────────────────────────────────────────────

pub(crate) const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserExceptionDeliveryBuildSpec {
    pub(crate) resume_stack_pointer: usize,
    pub(crate) exception_stack_pointer: Option<usize>,
    pub(crate) require_exception_stack: bool,
    pub(crate) frame_size: usize,
    pub(crate) handler: usize,
}

pub(crate) fn build_user_exception_delivery<Context: Copy, Frame>(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserExceptionHandlerInstallProfile {
    pub(crate) supported_flags: usize,
    pub(crate) allows_nested: bool,
    pub(crate) requires_exception_stack: bool,
    pub(crate) has_thread_exception_stack: bool,
}

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

fn normalize_optional_user_exception_stack_pointer(stack_pointer: usize) -> Result<Option<usize>> {
    let stack_pointer = (stack_pointer != 0).then_some(stack_pointer);
    if let Some(address) = stack_pointer {
        if !is_canonical_user_address(address) {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(stack_pointer)
}

const fn user_exception_nested_delivery_allowed(
    active_allows_nested: bool,
    registration_allows_nested: bool,
) -> bool {
    active_allows_nested && registration_allows_nested
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserExceptionDeliverySelection {
    Blocked,
    Deliver { stack_pointer: Option<usize> },
}

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
