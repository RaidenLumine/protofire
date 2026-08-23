//! src/kernel/process/thread/arch_x86_64.rs
//! x86_64 user-thread context and exception handling types.
pub use crate::abi::exception::{
    X86_64UserExceptionFrame, X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR,
    X86_64_EXCEPTION_INVALID_OPCODE_VECTOR, X86_64_EXCEPTION_PAGE_FAULT_VECTOR,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED, X86_64_USER_EXCEPTION_HANDLER_FLAG_NONE,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};
use crate::arch::{trap::TrapFrame as InterruptContext, x86_64::gdt};
use crate::{Error, Result};

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::lifecycle::should_enter_user_mode;
use super::types::{is_canonical_user_address, PendingExceptionFrameStack, UserThreadStart};
use super::Thread;

#[cfg(target_arch = "x86_64")]
use super::exception::{
    build_x86_64_exception_delivery, is_supported_x86_64_user_exception_vector,
    x86_64_user_exception_handler_allows_nested, x86_64_user_exception_handler_is_one_shot,
    x86_64_user_exception_handler_requires_exception_stack,
};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
use super::exception::{
    finish_user_exception_delivery, install_user_exception_handler_registration,
    plan_user_exception_delivery, pop_pending_user_exception_frame, UserExceptionDeliverySelection,
    UserExceptionHandlerInstallProfile,
};

// ── x86_64 user-thread context & exception handling ─────────────────

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86_64UserThreadContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub instruction_pointer: u64,
    pub code_segment: u64,
    pub rflags: u64,
    pub stack_pointer: u64,
    pub stack_segment: u64,
}

#[cfg(target_arch = "x86_64")]
impl X86_64UserThreadContext {
    pub(crate) const INITIAL_RFLAGS: u64 = 0x202;
    const RFLAGS_REQUIRED_BITS: u64 = 1 << 1;
    pub(crate) const RFLAGS_IOPL_MASK: u64 = 0b11 << 12;

    pub(crate) fn validate_runtime_state(self) -> Result<Self> {
        let instruction_pointer = self.instruction_pointer as usize;
        let stack_pointer = self.stack_pointer as usize;
        if instruction_pointer == 0 || !is_canonical_user_address(instruction_pointer) {
            return Err(Error::InvalidArgument);
        }

        if stack_pointer == 0 || !is_canonical_user_address(stack_pointer) {
            return Err(Error::InvalidArgument);
        }

        if self.code_segment != gdt::user_code_selector() as u64
            || self.stack_segment != gdt::user_data_selector() as u64
            || self.rflags & Self::RFLAGS_REQUIRED_BITS != Self::RFLAGS_REQUIRED_BITS
            || self.rflags & Self::RFLAGS_IOPL_MASK != 0
        {
            return Err(Error::InvalidArgument);
        }

        Ok(self)
    }

    /// Build an initial x86_64 user-thread context from a [`UserThreadStart`]
    /// descriptor.  All general-purpose registers are zeroed; the instruction
    /// pointer, stack pointer, and segment selectors are set for ring 3
    /// execution.
    pub fn from_start(start: UserThreadStart) -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            instruction_pointer: start.instruction_pointer as u64,
            code_segment: gdt::user_code_selector() as u64,
            rflags: Self::INITIAL_RFLAGS,
            stack_pointer: start.stack_pointer as u64,
            stack_segment: gdt::user_data_selector() as u64,
        }
    }

    pub(crate) fn from_interrupt(context: &InterruptContext) -> Self {
        Self {
            rax: context.rax,
            rbx: context.rbx,
            rcx: context.rcx,
            rdx: context.rdx,
            rsi: context.rsi,
            rdi: context.rdi,
            rbp: context.rbp,
            r8: context.r8,
            r9: context.r9,
            r10: context.r10,
            r11: context.r11,
            r12: context.r12,
            r13: context.r13,
            r14: context.r14,
            r15: context.r15,
            instruction_pointer: context.rip,
            code_segment: context.cs,
            rflags: context.rflags,
            stack_pointer: context.saved_stack_pointer,
            stack_segment: context.saved_stack_segment,
        }
    }

    pub(crate) fn write_to_interrupt(self, context: &mut InterruptContext) {
        context.rax = self.rax;
        context.rbx = self.rbx;
        context.rcx = self.rcx;
        context.rdx = self.rdx;
        context.rsi = self.rsi;
        context.rdi = self.rdi;
        context.rbp = self.rbp;
        context.r8 = self.r8;
        context.r9 = self.r9;
        context.r10 = self.r10;
        context.r11 = self.r11;
        context.r12 = self.r12;
        context.r13 = self.r13;
        context.r14 = self.r14;
        context.r15 = self.r15;
        context.rip = self.instruction_pointer;
        context.cs = self.code_segment;
        context.rflags = self.rflags;
        context.saved_stack_pointer = self.stack_pointer;
        context.saved_stack_segment = self.stack_segment;
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) const X86_64_EXCEPTION_VECTOR_COUNT: usize = 32;

#[cfg(target_arch = "x86_64")]
// Keep nested user-exception delivery bounded so the per-thread bookkeeping can
// stay fixed-size and avoid heap allocation inside trap handling.
pub const X86_64_PENDING_USER_EXCEPTION_FRAME_CAPACITY: usize = 4;

#[cfg(target_arch = "x86_64")]
pub(crate) const X86_64_USER_EXCEPTION_HANDLER_SUPPORTED_FLAGS: usize =
    X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT
        | X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK
        | X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86_64UserExceptionHandlerRegistration {
    pub handler: usize,
    pub stack_pointer: Option<usize>,
    pub flags: usize,
}

#[cfg(target_arch = "x86_64")]
pub(crate) type X86_64PendingExceptionFrameStack =
    PendingExceptionFrameStack<X86_64_PENDING_USER_EXCEPTION_FRAME_CAPACITY>;

#[cfg(target_arch = "x86_64")]
impl X86_64UserExceptionFrame {
    pub(crate) fn from_user_context(
        context: X86_64UserThreadContext,
        vector: u8,
        error_code: u64,
        fault_address: usize,
    ) -> Self {
        Self {
            vector: vector as u64,
            error_code,
            fault_address: fault_address as u64,
            rax: context.rax,
            rbx: context.rbx,
            rcx: context.rcx,
            rdx: context.rdx,
            rsi: context.rsi,
            rdi: context.rdi,
            rbp: context.rbp,
            r8: context.r8,
            r9: context.r9,
            r10: context.r10,
            r11: context.r11,
            r12: context.r12,
            r13: context.r13,
            r14: context.r14,
            r15: context.r15,
            instruction_pointer: context.instruction_pointer,
            stack_pointer: context.stack_pointer,
            rflags: context.rflags,
        }
    }

    pub(crate) fn into_user_context(self) -> X86_64UserThreadContext {
        X86_64UserThreadContext {
            rax: self.rax,
            rbx: self.rbx,
            rcx: self.rcx,
            rdx: self.rdx,
            rsi: self.rsi,
            rdi: self.rdi,
            rbp: self.rbp,
            r8: self.r8,
            r9: self.r9,
            r10: self.r10,
            r11: self.r11,
            r12: self.r12,
            r13: self.r13,
            r14: self.r14,
            r15: self.r15,
            instruction_pointer: self.instruction_pointer,
            code_segment: gdt::user_code_selector() as u64,
            rflags: self.rflags,
            stack_pointer: self.stack_pointer,
            stack_segment: gdt::user_data_selector() as u64,
        }
    }
}

// ── Thread: x86_64 context & exception delivery ─────────────────────

#[cfg(target_arch = "x86_64")]
impl Thread {
    /// Return a snapshot of the threadʼs last-known x86_64 user-mode register
    /// state, if one has been captured.
    pub fn x86_64_user_context(&self) -> Option<X86_64UserThreadContext> {
        *self.x86_64_user_context.lock()
    }

    /// Overwrite the threadʼs saved user-mode register state.
    /// Used by ptrace PTRACE_SETREGS.
    pub(crate) fn set_x86_64_user_context(&self, ctx: X86_64UserThreadContext) {
        *self.x86_64_user_context.lock() = Some(ctx);
    }

    pub(crate) fn validated_x86_64_user_context(&self) -> Result<Option<X86_64UserThreadContext>> {
        self.x86_64_user_context()
            .map(|context| {
                context
                    .validate_runtime_state()
                    .map_err(|_| Error::InternalError)
            })
            .transpose()
    }

    fn update_x86_64_user_context_if_valid(&self, context: X86_64UserThreadContext) -> bool {
        let Ok(context) = context.validate_runtime_state() else {
            return false;
        };
        *self.x86_64_user_context.lock() = Some(context);
        true
    }

    /// Return the x86_64 user exception stack pointer, if one was configured
    /// at thread creation.
    pub fn x86_64_exception_stack_pointer(&self) -> Option<usize> {
        self.execution_state.lock().x86_64_exception_stack_pointer
    }

    /// Return the registered user exception handler for the given interrupt
    /// vector, if one has been installed via `install_x86_64_exception_handler`.
    pub fn x86_64_exception_handler_registration(
        &self,
        vector: u8,
    ) -> Option<X86_64UserExceptionHandlerRegistration> {
        self.x86_64_exception_handlers
            .lock()
            .get(vector as usize)
            .copied()
            .flatten()
    }

    /// Return the registered user-mode page-fault handler, if any.
    pub fn x86_64_page_fault_handler_registration(
        &self,
    ) -> Option<X86_64UserExceptionHandlerRegistration> {
        self.x86_64_exception_handler_registration(X86_64_EXCEPTION_PAGE_FAULT_VECTOR)
    }

    /// Return the address of the registered user-mode page-fault handler, if any.
    pub fn x86_64_page_fault_handler(&self) -> Option<usize> {
        self.x86_64_page_fault_handler_registration()
            .map(|registration| registration.handler)
    }

    /// Number of nested exception frames currently pending delivery to user mode.
    pub fn x86_64_pending_exception_depth(&self) -> usize {
        self.x86_64_pending_exception_frames.lock().len()
    }

    fn reset_x86_64_exception_delivery_state(&self) {
        self.x86_64_pending_exception_frames.lock().clear();
    }

    pub(crate) fn clear_x86_64_user_runtime_state(&self) {
        *self.x86_64_user_context.lock() = None;
        *self.x86_64_exception_handlers.lock() = [None; X86_64_EXCEPTION_VECTOR_COUNT];
        self.reset_x86_64_exception_delivery_state();
    }

    pub(crate) fn capture_x86_64_user_context_from_interrupt(&self, context: &InterruptContext) {
        let _ = self
            .update_x86_64_user_context_if_valid(X86_64UserThreadContext::from_interrupt(context));
    }

    pub(crate) fn write_x86_64_user_context_to_interrupt(
        &self,
        context: &mut InterruptContext,
    ) -> Result<()> {
        let user_context = self
            .validated_x86_64_user_context()?
            .ok_or(Error::InternalError)?;
        user_context.write_to_interrupt(context);
        Ok(())
    }

    pub(crate) fn install_x86_64_exception_handler_with(
        &self,
        vector: u8,
        handler: usize,
        stack_pointer: usize,
        flags: usize,
    ) -> Result<()> {
        self.ensure_user_runtime_mutable()?;

        if !is_supported_x86_64_user_exception_vector(vector) {
            return Err(Error::Unsupported);
        }

        let mut handlers = self.x86_64_exception_handlers.lock();
        let slot = handlers
            .get_mut(vector as usize)
            .ok_or(Error::InvalidArgument)?;

        install_user_exception_handler_registration(
            slot,
            handler,
            stack_pointer,
            flags,
            UserExceptionHandlerInstallProfile {
                supported_flags: X86_64_USER_EXCEPTION_HANDLER_SUPPORTED_FLAGS,
                allows_nested: x86_64_user_exception_handler_allows_nested(flags),
                requires_exception_stack: x86_64_user_exception_handler_requires_exception_stack(
                    flags,
                ),
                has_thread_exception_stack: self.x86_64_exception_stack_pointer().is_some(),
            },
            || self.reset_x86_64_exception_delivery_state(),
            |handler, stack_pointer, flags| X86_64UserExceptionHandlerRegistration {
                handler,
                stack_pointer,
                flags,
            },
        )
    }

    pub(crate) fn deliver_x86_64_user_exception(
        &self,
        context: &mut InterruptContext,
        fault_address: Option<usize>,
    ) -> Result<bool> {
        self.ensure_user_runtime_mutable()?;
        let vector = context.vector as u8;
        let mut handlers = self.x86_64_exception_handlers.lock();
        let slot = handlers
            .get_mut(vector as usize)
            .ok_or(Error::InvalidArgument)?;
        let Some(registration) = *slot else {
            return Ok(false);
        };

        let resume_context =
            X86_64UserThreadContext::from_interrupt(context).validate_runtime_state()?;
        let mut pending = self.x86_64_pending_exception_frames.lock();
        let delivery_stack_pointer = match plan_user_exception_delivery(
            &pending,
            registration.stack_pointer,
            resume_context.stack_pointer as usize,
            self.x86_64_exception_stack_pointer(),
            x86_64_user_exception_handler_allows_nested(registration.flags),
            x86_64_user_exception_handler_allows_nested,
        )? {
            UserExceptionDeliverySelection::Blocked => return Ok(false),
            UserExceptionDeliverySelection::Deliver { stack_pointer } => stack_pointer,
        };
        let (frame_pointer, frame, handler_context) = build_x86_64_exception_delivery(
            resume_context,
            delivery_stack_pointer,
            x86_64_user_exception_handler_requires_exception_stack(registration.flags),
            vector,
            context.error_code,
            fault_address,
            registration.handler,
        )?;

        unsafe {
            (frame_pointer as *mut X86_64UserExceptionFrame).write(frame);
        }

        finish_user_exception_delivery(
            slot,
            &mut pending,
            frame_pointer,
            registration.flags,
            x86_64_user_exception_handler_is_one_shot(registration.flags),
        )?;

        *self.x86_64_user_context.lock() = Some(handler_context);
        handler_context.write_to_interrupt(context);
        Ok(true)
    }

    pub(crate) fn resume_x86_64_user_exception(
        &self,
        context: &mut InterruptContext,
        frame_pointer: usize,
    ) -> Result<bool> {
        self.ensure_user_runtime_mutable()?;
        {
            let pending = self.x86_64_pending_exception_frames.lock();
            let Some(active) = pending.top() else {
                return Ok(false);
            };
            if active.frame_pointer != frame_pointer {
                return Err(Error::InvalidArgument);
            }
        }

        let frame = unsafe { (frame_pointer as *const X86_64UserExceptionFrame).read() };
        let restored = frame.into_user_context().validate_runtime_state()?;

        {
            let mut pending = self.x86_64_pending_exception_frames.lock();
            if pop_pending_user_exception_frame(&mut pending, frame_pointer)?.is_none() {
                return Ok(false);
            }
        }

        let _ = self.update_x86_64_user_context_if_valid(restored);
        restored.write_to_interrupt(context);
        Ok(true)
    }

    pub(crate) fn replace_x86_64_user_image(&self, start: UserThreadStart) -> Result<()> {
        self.replace_user_execution_state(start, |execution_state| {
            execution_state.x86_64_exception_stack_pointer = start.exception_stack_pointer;
        })?;
        *self.x86_64_user_context.lock() = Some(X86_64UserThreadContext::from_start(start));
        // Replacing the image is `exec`-like: prior handlers and pending
        // exception frames belong to the old image and must not survive.
        *self.x86_64_exception_handlers.lock() = [None; X86_64_EXCEPTION_VECTOR_COUNT];
        self.reset_x86_64_exception_delivery_state();
        Ok(())
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl Thread {
    /// Entry trampoline for x86_64 user threads.  Validates the user context,
    /// switches to ring 3 if the thread has a valid `UserThreadStart`, or
    /// calls the kernel entry function for pure kernel threads.
    ///
    /// Called by the scheduler when this thread is dispatched.
    pub fn run_entry(&self) {
        let user_start_present = self.user_start().is_some();
        let user_context = match self.validated_x86_64_user_context() {
            Ok(user_context) => user_context,
            Err(_) => {
                crate::println!(
                    "[user  ] invalid x86_64 user context before ring3 entry pid={} tid={}",
                    self.pid(),
                    self.tid()
                );
                return;
            }
        };

        if user_start_present && user_context.is_none() {
            crate::println!(
                "[user  ] missing x86_64 user context before first ring3 entry pid={} tid={}",
                self.pid(),
                self.tid()
            );
            return;
        }

        // Enter ring3 only when both launch metadata and context snapshot exist.
        if should_enter_user_mode(user_start_present, user_context.is_some()) {
            let Some(context) = user_context else {
                return;
            };
            unsafe {
                crate::arch::x86_64::context::enter_user_mode_with_context(&context);
            }
        }

        let Some(entry) = self.kernel_entry() else {
            crate::println!(
                "[sched ] refusing to run thread with untyped kernel entry pid={} tid={} entry=0x{:x}",
                self.pid(),
                self.tid(),
                self.entry_point()
            );
            return;
        };
        crate::arch::interrupts::enable();
        entry();
    }
}
