//! src/kernel/process/thread/arch_aarch64.rs
//! AArch64 user-thread context and exception handling types.

use core::mem::size_of;

use crate::{Error, Result};

#[cfg(target_arch = "aarch64")]
use crate::arch::trap::TrapFrame as AArch64TrapFrame;

pub use crate::abi::exception::{
    AArch64UserExceptionFrame, AARCH64_EXCEPTION_DATA_ABORT_VECTOR,
    AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR, AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_NONE, AARCH64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};

use core::sync::atomic::Ordering;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use super::lifecycle::should_enter_user_mode;
use super::types::{PendingExceptionFrameStack, UserThreadStart};
use super::Thread;

#[cfg(target_arch = "aarch64")]
use super::exception::{
    aarch64_user_exception_handler_allows_nested, aarch64_user_exception_handler_is_one_shot,
    aarch64_user_exception_handler_requires_exception_stack, build_aarch64_exception_delivery,
    finish_user_exception_delivery, install_user_exception_handler_registration,
    is_supported_aarch64_user_exception_vector, plan_user_exception_delivery,
    pop_pending_user_exception_frame, UserExceptionDeliverySelection,
    UserExceptionHandlerInstallProfile,
};

// ── AArch64 user-thread context & exception handling ─────────────────

#[cfg(any(target_arch = "aarch64", test))]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AArch64UserThreadContext {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub saved_program_status: u64,
}

#[cfg(any(target_arch = "aarch64", test))]
const _: [(); 272] = [(); size_of::<AArch64UserThreadContext>()];

#[cfg(any(target_arch = "aarch64", test))]
impl AArch64UserThreadContext {
    const INITIAL_SPSR: u64 = 0;
    const USER_MODE_SPSR_MASK: u64 = 0b1111;
    const USER_MODE_SPSR_EL0T: u64 = 0b0000;

    fn validate_saved_program_status(saved_program_status: u64) -> Result<u64> {
        // Keep non-mode SPSR bits opaque, but never allow a stored user
        // context to re-enter a privileged exception level through ERET.
        if saved_program_status & Self::USER_MODE_SPSR_MASK != Self::USER_MODE_SPSR_EL0T {
            return Err(Error::InvalidArgument);
        }

        Ok(saved_program_status)
    }

    pub(crate) fn validate_runtime_state(self) -> Result<Self> {
        // Keep this check aligned with the generic user-thread entry contract:
        // trap resume and first EL0 entry should both reject obviously invalid
        // user instruction/stack pointers instead of depending on later arch
        // glue to discover the corruption.
        UserThreadStart::new(
            self.instruction_pointer as usize,
            self.stack_pointer as usize,
            None,
        )
        .validate()?;
        Self::validate_saved_program_status(self.saved_program_status)?;
        Ok(self)
    }

    /// Build an initial AArch64 user-thread context from a [`UserThreadStart`]
    /// descriptor.  All general-purpose registers are zeroed except x0–x2
    /// (argument registers); the instruction pointer, stack pointer, and
    /// SPSR are set for EL0 execution.
    pub fn from_start(start: UserThreadStart) -> Self {
        #[cfg(target_arch = "aarch64")]
        let [x0, x1, x2] = start.aarch64_argument_registers;
        #[cfg(not(target_arch = "aarch64"))]
        let [x0, x1, x2] = [0; 3];
        Self {
            x0: x0 as u64,
            x1: x1 as u64,
            x2: x2 as u64,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
            x7: 0,
            x8: 0,
            x9: 0,
            x10: 0,
            x11: 0,
            x12: 0,
            x13: 0,
            x14: 0,
            x15: 0,
            x16: 0,
            x17: 0,
            x18: 0,
            x19: 0,
            x20: 0,
            x21: 0,
            x22: 0,
            x23: 0,
            x24: 0,
            x25: 0,
            x26: 0,
            x27: 0,
            x28: 0,
            x29: 0,
            x30: 0,
            instruction_pointer: start.instruction_pointer as u64,
            stack_pointer: start.stack_pointer as u64,
            saved_program_status: Self::INITIAL_SPSR,
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn from_trap(frame: &AArch64TrapFrame) -> Self {
        Self {
            x0: frame.x0,
            x1: frame.x1,
            x2: frame.x2,
            x3: frame.x3,
            x4: frame.x4,
            x5: frame.x5,
            x6: frame.x6,
            x7: frame.x7,
            x8: frame.x8,
            x9: frame.x9,
            x10: frame.x10,
            x11: frame.x11,
            x12: frame.x12,
            x13: frame.x13,
            x14: frame.x14,
            x15: frame.x15,
            x16: frame.x16,
            x17: frame.x17,
            x18: frame.x18,
            x19: frame.x19,
            x20: frame.x20,
            x21: frame.x21,
            x22: frame.x22,
            x23: frame.x23,
            x24: frame.x24,
            x25: frame.x25,
            x26: frame.x26,
            x27: frame.x27,
            x28: frame.x28,
            x29: frame.x29,
            x30: frame.x30,
            instruction_pointer: frame.elr,
            stack_pointer: frame.stack_pointer,
            saved_program_status: frame.spsr,
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn validated_from_trap(frame: &AArch64TrapFrame) -> Result<Self> {
        Self::from_trap(frame).validate_runtime_state()
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn write_to_trap(self, frame: &mut AArch64TrapFrame) {
        frame.x0 = self.x0;
        frame.x1 = self.x1;
        frame.x2 = self.x2;
        frame.x3 = self.x3;
        frame.x4 = self.x4;
        frame.x5 = self.x5;
        frame.x6 = self.x6;
        frame.x7 = self.x7;
        frame.x8 = self.x8;
        frame.x9 = self.x9;
        frame.x10 = self.x10;
        frame.x11 = self.x11;
        frame.x12 = self.x12;
        frame.x13 = self.x13;
        frame.x14 = self.x14;
        frame.x15 = self.x15;
        frame.x16 = self.x16;
        frame.x17 = self.x17;
        frame.x18 = self.x18;
        frame.x19 = self.x19;
        frame.x20 = self.x20;
        frame.x21 = self.x21;
        frame.x22 = self.x22;
        frame.x23 = self.x23;
        frame.x24 = self.x24;
        frame.x25 = self.x25;
        frame.x26 = self.x26;
        frame.x27 = self.x27;
        frame.x28 = self.x28;
        frame.x29 = self.x29;
        frame.x30 = self.x30;
        frame.elr = self.instruction_pointer;
        frame.stack_pointer = self.stack_pointer;
        frame.spsr = self.saved_program_status;
    }
}

#[cfg(any(target_arch = "aarch64", test))]
pub(crate) const AARCH64_EXCEPTION_VECTOR_COUNT: usize = 64;

#[cfg(any(target_arch = "aarch64", test))]
// Keep nested user-exception delivery bounded so the per-thread bookkeeping can
// stay fixed-size and avoid heap allocation inside trap handling.
pub const AARCH64_PENDING_USER_EXCEPTION_FRAME_CAPACITY: usize = 4;

#[cfg(target_arch = "aarch64")]
pub(crate) const AARCH64_USER_EXCEPTION_HANDLER_SUPPORTED_FLAGS: usize =
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT
        | AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK
        | AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;

#[cfg(any(target_arch = "aarch64", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AArch64UserExceptionHandlerRegistration {
    pub handler: usize,
    pub stack_pointer: Option<usize>,
    pub flags: usize,
}

#[cfg(any(target_arch = "aarch64", test))]
pub(crate) type AArch64PendingExceptionFrameStack =
    PendingExceptionFrameStack<AARCH64_PENDING_USER_EXCEPTION_FRAME_CAPACITY>;

#[cfg(any(target_arch = "aarch64", test))]
#[cfg_attr(test, allow(dead_code))]
impl AArch64UserExceptionFrame {
    pub(crate) fn from_user_context(
        context: AArch64UserThreadContext,
        vector: u8,
        error_code: u64,
        fault_address: usize,
    ) -> Self {
        Self {
            vector: vector as u64,
            error_code,
            fault_address: fault_address as u64,
            x0: context.x0,
            x1: context.x1,
            x2: context.x2,
            x3: context.x3,
            x4: context.x4,
            x5: context.x5,
            x6: context.x6,
            x7: context.x7,
            x8: context.x8,
            x9: context.x9,
            x10: context.x10,
            x11: context.x11,
            x12: context.x12,
            x13: context.x13,
            x14: context.x14,
            x15: context.x15,
            x16: context.x16,
            x17: context.x17,
            x18: context.x18,
            x19: context.x19,
            x20: context.x20,
            x21: context.x21,
            x22: context.x22,
            x23: context.x23,
            x24: context.x24,
            x25: context.x25,
            x26: context.x26,
            x27: context.x27,
            x28: context.x28,
            x29: context.x29,
            x30: context.x30,
            instruction_pointer: context.instruction_pointer,
            stack_pointer: context.stack_pointer,
            saved_program_status: context.saved_program_status,
        }
    }

    pub(crate) fn into_user_context(self) -> AArch64UserThreadContext {
        AArch64UserThreadContext {
            x0: self.x0,
            x1: self.x1,
            x2: self.x2,
            x3: self.x3,
            x4: self.x4,
            x5: self.x5,
            x6: self.x6,
            x7: self.x7,
            x8: self.x8,
            x9: self.x9,
            x10: self.x10,
            x11: self.x11,
            x12: self.x12,
            x13: self.x13,
            x14: self.x14,
            x15: self.x15,
            x16: self.x16,
            x17: self.x17,
            x18: self.x18,
            x19: self.x19,
            x20: self.x20,
            x21: self.x21,
            x22: self.x22,
            x23: self.x23,
            x24: self.x24,
            x25: self.x25,
            x26: self.x26,
            x27: self.x27,
            x28: self.x28,
            x29: self.x29,
            x30: self.x30,
            instruction_pointer: self.instruction_pointer,
            stack_pointer: self.stack_pointer,
            saved_program_status: self.saved_program_status,
        }
    }
}

// ── Thread: aarch64 context & exception delivery ───────────────────

#[cfg(any(target_arch = "aarch64", test))]
impl Thread {
    /// Return a snapshot of the threadʼs last-known AArch64 user-mode register
    /// state, if one has been captured.
    pub fn aarch64_user_context(&self) -> Option<AArch64UserThreadContext> {
        *self.aarch64_user_context.lock()
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn validated_aarch64_user_context(
        &self,
    ) -> Result<Option<AArch64UserThreadContext>> {
        self.aarch64_user_context()
            .map(|context| {
                context
                    .validate_runtime_state()
                    .map_err(|_| Error::InternalError)
            })
            .transpose()
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn set_aarch64_user_context(&self, context: AArch64UserThreadContext) {
        *self.aarch64_user_context.lock() = Some(context);
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn update_aarch64_user_context_if_valid(
        &self,
        context: AArch64UserThreadContext,
    ) -> bool {
        let Ok(context) = context.validate_runtime_state() else {
            return false;
        };
        self.set_aarch64_user_context(context);
        true
    }

    /// Return the AArch64 user exception stack pointer, if one was configured
    /// at thread creation.
    pub fn aarch64_exception_stack_pointer(&self) -> Option<usize> {
        self.execution_state
            .lock()
            .user_start
            .and_then(|start| start.exception_stack_pointer)
    }

    /// Return the registered user exception handler for the given exception
    /// vector, if one has been installed.
    pub fn aarch64_exception_handler_registration(
        &self,
        vector: u8,
    ) -> Option<AArch64UserExceptionHandlerRegistration> {
        self.aarch64_exception_handlers
            .lock()
            .get(vector as usize)
            .copied()
            .flatten()
    }

    /// Number of nested exception frames currently pending delivery to EL0.
    pub fn aarch64_pending_exception_depth(&self) -> usize {
        self.aarch64_pending_exception_frames.lock().len()
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn mark_aarch64_exception_preempt_resume_logged(&self) -> bool {
        !self
            .aarch64_exception_preempt_resume_logged
            .swap(true, Ordering::SeqCst)
    }

    pub(crate) fn clear_aarch64_exception_preempt_resume_logged(&self) {
        self.aarch64_exception_preempt_resume_logged
            .store(false, Ordering::SeqCst);
    }

    fn reset_aarch64_exception_delivery_state(&self) {
        self.aarch64_pending_exception_frames.lock().clear();
        self.clear_aarch64_exception_preempt_resume_logged();
    }

    pub(crate) fn clear_aarch64_user_runtime_state(&self) {
        *self.aarch64_user_context.lock() = None;
        *self.aarch64_exception_handlers.lock() = [None; AARCH64_EXCEPTION_VECTOR_COUNT];
        self.reset_aarch64_exception_delivery_state();
    }
}

#[cfg(target_arch = "aarch64")]
impl Thread {
    pub(crate) fn capture_aarch64_user_context_from_trap(&self, frame: &AArch64TrapFrame) {
        let _ =
            self.update_aarch64_user_context_if_valid(AArch64UserThreadContext::from_trap(frame));
    }

    pub(crate) fn write_aarch64_user_context_to_trap(
        &self,
        frame: &mut AArch64TrapFrame,
    ) -> Result<()> {
        let user_context = self
            .validated_aarch64_user_context()?
            .ok_or(Error::InternalError)?;
        user_context.write_to_trap(frame);
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
impl Thread {
    pub(crate) fn install_aarch64_exception_handler_with(
        &self,
        vector: u8,
        handler: usize,
        stack_pointer: usize,
        flags: usize,
    ) -> Result<()> {
        self.ensure_user_runtime_mutable()?;

        if !is_supported_aarch64_user_exception_vector(vector) {
            return Err(Error::Unsupported);
        }

        let mut handlers = self.aarch64_exception_handlers.lock();
        let slot = handlers
            .get_mut(vector as usize)
            .ok_or(Error::InvalidArgument)?;

        install_user_exception_handler_registration(
            slot,
            handler,
            stack_pointer,
            flags,
            UserExceptionHandlerInstallProfile {
                supported_flags: AARCH64_USER_EXCEPTION_HANDLER_SUPPORTED_FLAGS,
                allows_nested: aarch64_user_exception_handler_allows_nested(flags),
                requires_exception_stack: aarch64_user_exception_handler_requires_exception_stack(
                    flags,
                ),
                has_thread_exception_stack: self.aarch64_exception_stack_pointer().is_some(),
            },
            || self.reset_aarch64_exception_delivery_state(),
            |handler, stack_pointer, flags| AArch64UserExceptionHandlerRegistration {
                handler,
                stack_pointer,
                flags,
            },
        )
    }
}

#[cfg(target_arch = "aarch64")]
impl Thread {
    pub(crate) fn deliver_aarch64_user_exception(
        &self,
        frame: &mut AArch64TrapFrame,
        vector: u8,
        error_code: u64,
        fault_address: Option<usize>,
    ) -> Result<bool> {
        self.ensure_user_runtime_mutable()?;
        let resume_context = AArch64UserThreadContext::from_trap(frame);
        let Some(handler_context) = self.deliver_aarch64_user_exception_from_context(
            resume_context,
            vector,
            error_code,
            fault_address,
        )?
        else {
            return Ok(false);
        };

        handler_context.write_to_trap(frame);
        Ok(true)
    }

    pub(crate) fn resume_aarch64_user_exception(
        &self,
        frame: &mut AArch64TrapFrame,
        frame_pointer: usize,
    ) -> Result<bool> {
        self.ensure_user_runtime_mutable()?;
        let Some(restored) = self.resume_aarch64_user_exception_to_context(frame_pointer)? else {
            return Ok(false);
        };
        restored.write_to_trap(frame);
        Ok(true)
    }
}

#[cfg(target_arch = "aarch64")]
impl Thread {
    pub(crate) fn deliver_aarch64_user_exception_from_context(
        &self,
        resume_context: AArch64UserThreadContext,
        vector: u8,
        error_code: u64,
        fault_address: Option<usize>,
    ) -> Result<Option<AArch64UserThreadContext>> {
        let mut handlers = self.aarch64_exception_handlers.lock();
        let slot = handlers
            .get_mut(vector as usize)
            .ok_or(Error::InvalidArgument)?;
        let Some(registration) = *slot else {
            return Ok(None);
        };
        let resume_context = resume_context.validate_runtime_state()?;

        let mut pending = self.aarch64_pending_exception_frames.lock();
        let delivery_stack_pointer = match plan_user_exception_delivery(
            &pending,
            registration.stack_pointer,
            resume_context.stack_pointer as usize,
            self.aarch64_exception_stack_pointer(),
            aarch64_user_exception_handler_allows_nested(registration.flags),
            aarch64_user_exception_handler_allows_nested,
        )? {
            UserExceptionDeliverySelection::Blocked => return Ok(None),
            UserExceptionDeliverySelection::Deliver { stack_pointer } => stack_pointer,
        };
        let (frame_pointer, exception_frame, handler_context) = build_aarch64_exception_delivery(
            resume_context,
            delivery_stack_pointer,
            aarch64_user_exception_handler_requires_exception_stack(registration.flags),
            vector,
            error_code,
            fault_address,
            registration.handler,
        )?;

        // Write the exception frame to the user stack.  When SPAN is
        // enabled, PSTATE.PAN blocks kernel access to user pages — use
        // with_user_access to temporarily grant access.
        unsafe {
            #[cfg(target_arch = "aarch64")]
            {
                crate::arch::aarch64::user_access::with_user_access(|| {
                    (frame_pointer as *mut AArch64UserExceptionFrame).write(exception_frame);
                });
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                (frame_pointer as *mut AArch64UserExceptionFrame).write(exception_frame);
            }
        }

        finish_user_exception_delivery(
            slot,
            &mut pending,
            frame_pointer,
            registration.flags,
            aarch64_user_exception_handler_is_one_shot(registration.flags),
        )?;

        self.set_aarch64_user_context(handler_context);
        Ok(Some(handler_context))
    }

    pub(crate) fn resume_aarch64_user_exception_to_context(
        &self,
        frame_pointer: usize,
    ) -> Result<Option<AArch64UserThreadContext>> {
        {
            let pending = self.aarch64_pending_exception_frames.lock();
            let Some(active) = pending.top() else {
                return Ok(None);
            };
            if active.frame_pointer != frame_pointer {
                return Err(Error::InvalidArgument);
            }
        }

        // Read the exception frame from the user stack.  When SPAN is
        // enabled, PSTATE.PAN blocks kernel access to user pages — use
        // with_user_access to temporarily grant access.
        let exception_frame = unsafe {
            #[cfg(target_arch = "aarch64")]
            {
                crate::arch::aarch64::user_access::with_user_access(|| {
                    (frame_pointer as *const AArch64UserExceptionFrame).read()
                })
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                (frame_pointer as *const AArch64UserExceptionFrame).read()
            }
        };
        let restored = exception_frame
            .into_user_context()
            .validate_runtime_state()?;

        let pending_empty = {
            let mut pending = self.aarch64_pending_exception_frames.lock();
            let Some(pending_empty) =
                pop_pending_user_exception_frame(&mut pending, frame_pointer)?
            else {
                return Ok(None);
            };
            pending_empty
        };

        if pending_empty {
            self.clear_aarch64_exception_preempt_resume_logged();
        }

        self.set_aarch64_user_context(restored);
        Ok(Some(restored))
    }

    pub(crate) fn replace_aarch64_user_image(&self, start: UserThreadStart) -> Result<()> {
        self.replace_user_execution_state(start, |_| {})?;
        self.set_aarch64_user_context(AArch64UserThreadContext::from_start(start));
        // Replacing the image is `exec`-like: prior handlers and pending
        // exception frames belong to the old image and must not survive.
        *self.aarch64_exception_handlers.lock() = [None; AARCH64_EXCEPTION_VECTOR_COUNT];
        self.reset_aarch64_exception_delivery_state();
        Ok(())
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl Thread {
    pub fn run_entry(&self) {
        let user_start_present = self.user_start().is_some();
        let user_context = match self.validated_aarch64_user_context() {
            Ok(user_context) => user_context,
            Err(_) => {
                crate::println!(
                    "[user  ] invalid aarch64 user context before EL0 entry pid={} tid={}",
                    self.pid(),
                    self.tid()
                );
                return;
            }
        };

        if user_start_present && user_context.is_none() {
            crate::println!(
                "[user  ] missing aarch64 user context before first EL0 entry pid={} tid={}",
                self.pid(),
                self.tid()
            );
            return;
        }

        // Enter EL0 only when both launch metadata and context snapshot exist.
        if should_enter_user_mode(user_start_present, user_context.is_some()) {
            let Some(context) = user_context else {
                return;
            };
            unsafe {
                crate::arch::aarch64::context::enter_user_mode_with_context(&context);
            }
        }

        // Fetch the immutable kernel entry before re-enabling IRQs so the
        // timer cannot keep preempting the Mutex-backed execution-state read.
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
