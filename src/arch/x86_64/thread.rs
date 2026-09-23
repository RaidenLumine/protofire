//! src/arch/x86_64/thread.rs
//!
//! x86_64 user-thread context and exception handling types.

pub use crate::abi::exception::X86_64UserExceptionFrame;
pub use crate::abi::exception::X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR;
pub use crate::abi::exception::X86_64_EXCEPTION_INVALID_OPCODE_VECTOR;
pub use crate::abi::exception::X86_64_EXCEPTION_PAGE_FAULT_VECTOR;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_NONE;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK;
use core::mem::size_of;

use crate::arch::trap::TrapFrame as InterruptContext;
use crate::arch::x86_64::gdt;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

use crate::kernel::process::thread::exception::build_user_exception_delivery;
use crate::kernel::process::thread::exception::finish_user_exception_delivery;
use crate::kernel::process::thread::exception::install_user_exception_handler_registration;
use crate::kernel::process::thread::exception::is_supported_x86_64_user_exception_vector;
use crate::kernel::process::thread::exception::plan_user_exception_delivery;
use crate::kernel::process::thread::exception::pop_pending_user_exception_frame;
use crate::kernel::process::thread::exception::x86_64_user_exception_handler_allows_nested;
use crate::kernel::process::thread::exception::x86_64_user_exception_handler_is_one_shot;
use crate::kernel::process::thread::exception::x86_64_user_exception_handler_requires_exception_stack;
use crate::kernel::process::thread::exception::PendingExceptionFrameStack;
use crate::kernel::process::thread::exception::UserExceptionDeliveryBuildSpec;
use crate::kernel::process::thread::exception::UserExceptionDeliverySelection;
use crate::kernel::process::thread::exception::UserExceptionHandlerInstallProfile;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::process::thread::lifecycle::should_enter_user_mode;
use crate::kernel::process::thread::types::is_canonical_user_address;
use crate::kernel::process::thread::types::UserThreadStart;
use crate::kernel::process::thread::Thread;

// ── x86_64 user-thread context & exception handling ─────────────────
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
pub(crate) const X86_64_EXCEPTION_VECTOR_COUNT: usize = 32;
// Keep nested user-exception delivery bounded so the per-thread bookkeeping can
// stay fixed-size and avoid heap allocation inside trap handling.
pub const X86_64_PENDING_USER_EXCEPTION_FRAME_CAPACITY: usize = 4;
pub(crate) const X86_64_USER_EXCEPTION_HANDLER_SUPPORTED_FLAGS: usize =
    X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT
        | X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK
        | X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86_64UserExceptionHandlerRegistration {
    pub handler: usize,
    pub stack_pointer: Option<usize>,
    pub flags: usize,
}
pub(crate) type X86_64PendingExceptionFrameStack =
    PendingExceptionFrameStack<X86_64_PENDING_USER_EXCEPTION_FRAME_CAPACITY>;
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

/// Write the user-mode exception frame into the user stack at `frame_pointer`.
///
/// The target is a user page, so on bare metal the store must run inside a
/// SMAP user-access window (`stac`); without it, delivering an exception to a
/// registered user handler takes a kernel-mode #PF as soon as CR4.SMAP is
/// enabled.  On host test builds `frame_pointer` points at ordinary host
/// memory and no guard is needed.
#[cfg(target_os = "none")]
unsafe fn write_x86_64_user_exception_frame(frame_pointer: usize, frame: X86_64UserExceptionFrame) {
    unsafe {
        crate::arch::x86_64::user_access::with_user_access(|| {
            (frame_pointer as *mut X86_64UserExceptionFrame).write(frame);
        });
    }
}

#[cfg(not(target_os = "none"))]
unsafe fn write_x86_64_user_exception_frame(frame_pointer: usize, frame: X86_64UserExceptionFrame) {
    unsafe {
        (frame_pointer as *mut X86_64UserExceptionFrame).write(frame);
    }
}

/// Read the user-mode exception frame back from the user stack at
/// `frame_pointer` (SMAP-guarded on bare metal, plain on host).
#[cfg(target_os = "none")]
unsafe fn read_x86_64_user_exception_frame(frame_pointer: usize) -> X86_64UserExceptionFrame {
    unsafe {
        crate::arch::x86_64::user_access::with_user_access(|| {
            (frame_pointer as *const X86_64UserExceptionFrame).read()
        })
    }
}

#[cfg(not(target_os = "none"))]
unsafe fn read_x86_64_user_exception_frame(frame_pointer: usize) -> X86_64UserExceptionFrame {
    unsafe { (frame_pointer as *const X86_64UserExceptionFrame).read() }
}
impl Thread {
    /// Return a snapshot of the threadʼs last-known x86_64 user-mode register
    /// state, if one has been captured.
    pub fn x86_64_user_context(&self) -> Option<X86_64UserThreadContext> {
        *self.x86_64.user_context.lock()
    }

    /// Overwrite the threadʼs saved user-mode register state.
    /// Used by ptrace PTRACE_SETREGS.
    pub(crate) fn set_x86_64_user_context(&self, ctx: X86_64UserThreadContext) {
        *self.x86_64.user_context.lock() = Some(ctx);
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
        *self.x86_64.user_context.lock() = Some(context);
        true
    }

    /// Return the x86_64 user exception stack pointer, if one was configured
    /// at thread creation.
    pub fn x86_64_exception_stack_pointer(&self) -> Option<usize> {
        self.user_start()
            .and_then(|start| start.exception_stack_pointer)
    }

    /// Return the registered user exception handler for the given interrupt
    /// vector, if one has been installed via
    /// `install_x86_64_exception_handler`.
    pub fn x86_64_exception_handler_registration(
        &self,
        vector: u8,
    ) -> Option<X86_64UserExceptionHandlerRegistration> {
        self.x86_64
            .exception_handlers
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

    /// Return the address of the registered user-mode page-fault handler, if
    /// any.
    pub fn x86_64_page_fault_handler(&self) -> Option<usize> {
        self.x86_64_page_fault_handler_registration()
            .map(|registration| registration.handler)
    }

    /// Number of nested exception frames currently pending delivery to user
    /// mode.
    pub fn x86_64_pending_exception_depth(&self) -> usize {
        self.x86_64.pending_exception_frames.lock().len()
    }

    fn reset_x86_64_exception_delivery_state(&self) {
        self.x86_64.pending_exception_frames.lock().clear();
    }

    pub(crate) fn clear_x86_64_user_runtime_state(&self) {
        *self.x86_64.user_context.lock() = None;
        *self.x86_64.exception_handlers.lock() = [None; X86_64_EXCEPTION_VECTOR_COUNT];
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

        let mut handlers = self.x86_64.exception_handlers.lock();
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
        let mut handlers = self.x86_64.exception_handlers.lock();
        let slot = handlers
            .get_mut(vector as usize)
            .ok_or(Error::InvalidArgument)?;
        let Some(registration) = *slot else {
            return Ok(false);
        };

        let resume_context =
            X86_64UserThreadContext::from_interrupt(context).validate_runtime_state()?;
        let mut pending = self.x86_64.pending_exception_frames.lock();
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
            write_x86_64_user_exception_frame(frame_pointer, frame);
        }

        finish_user_exception_delivery(
            slot,
            &mut pending,
            frame_pointer,
            registration.flags,
            x86_64_user_exception_handler_is_one_shot(registration.flags),
        )?;

        *self.x86_64.user_context.lock() = Some(handler_context);
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
            let pending = self.x86_64.pending_exception_frames.lock();
            let Some(active) = pending.top() else {
                return Ok(false);
            };
            if active.frame_pointer != frame_pointer {
                return Err(Error::InvalidArgument);
            }
        }

        let frame = unsafe { read_x86_64_user_exception_frame(frame_pointer) };
        let restored = frame.into_user_context().validate_runtime_state()?;

        {
            let mut pending = self.x86_64.pending_exception_frames.lock();
            if pop_pending_user_exception_frame(&mut pending, frame_pointer)?.is_none() {
                return Ok(false);
            }
        }

        let _ = self.update_x86_64_user_context_if_valid(restored);
        restored.write_to_interrupt(context);
        Ok(true)
    }

    pub(crate) fn replace_x86_64_user_image(&self, start: UserThreadStart) -> Result<()> {
        // The exception stack pointer is part of the start descriptor, and
        // `replace_user_execution_state` installs that; there is no second copy
        // to keep in step any more (the aarch64 half has called it this way all
        // along).
        self.replace_user_execution_state(start, |_| {})?;
        *self.x86_64.user_context.lock() = Some(X86_64UserThreadContext::from_start(start));
        // Replacing the image is `exec`-like: prior handlers and pending
        // exception frames belong to the old image and must not survive.
        *self.x86_64.exception_handlers.lock() = [None; X86_64_EXCEPTION_VECTOR_COUNT];
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
/// This architecture's per-thread state.
///
/// One field on `Thread` instead of three: the saved user context, the
/// installed exception handlers and the pending-frame stack only ever move
/// together — a thread that has a context has a handler table, and a delivery
/// touches both — so they are one object with one lifetime.
pub struct X86_64UserThreadState {
    /// Saved user context; absent until the thread first enters user mode.
    pub(crate) user_context: Mutex<Option<X86_64UserThreadContext>>,
    /// Installed user-exception handlers, indexed by vector.
    pub(crate) exception_handlers:
        Mutex<[Option<X86_64UserExceptionHandlerRegistration>; X86_64_EXCEPTION_VECTOR_COUNT]>,
    /// Frames stacked for nested deliveries that have not returned yet.
    pub(crate) pending_exception_frames: Mutex<X86_64PendingExceptionFrameStack>,
}

impl X86_64UserThreadState {
    pub(crate) const fn new() -> Self {
        Self {
            user_context: Mutex::new(None),
            exception_handlers: Mutex::new([None; X86_64_EXCEPTION_VECTOR_COUNT]),
            pending_exception_frames: Mutex::new(X86_64PendingExceptionFrameStack::new()),
        }
    }

    /// Take a plain-data copy, for suspending a thread and resuming it later.
    pub(crate) fn snapshot(&self) -> X86_64UserThreadStateSnapshot {
        X86_64UserThreadStateSnapshot {
            user_context: *self.user_context.lock(),
            exception_handlers: *self.exception_handlers.lock(),
            pending_exception_frames: *self.pending_exception_frames.lock(),
        }
    }

    /// Put a copy back, replacing what this thread holds now.
    pub(crate) fn restore(&self, snapshot: X86_64UserThreadStateSnapshot) {
        *self.user_context.lock() = snapshot.user_context;
        *self.exception_handlers.lock() = snapshot.exception_handlers;
        *self.pending_exception_frames.lock() = snapshot.pending_exception_frames;
    }

    /// The state a thread starts with, given where it will run.
    pub(crate) fn for_user_start(user_start: Option<UserThreadStart>) -> Self {
        let mut state = Self::new();
        state.user_context = Mutex::new(user_start.map(X86_64UserThreadContext::from_start));
        state
    }
}

/// A [`X86_64UserThreadState`] as plain data, taken and put back whole.
#[derive(Debug, Clone, Copy)]
pub(crate) struct X86_64UserThreadStateSnapshot {
    pub(crate) user_context: Option<X86_64UserThreadContext>,
    pub(crate) exception_handlers:
        [Option<X86_64UserExceptionHandlerRegistration>; X86_64_EXCEPTION_VECTOR_COUNT],
    pub(crate) pending_exception_frames: X86_64PendingExceptionFrameStack,
}

impl X86_64UserThreadStateSnapshot {
    /// Reject a snapshot a thread could not resume from.
    ///
    /// The context is required — a snapshot without one describes a thread that
    /// has never run in user mode — and it has to be one the architecture would
    /// accept on the way back in.
    pub(crate) fn validate(&self) -> Result<()> {
        self.user_context
            .ok_or(Error::InvalidArgument)?
            .validate_runtime_state()?;
        Ok(())
    }
}
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

impl crate::kernel::process::thread::types::UserForkContext for X86_64UserThreadContext {
    fn user_thread_start(&self) -> UserThreadStart {
        UserThreadStart::new(
            self.instruction_pointer as usize,
            self.stack_pointer as usize,
            None,
        )
    }

    fn install(&self, thread: &Thread) {
        *thread.x86_64.user_context.lock() = Some(*self);
    }
}
