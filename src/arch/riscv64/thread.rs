//! src/arch/riscv64/thread.rs
//!
//! RISC-V 64 user-thread context types.

use core::mem::size_of;

use crate::abi::exception::RiscV64UserExceptionFrame;
use crate::abi::exception::RISCV64_EXCEPTION_INSTRUCTION_ACCESS_FAULT_VECTOR;
use crate::abi::exception::RISCV64_EXCEPTION_INSTRUCTION_ADDRESS_MISALIGNED_VECTOR;
use crate::abi::exception::RISCV64_EXCEPTION_INSTRUCTION_PAGE_FAULT_VECTOR;
use crate::abi::exception::RISCV64_EXCEPTION_LOAD_ACCESS_FAULT_VECTOR;
use crate::abi::exception::RISCV64_EXCEPTION_LOAD_ADDRESS_MISALIGNED_VECTOR;
use crate::abi::exception::RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR;
use crate::abi::exception::RISCV64_EXCEPTION_STORE_ACCESS_FAULT_VECTOR;
use crate::abi::exception::RISCV64_EXCEPTION_STORE_ADDRESS_MISALIGNED_VECTOR;
use crate::abi::exception::RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR;
use crate::abi::exception::RISCV64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;
use crate::abi::exception::RISCV64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT;
use crate::abi::exception::RISCV64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK;
use crate::kernel::process::thread::exception::build_user_exception_delivery;
use crate::kernel::process::thread::exception::finish_user_exception_delivery;
use crate::kernel::process::thread::exception::install_user_exception_handler_registration;
use crate::kernel::process::thread::exception::plan_user_exception_delivery;
use crate::kernel::process::thread::exception::pop_pending_user_exception_frame;
use crate::kernel::process::thread::exception::PendingExceptionFrameStack;
use crate::kernel::process::thread::exception::UserExceptionDeliveryBuildSpec;
use crate::kernel::process::thread::exception::UserExceptionDeliverySelection;
use crate::kernel::process::thread::exception::UserExceptionHandlerInstallProfile;
use crate::kernel::process::thread::types::UserThreadStart;
use crate::kernel::process::thread::Thread;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

/// How many `scause` exception codes this machine can register a handler for.
///
/// The codes are the ones `src/abi/exception.rs` names, and the highest is 15,
/// so 16 slots hold every one of them.  A table sized to the largest code
/// rather than to a round number keeps `handler for code N` an index rather
/// than a search.
pub(crate) const RISCV64_EXCEPTION_VECTOR_COUNT: usize = 16;

// Keep nested user-exception delivery bounded so the per-thread bookkeeping can
// stay fixed-size and avoid heap allocation inside trap handling.
pub const RISCV64_PENDING_USER_EXCEPTION_FRAME_CAPACITY: usize = 4;

pub(crate) const RISCV64_USER_EXCEPTION_HANDLER_SUPPORTED_FLAGS: usize =
    RISCV64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT
        | RISCV64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK
        | RISCV64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;

/// A handler a thread installed for one `scause` exception code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiscV64UserExceptionHandlerRegistration {
    pub handler: usize,
    pub stack_pointer: Option<usize>,
    pub flags: usize,
}

pub(crate) type RiscV64PendingExceptionFrameStack =
    PendingExceptionFrameStack<RISCV64_PENDING_USER_EXCEPTION_FRAME_CAPACITY>;

impl RiscV64UserExceptionFrame {
    pub(crate) fn from_user_context(
        context: RiscV64UserThreadContext,
        vector: u8,
        error_code: u64,
        fault_address: usize,
    ) -> Self {
        Self {
            vector: vector as u64,
            error_code,
            fault_address: fault_address as u64,
            regs: context.regs(),
            instruction_pointer: context.instruction_pointer,
            saved_program_status: context.saved_program_status,
        }
    }

    /// The context a handler resumes this frame into.
    pub(crate) fn into_user_context(self) -> RiscV64UserThreadContext {
        let mut context = RiscV64UserThreadContext {
            x1: 0,
            x2: 0,
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
            x31: 0,
            instruction_pointer: self.instruction_pointer,
            saved_program_status: self.saved_program_status,
        };
        context.set_regs(self.regs);
        context
    }
}

/// Write an exception frame to the user stack, inside the window that makes
/// the store legal.
///
/// `sstatus.SUM` is what lets a supervisor store to a page the process owns
/// (RISCV64 has no separate kernel direct map for user pages), so the frame
/// cannot be written without opening it.  The window brackets the store alone,
/// for the reason `user_access`'s module documentation gives.
///
/// # Safety
///
/// `frame_pointer` must name a writable user stack slot of at least
/// [`RiscV64UserExceptionFrame`]'s size in the calling thread's address space.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
unsafe fn write_riscv64_user_exception_frame(
    frame_pointer: usize,
    frame: RiscV64UserExceptionFrame,
) {
    // SAFETY: the caller's contract is that the slot is writable, and the guard
    // is what makes the store legal under SUM.
    unsafe {
        crate::arch::riscv64::user_access::with_user_access(|| {
            (frame_pointer as *mut RiscV64UserExceptionFrame).write(frame);
        });
    }
}

/// Read an exception frame back from the user stack, under the same window.
///
/// # Safety
///
/// `frame_pointer` must name a readable user stack slot of at least
/// [`RiscV64UserExceptionFrame`]'s size in the calling thread's address space.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
unsafe fn read_riscv64_user_exception_frame(frame_pointer: usize) -> RiscV64UserExceptionFrame {
    // SAFETY: the caller's contract is that the slot is readable, and the guard
    // is what makes the load legal under SUM.
    unsafe {
        crate::arch::riscv64::user_access::with_user_access(|| {
            (frame_pointer as *const RiscV64UserExceptionFrame).read()
        })
    }
}

/// This architecture's per-thread state.
///
/// The handler table and the pending-frame stack are the same shape the other
/// two architectures keep, because the delivery machinery in
/// `kernel::process::thread::exception` is generic over them: riscv64 supplied
/// only the frame type and the trap glue, not a second implementation.
pub struct RiscV64UserThreadState {
    /// Saved user context; absent until the thread first enters user mode.
    pub(crate) user_context: Mutex<Option<RiscV64UserThreadContext>>,
    /// Installed user-exception handlers, indexed by `scause` exception code.
    pub(crate) exception_handlers:
        Mutex<[Option<RiscV64UserExceptionHandlerRegistration>; RISCV64_EXCEPTION_VECTOR_COUNT]>,
    /// Frames stacked for nested deliveries that have not returned yet.
    pub(crate) pending_exception_frames: Mutex<RiscV64PendingExceptionFrameStack>,
}

impl RiscV64UserThreadState {
    pub(crate) const fn new() -> Self {
        Self {
            user_context: Mutex::new(None),
            exception_handlers: Mutex::new([None; RISCV64_EXCEPTION_VECTOR_COUNT]),
            pending_exception_frames: Mutex::new(RiscV64PendingExceptionFrameStack::new()),
        }
    }

    /// Take a plain-data copy, for suspending a thread and resuming it later.
    pub(crate) fn snapshot(&self) -> RiscV64UserThreadStateSnapshot {
        RiscV64UserThreadStateSnapshot {
            user_context: *self.user_context.lock(),
            exception_handlers: *self.exception_handlers.lock(),
            pending_exception_frames: *self.pending_exception_frames.lock(),
        }
    }

    /// Drop this state: the saved context, the handler table and any pending
    /// frames.  What a terminating thread must not keep.
    pub(crate) fn clear(&self) {
        *self.user_context.lock() = None;
        *self.exception_handlers.lock() = [None; RISCV64_EXCEPTION_VECTOR_COUNT];
        self.pending_exception_frames.lock().clear();
    }

    /// Put a copy back, replacing what this thread holds now.
    pub(crate) fn restore(&self, snapshot: RiscV64UserThreadStateSnapshot) {
        *self.user_context.lock() = snapshot.user_context;
        *self.exception_handlers.lock() = snapshot.exception_handlers;
        *self.pending_exception_frames.lock() = snapshot.pending_exception_frames;
    }

    /// The state a thread starts with, given where it will run.
    pub(crate) fn for_user_start(user_start: Option<UserThreadStart>) -> Self {
        let mut state = Self::new();
        state.user_context = Mutex::new(user_start.map(RiscV64UserThreadContext::from_start));
        state
    }
}

/// A [`RiscV64UserThreadState`] as plain data, taken and put back whole.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RiscV64UserThreadStateSnapshot {
    pub(crate) user_context: Option<RiscV64UserThreadContext>,
    pub(crate) exception_handlers:
        [Option<RiscV64UserExceptionHandlerRegistration>; RISCV64_EXCEPTION_VECTOR_COUNT],
    pub(crate) pending_exception_frames: RiscV64PendingExceptionFrameStack,
}

impl RiscV64UserThreadStateSnapshot {
    /// Reject a snapshot a thread could not resume from; see the x86_64 half.
    pub(crate) fn validate(&self) -> Result<()> {
        self.user_context
            .ok_or(Error::InvalidArgument)?
            .validate_runtime_state()?;
        Ok(())
    }
}

// ── RISC-V 64 user-thread context ────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiscV64UserThreadContext {
    pub x1: u64,  // ra
    pub x2: u64,  // sp
    pub x3: u64,  // gp
    pub x4: u64,  // tp
    pub x5: u64,  // t0
    pub x6: u64,  // t1
    pub x7: u64,  // t2
    pub x8: u64,  // s0 / fp
    pub x9: u64,  // s1
    pub x10: u64, // a0
    pub x11: u64, // a1
    pub x12: u64, // a2
    pub x13: u64, // a3
    pub x14: u64, // a4
    pub x15: u64, // a5
    pub x16: u64, // a6
    pub x17: u64, // a7
    pub x18: u64, // s2
    pub x19: u64, // s3
    pub x20: u64, // s4
    pub x21: u64, // s5
    pub x22: u64, // s6
    pub x23: u64, // s7
    pub x24: u64, // s8
    pub x25: u64, // s9
    pub x26: u64, // s10
    pub x27: u64, // s11
    pub x28: u64, // t3
    pub x29: u64, // t4
    pub x30: u64, // t5
    pub x31: u64, // t6
    pub instruction_pointer: u64,
    pub saved_program_status: u64,
}

const _: [(); 264] = [(); size_of::<RiscV64UserThreadContext>()];

#[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
impl RiscV64UserThreadContext {
    // SPP = 0 → User mode; SPIE = 1 so `sret` arms SIE (interrupts enabled)
    // in user mode, matching the x86_64 (RFLAGS.IF) and AArch64 (SPSR)
    // user-mode convention.
    const INITIAL_SSTATUS: u64 = 1 << 5; // SPIE
    const SSTATUS_SPP_MASK: u64 = 1 << 8;
    const SSTATUS_SPP_USER: u64 = 0;

    fn validate_saved_program_status(saved_program_status: u64) -> Result<u64> {
        if saved_program_status & Self::SSTATUS_SPP_MASK != Self::SSTATUS_SPP_USER {
            return Err(Error::InvalidArgument);
        }
        Ok(saved_program_status)
    }

    pub(crate) fn validate_runtime_state(self) -> Result<Self> {
        UserThreadStart::new(self.instruction_pointer as usize, self.x2 as usize, None)
            .validate()?;
        Self::validate_saved_program_status(self.saved_program_status)?;
        Ok(self)
    }

    /// Build an initial RISC-V 64 user-thread context from a
    /// [`UserThreadStart`] descriptor.  All general-purpose registers are
    /// zeroed except a0–a2 (argument registers) and x2 (stack pointer); the
    /// instruction pointer and sstatus (SPP = User) are set for U-mode
    /// execution.
    pub fn from_start(start: UserThreadStart) -> Self {
        let [a0, a1, a2] = start.startup_arguments;
        Self {
            x1: 0,
            x2: start.stack_pointer as u64,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
            x7: 0,
            x8: 0,
            x9: 0,
            x10: a0 as u64,
            x11: a1 as u64,
            x12: a2 as u64,
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
            x31: 0,
            instruction_pointer: start.instruction_pointer as u64,
            saved_program_status: Self::INITIAL_SSTATUS,
        }
    }

    #[cfg(target_arch = "riscv64")]
    pub(crate) fn from_trap(frame: &crate::arch::riscv64::trap::TrapFrame) -> Self {
        Self {
            x1: frame.ra,
            x2: frame.stack_pointer,
            x3: frame.gp,
            x4: frame.tp,
            x5: frame.t0,
            x6: frame.t1,
            x7: frame.t2,
            x8: frame.s0,
            x9: frame.s1,
            x10: frame.a0,
            x11: frame.a1,
            x12: frame.a2,
            x13: frame.a3,
            x14: frame.a4,
            x15: frame.a5,
            x16: frame.a6,
            x17: frame.a7,
            x18: frame.s2,
            x19: frame.s3,
            x20: frame.s4,
            x21: frame.s5,
            x22: frame.s6,
            x23: frame.s7,
            x24: frame.s8,
            x25: frame.s9,
            x26: frame.s10,
            x27: frame.s11,
            x28: frame.t3,
            x29: frame.t4,
            x30: frame.t5,
            x31: frame.t6,
            instruction_pointer: frame.sepc,
            saved_program_status: frame.sstatus,
        }
    }

    #[cfg(target_arch = "riscv64")]
    pub(crate) fn validated_from_trap(
        frame: &crate::arch::riscv64::trap::TrapFrame,
    ) -> Result<Self> {
        Self::from_trap(frame).validate_runtime_state()
    }

    #[cfg(target_arch = "riscv64")]
    pub(crate) fn write_to_trap(self, frame: &mut crate::arch::riscv64::trap::TrapFrame) {
        frame.ra = self.x1;
        frame.stack_pointer = self.x2;
        frame.gp = self.x3;
        frame.tp = self.x4;
        frame.t0 = self.x5;
        frame.t1 = self.x6;
        frame.t2 = self.x7;
        frame.s0 = self.x8;
        frame.s1 = self.x9;
        frame.a0 = self.x10;
        frame.a1 = self.x11;
        frame.a2 = self.x12;
        frame.a3 = self.x13;
        frame.a4 = self.x14;
        frame.a5 = self.x15;
        frame.a6 = self.x16;
        frame.a7 = self.x17;
        frame.s2 = self.x18;
        frame.s3 = self.x19;
        frame.s4 = self.x20;
        frame.s5 = self.x21;
        frame.s6 = self.x22;
        frame.s7 = self.x23;
        frame.s8 = self.x24;
        frame.s9 = self.x25;
        frame.s10 = self.x26;
        frame.s11 = self.x27;
        frame.t3 = self.x28;
        frame.t4 = self.x29;
        frame.t5 = self.x30;
        frame.t6 = self.x31;
        frame.sepc = self.instruction_pointer;
        frame.sstatus = self.saved_program_status;
    }

    /// The interrupted code's `x1`..`x31`, in the order
    /// [`crate::abi::process::RISCV64_SIGNAL_FRAME_REGS`] documents.
    ///
    /// A signal frame is the user context in a form that survives being
    /// written to the user's stack, so the two have one register order
    /// between them — this pair — rather than a conversion at every use.
    pub(crate) fn regs(&self) -> [u64; crate::abi::process::RISCV64_SIGNAL_FRAME_REGS] {
        [
            self.x1, self.x2, self.x3, self.x4, self.x5, self.x6, self.x7, self.x8, self.x9,
            self.x10, self.x11, self.x12, self.x13, self.x14, self.x15, self.x16, self.x17,
            self.x18, self.x19, self.x20, self.x21, self.x22, self.x23, self.x24, self.x25,
            self.x26, self.x27, self.x28, self.x29, self.x30, self.x31,
        ]
    }

    /// Put the `x1`..`x31` back, read in the same order.
    pub(crate) fn set_regs(&mut self, regs: [u64; crate::abi::process::RISCV64_SIGNAL_FRAME_REGS]) {
        self.x1 = regs[0];
        self.x2 = regs[1];
        self.x3 = regs[2];
        self.x4 = regs[3];
        self.x5 = regs[4];
        self.x6 = regs[5];
        self.x7 = regs[6];
        self.x8 = regs[7];
        self.x9 = regs[8];
        self.x10 = regs[9];
        self.x11 = regs[10];
        self.x12 = regs[11];
        self.x13 = regs[12];
        self.x14 = regs[13];
        self.x15 = regs[14];
        self.x16 = regs[15];
        self.x17 = regs[16];
        self.x18 = regs[17];
        self.x19 = regs[18];
        self.x20 = regs[19];
        self.x21 = regs[20];
        self.x22 = regs[21];
        self.x23 = regs[22];
        self.x24 = regs[23];
        self.x25 = regs[24];
        self.x26 = regs[25];
        self.x27 = regs[26];
        self.x28 = regs[27];
        self.x29 = regs[28];
        self.x30 = regs[29];
        self.x31 = regs[30];
    }
}

// ── RISC-V 64 user-thread context on `Thread` ────────────────────────

/// The riscv64 half of the thread API, next to the x86_64 and aarch64
/// halves rather than scattered through the shared lifecycle code.
impl Thread {
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    /// Return the saved RISC-V user thread context (PC + GPRs), or `None` if
    /// this thread has never entered user mode.
    pub fn riscv64_user_context(&self) -> Option<RiscV64UserThreadContext> {
        *self.arch.riscv64.user_context.lock()
    }

    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    pub(crate) fn validated_riscv64_user_context(
        &self,
    ) -> Result<Option<RiscV64UserThreadContext>> {
        self.riscv64_user_context()
            .map(|context| {
                context
                    .validate_runtime_state()
                    .map_err(|_| Error::InternalError)
            })
            .transpose()
    }

    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    pub(crate) fn set_riscv64_user_context(&self, context: RiscV64UserThreadContext) {
        *self.arch.riscv64.user_context.lock() = Some(context);
    }

    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    fn update_riscv64_user_context_if_valid(&self, context: RiscV64UserThreadContext) -> bool {
        let Ok(context) = context.validate_runtime_state() else {
            return false;
        };
        self.set_riscv64_user_context(context);
        true
    }

    #[cfg(target_arch = "riscv64")]
    pub(crate) fn capture_riscv64_user_context_from_trap(
        &self,
        frame: &crate::arch::riscv64::trap::TrapFrame,
    ) {
        let _ =
            self.update_riscv64_user_context_if_valid(RiscV64UserThreadContext::from_trap(frame));
    }

    #[cfg(target_arch = "riscv64")]
    pub(crate) fn write_riscv64_user_context_to_trap(
        &self,
        frame: &mut crate::arch::riscv64::trap::TrapFrame,
    ) -> Result<()> {
        // Validated for the same reason its aarch64 twin is: the status word
        // can come back from a frame the user owns, and an SSTATUS that says
        // supervisor would make `sret` return to S-mode.
        let user_context = self
            .validated_riscv64_user_context()?
            .ok_or(Error::InternalError)?;
        user_context.write_to_trap(frame);
        Ok(())
    }

    /// The address of this thread's dedicated exception stack, if it has one.
    pub fn riscv64_exception_stack_pointer(&self) -> Option<usize> {
        self.user_start()
            .and_then(|start| start.exception_stack_pointer)
    }

    /// The handler this thread installed for a `scause` exception code.
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    pub fn riscv64_exception_handler_registration(
        &self,
        vector: u8,
    ) -> Option<RiscV64UserExceptionHandlerRegistration> {
        self.arch
            .riscv64
            .exception_handlers
            .lock()
            .get(vector as usize)
            .copied()
            .flatten()
    }

    /// How many nested exception frames are waiting to be returned from.
    pub fn riscv64_pending_exception_depth(&self) -> usize {
        self.arch.riscv64.pending_exception_frames.lock().len()
    }

    /// Drop the frames a nested delivery left stacked.
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    fn reset_riscv64_exception_delivery_state(&self) {
        self.arch.riscv64.pending_exception_frames.lock().clear();
    }

    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    pub(crate) fn install_riscv64_exception_handler_with(
        &self,
        vector: u8,
        handler: usize,
        stack_pointer: usize,
        flags: usize,
    ) -> Result<()> {
        self.ensure_user_runtime_mutable()?;

        if !is_supported_riscv64_user_exception_vector(vector) {
            return Err(Error::Unsupported);
        }

        let mut handlers = self.arch.riscv64.exception_handlers.lock();
        let slot = handlers
            .get_mut(vector as usize)
            .ok_or(Error::InvalidArgument)?;

        install_user_exception_handler_registration(
            slot,
            handler,
            stack_pointer,
            flags,
            UserExceptionHandlerInstallProfile {
                supported_flags: RISCV64_USER_EXCEPTION_HANDLER_SUPPORTED_FLAGS,
                allows_nested: riscv64_user_exception_handler_allows_nested(flags),
                requires_exception_stack: riscv64_user_exception_handler_requires_exception_stack(
                    flags,
                ),
                has_thread_exception_stack: self.riscv64_exception_stack_pointer().is_some(),
            },
            || self.reset_riscv64_exception_delivery_state(),
            |handler, stack_pointer, flags| RiscV64UserExceptionHandlerRegistration {
                handler,
                stack_pointer,
                flags,
            },
        )
    }

    /// Deliver a synchronous `scause` exception to this thread's handler.
    ///
    /// `Ok(true)` means the handler was entered and the trap frame rewritten
    /// to run it; `Ok(false)` means there was nothing to deliver to, which is
    /// the caller's signal to terminate the process the way it does for a
    /// thread that never installed one.
    ///
    /// The context comes in rather than being read from a trap frame, so a
    /// host can drive the whole delivery path — handler lookup, stack
    /// selection, nested-frame bookkeeping — without a machine.  The trap
    /// frame is the thin wrapper below.
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    pub(crate) fn deliver_riscv64_user_exception_from_context(
        &self,
        resume_context: RiscV64UserThreadContext,
        vector: u8,
        error_code: u64,
        fault_address: Option<usize>,
    ) -> Result<Option<RiscV64UserThreadContext>> {
        self.ensure_user_runtime_mutable()?;
        let mut handlers = self.arch.riscv64.exception_handlers.lock();
        let slot = handlers
            .get_mut(vector as usize)
            .ok_or(Error::InvalidArgument)?;
        let Some(registration) = *slot else {
            return Ok(None);
        };

        let resume_context = resume_context.validate_runtime_state()?;
        let mut pending = self.arch.riscv64.pending_exception_frames.lock();
        let delivery_stack_pointer = match plan_user_exception_delivery(
            &pending,
            registration.stack_pointer,
            resume_context.x2 as usize,
            self.riscv64_exception_stack_pointer(),
            riscv64_user_exception_handler_allows_nested(registration.flags),
            riscv64_user_exception_handler_allows_nested,
        )? {
            UserExceptionDeliverySelection::Blocked => return Ok(None),
            UserExceptionDeliverySelection::Deliver { stack_pointer } => stack_pointer,
        };
        let (frame_pointer, exception_frame, handler_context) = build_user_exception_delivery(
            UserExceptionDeliveryBuildSpec {
                resume_stack_pointer: resume_context.x2 as usize,
                exception_stack_pointer: delivery_stack_pointer,
                require_exception_stack: riscv64_user_exception_handler_requires_exception_stack(
                    registration.flags,
                ),
                frame_size: size_of::<RiscV64UserExceptionFrame>(),
                handler: registration.handler,
            },
            resume_context,
            |resume_context| {
                RiscV64UserExceptionFrame::from_user_context(
                    resume_context,
                    vector,
                    error_code,
                    fault_address.unwrap_or(0),
                )
            },
            |handler_context, handler, frame_pointer| {
                // The handler is entered the way the other two architectures
                // enter theirs: the synthetic frame is both the stack top and
                // the first argument, and nothing else about the interrupted
                // context is disturbed.  In particular `x1` is left holding
                // the interrupted code's own return address — the other two
                // leave their link register alone for the same reason, and
                // inventing one here would hand the handler a `ret` target
                // that is not where the interrupted code could return to.
                handler_context.instruction_pointer = handler as u64;
                handler_context.x2 = frame_pointer as u64;
                handler_context.x10 = frame_pointer as u64;
            },
        )?;

        // SAFETY: `frame_pointer` is the user stack address this path just
        // validated as writable, and the frame is the value it computes for it.
        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        unsafe {
            write_riscv64_user_exception_frame(frame_pointer, exception_frame);
        }
        #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
        {
            // A host build has no user pages to write into; the caller there
            // is a test asking whether the bookkeeping is right, and the frame
            // value it computed is what it checks.
            let _ = exception_frame;
        }

        finish_user_exception_delivery(
            slot,
            &mut pending,
            frame_pointer,
            registration.flags,
            riscv64_user_exception_handler_is_one_shot(registration.flags),
        )?;

        self.set_riscv64_user_context(handler_context);
        Ok(Some(handler_context))
    }

    #[cfg(target_arch = "riscv64")]
    /// Deliver an exception to this thread's handler, from a live trap frame.
    pub(crate) fn deliver_riscv64_user_exception(
        &self,
        frame: &mut crate::arch::riscv64::trap::TrapFrame,
        vector: u8,
        error_code: u64,
        fault_address: Option<usize>,
    ) -> Result<bool> {
        let resume_context = RiscV64UserThreadContext::from_trap(frame);
        let Some(handler_context) = self.deliver_riscv64_user_exception_from_context(
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

    /// Pop the frame a handler is returning from.
    ///
    /// Split from the trap-frame half for the same reason delivery is: the
    /// bookkeeping — that the pointer names the delivery this thread
    /// recorded, and that popping it leaves the stack consistent — is the part
    /// a host can check, and it is the part that used to be unreachable.
    ///
    /// The pointer check is [`PendingExceptionFrameStack::pop_expected`]'s,
    /// which is where the whole stack's contract is: it refuses a pointer that
    /// is not the top and answers `None` when there is nothing to pop.  A
    /// second copy of that check here was a second place for it to disagree.
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    pub(crate) fn pop_riscv64_user_exception_frame(&self, frame_pointer: usize) -> Result<bool> {
        self.ensure_user_runtime_mutable()?;
        let mut pending = self.arch.riscv64.pending_exception_frames.lock();
        Ok(pop_pending_user_exception_frame(&mut pending, frame_pointer)?.is_some())
    }

    #[cfg(target_arch = "riscv64")]
    /// Resume the context a handler asked to return to.
    ///
    /// The frame is read back from the user stack — it is the handler's own
    /// memory, so it is re-validated rather than trusted — and the thread's
    /// saved context and the trap frame are both set to it.  The pointer is
    /// checked and popped by the same call, so a frame that is not the one at
    /// the top of the pending stack is refused before its contents are read
    /// and leaves the bookkeeping intact.
    pub(crate) fn resume_riscv64_user_exception(
        &self,
        frame: &mut crate::arch::riscv64::trap::TrapFrame,
        frame_pointer: usize,
    ) -> Result<bool> {
        self.ensure_user_runtime_mutable()?;
        // The pointer has to name the delivery this thread recorded before the
        // frame is read: the slot is the handler's own memory, and a handler
        // that passes something else must be refused rather than have the
        // kernel read a page it never wrote.
        {
            let pending = self.arch.riscv64.pending_exception_frames.lock();
            if !pending.names_top(frame_pointer)? {
                return Ok(false);
            }
        }
        // SAFETY: the check above established that `frame_pointer` names the
        // delivery at the top of this thread's pending stack, so it is the slot
        // that delivery wrote; the value is re-validated before any of it
        // reaches a trap frame.
        let restored = unsafe { read_riscv64_user_exception_frame(frame_pointer) }
            .into_user_context()
            .validate_runtime_state()?;
        // Popping after the read, and with the same pointer, keeps the earlier
        // check and this one agreeing: a frame whose contents fail validation
        // leaves the bookkeeping as it was, so the handler can still return
        // from the delivery it is inside.
        if !self.pop_riscv64_user_exception_frame(frame_pointer)? {
            return Ok(false);
        }

        let _ = self.update_riscv64_user_context_if_valid(restored);
        restored.write_to_trap(frame);
        Ok(true)
    }
}

#[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
fn is_supported_riscv64_user_exception_vector(vector: u8) -> bool {
    matches!(
        vector,
        RISCV64_EXCEPTION_INSTRUCTION_ADDRESS_MISALIGNED_VECTOR
            | RISCV64_EXCEPTION_INSTRUCTION_ACCESS_FAULT_VECTOR
            | RISCV64_EXCEPTION_INSTRUCTION_PAGE_FAULT_VECTOR
            | RISCV64_EXCEPTION_LOAD_ADDRESS_MISALIGNED_VECTOR
            | RISCV64_EXCEPTION_LOAD_ACCESS_FAULT_VECTOR
            | RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR
            | RISCV64_EXCEPTION_STORE_ADDRESS_MISALIGNED_VECTOR
            | RISCV64_EXCEPTION_STORE_ACCESS_FAULT_VECTOR
            | RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR
    )
}

#[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
fn riscv64_user_exception_handler_is_one_shot(flags: usize) -> bool {
    flags & RISCV64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT != 0
}

#[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
fn riscv64_user_exception_handler_requires_exception_stack(flags: usize) -> bool {
    flags & RISCV64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK != 0
}

#[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
fn riscv64_user_exception_handler_allows_nested(flags: usize) -> bool {
    flags & RISCV64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED != 0
}

impl crate::kernel::process::thread::types::UserForkContext for RiscV64UserThreadContext {
    fn user_thread_start(&self) -> UserThreadStart {
        UserThreadStart::new(self.instruction_pointer as usize, self.x2 as usize, None)
    }

    fn install(&self, thread: &Thread) {
        thread.set_riscv64_user_context(*self);
    }
}

// ── RISC-V 64 entry trampoline ──────────────────────────────────────

impl Thread {
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    /// Entry trampoline for RISC-V user threads.  Validates the user context,
    /// switches to U-mode if the thread has a valid `UserThreadStart`, or
    /// calls the kernel entry function for pure kernel threads.
    ///
    /// Called by the scheduler when this thread is dispatched.
    pub fn run_entry(&self) {
        let user_start_present = self.user_start().is_some();
        let user_context = match self.validated_riscv64_user_context() {
            Ok(user_context) => user_context,
            Err(_) => {
                crate::println!(
                    "[user  ] invalid riscv64 user context before U-mode entry pid={} tid={}",
                    self.pid(),
                    self.tid()
                );
                return;
            }
        };

        if user_start_present && user_context.is_none() {
            crate::println!(
                "[user  ] missing riscv64 user context before first U-mode entry pid={} tid={}",
                self.pid(),
                self.tid()
            );
            return;
        }

        if crate::kernel::process::thread::lifecycle::should_enter_user_mode(
            user_start_present,
            user_context.is_some(),
        ) {
            let Some(context) = user_context else {
                return;
            };
            // SAFETY: `user_context` is present because the check above said so, and the
            // context was validated before this point.
            unsafe {
                crate::arch::riscv64::context::enter_user_mode_with_context(&context);
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
