//! src/kernel/process/thread/arch_riscv64.rs
//!
//! RISC-V 64 user-thread context types.

use core::mem::size_of;

use super::types::UserThreadStart;
use super::Thread;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

/// This architecture's per-thread state.
///
/// riscv64 keeps only the saved user context so far; the field exists as a
/// struct anyway so that the `Thread` has the same shape on every architecture
/// and adding state later does not mean touching the kernel's one struct.
pub struct RiscV64UserThreadState {
    /// Saved user context; absent until the thread first enters user mode.
    pub(crate) user_context: Mutex<Option<RiscV64UserThreadContext>>,
}

impl RiscV64UserThreadState {
    pub(crate) const fn new() -> Self {
        Self {
            user_context: Mutex::new(None),
        }
    }

    /// Take a plain-data copy, for suspending a thread and resuming it later.
    pub(crate) fn snapshot(&self) -> RiscV64UserThreadStateSnapshot {
        RiscV64UserThreadStateSnapshot {
            user_context: *self.user_context.lock(),
        }
    }

    /// Put a copy back, replacing what this thread holds now.
    #[allow(dead_code)]
    pub(crate) fn restore(&self, snapshot: RiscV64UserThreadStateSnapshot) {
        *self.user_context.lock() = snapshot.user_context;
    }
}

/// A [`RiscV64UserThreadState`] as plain data, taken and put back whole.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RiscV64UserThreadStateSnapshot {
    pub(crate) user_context: Option<RiscV64UserThreadContext>,
}

impl RiscV64UserThreadStateSnapshot {
    /// Reject a snapshot a thread could not resume from; see the x86_64 half.
    #[allow(dead_code)]
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
        #[cfg(target_arch = "riscv64")]
        let [a0, a1, a2] = start.riscv64_argument_registers;
        #[cfg(not(target_arch = "riscv64"))]
        let [a0, a1, a2] = [0; 3];
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
}

// ── RISC-V 64 user-thread context on `Thread` ────────────────────────

/// The riscv64 half of the thread API, next to the x86_64 and aarch64
/// halves rather than scattered through the shared lifecycle code.
impl Thread {
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    /// Return the saved RISC-V user thread context (PC + GPRs), or `None` if
    /// this thread has never entered user mode.
    pub fn riscv64_user_context(&self) -> Option<RiscV64UserThreadContext> {
        *self.riscv64.user_context.lock()
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
        *self.riscv64.user_context.lock() = Some(context);
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
    ) {
        let user_context = self.riscv64_user_context();
        if let Some(context) = user_context {
            context.write_to_trap(frame);
        }
    }

    #[cfg(target_arch = "riscv64")]
    #[allow(dead_code)]
    fn clear_riscv64_user_runtime_state(&self) {
        *self.riscv64.user_context.lock() = None;
    }
}

impl crate::kernel::process::thread::types::UserForkContext for RiscV64UserThreadContext {
    fn user_thread_start(&self) -> UserThreadStart {
        UserThreadStart::new(self.instruction_pointer as usize, self.x2 as usize, None)
    }

    fn install(&self, thread: &Thread) {
        thread.set_riscv64_user_context(*self);
    }
}
