//! src/kernel/process/thread/arch_riscv64.rs
//!
//! RISC-V 64 user-thread context types.
use core::mem::size_of;

use super::types::UserThreadStart;
use crate::{Error, Result};

// ── RISC-V 64 user-thread context ────────────────────────────────────

#[cfg(any(target_arch = "riscv64", test))]
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

#[cfg(any(target_arch = "riscv64", test))]
const _: [(); 264] = [(); size_of::<RiscV64UserThreadContext>()];

#[cfg(any(target_arch = "riscv64", test))]
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

    /// Build an initial RISC-V 64 user-thread context from a [`UserThreadStart`]
    /// descriptor.  All general-purpose registers are zeroed except a0–a2
    /// (argument registers) and x2 (stack pointer); the instruction pointer
    /// and sstatus (SPP = User) are set for U-mode execution.
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
