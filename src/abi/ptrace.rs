//! src/abi/ptrace.rs
//! Ptrace ABI: request codes, event codes, the event record, and the
//! user-mode register file layout shared between kernel and user space.

use core::mem::size_of;

// ── Request codes ──

pub const PTRACE_TRACEME: i32 = 0;
pub const PTRACE_ATTACH: i32 = 1;
pub const PTRACE_DETACH: i32 = 2;
pub const PTRACE_GETREGS: i32 = 3;
pub const PTRACE_SETREGS: i32 = 4;
pub const PTRACE_PEEKDATA: i32 = 5;
pub const PTRACE_POKEDATA: i32 = 6;
pub const PTRACE_CONT: i32 = 7;
pub const PTRACE_SINGLESTEP: i32 = 8;
pub const PTRACE_SYSCALL: i32 = 9;
pub const PTRACE_GETEVENTMSG: i32 = 10;

// ── Event codes ──

pub const PTRACE_EVENT_SIGNAL: u64 = 1;
pub const PTRACE_EVENT_SYSCALL_ENTRY: u64 = 2;
pub const PTRACE_EVENT_SYSCALL_EXIT: u64 = 3;
pub const PTRACE_EVENT_ATTACH: u64 = 4;
pub const PTRACE_EVENT_EXEC: u64 = 5;
pub const PTRACE_EVENT_CLONE: u64 = 6;
pub const PTRACE_EVENT_SINGLESTEP: u64 = 7;

// ── Event record ──

/// Record consumed via PTRACE_GETEVENTMSG: the last ptrace stop event.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PtraceEventRecord {
    pub tid: u64,
    pub event: u64,
    pub message: u64,
    pub syscall_number: u64,
}

pub const PTRACE_EVENT_RECORD_SIZE: usize = size_of::<PtraceEventRecord>();

// ── User-mode register file (x86_64) ──

/// 22 × u64 = 176 bytes: the x86_64 user-mode register file exchanged through
/// PTRACE_GETREGS / PTRACE_SETREGS.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PtraceUserRegsStruct {
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
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}

pub const PTRACE_REGS_SIZE_X86_64: usize = 176;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptrace_request_codes_are_stable() {
        assert_eq!(PTRACE_TRACEME, 0);
        assert_eq!(PTRACE_ATTACH, 1);
        assert_eq!(PTRACE_DETACH, 2);
        assert_eq!(PTRACE_GETREGS, 3);
        assert_eq!(PTRACE_SETREGS, 4);
        assert_eq!(PTRACE_PEEKDATA, 5);
        assert_eq!(PTRACE_POKEDATA, 6);
        assert_eq!(PTRACE_CONT, 7);
        assert_eq!(PTRACE_SINGLESTEP, 8);
        assert_eq!(PTRACE_SYSCALL, 9);
        assert_eq!(PTRACE_GETEVENTMSG, 10);
    }

    #[test]
    fn ptrace_event_codes_are_stable() {
        assert_eq!(PTRACE_EVENT_SIGNAL, 1);
        assert_eq!(PTRACE_EVENT_SYSCALL_ENTRY, 2);
        assert_eq!(PTRACE_EVENT_SYSCALL_EXIT, 3);
        assert_eq!(PTRACE_EVENT_ATTACH, 4);
        assert_eq!(PTRACE_EVENT_EXEC, 5);
        assert_eq!(PTRACE_EVENT_CLONE, 6);
        assert_eq!(PTRACE_EVENT_SINGLESTEP, 7);
    }

    #[test]
    fn ptrace_event_record_size_is_32() {
        assert_eq!(PTRACE_EVENT_RECORD_SIZE, 32);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ptrace_regs_size_is_176() {
        assert_eq!(
            core::mem::size_of::<PtraceUserRegsStruct>(),
            PTRACE_REGS_SIZE_X86_64
        );
    }
}
