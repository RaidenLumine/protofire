//! src/arch/trap.rs
//!
//! Shared trap-frame aliases and cross-architecture trap helpers.

#[cfg(target_arch = "aarch64")]
pub use super::aarch64::trap::TrapFrame;

#[cfg(target_arch = "aarch64")]
pub fn entered_from_user_mode(frame: &TrapFrame) -> bool {
    super::aarch64::trap::entered_from_user_mode(frame)
}

#[cfg(target_arch = "aarch64")]
pub fn instruction_pointer(frame: &TrapFrame) -> usize {
    super::aarch64::trap::instruction_pointer(frame)
}

#[cfg(target_arch = "aarch64")]
pub fn vector(frame: &TrapFrame) -> u8 {
    super::aarch64::trap::vector(frame)
}

#[cfg(target_arch = "x86_64")]
pub use super::x86_64::idt::InterruptContext as TrapFrame;

#[cfg(target_arch = "x86_64")]
pub fn entered_from_user_mode(frame: &TrapFrame) -> bool {
    frame.cs & 0x3 != 0
}

#[cfg(target_arch = "x86_64")]
pub fn instruction_pointer(frame: &TrapFrame) -> usize {
    frame.rip as usize
}

#[cfg(target_arch = "x86_64")]
pub fn vector(frame: &TrapFrame) -> u8 {
    frame.vector as u8
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapFrame;
