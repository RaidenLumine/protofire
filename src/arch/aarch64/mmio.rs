//! src/arch/aarch64/mmio.rs
//!
//! Word-sized volatile access to the device window, and the barrier that
//! orders it.
//!
//! The machines this kernel runs on put their interrupt controllers, their
//! ITS, and their PCIe BARs inside the low window the runtime tables map as
//! device memory, and every one of those register banks is reached the same
//! way: one load or store of the width the register has, never a cached copy.
//! These helpers are that one way, so each driver does not restate it — the
//! caller's part of the contract is the one thing that differs, which is which
//! register it is naming.

use core::arch::asm;
use core::ptr::read_volatile;
use core::ptr::write_volatile;

/// Read a 32-bit register.
pub(crate) fn read_u32(address: usize) -> u32 {
    // SAFETY: the caller names a 32-bit register inside the mapped device
    // window; the read is volatile, so it is the register's value and not a
    // cached one.
    unsafe { read_volatile(address as *const u32) }
}

/// Write a 32-bit register.
pub(crate) fn write_u32(address: usize, value: u32) {
    // SAFETY: as `read_u32` — the same register, on the write side.
    unsafe {
        write_volatile(address as *mut u32, value);
    }
}

/// Read a 64-bit register.
pub(crate) fn read_u64(address: usize) -> u64 {
    // SAFETY: as `read_u32`, for a register the caller knows is 64 bits wide.
    unsafe { read_volatile(address as *const u64) }
}

/// Write a 64-bit register.
pub(crate) fn write_u64(address: usize, value: u64) {
    // SAFETY: as `read_u64`, on the write side.
    unsafe {
        write_volatile(address as *mut u64, value);
    }
}

/// Write one byte of a register bank whose registers are a byte wide, such as
/// a priority array.
pub(crate) fn write_u8(address: usize, value: u8) {
    // SAFETY: as `read_u32`, at the width the caller named.
    unsafe {
        write_volatile(address as *mut u8, value);
    }
}

/// Order the accesses around it against the device.
///
/// These registers are behind the system bus rather than behind a cache, so a
/// write that is only visible to the compiler's ordering is not visible to the
/// device; the architecture asks for a `DSB` before an access is treated as
/// complete.
pub(crate) fn dsb_sy() {
    // SAFETY: a barrier instruction with no memory operand; it accesses
    // nothing, and its effect is the ordering that is the point.
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// Synchronise the instruction stream with the system-register accesses that
/// precede it, which is what a write to an interface-control register needs
/// before the registers it controls are used.
pub(crate) fn isb() {
    // SAFETY: an instruction-synchronisation barrier has no memory operand.
    unsafe {
        asm!("isb", options(nomem, nostack, preserves_flags));
    }
}
