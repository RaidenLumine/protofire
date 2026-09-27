//! src/user/demo/demo_program_aarch64_fault.rs
//!
//! Symbol bridge for the AArch64 fault-focused demo payload section.

#![cfg_attr(test, allow(dead_code))]

// The payload is hand-written ELF assembly, so it is assembled for the
// bare-metal aarch64 target and for an ELF host (Linux) only.  A COFF or
// Mach-O host cannot assemble it; those builds take the empty fallback below.
core::arch::global_asm!(include_str!("demo_program_aarch64_fault_payload.S"));

unsafe extern "C" {
    static protofire_demo_program_aarch64_fault_payload_start: u8;
    static protofire_demo_program_aarch64_fault_payload_end: u8;
}

pub fn payload_bytes() -> &'static [u8] {
    // SAFETY: as the other payload sections — the linker's start/end markers bound
    // the section this image carries.
    unsafe {
        let start = core::ptr::addr_of!(protofire_demo_program_aarch64_fault_payload_start);
        let end = core::ptr::addr_of!(protofire_demo_program_aarch64_fault_payload_end);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("aarch64 fault payload symbols must be ordered");

        core::slice::from_raw_parts(start, len)
    }
}
