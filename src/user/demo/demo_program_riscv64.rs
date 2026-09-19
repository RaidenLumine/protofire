//! src/user/demo/demo_program_riscv64.rs
//!
//! Symbol bridge for the raw RISC-V 64 demo payload section.

#![cfg_attr(test, allow(dead_code))]

#[cfg(test)]
const RISCV64_TARGET: &str = "riscv64gc-unknown-none-elf";
#[cfg(test)]
const PAYLOAD_START_SYMBOL: &str = "protofire_demo_program_riscv64_payload_start";
#[cfg(test)]
const PAYLOAD_END_SYMBOL: &str = "protofire_demo_program_riscv64_payload_end";

// The payload is hand-written ELF assembly, so it is assembled for the
// bare-metal RISC-V target and for an ELF host (Linux) only.  A COFF or Mach-O
// host cannot assemble it; those builds take the empty fallback below.
#[cfg(all(target_arch = "riscv64", any(target_os = "linux", target_os = "none")))]
core::arch::global_asm!(include_str!("demo_program_riscv64_payload.S"));

#[cfg(all(target_arch = "riscv64", any(target_os = "linux", target_os = "none")))]
unsafe extern "C" {
    static protofire_demo_program_riscv64_payload_start: u8;
    static protofire_demo_program_riscv64_payload_end: u8;
}

#[cfg(all(target_arch = "riscv64", any(target_os = "linux", target_os = "none")))]
pub fn payload_bytes() -> &'static [u8] {
    unsafe {
        let start = core::ptr::addr_of!(protofire_demo_program_riscv64_payload_start);
        let end = core::ptr::addr_of!(protofire_demo_program_riscv64_payload_end);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("riscv64 demo payload symbols must be ordered");

        core::slice::from_raw_parts(start, len)
    }
}

#[cfg(not(all(target_arch = "riscv64", any(target_os = "linux", target_os = "none"))))]
pub fn payload_bytes() -> &'static [u8] {
    &[]
}

#[cfg(test)]
mod tests {
    // The payload-section checks below inspect an ELF image and therefore run
    // on a Linux host only; their imports carry the same gate.
    #[cfg(target_os = "linux")]
    use super::PAYLOAD_END_SYMBOL;
    #[cfg(target_os = "linux")]
    use super::PAYLOAD_START_SYMBOL;
    #[cfg(target_os = "linux")]
    use super::RISCV64_TARGET;

    #[cfg(target_os = "linux")]
    #[test]
    fn asm_demo_payload_symbol_range_is_non_empty() {
        let Some(range) = crate::user::payload_test_support::target_symbol_range(
            RISCV64_TARGET,
            PAYLOAD_START_SYMBOL,
            PAYLOAD_END_SYMBOL,
        ) else {
            return;
        };

        assert!(!range.bytes.is_empty());
        assert!(range.end > range.start);
    }
}
