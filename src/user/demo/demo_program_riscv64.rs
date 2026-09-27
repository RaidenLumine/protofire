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
core::arch::global_asm!(include_str!("demo_program_riscv64_payload.S"));

// The bytes this build assembled are only read when they are the payload; with
// `abi_frozen_payload` the fixture is, and these symbols have no reader — which
// is why they are compiled out rather than left to warn.
#[cfg(not(feature = "abi_frozen_payload"))]
unsafe extern "C" {
    static protofire_demo_program_riscv64_payload_start: u8;
    static protofire_demo_program_riscv64_payload_end: u8;
}

/// The payload's machine code as it was on 2026-09-27.
///
/// With the `abi_frozen_payload` feature the ELF builder ships these bytes
/// instead of the ones this build assembled, so the boot runs a RISC-V program
/// that was *not* rebuilt — the second architecture the ABI gate covers, and
/// the one whose payload is hand-written assembly rather than a Rust section.
/// The bytes come out of the riscv64 kernel image, between the two symbols that
/// bound the payload inside `.text`:
///
/// ```text
/// cargo build --target riscv64gc-unknown-none-elf --features demo-disk
/// # file offset = .text file offset + (symbol address - .text address)
/// ```
///
/// Re-freezing is a deliberate act, not a build step.
#[cfg(feature = "abi_frozen_payload")]
const FROZEN_PAYLOAD: &[u8] = include_bytes!("fixtures/demo_payload_riscv64.bin");

/// Which copy of the payload this build ships: `frozen` or `compiled`.
///
/// The runtime check asserts the boot line that quotes this.
pub const fn payload_source() -> &'static str {
    if cfg!(feature = "abi_frozen_payload") {
        "frozen"
    } else {
        "compiled"
    }
}

#[cfg(not(feature = "abi_frozen_payload"))]
pub fn payload_bytes() -> &'static [u8] {
    // SAFETY: as the other payload sections — the linker's markers bound the
    // slice, and the section it names lives as long as the image does.
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

#[cfg(feature = "abi_frozen_payload")]
pub fn payload_bytes() -> &'static [u8] {
    FROZEN_PAYLOAD
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
