//! src/user/demo/demo_program_aarch64_fault.rs
//!
//! Symbol bridge for the AArch64 fault-focused demo payload section.

#![cfg_attr(test, allow(dead_code))]

#[cfg(test)]
const AARCH64_TARGET: &str = "aarch64-unknown-none";
#[cfg(test)]
const PAYLOAD_START_SYMBOL: &str = "xiu_demo_program_aarch64_fault_payload_start";
#[cfg(test)]
const PAYLOAD_CODE_END_SYMBOL: &str = "xiu_demo_program_aarch64_fault_payload_code_end";

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("demo_program_aarch64_fault_payload.S"));

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    static xiu_demo_program_aarch64_fault_payload_start: u8;
    static xiu_demo_program_aarch64_fault_payload_end: u8;
}

#[cfg(target_arch = "aarch64")]
pub fn payload_bytes() -> &'static [u8] {
    unsafe {
        let start = core::ptr::addr_of!(xiu_demo_program_aarch64_fault_payload_start);
        let end = core::ptr::addr_of!(xiu_demo_program_aarch64_fault_payload_end);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("aarch64 fault payload symbols must be ordered");

        core::slice::from_raw_parts(start, len)
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub fn payload_bytes() -> &'static [u8] {
    &[]
}

#[cfg(test)]
mod tests {
    use super::{AARCH64_TARGET, PAYLOAD_CODE_END_SYMBOL, PAYLOAD_START_SYMBOL};

    #[cfg(target_os = "linux")]
    #[test]
    fn asm_fault_payload_target_branches_stay_self_contained() {
        let Some(range) = crate::user::payload_test_support::target_symbol_range(
            AARCH64_TARGET,
            PAYLOAD_START_SYMBOL,
            PAYLOAD_CODE_END_SYMBOL,
        ) else {
            return;
        };

        assert!(!range.bytes.is_empty());
        crate::user::payload_test_support::assert_aarch64_direct_branches_stay_within(&range);
    }
}
