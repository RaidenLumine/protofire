//! src/user/demo/demo_program_x86_64.rs
//!
//! Symbol bridge for the raw x86_64 demo payload section.

#[cfg(test)]
const PAYLOAD_SECTION_NAME: &str = "adastra_demo_program_payload";

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("demo_program_x86_64_payload.asm"));

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    static adastra_demo_program_payload_start: u8;
    static adastra_demo_program_payload_end: u8;
}

#[cfg(target_arch = "x86_64")]
pub fn payload_bytes() -> &'static [u8] {
    unsafe {
        let start = core::ptr::addr_of!(adastra_demo_program_payload_start);
        let end = core::ptr::addr_of!(adastra_demo_program_payload_end);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("x86_64 demo payload symbols must be ordered");

        core::slice::from_raw_parts(start, len)
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn payload_bytes() -> &'static [u8] {
    &[]
}

#[cfg(test)]
mod tests {
    use super::payload_bytes;
    use super::PAYLOAD_SECTION_NAME;

    #[cfg(target_os = "linux")]
    #[test]
    fn asm_demo_payload_disassembly_stays_self_contained_and_scalar_only() {
        let Some(disassembly) = crate::user::payload_test_support::payload_disassembly(
            PAYLOAD_SECTION_NAME,
            !payload_bytes().is_empty(),
        ) else {
            return;
        };

        crate::user::payload_test_support::assert_self_contained_and_scalar_only(&disassembly);
    }
}
