//! src/user/demo/shell_payload_x86_64.rs
//!
//! Symbol bridge for the Ring 3 x86_64 shell payload section.

#[cfg(test)]
const PAYLOAD_SECTION_NAME: &str = "adastra_shell_payload";

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("shell_payload_x86_64.asm"));

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    static adastra_shell_payload_start: u8;
    static adastra_shell_payload_end: u8;
}

#[cfg(target_arch = "x86_64")]
pub fn payload_bytes() -> &'static [u8] {
    unsafe {
        let start = core::ptr::addr_of!(adastra_shell_payload_start);
        let end = core::ptr::addr_of!(adastra_shell_payload_end);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("x86_64 shell payload symbols must be ordered");

        core::slice::from_raw_parts(start, len)
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn payload_bytes() -> &'static [u8] {
    &[]
}

/// Entry is at offset 0 — the first instruction at
/// `adastra_shell_payload_start` is `jmp shell_main`.
pub fn payload_entry_offset() -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::{payload_bytes, PAYLOAD_SECTION_NAME};

    #[cfg(target_os = "linux")]
    #[test]
    fn asm_shell_payload_disassembly_stays_self_contained_and_scalar_only() {
        let Some(disassembly) = crate::user::payload_test_support::payload_disassembly(
            PAYLOAD_SECTION_NAME,
            !payload_bytes().is_empty(),
        ) else {
            return;
        };

        crate::user::payload_test_support::assert_self_contained_and_scalar_only(&disassembly);
    }
}
