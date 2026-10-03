//! src/user/demo/init_payload_x86_64.rs
//!
//! The x86_64 init payload: the section, the target's own way of taking an
//! address, and the accessors the ELF builder reads.
//!
//! The program itself — read `/system/rc.d`, declare what it holds, ask for the
//! services to be started — is [`define_init_payload!`], which emits a copy of
//! it into whichever section it is handed.  What differs between architectures
//! is exactly what is in this file; see
//! [`crate::user::demo::shell_payload_x86_64`] for the same shape on the shell.
//!
//! `src/fs/demo/` writes the result into `/system/init.elf`, which is the path
//! the kernel spawns at boot (`DEFAULT_INIT_PATH`).

/// The address of one of this payload's own literals.
///
/// A RIP-relative `lea`, not a cast: a cast yields an *absolute* address, and
/// this blob does not run at the address the linker gave it.
macro_rules! init_address {
    ($symbol:path) => {{
        let address: usize;
        // SAFETY: the instruction computes an address out of the instruction
        // pointer and a symbol in this same payload, and touches no memory.
        unsafe {
            core::arch::asm!(
                "lea {address}, [rip + {symbol}]",
                address = lateout(reg) address,
                symbol = sym $symbol,
                options(nostack, preserves_flags),
            );
        }
        address
    }};
}

// The section's own symbols, read by the two accessors below.
unsafe extern "C" {
    static adastra_init_payload_entry: u8;

    #[link_name = "__start_adastra_init_payload"]
    static ADASTRA_INIT_PAYLOAD_SECTION_START: u8;
    #[link_name = "__stop_adastra_init_payload"]
    static ADASTRA_INIT_PAYLOAD_SECTION_END: u8;
}

crate::user::syscall::define_x86_64_payload_runtime!("adastra_init_payload");

// The init program's own two syscalls.  They are emitted here rather than by
// every payload runtime, because only this payload calls them — a stub in a
// section that never uses it is bytes on the disk and one more thing moving
// when the linker lays a payload out.
crate::user::syscall::define_payload_service_stubs!("adastra_init_payload");

// The entry the loader jumps to.  As the shell's: nothing is passed, so the
// stub is the jump, and the program's buffers are the stack the loader left in
// `rsp`.
core::arch::global_asm!(
    r#"
.section adastra_init_payload,"ax",@progbits
.global adastra_init_payload_entry
.type adastra_init_payload_entry,@function
adastra_init_payload_entry:
    jmp {main}
"#,
    main = sym init_main,
);

crate::user::demo::init_payload::define_init_payload!("adastra_init_payload");

/// The payload's machine code and data.
pub fn payload_bytes() -> &'static [u8] {
    // SAFETY: the linker's own markers around this payload's section bound the
    // slice, which is live for the life of the image.
    unsafe {
        let start = core::ptr::addr_of!(ADASTRA_INIT_PAYLOAD_SECTION_START);
        let end = core::ptr::addr_of!(ADASTRA_INIT_PAYLOAD_SECTION_END);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("x86_64 init payload symbols must be ordered");

        core::slice::from_raw_parts(start, len)
    }
}

/// Where the payload's entry point sits inside those bytes.
pub fn payload_entry_offset() -> usize {
    let entry = core::ptr::addr_of!(adastra_init_payload_entry) as usize;
    let start = core::ptr::addr_of!(ADASTRA_INIT_PAYLOAD_SECTION_START) as usize;
    entry
        .checked_sub(start)
        .expect("x86_64 init payload entry must follow the section start")
}

#[cfg(test)]
mod tests {
    use super::payload_bytes;
    use super::payload_entry_offset;
    use super::INIT_BANNER;

    #[test]
    fn init_payload_is_a_non_empty_image_with_the_entry_inside_it() {
        let payload = payload_bytes();
        assert!(!payload.is_empty(), "the init payload section is empty");
        assert!(
            payload_entry_offset() < payload.len(),
            "the init payload entry is outside the section it is copied from"
        );
    }

    #[test]
    fn the_banner_is_the_line_the_boot_gate_asserts() {
        // `scripts/check-x8664-runtime.sh` requires this in the serial log.  A
        // rename has to walk past this test instead of turning a boot gate red
        // in an unrelated change.
        assert!(INIT_BANNER.starts_with(b"adastra init (ring 3)"));
    }
}
