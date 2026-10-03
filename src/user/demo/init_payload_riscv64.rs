//! src/user/demo/init_payload_riscv64.rs
//!
//! The RISC-V 64 init payload: the section, the target's own way of taking an
//! address, and the accessors the ELF builder reads.
//!
//! The program itself — read `/system/rc.d`, declare what it holds, ask for the
//! services to be started — is [`define_init_payload!`], the same body the
//! other two copies emit; see
//! [`crate::user::demo::init_payload_x86_64`] for the shape and
//! [`crate::user::demo::shell_payload_riscv64`] for this target's address form.

/// The address of one of this payload's own literals.
///
/// `la`, not a cast: a cast yields an *absolute* address, and this blob does
/// not run at the address the linker gave it.  The assembler resolves `la`
/// against the symbol's own position (`auipc` + `addi`), which is what a
/// position-independent blob needs; the long form would carry the kernel's page
/// and address the kernel's copy of the data.
macro_rules! init_address {
    ($symbol:path) => {{
        let address: usize;
        // SAFETY: the instruction computes an address out of the instruction
        // pointer and a symbol in this same payload, and touches no memory.
        unsafe {
            core::arch::asm!(
                "la {address}, {symbol}",
                address = lateout(reg) address,
                symbol = sym $symbol,
                options(nostack, preserves_flags),
            );
        }
        address
    }};
}

// The section's own symbols, read by the accessors below.
unsafe extern "C" {
    #[link_name = "__start_protofire_init_payload_riscv64"]
    static PROTOFIRE_INIT_PAYLOAD_RISCV64_SECTION_START: u8;
    #[link_name = "__stop_protofire_init_payload_riscv64"]
    static PROTOFIRE_INIT_PAYLOAD_RISCV64_SECTION_END: u8;
}

crate::user::syscall::define_riscv64_payload_runtime!("protofire_init_payload_riscv64");

// The init program's own two syscalls; see the x86_64 copy for why they are
// emitted by the payload rather than by every runtime.
crate::user::syscall::define_payload_service_stubs!("protofire_init_payload_riscv64");

crate::user::demo::init_payload::define_init_payload!("protofire_init_payload_riscv64");

/// The entry the loader jumps to.
///
/// This target hands over three registers — argument count, argument vector,
/// environment — which its other payloads unpack.  The init program reads none
/// of them: the directory it reads is fixed, and its buffers are the stack the
/// loader left in `sp`.
#[inline(never)]
#[link_section = "protofire_init_payload_riscv64"]
pub extern "C" fn protofire_init_payload_riscv64_entry(
    _argc: usize,
    _argv: usize,
    _envp: usize,
) -> ! {
    init_main()
}

/// The payload's machine code and data.
pub fn payload_bytes() -> &'static [u8] {
    // SAFETY: the linker's own markers around this payload's section bound the
    // slice, which is live for the life of the image.
    unsafe {
        let start = core::ptr::addr_of!(PROTOFIRE_INIT_PAYLOAD_RISCV64_SECTION_START);
        let end = core::ptr::addr_of!(PROTOFIRE_INIT_PAYLOAD_RISCV64_SECTION_END);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("riscv64 init payload symbols must be ordered");

        core::slice::from_raw_parts(start, len)
    }
}

/// Where the payload's entry point sits inside those bytes.
///
/// Not zero: the entry here is a function like any other in the section, so the
/// offset is wherever the compiler put it.
pub fn payload_entry_offset() -> usize {
    let entry = protofire_init_payload_riscv64_entry as *const () as usize;
    let start = core::ptr::addr_of!(PROTOFIRE_INIT_PAYLOAD_RISCV64_SECTION_START) as usize;
    entry
        .checked_sub(start)
        .expect("riscv64 init payload entry must follow the section start")
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
        assert!(INIT_BANNER.starts_with(b"adastra init (ring 3)"));
    }
}
