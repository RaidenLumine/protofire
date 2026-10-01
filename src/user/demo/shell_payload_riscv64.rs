//! src/user/demo/shell_payload_riscv64.rs
//!
//! The RISC-V 64 shell payload: the section, the target's own way of taking an
//! address, and the accessors the ELF builder reads.
//!
//! The program itself is
//! [`define_shell_payload!`](crate::user::demo::shell_payload::define_shell_payload),
//! the macro the other two architectures expand as well, so the three machines
//! run one shell.  This is the first Rust-authored payload on this target — the
//! demo launcher here is hand-written `.S`, and until now so was everything
//! else — which is why `define_riscv64_payload_runtime!` arrived with it.
//!
//! `src/fs/demo/` writes the result into `/apps/packages/shell/bin/shell.elf`,
//! so the prompt on this machine's console is ring-3 code and the
//! `host_proxy = "shell"` entry in the manifest is no longer the path a boot
//! takes.
//!
//! Everything in the section is either a syscall trap or a function in the same
//! section, and on this target the interesting reference is the one that takes a
//! literal's address: `la` has to assemble to a PC-relative pair (`auipc` +
//! `addi`), because the blob is copied out of the kernel image and run at
//! another address, where a `lui` with the kernel's page in it would address the
//! kernel's copy of the data.  The frozen-payload gate is what holds that line
//! here — the copy is run from the disk, so an absolute address faults — and the
//! assembly below is where the reason lives.

/// The address of one of this payload's own literals.
///
/// `la`, which the assembler resolves against the symbol's own position; the
/// long form would be `auipc` + `addi` and that is what this has to be.  The
/// assembly payloads on this target use the same instruction for the same
/// reason.
macro_rules! shell_address {
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

// The section's own symbols, read by the two accessors below.  With the
// `abi_frozen_payload` feature those answer with the frozen copy instead, so
// the declarations have no reader: the section is still compiled and still in
// the image, it is simply not the copy that ships.
#[cfg(not(feature = "abi_frozen_payload"))]
unsafe extern "C" {
    #[link_name = "__start_protofire_shell_payload_riscv64"]
    static PROTOFIRE_SHELL_PAYLOAD_RISCV64_SECTION_START: u8;
    #[link_name = "__stop_protofire_shell_payload_riscv64"]
    static PROTOFIRE_SHELL_PAYLOAD_RISCV64_SECTION_END: u8;
}

crate::user::syscall::define_riscv64_payload_runtime!("protofire_shell_payload_riscv64");

crate::user::demo::shell_payload::define_shell_payload!("protofire_shell_payload_riscv64");

/// The entry the loader jumps to.
///
/// This target hands over three registers — argument count, argument vector,
/// environment — which its assembly payloads unpack; the shell reads none of
/// them, so they are dropped and the shell's buffers are the stack the loader
/// already left in `sp`.
///
/// Public because it is the payload's entry point, and because that is what
/// keeps the compiler from warning the whole program away as dead code: under
/// the `abi_frozen_payload` feature the accessors below answer with the frozen
/// copy and would otherwise be the only readers of this function.
#[inline(never)]
#[link_section = "protofire_shell_payload_riscv64"]
pub extern "C" fn protofire_shell_payload_riscv64_entry(
    _argc: usize,
    _argv: usize,
    _envp: usize,
) -> ! {
    shell_main()
}

/// The payload's machine code and data, as it was on 2026-10-01.
///
/// With the `abi_frozen_payload` feature the ELF builder ships these bytes
/// instead of the section this build compiled, so the boot runs a RISC-V shell
/// that was *not* rebuilt — and, like the other two, one that waits for a
/// command and answers it, so the ABI gate exercises the console and directory
/// syscalls against a frozen caller.
///
/// The bytes come out of the RISC-V kernel image, between the
/// `__start_`/`__stop_protofire_shell_payload_riscv64` symbols:
///
/// ```text
/// cargo build --target riscv64gc-unknown-none-elf --features demo-disk
/// llvm-objcopy -O binary --only-section=protofire_shell_payload_riscv64 \
///     target/riscv64gc-unknown-none-elf/debug/protofire \
///     src/user/demo/fixtures/shell_payload_riscv64.bin
/// ```
///
/// Re-freezing is a deliberate act, not a build step: the payload carries the
/// ABI of the day it was built, and that is what makes the gate mean something.
#[cfg(feature = "abi_frozen_payload")]
const FROZEN_PAYLOAD: &[u8] = include_bytes!("fixtures/shell_payload_riscv64.bin");

/// Where the frozen payload's entry point sits inside those bytes.
///
/// Not zero, like the AArch64 copy: the entry here is a function like any other
/// in the section, so the offset is wherever the compiler put it — 2008 bytes
/// in, in the frozen copy.
#[cfg(feature = "abi_frozen_payload")]
const FROZEN_PAYLOAD_ENTRY_OFFSET: usize = 2008;

/// The payload's machine code and data, out of the kernel image's copy of it.
#[cfg(not(feature = "abi_frozen_payload"))]
pub fn payload_bytes() -> &'static [u8] {
    // SAFETY: the linker's own markers around this payload's section bound the
    // slice, which is live for the life of the image.
    unsafe {
        let start = core::ptr::addr_of!(PROTOFIRE_SHELL_PAYLOAD_RISCV64_SECTION_START);
        let end = core::ptr::addr_of!(PROTOFIRE_SHELL_PAYLOAD_RISCV64_SECTION_END);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("riscv64 shell payload symbols must be ordered");

        core::slice::from_raw_parts(start, len)
    }
}

#[cfg(feature = "abi_frozen_payload")]
pub fn payload_bytes() -> &'static [u8] {
    FROZEN_PAYLOAD
}

/// Where the payload's entry point sits inside those bytes.
#[cfg(not(feature = "abi_frozen_payload"))]
pub fn payload_entry_offset() -> usize {
    let entry = protofire_shell_payload_riscv64_entry as *const () as usize;
    let start = core::ptr::addr_of!(PROTOFIRE_SHELL_PAYLOAD_RISCV64_SECTION_START) as usize;
    entry
        .checked_sub(start)
        .expect("riscv64 shell payload entry must follow the section start")
}

#[cfg(feature = "abi_frozen_payload")]
pub fn payload_entry_offset() -> usize {
    FROZEN_PAYLOAD_ENTRY_OFFSET
}

/// Which copy of the payload this build ships: `frozen` or `compiled`.
///
/// The runtime check asserts the boot line that quotes this, so a run of the
/// ABI gate cannot pass while quietly testing a freshly built payload.
pub const fn payload_source() -> &'static str {
    if cfg!(feature = "abi_frozen_payload") {
        "frozen"
    } else {
        "compiled"
    }
}

#[cfg(test)]
mod tests {
    use crate::user::payload_test_support::target_payload_section;

    use super::payload_bytes;
    use super::payload_entry_offset;

    const RISCV64_TARGET: &str = "riscv64gc-unknown-none-elf";
    const SHELL_SECTION_NAME: &str = "protofire_shell_payload_riscv64";

    #[test]
    fn shell_payload_is_a_non_empty_image_with_the_entry_inside_it() {
        let payload = payload_bytes();
        assert!(!payload.is_empty(), "the shell payload section is empty");
        assert!(
            payload_entry_offset() < payload.len(),
            "the shell payload entry is outside the section it is copied from"
        );
    }

    #[test]
    fn the_built_section_addresses_its_own_data_with_auipc() {
        // The one reference that has to be checked on this target: `la` against
        // a literal.  A PC-relative pair starts with `auipc`; an absolute one
        // would be a `lui` carrying the page the payload was linked at, which is
        // the kernel's page and not the address the blob runs at.  The section
        // is read out of the built kernel, so this is the bytes the demo disk
        // gets.
        let Some(section) = target_payload_section(RISCV64_TARGET, SHELL_SECTION_NAME) else {
            // The RISC-V artifact is not built in every checkout that runs the
            // host tests; when it is missing there is nothing to read.
            return;
        };
        let mut auipc = 0;
        for word in section.bytes.chunks_exact(4) {
            let instruction = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            // `auipc` is opcode 0b0010111 = 0x17 in bits 0..7.
            if instruction & 0x7f == 0x17 {
                auipc += 1;
            }
        }
        assert!(
            auipc > 0,
            "the shell payload never computes a PC-relative address: its literals \
             must be reached with `auipc`, not with an absolute page"
        );
    }
}
