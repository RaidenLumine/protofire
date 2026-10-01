//! src/user/demo/shell_payload_aarch64.rs
//!
//! The AArch64 shell payload: the section, the target's own way of taking an
//! address, and the accessors the ELF builder reads.
//!
//! The program itself — banner, prompt, line reader, tokenizer, builtins — is
//! [`define_shell_payload!`](crate::user::demo::shell_payload::define_shell_payload),
//! the same macro the x86_64 payload expands; what differs between the two is
//! what is in this file.  `src/fs/demo/` writes the result into
//! `/apps/packages/shell/bin/shell.elf`, so the prompt on this machine's console
//! is ring-3 code as well, and the `host_proxy = "shell"` entry in the manifest
//! is no longer the path a boot takes.
//!
//! Everything in the section is either a syscall trap or a function in the same
//! section: the blob is copied out of the kernel image and run at another
//! address, so a call out of it would land in the kernel image's copy of the
//! callee.  On this target that property is held by the branch-range test in
//! [`crate::user::demo::demo_program_aarch64_elf`], which reads the built
//! kernel's section and requires every direct branch in it to stay inside it —
//! the linker-level relocation table the x86_64 check reads is not emitted for
//! this target.

/// The address of one of this payload's own literals.
///
/// `adr`, not a cast: a cast yields an *absolute* address, and this blob does
/// not run at the address the linker gave it.  The instruction's reach is one
/// megabyte, which every payload section is far inside.
macro_rules! shell_address {
    ($symbol:path) => {{
        let address: usize;
        // The macro carries its own `unsafe` because it expands in both unsafe
        // and safe contexts: inside an `unsafe fn` that makes the block
        // redundant (which the lint says), and anywhere else it is the only
        // thing keeping the assembly legal.
        #[allow(unused_unsafe)]
        // SAFETY: `adr` against a symbol in this same payload, resolved at
        // assembly time; the instruction touches no memory.
        unsafe {
            core::arch::asm!(
                "adr {address}, {symbol}",
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
    #[link_name = "__start_protofire_shell_payload_aarch64"]
    static PROTOFIRE_SHELL_PAYLOAD_AARCH64_SECTION_START: u8;
    #[link_name = "__stop_protofire_shell_payload_aarch64"]
    static PROTOFIRE_SHELL_PAYLOAD_AARCH64_SECTION_END: u8;
}

crate::user::syscall::define_aarch64_payload_runtime!("protofire_shell_payload_aarch64");

crate::user::demo::shell_payload::define_shell_payload!("protofire_shell_payload_aarch64");

/// The entry the loader jumps to.
///
/// This target hands over three registers — argument count, argument vector,
/// environment — which the other payloads here unpack.  The shell reads none of
/// them, so they are dropped and the shell's buffers are the stack the loader
/// already left in `sp`.
///
/// Public because it is the payload's entry point, and because that is what
/// keeps the compiler from warning the whole program away as dead code: under
/// the `abi_frozen_payload` feature the accessors below answer with the frozen
/// copy and would otherwise be the only readers of this function.  (The x86_64
/// copy needs no such thing — its entry is an assembly symbol, which the linker
/// keeps whether or not Rust can see a reader.)
#[inline(never)]
#[link_section = "protofire_shell_payload_aarch64"]
pub extern "C" fn protofire_shell_payload_aarch64_entry(
    _argc: usize,
    _argv: usize,
    _envp: usize,
) -> ! {
    shell_main()
}

/// The payload's machine code and data, as it was on 2026-10-01.
///
/// With the `abi_frozen_payload` feature the ELF builder ships these bytes
/// instead of the section this build compiled, so the boot runs an AArch64 shell
/// that was *not* rebuilt — and, like the x86_64 one, one that waits for a
/// command and answers it, so the ABI gate exercises the console and directory
/// syscalls against a frozen caller.
///
/// The bytes come out of the AArch64 kernel image, between the
/// `__start_`/`__stop_protofire_shell_payload_aarch64` symbols:
///
/// ```text
/// cargo build --target aarch64-unknown-none --features demo-disk
/// llvm-objcopy -O binary --only-section=protofire_shell_payload_aarch64 \
///     target/aarch64-unknown-none/debug/protofire \
///     src/user/demo/fixtures/shell_payload_aarch64.bin
/// ```
///
/// Re-freezing is a deliberate act, not a build step: the payload carries the
/// ABI of the day it was built, and that is what makes the gate mean something.
#[cfg(feature = "abi_frozen_payload")]
const FROZEN_PAYLOAD: &[u8] = include_bytes!("fixtures/shell_payload_aarch64.bin");

/// Where the frozen payload's entry point sits inside those bytes.
///
/// Not zero, and that is the point of this target's copy: the entry here is a
/// function like any other in the section, so the offset is wherever the
/// compiler put it — 2052 bytes in, in the frozen copy.
#[cfg(feature = "abi_frozen_payload")]
const FROZEN_PAYLOAD_ENTRY_OFFSET: usize = 2052;

/// The payload's machine code and data, out of the kernel image's copy of it.
#[cfg(not(feature = "abi_frozen_payload"))]
pub fn payload_bytes() -> &'static [u8] {
    // SAFETY: the linker's own markers around this payload's section bound the
    // slice, which is live for the life of the image.
    unsafe {
        let start = core::ptr::addr_of!(PROTOFIRE_SHELL_PAYLOAD_AARCH64_SECTION_START);
        let end = core::ptr::addr_of!(PROTOFIRE_SHELL_PAYLOAD_AARCH64_SECTION_END);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("aarch64 shell payload symbols must be ordered");

        core::slice::from_raw_parts(start, len)
    }
}

#[cfg(feature = "abi_frozen_payload")]
pub fn payload_bytes() -> &'static [u8] {
    FROZEN_PAYLOAD
}

/// Where the payload's entry point sits inside those bytes.
///
/// Not zero on this target: the entry function is a function like any other in
/// the section, so the loader's entry address lands wherever the compiler put
/// it.  The ABI gate freezes an AArch64 payload with a non-zero entry offset for
/// exactly this reason, and this is the shape it keeps working for.
#[cfg(not(feature = "abi_frozen_payload"))]
pub fn payload_entry_offset() -> usize {
    let entry = protofire_shell_payload_aarch64_entry as *const () as usize;
    let start = core::ptr::addr_of!(PROTOFIRE_SHELL_PAYLOAD_AARCH64_SECTION_START) as usize;
    entry
        .checked_sub(start)
        .expect("aarch64 shell payload entry must follow the section start")
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
    use crate::user::payload_test_support::assert_aarch64_direct_branches_stay_within;
    use crate::user::payload_test_support::target_payload_section;

    use super::payload_bytes;
    use super::payload_entry_offset;

    const AARCH64_TARGET: &str = "aarch64-unknown-none";
    const SHELL_SECTION_NAME: &str = "protofire_shell_payload_aarch64";

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
    fn every_direct_branch_in_the_shell_stays_inside_the_payload() {
        // The payload is copied out of the kernel image and run elsewhere, so a
        // `bl` to a function outside its section — the cold arm of a bounds
        // check, say — would run the kernel's copy of that function at the
        // kernel's address, from a payload that no longer lives there.
        let Some(section) = target_payload_section(AARCH64_TARGET, SHELL_SECTION_NAME) else {
            // The AArch64 artifact is not built in every checkout that runs the
            // host tests; when it is missing there is nothing to read.
            return;
        };
        assert!(
            !section.bytes.is_empty(),
            "the shell payload section is empty in the built kernel"
        );
        assert_aarch64_direct_branches_stay_within(&crate::user::payload_test_support::SymbolRange {
            bytes: section.bytes.clone(),
            start: section.section_start,
            end: section.section_start + section.bytes.len(),
        });
    }
}
