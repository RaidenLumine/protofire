//! src/user/demo/shell_payload_x86_64.rs
//!
//! The x86_64 shell payload: the section, the target's own way of taking an
//! address, and the accessors the ELF builder reads.
//!
//! The program itself — banner, prompt, line reader, tokenizer, builtins — is
//! [`define_shell_payload!`](crate::user::demo::shell_payload::define_shell_payload),
//! which emits a copy of it into whichever section it is handed.  A payload is a
//! blob of one target's machine code, so it is emitted once per architecture;
//! what differs between the copies is exactly what is in this file.
//!
//! `src/fs/demo/` writes the result into `/apps/packages/shell/bin/shell.elf`
//! and the boot runs it, so the prompt on the console is this code in ring 3 and
//! not the in-kernel Rust shell only a host without payload sections falls back
//! to.
//!
//! Everything in the section is either a syscall trap or a function in the same
//! section: the blob is copied out of the kernel image and run at another
//! address, so an absolute address, or a call to a function outside the section,
//! would name the kernel image's copy of whatever it pointed at.
//! `scripts/check-payload-relocations.sh` reads the image's relocation table to
//! hold that line, and `adastra_shell_payload` is one of the sections it names.
//!
//! This section used to hold a recovered assembly shell instead, with a symbol
//! bridge in this file's place.  That blob printed a banner and a prompt and then
//! faulted on the first command: its `read_line` kept the typed line at `[rsp]`,
//! which is the return address the `call` had just pushed, so `ret` jumped to the
//! bytes of the command — `help` became the instruction-fetch address
//! `0x706c6568`, in unmapped memory.  A boot with no keyboard sees the banner and
//! the prompt and nothing else, so that shell looked healthy for as long as
//! nothing typed at it.

/// The address of one of this payload's own literals.
///
/// A RIP-relative `lea`, not a cast: a cast yields an *absolute* address, and
/// this blob does not run at the address the linker gave it.
macro_rules! shell_address {
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

// The section's own symbols, read by the two accessors below.  With the
// `abi_frozen_payload` feature those answer with the frozen copy instead, so
// the declarations have no reader: the section is still compiled and still in
// the image, it is simply not the copy that ships.
#[cfg(not(feature = "abi_frozen_payload"))]
unsafe extern "C" {
    static adastra_shell_payload_entry: u8;

    #[link_name = "__start_adastra_shell_payload"]
    static ADASTRA_SHELL_PAYLOAD_SECTION_START: u8;
    #[link_name = "__stop_adastra_shell_payload"]
    static ADASTRA_SHELL_PAYLOAD_SECTION_END: u8;
}

crate::user::syscall::define_x86_64_payload_runtime!("adastra_shell_payload");

// The entry the loader jumps to.  The other payloads on this target take the
// initial stack in `rdi` to read argv and the environment; the shell reads
// neither, so the stub is the jump, and the shell's buffers are the stack the
// loader already left in `rsp`.
core::arch::global_asm!(
    r#"
.section adastra_shell_payload,"ax",@progbits
.global adastra_shell_payload_entry
.type adastra_shell_payload_entry,@function
adastra_shell_payload_entry:
    jmp {main}
"#,
    main = sym shell_main,
);

crate::user::demo::shell_payload::define_shell_payload!("adastra_shell_payload");

/// The payload's machine code and data, as it was on 2026-10-01.
///
/// With the `abi_frozen_payload` feature the ELF builder ships these bytes
/// instead of the section this build compiled, so the boot runs a shell that was
/// *not* rebuilt.  It is the third such program on this architecture and the
/// only interactive one: the launchers announce what they are and exit, while
/// this one waits for a command and answers it, which is what lets the ABI gate
/// exercise the console and directory syscalls against a frozen caller.
///
/// The bytes come out of the x86_64 kernel image, between the
/// `__start_`/`__stop_adastra_shell_payload` symbols:
///
/// ```text
/// cargo build --target x86_64-unknown-none --features demo-disk
/// objcopy -O binary --only-section=adastra_shell_payload \
///     target/x86_64-unknown-none/debug/protofire \
///     src/user/demo/fixtures/shell_payload_x86_64.bin
/// ```
///
/// Re-freezing is a deliberate act, not a build step: the payload carries the
/// ABI of the day it was built, and that is what makes the gate mean something.
#[cfg(feature = "abi_frozen_payload")]
const FROZEN_PAYLOAD: &[u8] = include_bytes!("fixtures/shell_payload_x86_64.bin");

/// Where the frozen payload's entry point sits inside those bytes.
#[cfg(feature = "abi_frozen_payload")]
const FROZEN_PAYLOAD_ENTRY_OFFSET: usize = 0;

#[cfg(not(feature = "abi_frozen_payload"))]
pub fn payload_bytes() -> &'static [u8] {
    // SAFETY: the linker's own markers around this payload's section bound the
    // slice, which is live for the life of the image.
    unsafe {
        let start = core::ptr::addr_of!(ADASTRA_SHELL_PAYLOAD_SECTION_START);
        let end = core::ptr::addr_of!(ADASTRA_SHELL_PAYLOAD_SECTION_END);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("x86_64 shell payload symbols must be ordered");

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
    let entry = core::ptr::addr_of!(adastra_shell_payload_entry) as usize;
    let start = core::ptr::addr_of!(ADASTRA_SHELL_PAYLOAD_SECTION_START) as usize;
    entry
        .checked_sub(start)
        .expect("x86_64 shell payload entry must follow the section start")
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
    use super::payload_bytes;
    use super::payload_entry_offset;
    use super::SHELL_BANNER;
    use super::SHELL_PROMPT_PREFIX;
    use super::SHELL_PROMPT_SUFFIX;

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
    fn the_banner_and_prompt_are_the_lines_the_boot_gates_assert() {
        // `scripts/check-x8664-runtime.sh` requires these in the serial log.
        // A rename has to walk past this test instead of turning a boot gate
        // red in an unrelated change.
        assert!(SHELL_BANNER.starts_with(b"adastra ring3 shell"));
        assert_eq!(SHELL_PROMPT_PREFIX, *b"adastra:");
        assert_eq!(SHELL_PROMPT_SUFFIX, *b"$ ");
    }
}
