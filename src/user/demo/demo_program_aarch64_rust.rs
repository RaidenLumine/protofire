//! src/user/demo/demo_program_aarch64_rust.rs
//!
//! Rust-authored AArch64 demo payload and its kernel-side validation helpers.
//!
//! The payload lives in its own linker section (`protofire_demo_program_aarch64_rust`)
//! so the kernel can extract it as a raw blob and relocate it into a user demo
//! slot.  Because of that relocation every datum the payload touches must be
//! addressed PC-relative through `adr_relative_address!` (`adrp` + `add :lo12:`);
//! a plain `fn as usize` would bake the kernel-link absolute address into the
//! section and break after the blob is copied to user space.
//!
//! Faults are recovered by skipping the fixed 4-byte AArch64 instruction that
//! raised the abort, so the trigger helpers below use exactly one faulting
//! instruction each and the exception handler advances the frame by 4 bytes.

#![cfg_attr(not(test), allow(dead_code))]

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
use crate::abi::exception::{
    AArch64AbortSyndrome, AArch64UserExceptionFrame, AARCH64_ABORT_ACCESS_KIND_EXECUTE,
    AARCH64_ABORT_ACCESS_KIND_READ, AARCH64_ABORT_ACCESS_KIND_WRITE,
    AARCH64_EXCEPTION_DATA_ABORT_VECTOR, AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
use crate::abi::process::{
    ProcessSpawnOptions, ProcessSpawnStringRef, ProcessTerminationRecord,
    PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS, PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT,
    PROCESS_SPAWN_OPTIONS_SIZE, PROCESS_TERMINATION_RECORD_SIZE,
};

/// Compute the runtime address of a symbol inside this payload section using
/// PC-relative `adrp`/`add :lo12:`.  The linker bakes the page-relative
/// offsets, and because the whole section moves as one unit when the kernel
/// relocates the blob into a user slot, the computed address stays correct at
/// whatever address the payload ends up running from.
#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
macro_rules! adr_relative_address {
    ($symbol:path) => {{
        let address: usize;
        unsafe {
            core::arch::asm!(
                "adrp {address}, {symbol}",
                "add {address}, {address}, #:lo12:{symbol}",
                address = lateout(reg) address,
                symbol = sym $symbol,
                options(nostack, preserves_flags),
            );
        }
        address
    }};
}

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_HELLO_MESSAGE: [u8; b"[user  ] hello from aarch64 rust payload\n".len()] =
    *b"[user  ] hello from aarch64 rust payload\n";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_TRIGGER_LOCAL_FAULT_MESSAGE: [u8;
    b"[user  ] aarch64-rust triggering local code-write fault\n".len()] =
    *b"[user  ] aarch64-rust triggering local code-write fault\n";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_RESUMED_LOCAL_FAULT_MESSAGE: [u8;
    b"[user  ] aarch64-rust resumed after local code-write fault\n".len()] =
    *b"[user  ] aarch64-rust resumed after local code-write fault\n";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_RESUMED_LOCAL_EXEC_FAULT_MESSAGE: [u8;
    b"[user  ] aarch64-rust resumed after local stack-exec fault\n".len()] =
    *b"[user  ] aarch64-rust resumed after local stack-exec fault\n";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_TRIGGER_NESTED_LOCAL_FAULT_MESSAGE: [u8;
    b"[user  ] aarch64-rust triggering nested local code-write fault\n".len()] =
    *b"[user  ] aarch64-rust triggering nested local code-write fault\n";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_RESUMED_NESTED_LOCAL_FAULT_MESSAGE: [u8;
    b"[user  ] aarch64-rust resumed after nested local code-write fault\n".len()] =
    *b"[user  ] aarch64-rust resumed after nested local code-write fault\n";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_WAIT_VECTOR_PREFIX: [u8; b"[user  ] aarch64-rust wait-vector: ".len()] =
    *b"[user  ] aarch64-rust wait-vector: ";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_WAIT_ERROR_PREFIX: [u8; b"[user  ] aarch64-rust wait-error: ".len()] =
    *b"[user  ] aarch64-rust wait-error: ";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_WAIT_FSC_PREFIX: [u8; b"[user  ] aarch64-rust wait-fsc: ".len()] =
    *b"[user  ] aarch64-rust wait-fsc: ";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_WAIT_ACCESS_PREFIX: [u8; b"[user  ] aarch64-rust wait-access: ".len()] =
    *b"[user  ] aarch64-rust wait-access: ";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_SPAWN_FAILED_PREFIX: [u8; b"[user  ] aarch64-rust spawn failed: ".len()] =
    *b"[user  ] aarch64-rust spawn failed: ";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_WAIT_FAILED_PREFIX: [u8; b"[user  ] aarch64-rust wait failed: ".len()] =
    *b"[user  ] aarch64-rust wait failed: ";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_WAIT_SIZE_PREFIX: [u8; b"[user  ] aarch64-rust wait-size: ".len()] =
    *b"[user  ] aarch64-rust wait-size: ";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_WAIT_KIND_PREFIX: [u8; b"[user  ] aarch64-rust wait-kind: ".len()] =
    *b"[user  ] aarch64-rust wait-kind: ";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_INSTALL_FAILED_PREFIX: [u8; b"[user  ] aarch64-rust install-handler failed: "
    .len()] = *b"[user  ] aarch64-rust install-handler failed: ";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_CHILD_CATALOG_PATH: [u8; b"app:demo-launcher-fault@0.1.0".len()] =
    *b"app:demo-launcher-fault@0.1.0";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_CHILD_ARGV0: [u8; b"demo-launcher-fault-rust-child".len()] =
    *b"demo-launcher-fault-rust-child";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_CHILD_ARGV1: [u8; b"--trigger-fault=stack-exec".len()] =
    *b"--trigger-fault=stack-exec";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_CHILD_ENV0: [u8; b"ASTRA_APP_ID=demo-launcher-fault-rust-child".len()] =
    *b"ASTRA_APP_ID=demo-launcher-fault-rust-child";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_CHILD_ENV1: [u8; b"ASTRA_PARENT=demo-launcher-rust".len()] =
    *b"ASTRA_PARENT=demo-launcher-rust";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_PERMISSION_LEVEL3: [u8; b"permission fault level 3".len()] =
    *b"permission fault level 3";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_READ_NAME: [u8; b"read".len()] = *b"read";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_WRITE_NAME: [u8; b"write".len()] = *b"write";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_EXECUTE_NAME: [u8; b"execute".len()] = *b"execute";

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_NEWLINE: [u8; b"\n".len()] = *b"\n";

/// A writable byte inside this RX section used as the fault probe target.  The
/// user view of the payload section is read-execute, so a store to this byte
/// raises a data abort (permission fault).
#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[link_section = "protofire_demo_program_aarch64_rust"]
static RUST_PAYLOAD_CODE_WRITE_PROBE: u8 = 0;

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
unsafe extern "C" {
    #[link_name = "__start_protofire_demo_program_aarch64_rust"]
    static PROTOFIRE_DEMO_PROGRAM_AARCH64_RUST_SECTION_START: u8;
    #[link_name = "__stop_protofire_demo_program_aarch64_rust"]
    static PROTOFIRE_DEMO_PROGRAM_AARCH64_RUST_SECTION_END: u8;
}

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
crate::user::syscall::define_aarch64_payload_runtime!("protofire_demo_program_aarch64_rust");

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[inline(never)]
#[link_section = "protofire_demo_program_aarch64_rust"]
extern "C" fn protofire_demo_program_aarch64_rust_entry(
    _argc: usize,
    _argv: usize,
    _envp: usize,
) -> ! {
    write_section_message(
        adr_relative_address!(RUST_PAYLOAD_HELLO_MESSAGE),
        RUST_PAYLOAD_HELLO_MESSAGE.len(),
    );

    let handler = adr_relative_address!(protofire_demo_program_aarch64_rust_exception_handler);
    let nested_handler_flags = AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK
        | AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;
    let install_data_status = install_exception_handler(
        AARCH64_EXCEPTION_DATA_ABORT_VECTOR,
        handler,
        0,
        nested_handler_flags,
    );
    if payload_runtime_status_is_error(install_data_status) {
        write_prefixed_hex(
            adr_relative_address!(RUST_PAYLOAD_INSTALL_FAILED_PREFIX),
            RUST_PAYLOAD_INSTALL_FAILED_PREFIX.len(),
            install_data_status,
        );
        exit_with_code(6);
    }
    let install_instruction_status = install_exception_handler(
        AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR,
        handler,
        0,
        nested_handler_flags,
    );
    if payload_runtime_status_is_error(install_instruction_status) {
        write_prefixed_hex(
            adr_relative_address!(RUST_PAYLOAD_INSTALL_FAILED_PREFIX),
            RUST_PAYLOAD_INSTALL_FAILED_PREFIX.len(),
            install_instruction_status,
        );
        exit_with_code(7);
    }

    write_section_message(
        adr_relative_address!(RUST_PAYLOAD_TRIGGER_LOCAL_FAULT_MESSAGE),
        RUST_PAYLOAD_TRIGGER_LOCAL_FAULT_MESSAGE.len(),
    );
    unsafe {
        trigger_local_code_write_fault_once();
    }
    write_section_message(
        adr_relative_address!(RUST_PAYLOAD_RESUMED_LOCAL_FAULT_MESSAGE),
        RUST_PAYLOAD_RESUMED_LOCAL_FAULT_MESSAGE.len(),
    );
    unsafe {
        trigger_local_stack_exec_fault_once();
    }
    write_section_message(
        adr_relative_address!(RUST_PAYLOAD_RESUMED_LOCAL_EXEC_FAULT_MESSAGE),
        RUST_PAYLOAD_RESUMED_LOCAL_EXEC_FAULT_MESSAGE.len(),
    );
    write_section_message(
        adr_relative_address!(RUST_PAYLOAD_TRIGGER_NESTED_LOCAL_FAULT_MESSAGE),
        RUST_PAYLOAD_TRIGGER_NESTED_LOCAL_FAULT_MESSAGE.len(),
    );
    unsafe {
        trigger_nested_local_code_write_fault_once();
    }
    write_section_message(
        adr_relative_address!(RUST_PAYLOAD_RESUMED_NESTED_LOCAL_FAULT_MESSAGE),
        RUST_PAYLOAD_RESUMED_NESTED_LOCAL_FAULT_MESSAGE.len(),
    );

    let child_argv = [
        ProcessSpawnStringRef {
            ptr: adr_relative_address!(RUST_PAYLOAD_CHILD_ARGV0),
            len: RUST_PAYLOAD_CHILD_ARGV0.len(),
        },
        ProcessSpawnStringRef {
            ptr: adr_relative_address!(RUST_PAYLOAD_CHILD_ARGV1),
            len: RUST_PAYLOAD_CHILD_ARGV1.len(),
        },
    ];
    let child_env = [
        ProcessSpawnStringRef {
            ptr: adr_relative_address!(RUST_PAYLOAD_CHILD_ENV0),
            len: RUST_PAYLOAD_CHILD_ENV0.len(),
        },
        ProcessSpawnStringRef {
            ptr: adr_relative_address!(RUST_PAYLOAD_CHILD_ENV1),
            len: RUST_PAYLOAD_CHILD_ENV1.len(),
        },
    ];
    let spawn_options = ProcessSpawnOptions {
        flags: PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS | PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT,
        argv: child_argv.as_ptr() as usize,
        argc: child_argv.len(),
        env: child_env.as_ptr() as usize,
        envc: child_env.len(),
        working_dir: 0,
        working_dir_len: 0,
    };
    let child_pid = spawn_process_with(
        adr_relative_address!(RUST_PAYLOAD_CHILD_CATALOG_PATH),
        RUST_PAYLOAD_CHILD_CATALOG_PATH.len(),
        (&spawn_options as *const ProcessSpawnOptions).cast::<u8>() as usize,
        PROCESS_SPAWN_OPTIONS_SIZE,
    );
    if payload_runtime_status_is_error(child_pid) {
        write_prefixed_hex(
            adr_relative_address!(RUST_PAYLOAD_SPAWN_FAILED_PREFIX),
            RUST_PAYLOAD_SPAWN_FAILED_PREFIX.len(),
            child_pid,
        );
        exit_with_code(1);
    }

    let mut termination = core::mem::MaybeUninit::<ProcessTerminationRecord>::uninit();
    let wait_size = wait_process_blocking(
        child_pid,
        termination.as_mut_ptr().cast::<u8>() as usize,
        PROCESS_TERMINATION_RECORD_SIZE,
    );
    if payload_runtime_status_is_error(wait_size) {
        write_prefixed_hex(
            adr_relative_address!(RUST_PAYLOAD_WAIT_FAILED_PREFIX),
            RUST_PAYLOAD_WAIT_FAILED_PREFIX.len(),
            wait_size,
        );
        exit_with_code(2);
    }
    if wait_size != PROCESS_TERMINATION_RECORD_SIZE {
        write_prefixed_hex(
            adr_relative_address!(RUST_PAYLOAD_WAIT_SIZE_PREFIX),
            RUST_PAYLOAD_WAIT_SIZE_PREFIX.len(),
            wait_size,
        );
        exit_with_code(3);
    }

    // The child faults by executing from the stack (`--trigger-fault=stack-exec`),
    // so the termination record carries an instruction-abort permission fault.
    let termination = termination.assume_init();
    write_prefixed_hex(
        adr_relative_address!(RUST_PAYLOAD_WAIT_VECTOR_PREFIX),
        RUST_PAYLOAD_WAIT_VECTOR_PREFIX.len(),
        termination.vector,
    );
    write_prefixed_hex(
        adr_relative_address!(RUST_PAYLOAD_WAIT_ERROR_PREFIX),
        RUST_PAYLOAD_WAIT_ERROR_PREFIX.len(),
        termination.error_code,
    );
    let syndrome = AArch64AbortSyndrome::from_exception(termination.vector, termination.error_code);
    write_prefixed_hex(
        adr_relative_address!(RUST_PAYLOAD_WAIT_FSC_PREFIX),
        RUST_PAYLOAD_WAIT_FSC_PREFIX.len(),
        syndrome
            .map(|s| s.fault_status_code() as usize)
            .unwrap_or(0),
    );
    write_prefixed_hex(
        adr_relative_address!(RUST_PAYLOAD_WAIT_ACCESS_PREFIX),
        RUST_PAYLOAD_WAIT_ACCESS_PREFIX.len(),
        syndrome
            .map(|s| s.access_kind_code() as usize)
            .unwrap_or(u8::MAX as usize),
    );
    write_prefixed_hex(
        adr_relative_address!(RUST_PAYLOAD_WAIT_KIND_PREFIX),
        RUST_PAYLOAD_WAIT_KIND_PREFIX.len(),
        termination.kind,
    );
    exit_with_code(0);
}

/// Payload exception handler.  The kernel delivers the abort frame in `x0` and
/// the payload is expected to return via `return_from_exception` after deciding
/// how to resume.  AArch64 instructions are fixed-width (4 bytes), so recovery
/// means skipping exactly one instruction past the faulting access.
#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[inline(never)]
#[link_section = "protofire_demo_program_aarch64_rust"]
extern "C" fn protofire_demo_program_aarch64_rust_exception_handler(
    frame: *mut AArch64UserExceptionFrame,
) -> ! {
    unsafe {
        let frame_ref = &mut *frame;
        if let Some(syndrome) =
            AArch64AbortSyndrome::from_exception(frame_ref.vector, frame_ref.error_code)
        {
            // These strings are the payload's own copies — kernel .rodata is
            // not position-independent and would be stale after relocation.
            write_section_message(
                adr_relative_address!(RUST_PAYLOAD_PERMISSION_LEVEL3),
                RUST_PAYLOAD_PERMISSION_LEVEL3.len(),
            );
            match syndrome.access_kind_code() {
                AARCH64_ABORT_ACCESS_KIND_READ => write_section_message(
                    adr_relative_address!(RUST_PAYLOAD_READ_NAME),
                    RUST_PAYLOAD_READ_NAME.len(),
                ),
                AARCH64_ABORT_ACCESS_KIND_WRITE => write_section_message(
                    adr_relative_address!(RUST_PAYLOAD_WRITE_NAME),
                    RUST_PAYLOAD_WRITE_NAME.len(),
                ),
                AARCH64_ABORT_ACCESS_KIND_EXECUTE => write_section_message(
                    adr_relative_address!(RUST_PAYLOAD_EXECUTE_NAME),
                    RUST_PAYLOAD_EXECUTE_NAME.len(),
                ),
                _ => {}
            }
            write_section_message(
                adr_relative_address!(RUST_PAYLOAD_NEWLINE),
                RUST_PAYLOAD_NEWLINE.len(),
            );
        }

        // Skip the single 4-byte instruction that raised the abort.
        frame_ref.instruction_pointer += 4;
        return_from_exception(frame);
    }
}

/// Store to a byte inside this RX payload section.  The user page is
/// read-execute (writes fault), so the `strb` below raises a data abort.  The
/// handler skips exactly the 4 bytes of the `strb` and resumes at the caller.
#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[inline(never)]
#[link_section = "protofire_demo_program_aarch64_rust"]
unsafe fn trigger_local_code_write_fault_once() {
    let probe = adr_relative_address!(RUST_PAYLOAD_CODE_WRITE_PROBE);
    core::arch::asm!(
        "mov w12, #'!'",
        "strb w12, [{probe}]",
        probe = in(reg) probe,
        out("x12") _,
        options(preserves_flags),
    );
}

/// Copy a `ret` instruction onto the (non-executable) user stack and branch to
/// it.  `br x11` raises an instruction abort; the handler skips the 4-byte `br`
/// and resumes at the copied `ret`, which returns to the stack restore below.
#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[inline(never)]
#[link_section = "protofire_demo_program_aarch64_rust"]
unsafe fn trigger_local_stack_exec_fault_once() {
    core::arch::asm!(
        "sub sp, sp, #16",
        "adr x11, 2f",
        "ldr w12, [x11]",
        "str w12, [sp]",
        "mov x11, sp",
        "adr x30, 3f",
        "br x11",
        "2:",
        ".word 0xd65f03c0",
        "3:",
        "add sp, sp, #16",
        out("x11") _,
        out("x12") _,
        out("x30") _,
        options(preserves_flags),
    );
}

/// A second store into the RX section.  The handler is installed with
/// `ALLOW_NESTED`, and this re-entry exercises that path from the payload's own
/// flow before it moves on to spawning the child.
#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[inline(never)]
#[link_section = "protofire_demo_program_aarch64_rust"]
unsafe fn trigger_nested_local_code_write_fault_once() {
    let probe = adr_relative_address!(RUST_PAYLOAD_CODE_WRITE_PROBE);
    core::arch::asm!(
        "mov w12, #'?'",
        "strb w12, [{probe}]",
        probe = in(reg) probe,
        out("x12") _,
        options(preserves_flags),
    );
}

/// Write `value` as `prefix` followed by a hex number and a newline.
#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[inline(never)]
#[link_section = "protofire_demo_program_aarch64_rust"]
fn write_prefixed_hex(prefix: usize, prefix_len: usize, value: usize) {
    write_section_message(prefix, prefix_len);
    payload_runtime_write_hex(value);
    write_section_message(
        adr_relative_address!(RUST_PAYLOAD_NEWLINE),
        RUST_PAYLOAD_NEWLINE.len(),
    );
}

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
pub fn payload_bytes() -> &'static [u8] {
    unsafe {
        let start = core::ptr::addr_of!(PROTOFIRE_DEMO_PROGRAM_AARCH64_RUST_SECTION_START);
        let end = core::ptr::addr_of!(PROTOFIRE_DEMO_PROGRAM_AARCH64_RUST_SECTION_END);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("aarch64 rust demo payload symbols must be ordered");
        core::slice::from_raw_parts(start, len)
    }
}

#[cfg(not(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none"))))]
pub fn payload_bytes() -> &'static [u8] {
    &[]
}

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
pub fn payload_entry_offset() -> usize {
    let entry = protofire_demo_program_aarch64_rust_entry as usize;
    let start = core::ptr::addr_of!(PROTOFIRE_DEMO_PROGRAM_AARCH64_RUST_SECTION_START) as usize;
    entry
        .checked_sub(start)
        .expect("aarch64 rust demo payload entry must follow section start")
}

#[cfg(not(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none"))))]
pub fn payload_entry_offset() -> usize {
    0
}
