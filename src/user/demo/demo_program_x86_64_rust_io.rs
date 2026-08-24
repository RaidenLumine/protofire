//! src/user/demo/demo_program_x86_64_rust_io.rs
//!
//! Rust-authored x86_64 demo I/O payload (files, directories, spawn/wait) and
//! its host-side validation helpers.

#![cfg_attr(not(test), allow(dead_code))]

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
use core::mem::MaybeUninit;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
use crate::abi::process::{
    ProcessSpawnOptions, ProcessSpawnStringRef, ProcessTerminationRecord,
    PROCESS_SPAWN_OPTIONS_SIZE, PROCESS_TERMINATION_KIND_EXCEPTION, PROCESS_TERMINATION_KIND_EXIT,
    PROCESS_TERMINATION_RECORD_SIZE,
};

const RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY: usize = 256;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
macro_rules! rip_relative_address {
    ($symbol:path) => {{
        let address: usize;
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

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_HELLO_MESSAGE: [u8; b"[user  ] hello from rust io payload\n".len()] =
    *b"[user  ] hello from rust io payload\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_RESUMED_AFTER_YIELD_MESSAGE: [u8;
    b"[user  ] resumed after rust io yield\n".len()] = *b"[user  ] resumed after rust io yield\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_APP_ID_PREFIX: [u8; b"[user  ] rust app-id: ".len()] =
    *b"[user  ] rust app-id: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_CWD_PREFIX: [u8; b"[user  ] rust cwd: ".len()] = *b"[user  ] rust cwd: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_IMAGE_PREFIX: [u8; b"[user  ] rust image: ".len()] =
    *b"[user  ] rust image: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_MANIFEST_PREFIX: [u8; b"[user  ] rust manifest: ".len()] =
    *b"[user  ] rust manifest: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_ARG0_PREFIX: [u8; b"[user  ] rust argv0: ".len()] =
    *b"[user  ] rust argv0: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_ENV0_PREFIX: [u8; b"[user  ] rust env0: ".len()] = *b"[user  ] rust env0: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_STACK_ARG0_PREFIX: [u8; b"[user  ] rust stack-argv0: ".len()] =
    *b"[user  ] rust stack-argv0: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_STACK_ENV0_PREFIX: [u8; b"[user  ] rust stack-env0: ".len()] =
    *b"[user  ] rust stack-env0: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_STACK_AUX_PAGESZ_PREFIX: [u8; b"[user  ] rust stack-aux-pagesz: ".len()] =
    *b"[user  ] rust stack-aux-pagesz: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_STACK_AUX_ENTRY_PREFIX: [u8; b"[user  ] rust stack-aux-entry: ".len()] =
    *b"[user  ] rust stack-aux-entry: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_FILE_PREFIX: [u8; b"[user  ] rust file: ".len()] = *b"[user  ] rust file: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_DATA_PREFIX: [u8; b"[user  ] rust data: ".len()] = *b"[user  ] rust data: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_MKDIR_PREFIX: [u8; b"[user  ] rust mkdir: ".len()] =
    *b"[user  ] rust mkdir: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_SESSION_FILE_PREFIX: [u8; b"[user  ] rust session-file: ".len()] =
    *b"[user  ] rust session-file: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_SESSION_PREFIX: [u8; b"[user  ] rust session: ".len()] =
    *b"[user  ] rust session: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_REMOVED_PREFIX: [u8; b"[user  ] rust removed: ".len()] =
    *b"[user  ] rust removed: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_PID_PREFIX: [u8; b"[user  ] rust wait-pid: ".len()] =
    *b"[user  ] rust wait-pid: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_EXIT_PREFIX: [u8; b"[user  ] rust wait-exit: ".len()] =
    *b"[user  ] rust wait-exit: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_VECTOR_PREFIX: [u8; b"[user  ] rust wait-vector: ".len()] =
    *b"[user  ] rust wait-vector: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_ERROR_PREFIX: [u8; b"[user  ] rust wait-error: ".len()] =
    *b"[user  ] rust wait-error: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_ADDRESS_PREFIX: [u8; b"[user  ] rust wait-addr: ".len()] =
    *b"[user  ] rust wait-addr: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_EXCEPTION_PID_PREFIX: [u8; b"[user  ] rust wait-exception-pid: "
    .len()] = *b"[user  ] rust wait-exception-pid: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_EXCEPTION_VECTOR_PREFIX: [u8;
    b"[user  ] rust wait-exception-vector: ".len()] = *b"[user  ] rust wait-exception-vector: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_EXCEPTION_ERROR_PREFIX: [u8; b"[user  ] rust wait-exception-error: "
    .len()] = *b"[user  ] rust wait-exception-error: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_EXCEPTION_ADDRESS_PREFIX: [u8; b"[user  ] rust wait-exception-addr: "
    .len()] = *b"[user  ] rust wait-exception-addr: ";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_CHILD_CATALOG_PATH: [u8; b"app:demo-launcher-rust@0.1.0".len()] =
    *b"app:demo-launcher-rust@0.1.0";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_CHILD_ARGV0: [u8; b"demo-launcher-rust-child".len()] =
    *b"demo-launcher-rust-child";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_CHILD_ARGV1: [u8; b"--spawned-by=rust-io".len()] =
    *b"--spawned-by=rust-io";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_CHILD_ENV0: [u8; b"ASTRA_APP_ID=demo-launcher-rust-child".len()] =
    *b"ASTRA_APP_ID=demo-launcher-rust-child";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_CHILD_ENV1: [u8; b"ASTRA_PARENT=demo-launcher-rust-io".len()] =
    *b"ASTRA_PARENT=demo-launcher-rust-io";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_EXCEPTION_CHILD_ARGV0: [u8;
    b"demo-launcher-rust-unhandled-page-fault-child".len()] =
    *b"demo-launcher-rust-unhandled-page-fault-child";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_EXCEPTION_CHILD_ARGV1: [u8; b"--trigger-unhandled-page-fault".len()] =
    *b"--trigger-unhandled-page-fault";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_WAIT_EXCEPTION_CHILD_ENV0: [u8;
    b"ASTRA_APP_ID=demo-launcher-rust-unhandled-page-fault-child".len()] =
    *b"ASTRA_APP_ID=demo-launcher-rust-unhandled-page-fault-child";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_NEWLINE: [u8; b"\n".len()] = *b"\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_README_PATH: [u8; b"/system/runtime/README.txt".len()] =
    *b"/system/runtime/README.txt";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_DATA_PATH: [u8; b"/data/users/guest/downloads/ring3-rust-io.txt".len()] =
    *b"/data/users/guest/downloads/ring3-rust-io.txt";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_STATE_DIR_PATH: [u8; b"/data/users/guest/downloads/rust-io-state".len()] =
    *b"/data/users/guest/downloads/rust-io-state";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_SESSION_PATH: [u8;
    b"/data/users/guest/downloads/rust-io-state/session.log".len()] =
    *b"/data/users/guest/downloads/rust-io-state/session.log";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_TEMP_PATH: [u8; b"/data/users/guest/downloads/rust-io-state/temp.bin"
    .len()] = *b"/data/users/guest/downloads/rust-io-state/temp.bin";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_DATA_BYTES: [u8; b"rust io data path roundtrip".len()] =
    *b"rust io data path roundtrip";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_SESSION_BYTES: [u8; b"rust io session persisted".len()] =
    *b"rust io session persisted";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_SESSION_TRUNCATED_BYTES: [u8; b"rust io session".len()] =
    *b"rust io session";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust_io"]
static RUST_IO_PAYLOAD_TEMP_BYTES: [u8; b"temporary rust io state".len()] =
    *b"temporary rust io state";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
unsafe extern "C" {
    static adastra_demo_program_rust_io_entry: u8;

    #[link_name = "__start_adastra_demo_program_rust_io"]
    static ASTRA_DEMO_PROGRAM_RUST_IO_SECTION_START: u8;
    #[link_name = "__stop_adastra_demo_program_rust_io"]
    static ASTRA_DEMO_PROGRAM_RUST_IO_SECTION_END: u8;
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
crate::user::syscall::define_x86_64_payload_runtime!("adastra_demo_program_rust_io");

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
core::arch::global_asm!(
    r#"
.section adastra_demo_program_rust_io,"ax",@progbits
.global adastra_demo_program_rust_io_entry
.type adastra_demo_program_rust_io_entry,@function
adastra_demo_program_rust_io_entry:
    mov rdi, rsp
    jmp {main}
"#,
    main = sym adastra_demo_program_rust_io_main_from_stack,
);

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
pub fn payload_bytes() -> &'static [u8] {
    unsafe {
        let start = core::ptr::addr_of!(ASTRA_DEMO_PROGRAM_RUST_IO_SECTION_START);
        let end = core::ptr::addr_of!(ASTRA_DEMO_PROGRAM_RUST_IO_SECTION_END);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("rust io demo payload symbols must be ordered");
        core::slice::from_raw_parts(start, len)
    }
}

#[cfg(not(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none"))))]
pub fn payload_bytes() -> &'static [u8] {
    &[]
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
pub fn payload_entry_offset() -> usize {
    let entry = core::ptr::addr_of!(adastra_demo_program_rust_io_entry) as usize;
    let start = core::ptr::addr_of!(ASTRA_DEMO_PROGRAM_RUST_IO_SECTION_START) as usize;
    entry
        .checked_sub(start)
        .expect("rust io demo payload entry must follow section start")
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
fn ensure_ok(status: usize, exit_code: usize) -> usize {
    if payload_runtime_status_is_error(status) {
        exit_with_code(exit_code);
    }
    status
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
fn ensure_exact(actual: usize, expected: usize, exit_code: usize) {
    if actual != expected {
        exit_with_code(exit_code);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
fn ensure_ok_or_already_exists(status: usize, _exit_code: usize) {
    // The state directory may already exist on a re-run; continue either way.
    let _ = status;
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
fn write_prefixed_bytes(prefix: usize, prefix_len: usize, bytes: usize, byte_len: usize) {
    write_section_message(prefix, prefix_len);
    write_section_message(bytes, byte_len);
    write_section_message(
        rip_relative_address!(RUST_IO_PAYLOAD_NEWLINE),
        RUST_IO_PAYLOAD_NEWLINE.len(),
    );
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
fn write_prefixed_c_string(prefix: usize, prefix_len: usize, c_string: usize) {
    write_section_message(prefix, prefix_len);
    payload_runtime_write_c_string(c_string);
    write_section_message(
        rip_relative_address!(RUST_IO_PAYLOAD_NEWLINE),
        RUST_IO_PAYLOAD_NEWLINE.len(),
    );
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
fn write_prefixed_hex(prefix: usize, prefix_len: usize, value: usize) {
    write_section_message(prefix, prefix_len);
    payload_runtime_write_hex(value);
    write_section_message(
        rip_relative_address!(RUST_IO_PAYLOAD_NEWLINE),
        RUST_IO_PAYLOAD_NEWLINE.len(),
    );
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[allow(clippy::too_many_arguments)]
fn spawn_child_and_wait(
    catalog_path: usize,
    catalog_path_len: usize,
    argv0: usize,
    argv0_len: usize,
    argv1: usize,
    argv1_len: usize,
    env0: usize,
    env0_len: usize,
    env1: usize,
    env1_len: usize,
    pid_prefix: usize,
    pid_prefix_len: usize,
    exit_prefix: usize,
    exit_prefix_len: usize,
    vector_prefix: usize,
    vector_prefix_len: usize,
    error_prefix: usize,
    error_prefix_len: usize,
    address_prefix: usize,
    address_prefix_len: usize,
) {
    let child_argv = [
        ProcessSpawnStringRef {
            ptr: argv0,
            len: argv0_len,
        },
        ProcessSpawnStringRef {
            ptr: argv1,
            len: argv1_len,
        },
    ];
    let child_env = [
        ProcessSpawnStringRef {
            ptr: env0,
            len: env0_len,
        },
        ProcessSpawnStringRef {
            ptr: env1,
            len: env1_len,
        },
    ];
    let spawn_options = ProcessSpawnOptions::override_argv_env(
        child_argv.as_ptr() as usize,
        child_argv.len(),
        child_env.as_ptr() as usize,
        child_env.len(),
    );
    let child_pid = ensure_ok(
        spawn_process_with(
            catalog_path,
            catalog_path_len,
            (&spawn_options as *const ProcessSpawnOptions).cast::<u8>() as usize,
            PROCESS_SPAWN_OPTIONS_SIZE,
        ),
        40,
    );
    write_prefixed_hex(pid_prefix, pid_prefix_len, child_pid);

    let mut record = ProcessTerminationRecord::none();
    let wait_size = ensure_ok(
        wait_process_blocking(
            child_pid,
            (&mut record as *mut ProcessTerminationRecord).cast::<u8>() as usize,
            PROCESS_TERMINATION_RECORD_SIZE,
        ),
        41,
    );
    ensure_exact(wait_size, PROCESS_TERMINATION_RECORD_SIZE, 42);

    match record.kind {
        PROCESS_TERMINATION_KIND_EXIT => {
            write_prefixed_hex(exit_prefix, exit_prefix_len, record.status);
        }
        PROCESS_TERMINATION_KIND_EXCEPTION => {
            write_prefixed_hex(vector_prefix, vector_prefix_len, record.vector as usize);
            write_prefixed_hex(error_prefix, error_prefix_len, record.error_code as usize);
            if record.fault_address_present != 0 {
                write_prefixed_hex(address_prefix, address_prefix_len, record.fault_address);
            }
        }
        _ => exit_with_code(43),
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[inline(never)]
#[link_section = "adastra_demo_program_rust_io"]
extern "C" fn adastra_demo_program_rust_io_main_from_stack(initial_stack: usize) -> ! {
    let read_write_create_flags = crate::abi::io::OPEN_FLAG_READ_WRITE_CREATE;

    write_section_message(
        rip_relative_address!(RUST_IO_PAYLOAD_HELLO_MESSAGE),
        RUST_IO_PAYLOAD_HELLO_MESSAGE.len(),
    );

    yield_now();
    write_section_message(
        rip_relative_address!(RUST_IO_PAYLOAD_RESUMED_AFTER_YIELD_MESSAGE),
        RUST_IO_PAYLOAD_RESUMED_AFTER_YIELD_MESSAGE.len(),
    );

    // ── launch metadata ──────────────────────────────────────────────────
    let mut app_id_buffer = MaybeUninit::<[u8; RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY]>::uninit();
    let app_id_len = ensure_ok(
        app_id(
            app_id_buffer.as_mut_ptr() as usize,
            RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY,
        ),
        1,
    );
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_APP_ID_PREFIX),
        RUST_IO_PAYLOAD_APP_ID_PREFIX.len(),
        app_id_buffer.as_ptr() as *const u8 as usize,
        app_id_len,
    );

    let mut cwd_buffer = MaybeUninit::<[u8; RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY]>::uninit();
    let cwd_len = ensure_ok(
        current_dir(
            cwd_buffer.as_mut_ptr() as usize,
            RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY,
        ),
        2,
    );
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_CWD_PREFIX),
        RUST_IO_PAYLOAD_CWD_PREFIX.len(),
        cwd_buffer.as_ptr() as *const u8 as usize,
        cwd_len,
    );

    let mut image_buffer = MaybeUninit::<[u8; RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY]>::uninit();
    let image_len = ensure_ok(
        image_path(
            image_buffer.as_mut_ptr() as usize,
            RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY,
        ),
        3,
    );
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_IMAGE_PREFIX),
        RUST_IO_PAYLOAD_IMAGE_PREFIX.len(),
        image_buffer.as_ptr() as *const u8 as usize,
        image_len,
    );

    let mut manifest_buffer = MaybeUninit::<[u8; RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY]>::uninit();
    let manifest_len = ensure_ok(
        manifest_path(
            manifest_buffer.as_mut_ptr() as usize,
            RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY,
        ),
        4,
    );
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_MANIFEST_PREFIX),
        RUST_IO_PAYLOAD_MANIFEST_PREFIX.len(),
        manifest_buffer.as_ptr() as *const u8 as usize,
        manifest_len,
    );

    let mut argv0_buffer = MaybeUninit::<[u8; RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY]>::uninit();
    let argv0_len = ensure_ok(
        arg_value(
            0,
            argv0_buffer.as_mut_ptr() as usize,
            RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY,
        ),
        5,
    );
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_ARG0_PREFIX),
        RUST_IO_PAYLOAD_ARG0_PREFIX.len(),
        argv0_buffer.as_ptr() as *const u8 as usize,
        argv0_len,
    );

    let env_count = ensure_ok(env_count(), 6);
    if env_count > 0 {
        let mut env_buffer = MaybeUninit::<[u8; RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY]>::uninit();
        let env_len = ensure_ok(
            env_value(
                0,
                env_buffer.as_mut_ptr() as usize,
                RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY,
            ),
            7,
        );
        write_prefixed_bytes(
            rip_relative_address!(RUST_IO_PAYLOAD_ENV0_PREFIX),
            RUST_IO_PAYLOAD_ENV0_PREFIX.len(),
            env_buffer.as_ptr() as *const u8 as usize,
            env_len,
        );
    }

    // ── initial user-stack inspection ────────────────────────────────────
    let stack_argv0 = payload_runtime_stack_argv_value(initial_stack, 0);
    write_prefixed_c_string(
        rip_relative_address!(RUST_IO_PAYLOAD_STACK_ARG0_PREFIX),
        RUST_IO_PAYLOAD_STACK_ARG0_PREFIX.len(),
        stack_argv0,
    );

    let stack_env0 = payload_runtime_stack_env_value(initial_stack, 0);
    write_prefixed_c_string(
        rip_relative_address!(RUST_IO_PAYLOAD_STACK_ENV0_PREFIX),
        RUST_IO_PAYLOAD_STACK_ENV0_PREFIX.len(),
        stack_env0,
    );

    let aux_pagesz =
        payload_runtime_stack_find_auxv_value(initial_stack, PAYLOAD_RUNTIME_X86_64_AUXV_AT_PAGESZ);
    write_prefixed_hex(
        rip_relative_address!(RUST_IO_PAYLOAD_STACK_AUX_PAGESZ_PREFIX),
        RUST_IO_PAYLOAD_STACK_AUX_PAGESZ_PREFIX.len(),
        aux_pagesz,
    );

    let aux_entry =
        payload_runtime_stack_find_auxv_value(initial_stack, PAYLOAD_RUNTIME_X86_64_AUXV_AT_ENTRY);
    write_prefixed_hex(
        rip_relative_address!(RUST_IO_PAYLOAD_STACK_AUX_ENTRY_PREFIX),
        RUST_IO_PAYLOAD_STACK_AUX_ENTRY_PREFIX.len(),
        aux_entry,
    );

    // ── runtime README ───────────────────────────────────────────────────
    let readme_fd = ensure_ok(
        open_path(
            rip_relative_address!(RUST_IO_PAYLOAD_README_PATH),
            RUST_IO_PAYLOAD_README_PATH.len(),
            crate::abi::io::OPEN_FLAG_READ,
        ),
        10,
    );
    let mut readme_buffer = MaybeUninit::<[u8; RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY]>::uninit();
    let readme_count = ensure_ok(
        read_fd(
            readme_fd,
            readme_buffer.as_mut_ptr() as *mut u8 as usize,
            RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY,
            0,
        ),
        11,
    );
    ensure_ok(close_fd(readme_fd), 12);
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_FILE_PREFIX),
        RUST_IO_PAYLOAD_FILE_PREFIX.len(),
        readme_buffer.as_ptr() as *const u8 as usize,
        readme_count,
    );

    // ── data file write/read round trip ──────────────────────────────────
    let data_fd = ensure_ok(
        open_path(
            rip_relative_address!(RUST_IO_PAYLOAD_DATA_PATH),
            RUST_IO_PAYLOAD_DATA_PATH.len(),
            read_write_create_flags,
        ),
        13,
    );
    ensure_exact(
        write_fd(
            data_fd,
            rip_relative_address!(RUST_IO_PAYLOAD_DATA_BYTES),
            RUST_IO_PAYLOAD_DATA_BYTES.len(),
        ),
        RUST_IO_PAYLOAD_DATA_BYTES.len(),
        14,
    );
    ensure_ok(seek_fd(data_fd, 0, crate::kernel::fs::SEEK_SET), 15);
    let mut data_buffer = MaybeUninit::<[u8; RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY]>::uninit();
    let data_count = ensure_ok(
        read_fd(
            data_fd,
            data_buffer.as_mut_ptr() as *mut u8 as usize,
            RUST_IO_PAYLOAD_DATA_BYTES.len(),
            0,
        ),
        16,
    );
    ensure_ok(close_fd(data_fd), 17);
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_DATA_PREFIX),
        RUST_IO_PAYLOAD_DATA_PREFIX.len(),
        data_buffer.as_ptr() as *const u8 as usize,
        data_count,
    );

    // ── state directory + session log ────────────────────────────────────
    ensure_ok_or_already_exists(
        make_dir(
            rip_relative_address!(RUST_IO_PAYLOAD_STATE_DIR_PATH),
            RUST_IO_PAYLOAD_STATE_DIR_PATH.len(),
        ),
        18,
    );
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_MKDIR_PREFIX),
        RUST_IO_PAYLOAD_MKDIR_PREFIX.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_STATE_DIR_PATH),
        RUST_IO_PAYLOAD_STATE_DIR_PATH.len(),
    );

    let session_fd = ensure_ok(
        open_path(
            rip_relative_address!(RUST_IO_PAYLOAD_SESSION_PATH),
            RUST_IO_PAYLOAD_SESSION_PATH.len(),
            read_write_create_flags,
        ),
        19,
    );
    ensure_exact(
        write_fd(
            session_fd,
            rip_relative_address!(RUST_IO_PAYLOAD_SESSION_BYTES),
            RUST_IO_PAYLOAD_SESSION_BYTES.len(),
        ),
        RUST_IO_PAYLOAD_SESSION_BYTES.len(),
        20,
    );
    ensure_exact(
        set_len(session_fd, RUST_IO_PAYLOAD_SESSION_TRUNCATED_BYTES.len()),
        RUST_IO_PAYLOAD_SESSION_TRUNCATED_BYTES.len(),
        21,
    );
    ensure_ok(seek_fd(session_fd, 0, crate::kernel::fs::SEEK_SET), 22);
    let mut session_buffer = MaybeUninit::<[u8; RUST_IO_PAYLOAD_READ_BUFFER_CAPACITY]>::uninit();
    let session_count = ensure_ok(
        read_fd(
            session_fd,
            session_buffer.as_mut_ptr() as *mut u8 as usize,
            RUST_IO_PAYLOAD_SESSION_TRUNCATED_BYTES.len(),
            0,
        ),
        23,
    );
    ensure_ok(close_fd(session_fd), 24);
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_SESSION_FILE_PREFIX),
        RUST_IO_PAYLOAD_SESSION_FILE_PREFIX.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_SESSION_PATH),
        RUST_IO_PAYLOAD_SESSION_PATH.len(),
    );
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_SESSION_PREFIX),
        RUST_IO_PAYLOAD_SESSION_PREFIX.len(),
        session_buffer.as_ptr() as *const u8 as usize,
        session_count,
    );

    // ── temporary file create + remove ───────────────────────────────────
    let temp_fd = ensure_ok(
        open_path(
            rip_relative_address!(RUST_IO_PAYLOAD_TEMP_PATH),
            RUST_IO_PAYLOAD_TEMP_PATH.len(),
            read_write_create_flags,
        ),
        25,
    );
    ensure_exact(
        write_fd(
            temp_fd,
            rip_relative_address!(RUST_IO_PAYLOAD_TEMP_BYTES),
            RUST_IO_PAYLOAD_TEMP_BYTES.len(),
        ),
        RUST_IO_PAYLOAD_TEMP_BYTES.len(),
        26,
    );
    ensure_ok(close_fd(temp_fd), 27);
    ensure_ok(
        remove_path(
            rip_relative_address!(RUST_IO_PAYLOAD_TEMP_PATH),
            RUST_IO_PAYLOAD_TEMP_PATH.len(),
        ),
        28,
    );
    write_prefixed_bytes(
        rip_relative_address!(RUST_IO_PAYLOAD_REMOVED_PREFIX),
        RUST_IO_PAYLOAD_REMOVED_PREFIX.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_TEMP_PATH),
        RUST_IO_PAYLOAD_TEMP_PATH.len(),
    );

    // ── spawn + wait the normal rust child ───────────────────────────────
    spawn_child_and_wait(
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_CHILD_CATALOG_PATH),
        RUST_IO_PAYLOAD_WAIT_CHILD_CATALOG_PATH.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_CHILD_ARGV0),
        RUST_IO_PAYLOAD_WAIT_CHILD_ARGV0.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_CHILD_ARGV1),
        RUST_IO_PAYLOAD_WAIT_CHILD_ARGV1.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_CHILD_ENV0),
        RUST_IO_PAYLOAD_WAIT_CHILD_ENV0.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_CHILD_ENV1),
        RUST_IO_PAYLOAD_WAIT_CHILD_ENV1.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_PID_PREFIX),
        RUST_IO_PAYLOAD_WAIT_PID_PREFIX.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_EXIT_PREFIX),
        RUST_IO_PAYLOAD_WAIT_EXIT_PREFIX.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_VECTOR_PREFIX),
        RUST_IO_PAYLOAD_WAIT_VECTOR_PREFIX.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_ERROR_PREFIX),
        RUST_IO_PAYLOAD_WAIT_ERROR_PREFIX.len(),
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_ADDRESS_PREFIX),
        RUST_IO_PAYLOAD_WAIT_ADDRESS_PREFIX.len(),
    );

    // ── spawn + wait the unhandled-page-fault exception child ────────────
    let exception_child_argv = [
        ProcessSpawnStringRef {
            ptr: rip_relative_address!(RUST_IO_PAYLOAD_WAIT_EXCEPTION_CHILD_ARGV0),
            len: RUST_IO_PAYLOAD_WAIT_EXCEPTION_CHILD_ARGV0.len(),
        },
        ProcessSpawnStringRef {
            ptr: rip_relative_address!(RUST_IO_PAYLOAD_WAIT_EXCEPTION_CHILD_ARGV1),
            len: RUST_IO_PAYLOAD_WAIT_EXCEPTION_CHILD_ARGV1.len(),
        },
    ];
    let exception_child_env = [ProcessSpawnStringRef {
        ptr: rip_relative_address!(RUST_IO_PAYLOAD_WAIT_EXCEPTION_CHILD_ENV0),
        len: RUST_IO_PAYLOAD_WAIT_EXCEPTION_CHILD_ENV0.len(),
    }];
    let exception_spawn_options = ProcessSpawnOptions::override_argv_env(
        exception_child_argv.as_ptr() as usize,
        exception_child_argv.len(),
        exception_child_env.as_ptr() as usize,
        exception_child_env.len(),
    );
    let exception_child_pid = ensure_ok(
        spawn_process_with(
            rip_relative_address!(RUST_IO_PAYLOAD_WAIT_CHILD_CATALOG_PATH),
            RUST_IO_PAYLOAD_WAIT_CHILD_CATALOG_PATH.len(),
            (&exception_spawn_options as *const ProcessSpawnOptions).cast::<u8>() as usize,
            PROCESS_SPAWN_OPTIONS_SIZE,
        ),
        50,
    );
    write_prefixed_hex(
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_EXCEPTION_PID_PREFIX),
        RUST_IO_PAYLOAD_WAIT_EXCEPTION_PID_PREFIX.len(),
        exception_child_pid,
    );

    let mut exception_record = ProcessTerminationRecord::none();
    let exception_wait_size = ensure_ok(
        wait_process_blocking(
            exception_child_pid,
            (&mut exception_record as *mut ProcessTerminationRecord).cast::<u8>() as usize,
            PROCESS_TERMINATION_RECORD_SIZE,
        ),
        51,
    );
    ensure_exact(exception_wait_size, PROCESS_TERMINATION_RECORD_SIZE, 52);
    write_prefixed_hex(
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_EXCEPTION_VECTOR_PREFIX),
        RUST_IO_PAYLOAD_WAIT_EXCEPTION_VECTOR_PREFIX.len(),
        exception_record.vector as usize,
    );
    write_prefixed_hex(
        rip_relative_address!(RUST_IO_PAYLOAD_WAIT_EXCEPTION_ERROR_PREFIX),
        RUST_IO_PAYLOAD_WAIT_EXCEPTION_ERROR_PREFIX.len(),
        exception_record.error_code as usize,
    );
    if exception_record.fault_address_present != 0 {
        write_prefixed_hex(
            rip_relative_address!(RUST_IO_PAYLOAD_WAIT_EXCEPTION_ADDRESS_PREFIX),
            RUST_IO_PAYLOAD_WAIT_EXCEPTION_ADDRESS_PREFIX.len(),
            exception_record.fault_address,
        );
    }

    exit_with_code(0);
}
