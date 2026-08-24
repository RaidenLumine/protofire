//! src/user/demo/demo_program_x86_64_rust.rs
//!
//! Rust-authored x86_64 demo payload and its host-side validation helpers.

#![cfg_attr(not(test), allow(dead_code))]

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
use core::arch::asm;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
use crate::user::exception::{
    X86_64UserExceptionFrame, X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR,
    X86_64_EXCEPTION_INVALID_OPCODE_VECTOR, X86_64_EXCEPTION_PAGE_FAULT_VECTOR,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};

const RUST_PAYLOAD_HELLO_LEN: usize = 33;
const RUST_PAYLOAD_TRIGGER_PAGE_FAULT_LEN: usize = 36;
const RUST_PAYLOAD_RESUMED_AFTER_FAULT_LEN: usize = 42;
const RUST_PAYLOAD_TRIGGER_INVALID_OPCODE_LEN: usize = 40;
const RUST_PAYLOAD_RESUMED_AFTER_INVALID_OPCODE_LEN: usize = 51;
const RUST_PAYLOAD_TRIGGER_GENERAL_PROTECTION_LEN: usize = 44;
const RUST_PAYLOAD_RESUMED_AFTER_GENERAL_PROTECTION_LEN: usize = 55;
const RUST_PAYLOAD_TRIGGER_UNHANDLED_PAGE_FAULT_LEN: usize = 46;
const RUST_PAYLOAD_UNHANDLED_PAGE_FAULT_ARG_LEN: usize = 30;
const RUST_PAYLOAD_PAGE_FAULT_RECOVERY_STACK_DELTA: u64 = 0x100;

// The fault-trigger helpers use hand-written instructions of a fixed length so
// the recovery handlers below can skip the exact faulting bytes and resume the
// payload on the other side.  The lengths must match `trigger_*_once`.
const RUST_PAYLOAD_PAGE_FAULT_INSTRUCTION_SKIP: u64 = 3; // `mov r10, qword ptr [r10]`
const RUST_PAYLOAD_INVALID_OPCODE_INSTRUCTION_SKIP: u64 = 2; // `ud2`
const RUST_PAYLOAD_GENERAL_PROTECTION_INSTRUCTION_SKIP: u64 = 1; // `hlt`

const RUST_PAYLOAD_UNMAPPED_ADDRESS: usize = 0xfeed_beef_0000;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
macro_rules! rip_relative_address {
    ($symbol:path) => {{
        let address: usize;
        unsafe {
            asm!(
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
#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_HELLO_MESSAGE: [u8; RUST_PAYLOAD_HELLO_LEN] =
    *b"[user  ] hello from rust payload\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_TRIGGER_PAGE_FAULT_MESSAGE: [u8; RUST_PAYLOAD_TRIGGER_PAGE_FAULT_LEN] =
    *b"[user  ] triggering rust page fault\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_RESUMED_AFTER_FAULT_MESSAGE: [u8; RUST_PAYLOAD_RESUMED_AFTER_FAULT_LEN] =
    *b"[user  ] resumed after rust fault handler\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_TRIGGER_INVALID_OPCODE_MESSAGE: [u8; RUST_PAYLOAD_TRIGGER_INVALID_OPCODE_LEN] =
    *b"[user  ] triggering rust invalid opcode\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_RESUMED_AFTER_INVALID_OPCODE_MESSAGE: [u8;
    RUST_PAYLOAD_RESUMED_AFTER_INVALID_OPCODE_LEN] =
    *b"[user  ] resumed after rust invalid opcode handler\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_TRIGGER_GENERAL_PROTECTION_MESSAGE: [u8;
    RUST_PAYLOAD_TRIGGER_GENERAL_PROTECTION_LEN] =
    *b"[user  ] triggering rust general protection\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_RESUMED_AFTER_GENERAL_PROTECTION_MESSAGE: [u8;
    RUST_PAYLOAD_RESUMED_AFTER_GENERAL_PROTECTION_LEN] =
    *b"[user  ] resumed after rust general protection handler\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_TRIGGER_UNHANDLED_PAGE_FAULT_MESSAGE: [u8;
    RUST_PAYLOAD_TRIGGER_UNHANDLED_PAGE_FAULT_LEN] =
    *b"[user  ] triggering rust unhandled page fault\n";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_UNHANDLED_PAGE_FAULT_ARG: [u8; RUST_PAYLOAD_UNHANDLED_PAGE_FAULT_ARG_LEN] =
    *b"--trigger-unhandled-page-fault";

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
crate::user::syscall::define_x86_64_payload_runtime!("adastra_demo_program_rust");

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
unsafe extern "C" {
    static adastra_demo_program_rust_entry: u8;

    #[link_name = "__start_adastra_demo_program_rust"]
    static ADASTRA_DEMO_PROGRAM_RUST_SECTION_START: u8;
    #[link_name = "__stop_adastra_demo_program_rust"]
    static ADASTRA_DEMO_PROGRAM_RUST_SECTION_END: u8;
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
core::arch::global_asm!(
    r#"
.section adastra_demo_program_rust,"ax",@progbits
.global adastra_demo_program_rust_entry
.type adastra_demo_program_rust_entry,@function
adastra_demo_program_rust_entry:
    mov rdi, rsp
    jmp {main}
"#,
    main = sym adastra_demo_program_rust_main_from_stack,
);

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
pub fn payload_bytes() -> &'static [u8] {
    unsafe {
        let start = core::ptr::addr_of!(ADASTRA_DEMO_PROGRAM_RUST_SECTION_START);
        let end = core::ptr::addr_of!(ADASTRA_DEMO_PROGRAM_RUST_SECTION_END);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("rust demo payload symbols must be ordered");
        core::slice::from_raw_parts(start, len)
    }
}

#[cfg(not(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none"))))]
pub fn payload_bytes() -> &'static [u8] {
    &[]
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
pub fn payload_entry_offset() -> usize {
    let entry = core::ptr::addr_of!(adastra_demo_program_rust_entry) as usize;
    let start = core::ptr::addr_of!(ADASTRA_DEMO_PROGRAM_RUST_SECTION_START) as usize;
    entry
        .checked_sub(start)
        .expect("rust demo payload entry must follow section start")
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
extern "C" fn rust_payload_recover_page_fault(frame: *mut X86_64UserExceptionFrame) -> ! {
    unsafe {
        let frame_ref = &mut *frame;
        frame_ref.instruction_pointer += RUST_PAYLOAD_PAGE_FAULT_INSTRUCTION_SKIP;
        // Move the user stack past the faulting frame so the resumed payload
        // continues with the same recovery area the handler received.
        frame_ref.stack_pointer = frame_ref
            .stack_pointer
            .wrapping_add(RUST_PAYLOAD_PAGE_FAULT_RECOVERY_STACK_DELTA);
        return_from_exception(frame);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
extern "C" fn rust_payload_recover_invalid_opcode(frame: *mut X86_64UserExceptionFrame) -> ! {
    unsafe {
        let frame_ref = &mut *frame;
        frame_ref.instruction_pointer += RUST_PAYLOAD_INVALID_OPCODE_INSTRUCTION_SKIP;
        return_from_exception(frame);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
extern "C" fn rust_payload_recover_general_protection(frame: *mut X86_64UserExceptionFrame) -> ! {
    unsafe {
        let frame_ref = &mut *frame;
        frame_ref.instruction_pointer += RUST_PAYLOAD_GENERAL_PROTECTION_INSTRUCTION_SKIP;
        return_from_exception(frame);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
unsafe fn trigger_page_fault_once() {
    // A single 3-byte load from an unmapped address.  The recovery handler
    // skips exactly these three bytes to resume after the faulting access.
    core::arch::asm!(
        "mov r10, qword ptr [r10]",
        in("r10") RUST_PAYLOAD_UNMAPPED_ADDRESS,
        options(nostack),
    );
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
unsafe fn trigger_invalid_opcode_once() {
    // `ud2` is exactly two bytes; the recovery handler skips them.
    core::arch::asm!("ud2", options(nostack));
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
unsafe fn trigger_general_protection_once() {
    // `hlt` is a 1-byte privileged instruction that raises #GP in ring 3.
    core::arch::asm!("hlt", options(nostack));
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[inline(never)]
#[link_section = "adastra_demo_program_rust"]
extern "C" fn adastra_demo_program_rust_main_from_stack(_initial_stack: usize) -> ! {
    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_HELLO_MESSAGE),
        RUST_PAYLOAD_HELLO_MESSAGE.len(),
    );

    // Install recovery handlers for each fault the payload triggers below.
    install_exception_handler(
        X86_64_EXCEPTION_PAGE_FAULT_VECTOR,
        rust_payload_recover_page_fault as *const () as usize,
        0,
        X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
    );
    install_exception_handler(
        X86_64_EXCEPTION_INVALID_OPCODE_VECTOR,
        rust_payload_recover_invalid_opcode as *const () as usize,
        0,
        X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
    );
    install_exception_handler(
        X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR,
        rust_payload_recover_general_protection as *const () as usize,
        0,
        X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
    );

    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_TRIGGER_PAGE_FAULT_MESSAGE),
        RUST_PAYLOAD_TRIGGER_PAGE_FAULT_MESSAGE.len(),
    );
    unsafe {
        trigger_page_fault_once();
    }
    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_RESUMED_AFTER_FAULT_MESSAGE),
        RUST_PAYLOAD_RESUMED_AFTER_FAULT_MESSAGE.len(),
    );

    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_TRIGGER_INVALID_OPCODE_MESSAGE),
        RUST_PAYLOAD_TRIGGER_INVALID_OPCODE_MESSAGE.len(),
    );
    unsafe {
        trigger_invalid_opcode_once();
    }
    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_RESUMED_AFTER_INVALID_OPCODE_MESSAGE),
        RUST_PAYLOAD_RESUMED_AFTER_INVALID_OPCODE_MESSAGE.len(),
    );

    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_TRIGGER_GENERAL_PROTECTION_MESSAGE),
        RUST_PAYLOAD_TRIGGER_GENERAL_PROTECTION_MESSAGE.len(),
    );
    unsafe {
        trigger_general_protection_once();
    }
    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_RESUMED_AFTER_GENERAL_PROTECTION_MESSAGE),
        RUST_PAYLOAD_RESUMED_AFTER_GENERAL_PROTECTION_MESSAGE.len(),
    );

    // The final phase advertises the unhandled page fault path.  The payload
    // exits here; the ring3 launcher child exercises the unhandled path with
    // `--trigger-unhandled-page-fault`.
    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_TRIGGER_UNHANDLED_PAGE_FAULT_MESSAGE),
        RUST_PAYLOAD_TRIGGER_UNHANDLED_PAGE_FAULT_MESSAGE.len(),
    );
    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_UNHANDLED_PAGE_FAULT_ARG),
        RUST_PAYLOAD_UNHANDLED_PAGE_FAULT_ARG.len(),
    );

    exit_with_code(1);
}
