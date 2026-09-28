//! src/user/demo/demo_program_x86_64_rust.rs
//!
//! Rust-authored x86_64 demo payload and its host-side validation helpers.

// The payload body and its constants exist only for x86_64 Linux/bare-metal
// builds.  Outside the unit-test harness, and on every host that cannot carry
// an ELF payload section (a Windows host, for instance), the empty fallbacks
// below are compiled instead and those constants end up unreferenced.
#![cfg_attr(
    any(
        not(test),
        not(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))
    ),
    allow(dead_code)
)]

use core::arch::asm;

use crate::user::exception::X86_64UserExceptionFrame;
use crate::user::exception::X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR;
use crate::user::exception::X86_64_EXCEPTION_INVALID_OPCODE_VECTOR;
use crate::user::exception::X86_64_EXCEPTION_PAGE_FAULT_VECTOR;
use crate::user::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK;

const RUST_PAYLOAD_HELLO_LEN: usize = 33;
const RUST_PAYLOAD_TRIGGER_PAGE_FAULT_LEN: usize = 36;
const RUST_PAYLOAD_RESUMED_AFTER_FAULT_LEN: usize = 42;
const RUST_PAYLOAD_TRIGGER_INVALID_OPCODE_LEN: usize = 40;
const RUST_PAYLOAD_RESUMED_AFTER_INVALID_OPCODE_LEN: usize = 51;
const RUST_PAYLOAD_TRIGGER_GENERAL_PROTECTION_LEN: usize = 44;
const RUST_PAYLOAD_RESUMED_AFTER_GENERAL_PROTECTION_LEN: usize = 55;
const RUST_PAYLOAD_TRIGGER_UNHANDLED_PAGE_FAULT_LEN: usize = 46;
const RUST_PAYLOAD_UNHANDLED_PAGE_FAULT_ARG_LEN: usize = 30;

// The fault-trigger helpers use hand-written instructions of a fixed length so
// the recovery handlers below can skip the exact faulting bytes and resume the
// payload on the other side.  The lengths must match `trigger_*_once`.
const RUST_PAYLOAD_PAGE_FAULT_INSTRUCTION_SKIP: u64 = 3; // `mov r10, qword ptr [r10]`
const RUST_PAYLOAD_INVALID_OPCODE_INSTRUCTION_SKIP: u64 = 2; // `ud2`
const RUST_PAYLOAD_GENERAL_PROTECTION_INSTRUCTION_SKIP: u64 = 1; // `hlt`

const RUST_PAYLOAD_UNMAPPED_ADDRESS: usize = 0xfeed_beef_0000;

macro_rules! rip_relative_address {
    ($symbol:path) => {{
        let address: usize;
        // SAFETY: `lea` with a RIP-relative reference to a symbol in this same
        // payload; the instruction computes an address and touches no memory.
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

#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_HELLO_MESSAGE: [u8; RUST_PAYLOAD_HELLO_LEN] =
    *b"[user  ] hello from rust payload\n";

#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_TRIGGER_PAGE_FAULT_MESSAGE: [u8; RUST_PAYLOAD_TRIGGER_PAGE_FAULT_LEN] =
    *b"[user  ] triggering rust page fault\n";

#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_RESUMED_AFTER_FAULT_MESSAGE: [u8; RUST_PAYLOAD_RESUMED_AFTER_FAULT_LEN] =
    *b"[user  ] resumed after rust fault handler\n";

#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_TRIGGER_INVALID_OPCODE_MESSAGE: [u8; RUST_PAYLOAD_TRIGGER_INVALID_OPCODE_LEN] =
    *b"[user  ] triggering rust invalid opcode\n";

#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_RESUMED_AFTER_INVALID_OPCODE_MESSAGE: [u8;
    RUST_PAYLOAD_RESUMED_AFTER_INVALID_OPCODE_LEN] =
    *b"[user  ] resumed after rust invalid opcode handler\n";

#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_TRIGGER_GENERAL_PROTECTION_MESSAGE: [u8;
    RUST_PAYLOAD_TRIGGER_GENERAL_PROTECTION_LEN] =
    *b"[user  ] triggering rust general protection\n";

#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_RESUMED_AFTER_GENERAL_PROTECTION_MESSAGE: [u8;
    RUST_PAYLOAD_RESUMED_AFTER_GENERAL_PROTECTION_LEN] =
    *b"[user  ] resumed after rust general protection handler\n";

#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_TRIGGER_UNHANDLED_PAGE_FAULT_MESSAGE: [u8;
    RUST_PAYLOAD_TRIGGER_UNHANDLED_PAGE_FAULT_LEN] =
    *b"[user  ] triggering rust unhandled page fault\n";

#[link_section = "adastra_demo_program_rust"]
static RUST_PAYLOAD_UNHANDLED_PAGE_FAULT_ARG: [u8; RUST_PAYLOAD_UNHANDLED_PAGE_FAULT_ARG_LEN] =
    *b"--trigger-unhandled-page-fault";

crate::user::syscall::define_x86_64_payload_runtime!("adastra_demo_program_rust");

unsafe extern "C" {
    static adastra_demo_program_rust_entry: u8;

    #[link_name = "__start_adastra_demo_program_rust"]
    static ADASTRA_DEMO_PROGRAM_RUST_SECTION_START: u8;
    #[link_name = "__stop_adastra_demo_program_rust"]
    static ADASTRA_DEMO_PROGRAM_RUST_SECTION_END: u8;
}

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

pub fn payload_bytes() -> &'static [u8] {
    // SAFETY: as the other payload sections — the linker's markers bound it.
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


pub fn payload_entry_offset() -> usize {
    let entry = core::ptr::addr_of!(adastra_demo_program_rust_entry) as usize;
    let start = core::ptr::addr_of!(ADASTRA_DEMO_PROGRAM_RUST_SECTION_START) as usize;
    entry
        .checked_sub(start)
        .expect("rust demo payload entry must follow section start")
}

// Hosts that cannot carry the ELF payload sections (e.g. a Windows host, whose
// objects are COFF) get an empty payload and a zero entry offset so the ELF
// builder facades still link.

#[inline(never)]
#[link_section = "adastra_demo_program_rust"]
extern "C" fn rust_payload_recover_page_fault(frame: *mut X86_64UserExceptionFrame) -> ! {
    // SAFETY: `frame` is the exception frame the kernel built for this vector and
    // the handler is registered for it, so the pointer is live for this call.
    //
    // The fields are reached through raw pointers rather than a `&mut`: taking a
    // reference to the frame compiles the null and alignment checks, and their
    // cold arms call `core::panicking`, which is outside the payload section —
    // a payload that refers to it is not one that can be copied elsewhere.
    //
    // The stack pointer is deliberately left where the fault found it.  This
    // handler used to add a fixed 0x100 bytes to it "to move past the frame",
    // and that walks the user stack *up* on every recovery: a payload that
    // takes a handful of faults walks itself out of its own stack, the kernel
    // then refuses the resume (`resume-from-exception` reports an invalid
    // argument), the refused syscall returns to a handler that is `-> !` and
    // lands in `ud2`, and what the boot shows is an invalid-opcode storm and a
    // process the kernel has to kill.  A recovery continues with the frame it
    // had; the exception frame the kernel built is below that stack pointer
    // and is already consumed by the time this returns.
    unsafe {
        let instruction_pointer = core::ptr::addr_of_mut!((*frame).instruction_pointer);
        core::ptr::write(
            instruction_pointer,
            core::ptr::read(instruction_pointer).wrapping_add(RUST_PAYLOAD_PAGE_FAULT_INSTRUCTION_SKIP),
        );
        return_from_exception(frame);
    }
}

#[inline(never)]
#[link_section = "adastra_demo_program_rust"]
extern "C" fn rust_payload_recover_invalid_opcode(frame: *mut X86_64UserExceptionFrame) -> ! {
    // SAFETY: as the page-fault handler above — the frame of this vector,
    // reached the same way.
    unsafe {
        let instruction_pointer = core::ptr::addr_of_mut!((*frame).instruction_pointer);
        core::ptr::write(
            instruction_pointer,
            core::ptr::read(instruction_pointer)
                .wrapping_add(RUST_PAYLOAD_INVALID_OPCODE_INSTRUCTION_SKIP),
        );
        return_from_exception(frame);
    }
}

#[inline(never)]
#[link_section = "adastra_demo_program_rust"]
extern "C" fn rust_payload_recover_general_protection(frame: *mut X86_64UserExceptionFrame) -> ! {
    // SAFETY: as above — the frame of this vector, reached the same way.
    unsafe {
        let instruction_pointer = core::ptr::addr_of_mut!((*frame).instruction_pointer);
        core::ptr::write(
            instruction_pointer,
            core::ptr::read(instruction_pointer)
                .wrapping_add(RUST_PAYLOAD_GENERAL_PROTECTION_INSTRUCTION_SKIP),
        );
        return_from_exception(frame);
    }
}

unsafe fn trigger_page_fault_once() {
    // SAFETY: a deliberate fault — the load is from an address this payload knows
    // is unmapped, and the recovery handler skips exactly its bytes.
    unsafe {
        // A single 3-byte load from an unmapped address.  The recovery handler
        // skips exactly these three bytes to resume after the faulting access.
        core::arch::asm!(
            "mov r10, qword ptr [r10]",
            in("r10") RUST_PAYLOAD_UNMAPPED_ADDRESS,
            options(nostack),
        );
    }
}

unsafe fn trigger_invalid_opcode_once() {
    // SAFETY: as above — a deliberate `ud2`, resumed by its handler.
    unsafe {
        // `ud2` is exactly two bytes; the recovery handler skips them.
        core::arch::asm!("ud2", options(nostack));
    }
}

unsafe fn trigger_general_protection_once() {
    // SAFETY: as above — a deliberate privileged instruction in ring 3.
    unsafe {
        // `hlt` is a 1-byte privileged instruction that raises #GP in ring 3.
        core::arch::asm!("hlt", options(nostack));
    }
}

#[inline(never)]
#[link_section = "adastra_demo_program_rust"]
extern "C" fn adastra_demo_program_rust_main_from_stack(_initial_stack: usize) -> ! {
    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_HELLO_MESSAGE),
        RUST_PAYLOAD_HELLO_MESSAGE.len(),
    );

    // Install recovery handlers for each fault the payload triggers below.
    //
    // The address is taken with `rip_relative_address!` rather than by casting
    // the function pointer: a cast is an *absolute* address, and this payload is
    // copied out of the kernel image and run at another address, where an
    // absolute one still names the kernel's copy.  The handlers carry the
    // payload's `link_section` for the same reason — the reference has to land
    // inside the blob.
    install_exception_handler(
        X86_64_EXCEPTION_PAGE_FAULT_VECTOR,
        rip_relative_address!(rust_payload_recover_page_fault),
        0,
        X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
    );
    install_exception_handler(
        X86_64_EXCEPTION_INVALID_OPCODE_VECTOR,
        rip_relative_address!(rust_payload_recover_invalid_opcode),
        0,
        X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
    );
    install_exception_handler(
        X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR,
        rip_relative_address!(rust_payload_recover_general_protection),
        0,
        X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
    );

    write_section_message(
        rip_relative_address!(RUST_PAYLOAD_TRIGGER_PAGE_FAULT_MESSAGE),
        RUST_PAYLOAD_TRIGGER_PAGE_FAULT_MESSAGE.len(),
    );
    // SAFETY: the deliberate fault below is the one this message describes; the
    // handler registered for that vector resumes after it.
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
    // SAFETY: as above — the invalid-opcode probe and its message.
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
    // SAFETY: as above — the general-protection probe and its message.
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
