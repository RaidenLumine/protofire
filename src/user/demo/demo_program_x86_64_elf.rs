//! src/user/demo/demo_program_x86_64_elf.rs
//!
//! Convenience wrappers that build loadable x86_64 ELF artifacts from the
//! kernel's raw demo payload sections.  The shared ELF layout logic lives in
//! `demo_payloads::elf_builder`.

use crate::user::demo::elf_builder::build_artifact_from_payload;
pub use crate::user::demo::elf_builder::DemoProgramArtifact;

use crate::user::program::{DEMO_PROGRAM_ENTRY, DEMO_PROGRAM_MACHINE};

pub fn build_demo_program_artifact() -> DemoProgramArtifact {
    build_artifact_from_payload(
        super::demo_program_x86_64::payload_bytes(),
        0,
        DEMO_PROGRAM_ENTRY as u64,
        DEMO_PROGRAM_MACHINE,
    )
}

pub fn build_rust_demo_program_artifact() -> DemoProgramArtifact {
    use super::demo_program_x86_64_rust;

    build_artifact_from_payload(
        demo_program_x86_64_rust::payload_bytes(),
        demo_program_x86_64_rust::payload_entry_offset(),
        DEMO_PROGRAM_ENTRY as u64,
        DEMO_PROGRAM_MACHINE,
    )
}

pub fn build_rust_io_demo_program_artifact() -> DemoProgramArtifact {
    use super::demo_program_x86_64_rust_io;

    build_artifact_from_payload(
        demo_program_x86_64_rust_io::payload_bytes(),
        demo_program_x86_64_rust_io::payload_entry_offset(),
        DEMO_PROGRAM_ENTRY as u64,
        DEMO_PROGRAM_MACHINE,
    )
}

/// Build a real x86_64 ELF64 artifact for the Ring 3 shell.
///
/// The shell payload is a self-contained assembly program that uses the
/// `int 0x80` syscall ABI for all I/O.  It has a proper PT_LOAD segment
/// and runs in user mode (Ring 3) on bare-metal.
pub fn build_shell_program_artifact() -> DemoProgramArtifact {
    build_artifact_from_payload(
        super::shell_payload_x86_64::payload_bytes(),
        super::shell_payload_x86_64::payload_entry_offset(),
        DEMO_PROGRAM_ENTRY as u64,
        DEMO_PROGRAM_MACHINE,
    )
}

#[cfg(test)]
mod tests {
    use crate::user::{
        demo_program_x86_64_rust, demo_program_x86_64_rust_io,
        elf::parse_elf64,
        program::{DEMO_PROGRAM_ENTRY, DEMO_PROGRAM_MACHINE},
    };

    use super::{
        build_demo_program_artifact, build_rust_demo_program_artifact,
        build_rust_io_demo_program_artifact, build_shell_program_artifact,
    };

    const RESUMED_MESSAGE: &[u8] = b"[user  ] resumed after yield\n";
    const APP_ID_PREFIX: &[u8] = b"[user  ] app-id: ";
    const CWD_PREFIX: &[u8] = b"[user  ] cwd: ";
    const IMAGE_PREFIX: &[u8] = b"[user  ] image: ";
    const MANIFEST_PREFIX: &[u8] = b"[user  ] manifest: ";
    const ARG0_PREFIX: &[u8] = b"[user  ] argv0: ";
    const ENV0_PREFIX: &[u8] = b"[user  ] env0: ";
    const STACK_ARG0_PREFIX: &[u8] = b"[user  ] stack-argv0: ";
    const STACK_ENV0_PREFIX: &[u8] = b"[user  ] stack-env0: ";
    const STACK_AUX_PAGESZ_PREFIX: &[u8] = b"[user  ] stack-aux-pagesz: ";
    const STACK_AUX_ENTRY_PREFIX: &[u8] = b"[user  ] stack-aux-entry: ";
    const FILE_PREFIX: &[u8] = b"[user  ] file: ";
    const DATA_PREFIX: &[u8] = b"[user  ] data: ";
    const MKDIR_PREFIX: &[u8] = b"[user  ] mkdir: ";
    const SESSION_FILE_PREFIX: &[u8] = b"[user  ] session-file: ";
    const SESSION_PREFIX: &[u8] = b"[user  ] session: ";
    const REMOVED_PREFIX: &[u8] = b"[user  ] removed: ";
    const TRIGGER_FAULT_PREFIX: &[u8] = b"[user  ] triggering page fault: ";
    const TRIGGER_ONE_SHOT_FAULT_PREFIX: &[u8] = b"[user  ] triggering one-shot page fault: ";
    const TRIGGER_NESTED_FAULT_PREFIX: &[u8] = b"[user  ] triggering nested page fault: ";
    const TRIGGER_NESTED_FAULT_FROM_HANDLER_PREFIX: &[u8] =
        b"[user  ] triggering nested page fault from handler";
    const TRIGGER_INVALID_OPCODE_PREFIX: &[u8] = b"[user  ] triggering invalid opcode: ";
    const TRIGGER_GENERAL_PROTECTION_PREFIX: &[u8] = b"[user  ] triggering general protection: ";
    const RESUMED_AFTER_FAULT_PREFIX: &[u8] = b"[user  ] resumed after fault handler";
    const RESUMED_AFTER_ONE_SHOT_FAULT_PREFIX: &[u8] =
        b"[user  ] resumed after one-shot fault handler";
    const RESUMED_INSIDE_NESTED_FAULT_HANDLER_PREFIX: &[u8] =
        b"[user  ] resumed inside page fault handler after nested fault";
    const RESUMED_AFTER_NESTED_FAULT_PREFIX: &[u8] = b"[user  ] resumed after nested fault handler";
    const RESUMED_AFTER_INVALID_OPCODE_PREFIX: &[u8] =
        b"[user  ] resumed after invalid opcode handler";
    const RESUMED_AFTER_GENERAL_PROTECTION_PREFIX: &[u8] =
        b"[user  ] resumed after general protection handler";
    const RETRIGGER_ONE_SHOT_FAULT_PREFIX: &[u8] =
        b"[user  ] retriggering page fault after one-shot handler: ";
    const UNEXPECTED_RESUME_AFTER_ONE_SHOT_FAULT_PREFIX: &[u8] =
        b"[user  ] unexpected resume after one-shot handler";
    const README_PATH: &[u8] = b"/system/runtime/README.txt";
    const DATA_PATH: &[u8] = b"/data/users/guest/downloads/ring3-session.txt";
    const DATA_PAYLOAD: &[u8] = b"ring3 data path round-trip";
    const SESSION_DIR: &[u8] = b"/data/users/guest/downloads/demo-state";
    const SESSION_LOG_PATH: &[u8] = b"/data/users/guest/downloads/demo-state/demo-session.log";
    const TEMP_PATH: &[u8] = b"/data/users/guest/downloads/demo-state/demo-temp.bin";
    const TRIGGER_FAULT_ARG: &[u8] = b"--trigger-fault=page";
    const TRIGGER_ONE_SHOT_FAULT_ARG: &[u8] = b"--trigger-fault=page-one-shot";
    const TRIGGER_NESTED_FAULT_ARG: &[u8] = b"--trigger-fault=page-nested";
    const TRIGGER_UD2_ARG: &[u8] = b"--trigger-fault=ud2";
    const TRIGGER_GP_ARG: &[u8] = b"--trigger-fault=gp";
    const RUST_HELLO_MESSAGE: &[u8] = b"[user  ] hello from rust payload\n";
    const RUST_TRIGGER_PAGE_FAULT_MESSAGE: &[u8] = b"[user  ] triggering rust page fault\n";
    const RUST_RESUMED_AFTER_FAULT_MESSAGE: &[u8] = b"[user  ] resumed after rust fault handler\n";
    const RUST_TRIGGER_INVALID_OPCODE_MESSAGE: &[u8] = b"[user  ] triggering rust invalid opcode\n";
    const RUST_RESUMED_AFTER_INVALID_OPCODE_MESSAGE: &[u8] =
        b"[user  ] resumed after rust invalid opcode handler\n";
    const RUST_TRIGGER_GENERAL_PROTECTION_MESSAGE: &[u8] =
        b"[user  ] triggering rust general protection\n";
    const RUST_RESUMED_AFTER_GENERAL_PROTECTION_MESSAGE: &[u8] =
        b"[user  ] resumed after rust general protection handler\n";
    const RUST_TRIGGER_UNHANDLED_PAGE_FAULT_MESSAGE: &[u8] =
        b"[user  ] triggering rust unhandled page fault\n";
    const RUST_UNHANDLED_PAGE_FAULT_ARG: &[u8] = b"--trigger-unhandled-page-fault";
    const RUST_IO_HELLO_MESSAGE: &[u8] = b"[user  ] hello from rust io payload\n";
    const RUST_IO_RESUMED_AFTER_YIELD_MESSAGE: &[u8] = b"[user  ] resumed after rust io yield\n";
    const RUST_IO_APP_ID_PREFIX: &[u8] = b"[user  ] rust app-id: ";
    const RUST_IO_CWD_PREFIX: &[u8] = b"[user  ] rust cwd: ";
    const RUST_IO_IMAGE_PREFIX: &[u8] = b"[user  ] rust image: ";
    const RUST_IO_MANIFEST_PREFIX: &[u8] = b"[user  ] rust manifest: ";
    const RUST_IO_ARG0_PREFIX: &[u8] = b"[user  ] rust argv0: ";
    const RUST_IO_ENV0_PREFIX: &[u8] = b"[user  ] rust env0: ";
    const RUST_IO_STACK_ARG0_PREFIX: &[u8] = b"[user  ] rust stack-argv0: ";
    const RUST_IO_STACK_ENV0_PREFIX: &[u8] = b"[user  ] rust stack-env0: ";
    const RUST_IO_STACK_AUX_PAGESZ_PREFIX: &[u8] = b"[user  ] rust stack-aux-pagesz: ";
    const RUST_IO_STACK_AUX_ENTRY_PREFIX: &[u8] = b"[user  ] rust stack-aux-entry: ";
    const RUST_IO_FILE_PREFIX: &[u8] = b"[user  ] rust file: ";
    const RUST_IO_DATA_PREFIX: &[u8] = b"[user  ] rust data: ";
    const RUST_IO_MKDIR_PREFIX: &[u8] = b"[user  ] rust mkdir: ";
    const RUST_IO_SESSION_FILE_PREFIX: &[u8] = b"[user  ] rust session-file: ";
    const RUST_IO_SESSION_PREFIX: &[u8] = b"[user  ] rust session: ";
    const RUST_IO_REMOVED_PREFIX: &[u8] = b"[user  ] rust removed: ";
    const RUST_IO_WAIT_PID_PREFIX: &[u8] = b"[user  ] rust wait-pid: ";
    const RUST_IO_WAIT_EXIT_PREFIX: &[u8] = b"[user  ] rust wait-exit: ";
    const RUST_IO_WAIT_VECTOR_PREFIX: &[u8] = b"[user  ] rust wait-vector: ";
    const RUST_IO_WAIT_ERROR_PREFIX: &[u8] = b"[user  ] rust wait-error: ";
    const RUST_IO_WAIT_ADDRESS_PREFIX: &[u8] = b"[user  ] rust wait-addr: ";
    const RUST_IO_WAIT_EXCEPTION_PID_PREFIX: &[u8] = b"[user  ] rust wait-exception-pid: ";
    const RUST_IO_WAIT_EXCEPTION_VECTOR_PREFIX: &[u8] = b"[user  ] rust wait-exception-vector: ";
    const RUST_IO_WAIT_EXCEPTION_ERROR_PREFIX: &[u8] = b"[user  ] rust wait-exception-error: ";
    const RUST_IO_WAIT_EXCEPTION_ADDRESS_PREFIX: &[u8] = b"[user  ] rust wait-exception-addr: ";
    const RUST_IO_WAIT_CHILD_CATALOG_PATH: &[u8] = b"app:demo-launcher-rust@0.1.0";
    const RUST_IO_WAIT_EXCEPTION_CHILD_ARGV0: &[u8] =
        b"demo-launcher-rust-unhandled-page-fault-child";
    const RUST_IO_WAIT_EXCEPTION_CHILD_ARGV1: &[u8] = b"--trigger-unhandled-page-fault";
    const RUST_IO_WAIT_EXCEPTION_CHILD_ENV0: &[u8] =
        b"ASTRA_APP_ID=demo-launcher-rust-unhandled-page-fault-child";
    const RUST_IO_README_PATH: &[u8] = b"/system/runtime/README.txt";
    const RUST_IO_DATA_PATH: &[u8] = b"/data/users/guest/downloads/ring3-rust-io.txt";
    const RUST_IO_STATE_DIR: &[u8] = b"/data/users/guest/downloads/rust-io-state";
    const RUST_IO_SESSION_PATH: &[u8] = b"/data/users/guest/downloads/rust-io-state/session.log";
    const RUST_IO_TEMP_PATH: &[u8] = b"/data/users/guest/downloads/rust-io-state/temp.bin";
    const RUST_IO_DATA_PAYLOAD: &[u8] = b"rust io data path roundtrip";
    const RUST_IO_SESSION_PAYLOAD: &[u8] = b"rust io session persisted";
    const RUST_IO_SESSION_TRUNCATED: &[u8] = b"rust io session";
    const NEWLINE: &[u8] = b"\n";

    #[test]
    fn demo_program_artifact_is_loadable_and_contains_runtime_strings() {
        let artifact = build_demo_program_artifact();
        let parsed = parse_elf64(&artifact.bytes).expect("parse demo elf");
        let segments = parsed.load_segments().expect("load demo segments");

        assert_eq!(parsed.machine, DEMO_PROGRAM_MACHINE);
        assert_eq!(parsed.entry_point, DEMO_PROGRAM_ENTRY);
        assert!(parsed.entry_in_load_segment().expect("entry coverage"));
        assert_eq!(segments.len(), 1);

        for required in [
            RESUMED_MESSAGE,
            APP_ID_PREFIX,
            CWD_PREFIX,
            IMAGE_PREFIX,
            MANIFEST_PREFIX,
            ARG0_PREFIX,
            ENV0_PREFIX,
            STACK_ARG0_PREFIX,
            STACK_ENV0_PREFIX,
            STACK_AUX_PAGESZ_PREFIX,
            STACK_AUX_ENTRY_PREFIX,
            FILE_PREFIX,
            DATA_PREFIX,
            MKDIR_PREFIX,
            SESSION_FILE_PREFIX,
            SESSION_PREFIX,
            REMOVED_PREFIX,
            TRIGGER_FAULT_PREFIX,
            TRIGGER_ONE_SHOT_FAULT_PREFIX,
            TRIGGER_NESTED_FAULT_PREFIX,
            TRIGGER_NESTED_FAULT_FROM_HANDLER_PREFIX,
            TRIGGER_INVALID_OPCODE_PREFIX,
            TRIGGER_GENERAL_PROTECTION_PREFIX,
            RESUMED_AFTER_FAULT_PREFIX,
            RESUMED_AFTER_ONE_SHOT_FAULT_PREFIX,
            RESUMED_INSIDE_NESTED_FAULT_HANDLER_PREFIX,
            RESUMED_AFTER_NESTED_FAULT_PREFIX,
            RESUMED_AFTER_INVALID_OPCODE_PREFIX,
            RESUMED_AFTER_GENERAL_PROTECTION_PREFIX,
            RETRIGGER_ONE_SHOT_FAULT_PREFIX,
            UNEXPECTED_RESUME_AFTER_ONE_SHOT_FAULT_PREFIX,
            README_PATH,
            DATA_PATH,
            DATA_PAYLOAD,
            SESSION_DIR,
            SESSION_LOG_PATH,
            TEMP_PATH,
            TRIGGER_FAULT_ARG,
            TRIGGER_ONE_SHOT_FAULT_ARG,
            TRIGGER_NESTED_FAULT_ARG,
            TRIGGER_UD2_ARG,
            TRIGGER_GP_ARG,
            NEWLINE,
        ] {
            assert!(
                contains_bytes(&artifact.bytes, required),
                "demo ELF should contain runtime string {:?}",
                required
            );
        }
    }

    #[test]
    fn rust_demo_program_artifact_is_loadable_and_contains_runtime_messages() {
        let artifact = build_rust_demo_program_artifact();
        let parsed = parse_elf64(&artifact.bytes).expect("parse rust demo elf");
        let segments = parsed.load_segments().expect("load rust demo segments");
        let entry_offset = demo_program_x86_64_rust::payload_entry_offset();
        let expected_entry_point = DEMO_PROGRAM_ENTRY + entry_offset;

        assert_eq!(parsed.machine, DEMO_PROGRAM_MACHINE);
        assert_eq!(parsed.entry_point, expected_entry_point);
        assert!(parsed.entry_in_load_segment().expect("entry coverage"));
        assert_eq!(segments.len(), 1);
        assert!(entry_offset < segments[0].memory_size);
        for required in [
            RUST_HELLO_MESSAGE,
            RUST_TRIGGER_PAGE_FAULT_MESSAGE,
            RUST_RESUMED_AFTER_FAULT_MESSAGE,
            RUST_TRIGGER_INVALID_OPCODE_MESSAGE,
            RUST_RESUMED_AFTER_INVALID_OPCODE_MESSAGE,
            RUST_TRIGGER_GENERAL_PROTECTION_MESSAGE,
            RUST_RESUMED_AFTER_GENERAL_PROTECTION_MESSAGE,
            RUST_TRIGGER_UNHANDLED_PAGE_FAULT_MESSAGE,
            RUST_UNHANDLED_PAGE_FAULT_ARG,
        ] {
            assert!(
                contains_bytes(&artifact.bytes, required),
                "rust demo ELF should contain runtime string {:?}",
                required
            );
        }
    }

    #[test]
    fn rust_io_demo_program_artifact_is_loadable_and_contains_runtime_messages() {
        let artifact = build_rust_io_demo_program_artifact();
        let parsed = parse_elf64(&artifact.bytes).expect("parse rust io demo elf");
        let segments = parsed.load_segments().expect("load rust io demo segments");
        let entry_offset = demo_program_x86_64_rust_io::payload_entry_offset();
        let expected_entry_point = DEMO_PROGRAM_ENTRY + entry_offset;

        assert_eq!(parsed.machine, DEMO_PROGRAM_MACHINE);
        assert_eq!(parsed.entry_point, expected_entry_point);
        assert!(parsed.entry_in_load_segment().expect("entry coverage"));
        assert_eq!(segments.len(), 1);
        assert!(entry_offset < segments[0].memory_size);
        for required in [
            RUST_IO_HELLO_MESSAGE,
            RUST_IO_RESUMED_AFTER_YIELD_MESSAGE,
            RUST_IO_APP_ID_PREFIX,
            RUST_IO_CWD_PREFIX,
            RUST_IO_IMAGE_PREFIX,
            RUST_IO_MANIFEST_PREFIX,
            RUST_IO_ARG0_PREFIX,
            RUST_IO_ENV0_PREFIX,
            RUST_IO_STACK_ARG0_PREFIX,
            RUST_IO_STACK_ENV0_PREFIX,
            RUST_IO_STACK_AUX_PAGESZ_PREFIX,
            RUST_IO_STACK_AUX_ENTRY_PREFIX,
            RUST_IO_FILE_PREFIX,
            RUST_IO_DATA_PREFIX,
            RUST_IO_MKDIR_PREFIX,
            RUST_IO_SESSION_FILE_PREFIX,
            RUST_IO_SESSION_PREFIX,
            RUST_IO_REMOVED_PREFIX,
            RUST_IO_WAIT_PID_PREFIX,
            RUST_IO_WAIT_EXIT_PREFIX,
            RUST_IO_WAIT_VECTOR_PREFIX,
            RUST_IO_WAIT_ERROR_PREFIX,
            RUST_IO_WAIT_ADDRESS_PREFIX,
            RUST_IO_WAIT_EXCEPTION_PID_PREFIX,
            RUST_IO_WAIT_EXCEPTION_VECTOR_PREFIX,
            RUST_IO_WAIT_EXCEPTION_ERROR_PREFIX,
            RUST_IO_WAIT_EXCEPTION_ADDRESS_PREFIX,
            RUST_IO_WAIT_CHILD_CATALOG_PATH,
            RUST_IO_WAIT_EXCEPTION_CHILD_ARGV0,
            RUST_IO_WAIT_EXCEPTION_CHILD_ARGV1,
            RUST_IO_WAIT_EXCEPTION_CHILD_ENV0,
            RUST_IO_README_PATH,
            RUST_IO_DATA_PATH,
            RUST_IO_STATE_DIR,
            RUST_IO_SESSION_PATH,
            RUST_IO_TEMP_PATH,
            RUST_IO_DATA_PAYLOAD,
            RUST_IO_SESSION_PAYLOAD,
            RUST_IO_SESSION_TRUNCATED,
            NEWLINE,
        ] {
            assert!(
                contains_bytes(&artifact.bytes, required),
                "rust io demo ELF should contain runtime string {:?}",
                required
            );
        }
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn shell_program_artifact_has_loadable_segments() {
        let artifact = build_shell_program_artifact();
        let parsed = parse_elf64(&artifact.bytes).expect("parse shell elf");
        let segments = parsed.load_segments().expect("load shell segments");

        assert_eq!(parsed.machine, DEMO_PROGRAM_MACHINE);
        assert!(
            !segments.is_empty(),
            "shell ELF must have at least one load segment"
        );
        assert!(
            parsed.entry_point != 0,
            "shell ELF must have a non-zero entry point"
        );
        assert!(
            artifact.bytes.len() > 64,
            "shell artifact must contain payload data"
        );
    }
}
