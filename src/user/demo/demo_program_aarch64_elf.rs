//! src/user/demo/demo_program_aarch64_elf.rs
//!
#![cfg_attr(test, allow(dead_code))]
//! Convenience wrappers that build loadable AArch64 ELF artifacts from the
//! kernel's raw demo payload sections.  The shared ELF layout logic lives in
//! `crate::user::demo::elf_builder`.

pub use crate::user::demo::elf_builder::DemoProgramArtifact;
use crate::user::demo::elf_builder::{build_artifact_from_payload, build_metadata_only_artifact};

use crate::user::program::DEMO_PROGRAM_ENTRY;

const AARCH64_DEMO_PROGRAM_MACHINE: u16 = 0xB7;

pub fn build_demo_program_artifact() -> DemoProgramArtifact {
    build_artifact_from_payload(
        super::demo_program_aarch64::payload_bytes(),
        0,
        DEMO_PROGRAM_ENTRY as u64,
        AARCH64_DEMO_PROGRAM_MACHINE,
    )
}

pub fn build_fault_demo_program_artifact() -> DemoProgramArtifact {
    build_artifact_from_payload(
        super::demo_program_aarch64_fault::payload_bytes(),
        0,
        DEMO_PROGRAM_ENTRY as u64,
        AARCH64_DEMO_PROGRAM_MACHINE,
    )
}

pub fn build_rust_demo_program_artifact() -> DemoProgramArtifact {
    build_artifact_from_payload(
        super::demo_program_aarch64_rust::payload_bytes(),
        super::demo_program_aarch64_rust::payload_entry_offset(),
        DEMO_PROGRAM_ENTRY as u64,
        AARCH64_DEMO_PROGRAM_MACHINE,
    )
}

/// Build a metadata-only ELF64 artifact for the shell.
///
/// The shell runs via the host-proxy path (`shell_user_main`) on all platforms.
/// This ELF carries no PT_LOAD segments so the loader falls back to proxy
/// execution.
pub fn build_shell_program_artifact() -> DemoProgramArtifact {
    build_metadata_only_artifact(AARCH64_DEMO_PROGRAM_MACHINE)
}

#[cfg(test)]
mod tests {
    use crate::user::{
        elf::parse_elf64,
        payload_test_support::{target_payload_section, target_symbol_range},
        program::DEMO_PROGRAM_ENTRY,
    };

    use crate::user::demo::elf_builder::build_artifact_from_payload;

    use super::{build_shell_program_artifact, DemoProgramArtifact, AARCH64_DEMO_PROGRAM_MACHINE};

    const AARCH64_TARGET: &str = "aarch64-unknown-none";
    const RUST_SECTION_NAME: &str = "protofire_demo_program_aarch64_rust";
    const DEMO_PAYLOAD_START: &str = "protofire_demo_program_aarch64_payload_start";
    const DEMO_PAYLOAD_END: &str = "protofire_demo_program_aarch64_payload_end";
    const FAULT_PAYLOAD_START: &str = "protofire_demo_program_aarch64_fault_payload_start";
    const FAULT_PAYLOAD_END: &str = "protofire_demo_program_aarch64_fault_payload_end";
    const DEMO_PHASE0_MESSAGE: &[u8] = b"[user  ] aarch64 payload start\n";
    const DEMO_PHASE1_MESSAGE: &[u8] = b"[user  ] aarch64 payload resume-1\n";
    const DEMO_PHASE2_MESSAGE: &[u8] = b"[user  ] aarch64 payload resume-2\n";
    const DEMO_EXEC_REQUEST_MESSAGE: &[u8] = b"[user  ] aarch64 exec-request\n";
    const DEMO_EXEC_CHILD_MESSAGE: &[u8] = b"[user  ] aarch64 exec-child\n";
    const DEMO_APP_ID_PREFIX: &[u8] = b"[user  ] aarch64 app-id: ";
    const DEMO_IMAGE_PREFIX: &[u8] = b"[user  ] aarch64 image: ";
    const DEMO_CWD_PREFIX: &[u8] = b"[user  ] aarch64 cwd: ";
    const DEMO_ARGV0_PREFIX: &[u8] = b"[user  ] aarch64 argv0: ";
    const DEMO_ENV0_PREFIX: &[u8] = b"[user  ] aarch64 env0: ";
    const DEMO_REG_ARGC_PREFIX: &[u8] = b"[user  ] aarch64 reg-argc: ";
    const DEMO_REG_ARGV_PREFIX: &[u8] = b"[user  ] aarch64 reg-argv: ";
    const DEMO_REG_ENVP_PREFIX: &[u8] = b"[user  ] aarch64 reg-envp: ";
    const DEMO_STACK_ARGC_PREFIX: &[u8] = b"[user  ] aarch64 stack-argc: ";
    const DEMO_STACK_ARGV0_PREFIX: &[u8] = b"[user  ] aarch64 stack-argv0: ";
    const DEMO_STACK_ENV0_PREFIX: &[u8] = b"[user  ] aarch64 stack-env0: ";
    const DEMO_CODE_WAIT_VECTOR_PREFIX: &[u8] = b"[user  ] aarch64 code-write wait-vector: ";
    const DEMO_STACK_EXEC_WAIT_VECTOR_PREFIX: &[u8] = b"[user  ] aarch64 stack-exec wait-vector: ";
    const DEMO_STACK_GUARD_WAIT_VECTOR_PREFIX: &[u8] =
        b"[user  ] aarch64 stack-guard wait-vector: ";
    const DEMO_WAIT_ERROR_PREFIX: &[u8] = b"[user  ] aarch64 wait-error: ";
    const DEMO_WAIT_FSC_PREFIX: &[u8] = b"[user  ] aarch64 wait-fsc: ";
    const DEMO_WAIT_ACCESS_PREFIX: &[u8] = b"[user  ] aarch64 wait-access: ";
    const DEMO_WAIT_ADDRESS_PREFIX: &[u8] = b"[user  ] aarch64 wait-addr: ";
    const DEMO_SPAWN_STATUS_PREFIX: &[u8] = b"[user  ] aarch64 spawn-status: ";
    const DEMO_WAIT_STATUS_PREFIX: &[u8] = b"[user  ] aarch64 wait-status: ";
    const DEMO_WAIT_SIZE_PREFIX: &[u8] = b"[user  ] aarch64 wait-size: ";
    const DEMO_WAIT_KIND_PREFIX: &[u8] = b"[user  ] aarch64 wait-kind: ";
    const DEMO_WAIT_EXIT_STATUS_PREFIX: &[u8] = b"[user  ] aarch64 wait-exit-status: ";
    const DEMO_EXEC_ERROR_PREFIX: &[u8] = b"[user  ] aarch64 exec-error: ";
    const DEMO_EXEC_CATALOG_PATH: &[u8] = b"app:demo-launcher-exec@0.1.0";
    const DEMO_CHILD_CATALOG_PATH: &[u8] = b"app:demo-launcher-fault@0.1.0";
    const DEMO_CHILD_ARGV0: &[u8] = b"demo-launcher-fault";
    const DEMO_CHILD_CODE_WRITE_ARG: &[u8] = b"--trigger-fault=code-write";
    const DEMO_CHILD_STACK_EXEC_ARG: &[u8] = b"--trigger-fault=stack-exec";
    const DEMO_CHILD_STACK_GUARD_ARG: &[u8] = b"--trigger-fault=stack-guard";
    const DEMO_ACCESS_READ: &[u8] = b"read\0";
    const DEMO_ACCESS_WRITE: &[u8] = b"write\0";
    const DEMO_ACCESS_EXECUTE: &[u8] = b"execute\0";
    const DEMO_PERMISSION_LEVEL3: &[u8] = b"permission fault level 3\0";
    const DEMO_ALIGNMENT_FAULT: &[u8] = b"alignment fault\0";
    const FAULT_CODE_WRITE_MESSAGE: &[u8] = b"[user  ] aarch64 child code-write fault\n";
    const FAULT_CODE_WRITE_UNEXPECTED_MESSAGE: &[u8] =
        b"[user  ] aarch64 child code-write unexpectedly succeeded\n";
    const FAULT_STACK_EXEC_MESSAGE: &[u8] = b"[user  ] aarch64 child stack-exec fault\n";
    const FAULT_STACK_EXEC_UNEXPECTED_MESSAGE: &[u8] =
        b"[user  ] aarch64 child stack-exec unexpectedly succeeded\n";
    const FAULT_STACK_GUARD_MESSAGE: &[u8] = b"[user  ] aarch64 child stack-guard fault\n";
    const FAULT_STACK_GUARD_UNEXPECTED_MESSAGE: &[u8] =
        b"[user  ] aarch64 child stack-guard unexpectedly succeeded\n";
    const RUST_HELLO_MESSAGE: &[u8] = b"[user  ] hello from aarch64 rust payload\n";
    const RUST_WAIT_VECTOR_PREFIX: &[u8] = b"[user  ] aarch64-rust wait-vector: ";
    const RUST_WAIT_ERROR_PREFIX: &[u8] = b"[user  ] aarch64-rust wait-error: ";
    const RUST_WAIT_FSC_PREFIX: &[u8] = b"[user  ] aarch64-rust wait-fsc: ";
    const RUST_WAIT_ACCESS_PREFIX: &[u8] = b"[user  ] aarch64-rust wait-access: ";
    const RUST_SPAWN_FAILED_PREFIX: &[u8] = b"[user  ] aarch64-rust spawn failed: ";
    const RUST_WAIT_FAILED_PREFIX: &[u8] = b"[user  ] aarch64-rust wait failed: ";
    const RUST_WAIT_SIZE_FAILED_PREFIX: &[u8] = b"[user  ] aarch64-rust wait-size: ";
    const RUST_WAIT_KIND_FAILED_PREFIX: &[u8] = b"[user  ] aarch64-rust wait-kind: ";
    const RUST_INSTALL_HANDLER_FAILED_PREFIX: &[u8] =
        b"[user  ] aarch64-rust install-handler failed: ";
    const RUST_CHILD_CATALOG_PATH: &[u8] = b"app:demo-launcher-fault@0.1.0";
    const RUST_CHILD_ARGV0: &[u8] = b"demo-launcher-fault-rust-child";
    const RUST_CHILD_ARGV1: &[u8] = b"--trigger-fault=stack-exec";
    const RUST_CHILD_ENV0: &[u8] = b"ASTRA_APP_ID=demo-launcher-fault-rust-child";
    const RUST_CHILD_ENV1: &[u8] = b"ASTRA_PARENT=demo-launcher-rust";
    const RUST_PERMISSION_LEVEL3: &[u8] = b"permission fault level 3";
    const RUST_READ_NAME: &[u8] = b"read";
    const RUST_WRITE_NAME: &[u8] = b"write";
    const RUST_EXECUTE_NAME: &[u8] = b"execute";
    const NEWLINE: &[u8] = b"\n";

    #[test]
    fn demo_program_artifact_is_loadable_and_contains_runtime_strings() {
        let Some(range) = target_symbol_range(AARCH64_TARGET, DEMO_PAYLOAD_START, DEMO_PAYLOAD_END)
        else {
            return;
        };
        assert_artifact_contains_runtime_strings(
            &range.bytes,
            range.end - range.start,
            0,
            &[
                DEMO_PHASE0_MESSAGE,
                DEMO_PHASE1_MESSAGE,
                DEMO_PHASE2_MESSAGE,
                DEMO_EXEC_REQUEST_MESSAGE,
                DEMO_EXEC_CHILD_MESSAGE,
                DEMO_APP_ID_PREFIX,
                DEMO_IMAGE_PREFIX,
                DEMO_CWD_PREFIX,
                DEMO_ARGV0_PREFIX,
                DEMO_ENV0_PREFIX,
                DEMO_REG_ARGC_PREFIX,
                DEMO_REG_ARGV_PREFIX,
                DEMO_REG_ENVP_PREFIX,
                DEMO_STACK_ARGC_PREFIX,
                DEMO_STACK_ARGV0_PREFIX,
                DEMO_STACK_ENV0_PREFIX,
                DEMO_CODE_WAIT_VECTOR_PREFIX,
                DEMO_STACK_EXEC_WAIT_VECTOR_PREFIX,
                DEMO_STACK_GUARD_WAIT_VECTOR_PREFIX,
                DEMO_WAIT_ERROR_PREFIX,
                DEMO_WAIT_FSC_PREFIX,
                DEMO_WAIT_ACCESS_PREFIX,
                DEMO_WAIT_ADDRESS_PREFIX,
                DEMO_SPAWN_STATUS_PREFIX,
                DEMO_WAIT_STATUS_PREFIX,
                DEMO_WAIT_SIZE_PREFIX,
                DEMO_WAIT_KIND_PREFIX,
                DEMO_WAIT_EXIT_STATUS_PREFIX,
                DEMO_EXEC_ERROR_PREFIX,
                DEMO_EXEC_CATALOG_PATH,
                DEMO_CHILD_CATALOG_PATH,
                DEMO_CHILD_ARGV0,
                DEMO_CHILD_CODE_WRITE_ARG,
                DEMO_CHILD_STACK_EXEC_ARG,
                DEMO_CHILD_STACK_GUARD_ARG,
                DEMO_ACCESS_READ,
                DEMO_ACCESS_WRITE,
                DEMO_ACCESS_EXECUTE,
                DEMO_PERMISSION_LEVEL3,
                DEMO_ALIGNMENT_FAULT,
                NEWLINE,
            ],
            "aarch64 demo ELF",
        );
    }

    #[test]
    fn fault_demo_program_artifact_is_loadable_and_contains_runtime_strings() {
        let Some(range) =
            target_symbol_range(AARCH64_TARGET, FAULT_PAYLOAD_START, FAULT_PAYLOAD_END)
        else {
            return;
        };
        assert_artifact_contains_runtime_strings(
            &range.bytes,
            range.end - range.start,
            0,
            &[
                FAULT_CODE_WRITE_MESSAGE,
                FAULT_CODE_WRITE_UNEXPECTED_MESSAGE,
                FAULT_STACK_EXEC_MESSAGE,
                FAULT_STACK_EXEC_UNEXPECTED_MESSAGE,
                FAULT_STACK_GUARD_MESSAGE,
                FAULT_STACK_GUARD_UNEXPECTED_MESSAGE,
            ],
            "aarch64 fault ELF",
        );
    }

    #[test]
    fn rust_demo_program_artifact_is_loadable_and_contains_runtime_messages() {
        let Some(section) = target_payload_section(AARCH64_TARGET, RUST_SECTION_NAME) else {
            return;
        };
        let entry_offset = section
            .functions
            .iter()
            .find(|function| {
                function
                    .name
                    .contains("protofire_demo_program_aarch64_rust_entry")
            })
            .map(|function| function.start - section.section_start)
            .expect("aarch64 rust payload entry should exist inside the section");
        assert_artifact_contains_runtime_strings(
            &section.bytes,
            section.bytes.len(),
            entry_offset,
            &[
                RUST_HELLO_MESSAGE,
                RUST_WAIT_VECTOR_PREFIX,
                RUST_WAIT_ERROR_PREFIX,
                RUST_WAIT_FSC_PREFIX,
                RUST_WAIT_ACCESS_PREFIX,
                RUST_SPAWN_FAILED_PREFIX,
                RUST_WAIT_FAILED_PREFIX,
                RUST_WAIT_SIZE_FAILED_PREFIX,
                RUST_WAIT_KIND_FAILED_PREFIX,
                RUST_INSTALL_HANDLER_FAILED_PREFIX,
                RUST_CHILD_CATALOG_PATH,
                RUST_CHILD_ARGV0,
                RUST_CHILD_ARGV1,
                RUST_CHILD_ENV0,
                RUST_CHILD_ENV1,
                RUST_PERMISSION_LEVEL3,
                RUST_READ_NAME,
                RUST_WRITE_NAME,
                RUST_EXECUTE_NAME,
                NEWLINE,
            ],
            "aarch64 rust ELF",
        );
    }

    fn assert_loadable_artifact(artifact: &DemoProgramArtifact, expected_entry_point: usize) {
        let parsed = parse_elf64(&artifact.bytes).expect("parse aarch64 demo elf");
        let segments = parsed.load_segments().expect("load aarch64 demo segments");

        assert_eq!(parsed.machine, AARCH64_DEMO_PROGRAM_MACHINE);
        assert_eq!(parsed.entry_point, expected_entry_point);
        assert!(parsed.entry_in_load_segment().expect("entry coverage"));
        assert_eq!(segments.len(), 1);
    }

    fn assert_artifact_contains_runtime_strings(
        payload: &[u8],
        payload_span: usize,
        entry_offset: usize,
        required: &[&[u8]],
        artifact_name: &str,
    ) {
        let artifact = build_artifact_from_payload(
            payload,
            entry_offset,
            DEMO_PROGRAM_ENTRY as u64,
            AARCH64_DEMO_PROGRAM_MACHINE,
        );

        assert_eq!(payload.len(), payload_span);
        assert_loadable_artifact(&artifact, DEMO_PROGRAM_ENTRY + entry_offset);
        assert_contains_required_strings(&artifact.bytes, required, artifact_name);
    }

    fn assert_contains_required_strings(haystack: &[u8], required: &[&[u8]], artifact_name: &str) {
        for required in required {
            assert!(
                contains_bytes(haystack, required),
                "{} should contain runtime string {:?}",
                artifact_name,
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
    fn shell_program_artifact_has_no_loadable_segments() {
        let artifact = build_shell_program_artifact();
        let parsed = parse_elf64(&artifact.bytes).expect("parse shell elf");
        let segments = parsed.load_segments().expect("load shell segments");

        assert_eq!(parsed.machine, AARCH64_DEMO_PROGRAM_MACHINE);
        assert!(segments.is_empty(), "shell ELF must have no load segments");
        assert_eq!(artifact.bytes.len(), 64, "shell artifact is header-only");
    }
}
