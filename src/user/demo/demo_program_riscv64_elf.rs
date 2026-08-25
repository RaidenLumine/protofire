//! src/user/demo/demo_program_riscv64_elf.rs
//!
//! Convenience wrappers that build loadable RISC-V 64 ELF artifacts from the
//! kernel's raw demo payload sections.  The shared ELF layout logic lives in
//! `super::elf_builder`.

#![cfg_attr(test, allow(dead_code))]

use super::elf_builder::build_artifact_from_payload;
use super::elf_builder::build_metadata_only_artifact;
pub use super::elf_builder::DemoProgramArtifact;

use crate::user::program::DEMO_PROGRAM_ENTRY;

const RISCV64_DEMO_PROGRAM_MACHINE: u16 = 0xF3; // EM_RISCV

pub fn build_demo_program_artifact() -> DemoProgramArtifact {
    build_artifact_from_payload(
        super::demo_program_riscv64::payload_bytes(),
        0,
        DEMO_PROGRAM_ENTRY as u64,
        RISCV64_DEMO_PROGRAM_MACHINE,
    )
}

/// Build a metadata-only ELF64 artifact for the shell.
///
/// The shell runs via the host-proxy path (`shell_user_main`) on all platforms.
/// This ELF carries no PT_LOAD segments so the loader falls back to proxy
/// execution.
pub fn build_shell_program_artifact() -> DemoProgramArtifact {
    build_metadata_only_artifact(RISCV64_DEMO_PROGRAM_MACHINE)
}

#[cfg(test)]
mod tests {
    use crate::user::elf::parse_elf64;
    use crate::user::program::DEMO_PROGRAM_ENTRY;

    use crate::user::demo::elf_builder::build_artifact_from_payload;

    use super::build_shell_program_artifact;
    use super::DemoProgramArtifact;
    use super::RISCV64_DEMO_PROGRAM_MACHINE;

    const RISCV64_TARGET: &str = "riscv64gc-unknown-none-elf";
    const DEMO_PAYLOAD_START: &str = "protofire_demo_program_riscv64_payload_start";
    const DEMO_PAYLOAD_END: &str = "protofire_demo_program_riscv64_payload_end";

    const DEMO_PHASE0_MESSAGE: &[u8] = b"[user  ] riscv64 payload start\n";
    const DEMO_PHASE1_MESSAGE: &[u8] = b"[user  ] riscv64 payload resume-1\n";
    const DEMO_PHASE2_MESSAGE: &[u8] = b"[user  ] riscv64 payload resume-2\n";
    const DEMO_APP_ID_PREFIX: &[u8] = b"[user  ] riscv64 app-id: ";
    const DEMO_IMAGE_PREFIX: &[u8] = b"[user  ] riscv64 image: ";
    const DEMO_CWD_PREFIX: &[u8] = b"[user  ] riscv64 cwd: ";
    const DEMO_ARGV0_PREFIX: &[u8] = b"[user  ] riscv64 argv0: ";
    const NEWLINE: &[u8] = b"\n";

    #[test]
    fn demo_program_artifact_is_loadable_and_contains_runtime_strings() {
        let Some(range) = crate::user::payload_test_support::target_symbol_range(
            RISCV64_TARGET,
            DEMO_PAYLOAD_START,
            DEMO_PAYLOAD_END,
        ) else {
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
                DEMO_APP_ID_PREFIX,
                DEMO_IMAGE_PREFIX,
                DEMO_CWD_PREFIX,
                DEMO_ARGV0_PREFIX,
                NEWLINE,
            ],
            "riscv64 demo ELF",
        );
    }

    fn assert_loadable_artifact(artifact: &DemoProgramArtifact, expected_entry_point: usize) {
        let parsed = parse_elf64(&artifact.bytes).expect("parse riscv64 demo elf");
        let segments = parsed.load_segments().expect("load riscv64 demo segments");

        assert_eq!(parsed.machine, RISCV64_DEMO_PROGRAM_MACHINE);
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
            RISCV64_DEMO_PROGRAM_MACHINE,
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

        assert_eq!(parsed.machine, RISCV64_DEMO_PROGRAM_MACHINE);
        assert!(segments.is_empty(), "shell ELF must have no load segments");
        assert_eq!(artifact.bytes.len(), 64, "shell artifact is header-only");
    }
}
