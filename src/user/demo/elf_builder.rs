//! src/user/demo/elf_builder.rs
//! Shared ELF64 artifact construction for demo programs.
//!
//! This module provides the canonical `build_artifact_from_payload` helper
//! that wraps a raw binary payload inside a well-formed ELF64 executable.
//! Merged in from the former `demo-payloads` crate so the kernel owns the
//! ELF layout logic in exactly one place.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

// ── ELF64 layout constants ──────────────────────────────────────────────

const ELF64_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF64_PROGRAM_HEADER_OFFSET: usize = ELF64_HEADER_SIZE;
const ELF64_LOAD_SEGMENT_OFFSET: usize = 0x1000;
const ELF64_LOAD_SEGMENT_ALIGNMENT: usize = 0x1000;
const ELF64_LOAD_SEGMENT_FLAGS: u32 = 0b101; // R+X

// ── public types ─────────────────────────────────────────────────────────

/// A ready-to-write ELF64 executable image.
pub struct DemoProgramArtifact {
    pub bytes: Vec<u8>,
}

// ── full-ELF builder (payload with PT_LOAD segment) ─────────────────────

/// Build an ELF64 executable artifact from a raw binary payload.
///
/// The returned image has a proper ELF64 header, one `PT_LOAD` program
/// header, and the payload mapped at the standard user-space entry point.
pub fn build_artifact_from_payload(
    payload: &[u8],
    entry_offset: usize,
    entry_base: u64,
    machine: u16,
) -> DemoProgramArtifact {
    assert!(
        !payload.is_empty(),
        "demo payload must not be empty for ELF generation"
    );
    assert!(
        entry_offset < payload.len(),
        "demo payload entry must be inside the payload image"
    );

    let entry_point = entry_base
        .checked_add(entry_offset as u64)
        .expect("demo ELF entry point must fit in u64");

    let mut image = vec![0_u8; ELF64_LOAD_SEGMENT_OFFSET + payload.len()];

    // ELF ident
    image[0..4].copy_from_slice(b"\x7FELF");
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // ELFDATA2LSB
    image[6] = 1; // EV_CURRENT

    // ELF header fields
    write_u16(&mut image, 16, 2); // e_type = ET_EXEC
    write_u16(&mut image, 18, machine);
    write_u32(&mut image, 20, 1); // e_version
    write_u64(&mut image, 24, entry_point);
    write_u64(&mut image, 32, ELF64_PROGRAM_HEADER_OFFSET as u64);
    write_u16(&mut image, 52, ELF64_HEADER_SIZE as u16); // e_ehsize
    write_u16(&mut image, 54, ELF64_PROGRAM_HEADER_SIZE as u16); // e_phentsize
    write_u16(&mut image, 56, 1); // e_phnum = 1

    // Program header (PT_LOAD)
    let ph = ELF64_PROGRAM_HEADER_OFFSET;
    write_u32(&mut image, ph, 1); // p_type = PT_LOAD
    write_u32(&mut image, ph + 4, ELF64_LOAD_SEGMENT_FLAGS);
    write_u64(&mut image, ph + 8, ELF64_LOAD_SEGMENT_OFFSET as u64); // p_offset
    write_u64(&mut image, ph + 16, entry_base); // p_vaddr
    write_u64(&mut image, ph + 24, entry_base); // p_paddr
    write_u64(&mut image, ph + 32, payload.len() as u64); // p_filesz
    write_u64(&mut image, ph + 40, payload.len() as u64); // p_memsz
    write_u64(&mut image, ph + 48, ELF64_LOAD_SEGMENT_ALIGNMENT as u64); // p_align

    // Copy payload into the load segment
    image[ELF64_LOAD_SEGMENT_OFFSET..ELF64_LOAD_SEGMENT_OFFSET + payload.len()]
        .copy_from_slice(payload);

    DemoProgramArtifact { bytes: image }
}

// ── metadata-only ELF builder (no PT_LOAD — falls back to host proxy) ───

/// Build a metadata-only ELF64 header (no program headers, entry = 0).
///
/// Used for platforms where the shell runs via host-proxy execution rather
/// than as a native ELF with loadable segments.
pub fn build_metadata_only_artifact(machine: u16) -> DemoProgramArtifact {
    let mut image = vec![0_u8; ELF64_HEADER_SIZE];
    image[0..4].copy_from_slice(b"\x7FELF");
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // ELFDATA2LSB
    image[6] = 1; // EV_CURRENT
    write_u16(&mut image, 16, 2); // e_type = ET_EXEC
    write_u16(&mut image, 18, machine);
    write_u32(&mut image, 20, 1); // e_version
                                  // e_entry = 0 (no entry — proxy execution)
    write_u16(&mut image, 52, ELF64_HEADER_SIZE as u16); // e_ehsize
    write_u16(&mut image, 54, 0); // e_phentsize = 0
    write_u16(&mut image, 56, 0); // e_phnum = 0
    write_u16(&mut image, 58, 0); // e_shentsize = 0
    write_u16(&mut image, 60, 0); // e_shnum = 0
    write_u16(&mut image, 62, 0); // e_shstrndx = 0
    DemoProgramArtifact { bytes: image }
}

// ── helpers ──────────────────────────────────────────────────────────────

fn write_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(image: &mut [u8], offset: usize, value: u64) {
    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
