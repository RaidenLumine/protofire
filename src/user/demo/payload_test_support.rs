//! src/user/demo/payload_test_support.rs
//! Host-side inspection helpers used by the assembly and Rust demo payload
//! tests.
//!
//! These helpers locate the built payload artifact (either the currently
//! running test binary for the host x86_64 payloads, or a cross-compiled
//! kernel image for the aarch64/riscv64 payloads), parse its ELF sections
//! and symbol table, and expose symbol ranges and decoded instructions so
//! the tests can assert position-independence and scalar-only invariants.
//!
//! Everything degrades to `None` when the artifact is not available (for
//! example when the cross target has not been built), in which case the
//! calling test silently skips.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

// ── public result types ──────────────────────────────────────────────

/// The bytes between two payload boundary symbols, plus their addresses.
pub struct SymbolRange {
    pub bytes: Vec<u8>,
    pub start: usize,
    pub end: usize,
}

/// A function symbol that lives inside a payload section.
pub struct PayloadFunction {
    pub name: String,
    pub start: usize,
}

/// A payload section plus the functions resolved inside it.
pub struct PayloadSection {
    pub functions: Vec<PayloadFunction>,
    pub section_start: usize,
    pub bytes: Vec<u8>,
}

/// A decoded instruction stream for a host payload section.
pub struct Disassembly {
    instructions: Vec<DecodedInstruction>,
    code_len: usize,
}

struct DecodedInstruction {
    offset: usize,
    uses_simd: bool,
    uses_rip_relative: bool,
    uses_absolute_immediate: bool,
    branch_target: Option<usize>,
}

#[derive(Default)]
struct DecodeFlags {
    uses_simd: bool,
    uses_rip_relative: bool,
    uses_absolute_immediate: bool,
    branch_target: Option<usize>,
}

// ── artifact location ────────────────────────────────────────────────

static ARTIFACT_CACHE: OnceLock<Mutex<HashMap<String, Option<PathBuf>>>> = OnceLock::new();

/// Locate a payload artifact for `target`.  `"host"` resolves to the running
/// test executable; any other target is looked up in (or built into) the
/// Cargo target directory.
fn artifact_for(target: &str) -> Option<PathBuf> {
    let cache = ARTIFACT_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(entry) = cache.lock().unwrap().get(target).cloned() {
        return entry;
    }
    let resolved = if target == "host" {
        std::env::current_exe().ok()
    } else {
        cross_target_artifact(target)
    };
    let mut guard = cache.lock().unwrap();
    guard.entry(target.to_string()).or_insert(resolved).clone()
}

/// Find or build the kernel binary for a cross target.
fn cross_target_artifact(target: &str) -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("target"));
    let executable = target_dir.join(target).join("debug").join("protofire");

    // Reuse an existing build (`make build-aarch64` / `build-riscv64`),
    // otherwise attempt a quiet offline build so the tests stay self
    // contained.  Any failure degrades to `None` and the test skips.
    if executable.is_file() {
        return Some(executable);
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
    let build_output = Command::new(&cargo)
        .args([
            "build",
            "--offline",
            "--target",
            target,
            "--bin",
            "protofire",
            "--target-dir",
        ])
        .arg(&target_dir)
        .current_dir(&manifest_dir)
        .output()
        .ok()?;
    if !build_output.status.success() {
        return None;
    }
    executable.is_file().then_some(executable)
}

// ── ELF section / symbol parsing ─────────────────────────────────────

struct ElfSection {
    name: String,
    addr: u64,
    offset: u64,
    size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SymbolKind {
    /// STT_FUNC — an executable function symbol.
    Function,
    /// STT_OBJECT — an embedded data object (typically a string table).
    Object,
    /// STT_NOTYPE or anything else — a bare boundary marker.
    Other,
}

struct ElfSymbol {
    name: String,
    value: u64,
    kind: SymbolKind,
}

fn parse_elf_sections_and_symbols(image: &[u8]) -> Option<(Vec<ElfSection>, Vec<ElfSymbol>)> {
    if image.len() < 64 || &image[0..4] != b"\x7fELF" {
        return None;
    }
    let e_shoff = u64::from_le_bytes(image[0x28..0x30].try_into().ok()?);
    let e_shentsize = u16::from_le_bytes(image[0x3a..0x3c].try_into().ok()?) as usize;
    let e_shnum = u16::from_le_bytes(image[0x3c..0x3e].try_into().ok()?) as usize;
    let e_shstrndx = u16::from_le_bytes(image[0x3e..0x40].try_into().ok()?) as usize;
    if e_shentsize < 64 || e_shnum == 0 || e_shoff as usize >= image.len() {
        return None;
    }

    // Read the section-name string table header to index names by offset.
    let shstr_index = e_shstrndx * e_shentsize;
    let shstr_hdr = e_shoff as usize + shstr_index;
    if shstr_hdr + 0x28 > image.len() {
        return None;
    }
    let shstr_off =
        u64::from_le_bytes(image[shstr_hdr + 0x18..shstr_hdr + 0x20].try_into().ok()?) as usize;
    let shstr_size =
        u64::from_le_bytes(image[shstr_hdr + 0x20..shstr_hdr + 0x28].try_into().ok()?) as usize;
    let shstr = image.get(shstr_off..shstr_off + shstr_size)?;

    let section_name = |name_off: u32| -> String {
        let start = name_off as usize;
        if start >= shstr.len() {
            return String::new();
        }
        let end = shstr[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(shstr.len());
        String::from_utf8_lossy(&shstr[start..end]).into_owned()
    };

    let mut sections = Vec::new();
    let mut symtab: Option<(u64, u64, u64)> = None; // (offset, size, entsize)
    let mut strtab: Option<(u64, u64)> = None; // (offset, size)

    for i in 0..e_shnum {
        let off = e_shoff as usize + i * e_shentsize;
        if off + 64 > image.len() {
            break;
        }
        let name_off = u32::from_le_bytes(image[off..off + 4].try_into().ok()?);
        let sh_type = u32::from_le_bytes(image[off + 4..off + 8].try_into().ok()?);
        let sh_addr = u64::from_le_bytes(image[off + 0x10..off + 0x18].try_into().ok()?);
        let sh_offset = u64::from_le_bytes(image[off + 0x18..off + 0x20].try_into().ok()?);
        let sh_size = u64::from_le_bytes(image[off + 0x20..off + 0x28].try_into().ok()?);
        let sh_entsize = u64::from_le_bytes(image[off + 0x38..off + 0x40].try_into().ok()?);
        let name = section_name(name_off);

        if sh_type == 2 {
            // SHT_SYMTAB (2) — note SHT_NOBITS is also section type 8, so the
            // symtab match must be `2`, not `8`, or the linker's `.bss`/`.tbss`
            // sections get misread as a gigantic symbol table.
            symtab = Some((sh_offset, sh_size, sh_entsize));
        } else if sh_type == 3 && i != e_shstrndx {
            // SHT_STRTAB (skip the section-name table itself)
            strtab = Some((sh_offset, sh_size));
        }
        sections.push(ElfSection {
            name,
            addr: sh_addr,
            offset: sh_offset,
            size: sh_size,
        });
    }

    let mut symbols = Vec::new();
    if let (Some((sym_off, sym_size, sym_entsize)), Some((str_off, str_size))) = (symtab, strtab) {
        let entsize = if sym_entsize == 0 {
            24
        } else {
            sym_entsize as usize
        };
        let count = sym_size as usize / entsize;
        let strtab_bytes = image.get(str_off as usize..(str_off + str_size) as usize)?;
        for i in 0..count {
            let off = sym_off as usize + i * entsize;
            if off + 24 > image.len() {
                break;
            }
            let st_name = u32::from_le_bytes(image[off..off + 4].try_into().ok()?);
            let st_info = image.get(off + 4).copied().unwrap_or(0);
            let st_value = u64::from_le_bytes(image[off + 8..off + 16].try_into().ok()?);
            let kind = match st_info & 0x0f {
                1 => SymbolKind::Object,
                2 => SymbolKind::Function,
                _ => SymbolKind::Other,
            };
            let name = {
                let start = st_name as usize;
                if start >= strtab_bytes.len() {
                    String::new()
                } else {
                    let end = strtab_bytes[start..]
                        .iter()
                        .position(|&b| b == 0)
                        .map(|p| start + p)
                        .unwrap_or(strtab_bytes.len());
                    String::from_utf8_lossy(&strtab_bytes[start..end]).into_owned()
                }
            };
            if !name.is_empty() {
                symbols.push(ElfSymbol {
                    name,
                    value: st_value,
                    kind,
                });
            }
        }
    }

    Some((sections, symbols))
}

/// Map a virtual address to its file offset in the image.
fn file_offset_for_addr(sections: &[ElfSection], addr: u64) -> Option<u64> {
    for section in sections {
        if section.size > 0 && addr >= section.addr && addr < section.addr + section.size {
            return Some(section.offset + (addr - section.addr));
        }
    }
    None
}

// ── public inspection entry points ───────────────────────────────────

/// Return the bytes between two symbols in the payload artifact for `target`.
pub fn target_symbol_range(
    target: &str,
    start_symbol: &str,
    end_symbol: &str,
) -> Option<SymbolRange> {
    let path = artifact_for(target)?;
    let image = std::fs::read(path).ok()?;
    let (sections, symbols) = parse_elf_sections_and_symbols(&image)?;
    let start = symbols.iter().find(|s| s.name == start_symbol)?;
    let end = symbols.iter().find(|s| s.name == end_symbol)?;
    if start.value >= end.value {
        return None;
    }
    let start_off = file_offset_for_addr(&sections, start.value)? as usize;
    let end_off = file_offset_for_addr(&sections, end.value)? as usize;
    if end_off > image.len() {
        return None;
    }
    let bytes = image[start_off..end_off].to_vec();
    Some(SymbolRange {
        bytes,
        start: start.value as usize,
        end: end.value as usize,
    })
}

/// Return a payload section plus the function symbols that live inside it.
pub fn target_payload_section(target: &str, section_name: &str) -> Option<PayloadSection> {
    let path = artifact_for(target)?;
    let image = std::fs::read(path).ok()?;
    let (sections, symbols) = parse_elf_sections_and_symbols(&image)?;
    let section = sections.iter().find(|s| s.name == section_name)?;
    let functions = symbols
        .iter()
        .filter(|s| s.value >= section.addr && s.value < section.addr + section.size)
        .map(|s| PayloadFunction {
            name: s.name.clone(),
            start: s.value as usize,
        })
        .collect();
    let end_off = (section.offset + section.size) as usize;
    if end_off > image.len() {
        return None;
    }
    let bytes = image[section.offset as usize..end_off].to_vec();
    Some(PayloadSection {
        functions,
        section_start: section.addr as usize,
        bytes,
    })
}

/// Decode the payload section `section_name` in the running test binary.
pub fn payload_disassembly(section_name: &str, expect_section: bool) -> Option<Disassembly> {
    let image = std::fs::read(artifact_for("host")?).ok()?;
    let (sections, symbols) = parse_elf_sections_and_symbols(&image)?;
    let Some(section) = sections.iter().find(|s| s.name == section_name) else {
        return if expect_section {
            None
        } else {
            empty_disassembly()
        };
    };
    let start = section.offset as usize;
    let end = (section.offset + section.size) as usize;
    if end > image.len() || section.size == 0 {
        return if expect_section {
            None
        } else {
            empty_disassembly()
        };
    }
    let code = &image[start..end];
    let data_regions = data_regions_in_section(&symbols, section.addr, section.addr + section.size);
    let instructions = decode_x86_64(code, section.addr as usize, &data_regions);
    Some(Disassembly {
        instructions,
        code_len: code.len(),
    })
}

/// Byte ranges inside a section that hold embedded data rather than code.
///
/// The payload sections interleave code with string tables (messages, paths,
/// command names) that the assembly reaches with RIP-relative `lea`s.  An
/// `STT_OBJECT` symbol owns the bytes from its address up to the next symbol;
/// those bytes are data, not instructions, so the linear decode sweep must not
/// descend into them.
fn data_regions_in_section(
    symbols: &[ElfSymbol],
    sec_start: u64,
    sec_end: u64,
) -> Vec<(usize, usize)> {
    // Every symbol start inside the section (any type), sorted and deduped.
    let mut all: Vec<u64> = symbols
        .iter()
        .filter(|s| s.value >= sec_start && s.value < sec_end)
        .map(|s| s.value)
        .collect();
    all.sort_unstable();
    all.dedup();

    let mut objects: Vec<u64> = symbols
        .iter()
        .filter(|s| s.kind == SymbolKind::Object && s.value >= sec_start && s.value < sec_end)
        .map(|s| s.value)
        .collect();
    objects.sort_unstable();
    objects.dedup();

    let mut regions = Vec::new();
    for &object in &objects {
        let start = (object - sec_start) as usize;
        let end = all
            .iter()
            .find(|&&value| value > object)
            .map(|&value| (value - sec_start) as usize)
            .unwrap_or((sec_end - sec_start) as usize);
        if end > start {
            regions.push((start, end));
        }
    }
    regions
}

fn empty_disassembly() -> Option<Disassembly> {
    Some(Disassembly {
        instructions: Vec::new(),
        code_len: 0,
    })
}

// ── invariants ───────────────────────────────────────────────────────

/// Assert the decoded x86_64 payload stays self-contained and scalar-only.
pub fn assert_self_contained_and_scalar_only(disassembly: &Disassembly) {
    for instruction in &disassembly.instructions {
        assert!(
            !instruction.uses_simd,
            "payload uses a SIMD (XMM/YMM) instruction at offset {:#x}",
            instruction.offset
        );
        assert!(
            !instruction.uses_rip_relative,
            "payload uses rip-relative addressing at offset {:#x}; the payload must stay position independent",
            instruction.offset
        );
        assert!(
            !instruction.uses_absolute_immediate,
            "payload materializes an absolute 64-bit immediate at offset {:#x}; the payload must stay position independent",
            instruction.offset
        );
        if let Some(target) = instruction.branch_target {
            assert!(
                target < disassembly.code_len,
                "payload direct branch at offset {:#x} targets {:#x}, outside the {:#x}-byte payload",
                instruction.offset,
                target,
                disassembly.code_len
            );
        }
    }
}

/// Assert every direct branch in the AArch64 payload stays inside the range.
pub fn assert_aarch64_direct_branches_stay_within(range: &SymbolRange) {
    let code = &range.bytes;
    for (index, chunk) in code.chunks(4).enumerate() {
        if chunk.len() < 4 {
            break;
        }
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        // B / BL: 26-bit signed immediate, offset from the current instruction.
        if word & 0x7c00_0000 == 0x1400_0000 {
            let imm26 = word & 0x03ff_ffff;
            let offset = ((imm26 << 6) as i32) >> 6;
            let target = range.start + index * 4 + (offset as i64 as usize);
            assert!(
                target >= range.start && target < range.end,
                "aarch64 direct branch at symbol offset {:#x} targets {:#x}, outside [{:#x}, {:#x})",
                index * 4,
                target,
                range.start,
                range.end
            );
        }
        // B.cond: 19-bit signed immediate.
        if word & 0xff00_0010 == 0x5400_0000 {
            let imm19 = (word >> 5) & 0x7_ffff;
            let offset = ((imm19 << 13) as i32) >> 13;
            let target = range.start + index * 4 + (offset as i64 as usize);
            assert!(
                target >= range.start && target < range.end,
                "aarch64 conditional branch at symbol offset {:#x} targets {:#x}, outside [{:#x}, {:#x})",
                index * 4,
                target,
                range.start,
                range.end
            );
        }
    }
}

// ── x86-64 length decoding ───────────────────────────────────────────

/// Decode a single x86-64 instruction beginning at `code[ip..]`.
///
/// Returns `(instruction_length, flags)`.  The length is correct for the
/// integer/control-flow instruction families the payloads emit; unknown
/// encodings fall back to a conservative single-byte length so the scan
/// never runs away.
fn decode_x86_64(
    code: &[u8],
    base_addr: usize,
    data_regions: &[(usize, usize)],
) -> Vec<DecodedInstruction> {
    let mut instructions = Vec::new();
    let mut ip = 0usize;
    while ip < code.len() {
        // Jump over embedded string-table bytes; they are not instructions and
        // a linear sweep would mis-decode them into bogus opcodes.
        if let Some((_, end)) = data_regions
            .iter()
            .find(|(start, end)| ip >= *start && ip < *end)
        {
            ip = *end;
            continue;
        }
        let (length, flags) = decode_one(code, ip);
        let offset = ip;
        let branch_target = flags.branch_target.map(|absolute| {
            if absolute >= base_addr {
                absolute - base_addr
            } else {
                absolute
            }
        });
        instructions.push(DecodedInstruction {
            offset,
            uses_simd: flags.uses_simd,
            uses_rip_relative: flags.uses_rip_relative,
            uses_absolute_immediate: flags.uses_absolute_immediate,
            branch_target,
        });
        ip += length.max(1);
    }
    instructions
}

/// Advance past a ModRM byte (plus SIB/displacement), recording flags.
///
/// `flag_rip_relative` controls whether a ModRM of `mod=00, rm=101` marks the
/// instruction as using RIP-relative addressing. It is `false` for `lea`,
/// whose RIP-relative displacement only *computes* an address and never
/// dereferences it — such an instruction is position-independent.
fn after_modrm(
    code: &[u8],
    modrm_pos: usize,
    flags: &mut DecodeFlags,
    flag_rip_relative: bool,
) -> usize {
    let Some(&byte) = code.get(modrm_pos) else {
        return modrm_pos;
    };
    let mode = byte >> 6;
    let rm = byte & 0x07;
    let disp_len = match mode {
        0 => {
            if rm == 0x05 {
                if flag_rip_relative {
                    flags.uses_rip_relative = true;
                }
                4
            } else {
                0
            }
        }
        1 => 1,
        2 => 4,
        _ => 0,
    };
    modrm_pos + 1 + disp_len
}

fn decode_one(code: &[u8], ip: usize) -> (usize, DecodeFlags) {
    let mut flags = DecodeFlags::default();
    let mut index = ip;
    let mut rex_w = false;
    let mut simd_prefix = 0u8; // 0 = none, 1 = 66, 2 = F2, 3 = F3

    // ── legacy + REX prefixes ───────────────────────────────────────
    loop {
        let Some(&byte) = code.get(index) else {
            return (index - ip, flags);
        };
        match byte {
            0x66 => {
                simd_prefix = 1;
                index += 1;
            }
            0xf2 => {
                simd_prefix = 2;
                index += 1;
            }
            0xf3 => {
                simd_prefix = 3;
                index += 1;
            }
            0xf0 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => {
                index += 1;
            }
            0x40..=0x4f => {
                rex_w = byte & 0x08 != 0;
                index += 1;
            }
            _ => break,
        }
    }
    let Some(&opcode) = code.get(index) else {
        return (index - ip, flags);
    };
    index += 1;

    // ── two-byte (0F) opcodes ───────────────────────────────────────
    if opcode == 0x0f {
        let Some(&second) = code.get(index) else {
            return (index - ip, flags);
        };
        index += 1;
        match second {
            0x05 => return (index - ip, flags), // syscall
            0x34 => return (index - ip, flags), // sysenter
            0x80..=0x8f => {
                // jcc rel32
                if index + 4 <= code.len() {
                    let rel = i32::from_le_bytes(code[index..index + 4].try_into().unwrap());
                    flags.branch_target = Some(((ip as i64) + 6 + (rel as i64)).max(0) as usize);
                }
                index += 4;
                return (index - ip, flags);
            }
            0x1f => {
                // nop r/m
                index = after_modrm(code, index, &mut flags, true);
                return (index - ip, flags);
            }
            0xaf | 0xb6 | 0xb7 | 0xbe | 0xbf => {
                // imul / movzx / movsx with ModRM
                index = after_modrm(code, index, &mut flags, true);
                return (index - ip, flags);
            }
            _ => {
                // Unrecognized two-byte family.  A SIMD prefix means the
                // payload touched the SSE/AVX register file.
                if simd_prefix != 0 {
                    flags.uses_simd = true;
                }
                index = after_modrm(code, index, &mut flags, true);
                return (index - ip, flags);
            }
        }
    }

    // ── single-byte opcodes ─────────────────────────────────────────
    match opcode {
        // push r64 / pop r64
        0x50..=0x5f => (index - ip, flags),
        // push imm8 / imm32
        0x6a => (index - ip + 1, flags),
        0x68 => (index - ip + 4, flags),
        // jcc / jmp rel8
        0x70..=0x7f | 0xeb => {
            if index < code.len() {
                let rel = code[index] as i8 as i64;
                flags.branch_target = Some(((ip as i64) + 2 + rel).max(0) as usize);
            }
            index += 1;
            (index - ip, flags)
        }
        // group1 (add/or/adc/sbb/and/sub/xor/cmp) with immediate
        0x80 | 0x81 | 0x83 => {
            index = after_modrm(code, index, &mut flags, true);
            let imm_len = match opcode {
                0x80 | 0x83 => 1,
                _ => {
                    if simd_prefix == 1 {
                        2 // 66 operand-size prefix → imm16
                    } else {
                        4
                    }
                }
            };
            index = (index + imm_len).min(code.len());
            (index - ip, flags)
        }
        // AL/EAX immediate forms: add or adc sbb and sub xor cmp
        0x04 | 0x05 | 0x0c | 0x0d | 0x14 | 0x15 | 0x1c | 0x1d | 0x24 | 0x25 | 0x2c | 0x2d
        | 0x34 | 0x35 | 0x3c | 0x3d => {
            let imm_len = if opcode & 1 == 1 {
                if simd_prefix == 1 {
                    2
                } else {
                    4
                }
            } else {
                1
            };
            index = (index + imm_len).min(code.len());
            (index - ip, flags)
        }
        // ModRM integer-family opcodes
        0x00..=0x03
        | 0x08..=0x0b
        | 0x10..=0x13
        | 0x18..=0x1b
        | 0x20..=0x23
        | 0x28..=0x2b
        | 0x30..=0x33
        | 0x38..=0x3b
        | 0x84..=0x8c
        | 0x8f
        | 0xd0..=0xd3 => {
            index = after_modrm(code, index, &mut flags, true);
            (index - ip, flags)
        }
        // lea r64, m — address computation is position-independent even with a
        // RIP-relative displacement (it only forms an address; it never derefs),
        // so it must not be flagged as a rip-relative memory access.
        0x8d => {
            index = after_modrm(code, index, &mut flags, false);
            (index - ip, flags)
        }
        // test r/m, imm8/imm32
        0xf6 | 0xf7 => {
            index = after_modrm(code, index, &mut flags, true);
            let imm_len = if opcode == 0xf7 && simd_prefix != 1 {
                4
            } else {
                1
            };
            index = (index + imm_len).min(code.len());
            (index - ip, flags)
        }
        // test al/eax, imm
        0xa8 | 0xa9 => {
            let imm_len = if opcode == 0xa9 && simd_prefix != 1 {
                4
            } else {
                1
            };
            index = (index + imm_len).min(code.len());
            (index - ip, flags)
        }
        // mov r8/rm, imm
        0xb0..=0xbf => {
            if rex_w {
                // movabs r64, imm64 — absolute address materialization
                flags.uses_absolute_immediate = true;
                index = (index + 8).min(code.len());
            } else {
                let imm_len = if opcode <= 0xb7 { 1 } else { 4 };
                index = (index + imm_len).min(code.len());
            }
            (index - ip, flags)
        }
        // mov r/m, imm8/imm32
        0xc6 | 0xc7 => {
            index = after_modrm(code, index, &mut flags, true);
            let imm_len = if (rex_w || simd_prefix != 1) && opcode == 0xc7 {
                4
            } else {
                1
            };
            index = (index + imm_len).min(code.len());
            (index - ip, flags)
        }
        // ret / ret imm16
        0xc3 => (index - ip, flags),
        0xc2 => (index - ip + 2, flags),
        // int imm8 / into
        0xcd => (index - ip + 1, flags),
        0xce => (index - ip, flags),
        // call / jmp rel32
        0xe8 | 0xe9 => {
            if index + 4 <= code.len() {
                let rel = i32::from_le_bytes(code[index..index + 4].try_into().unwrap());
                flags.branch_target = Some(((ip as i64) + 5 + (rel as i64)).max(0) as usize);
            }
            index += 4;
            (index - ip, flags)
        }
        // group3/4/5: not/neg/mul/imul/div/idiv, inc/dec, call/jmp/push r/m
        0xfe | 0xff => {
            index = after_modrm(code, index, &mut flags, true);
            (index - ip, flags)
        }
        // leave
        0xc9 => (index - ip, flags),
        // pushf/popf/pusha/... single-byte stack ops
        0x9c..=0x9f => (index - ip, flags),
        // in/out (port I/O)
        0xe4 | 0xe6 | 0xec | 0xee => (index - ip, flags),
        0xe5 | 0xe7 => (index - ip + 1, flags),
        // movabs via A0-A3 (absolute moffs) — breaks PIC
        0xa0..=0xa3 => {
            flags.uses_absolute_immediate = true;
            (index - ip + 8, flags)
        }
        _ => {
            // Anything else: consume a ModRM if one is plausibly present and
            // fall back to one byte, keeping the scan bounded.
            index = after_modrm(code, index, &mut flags, true);
            (index - ip, flags)
        }
    }
}
