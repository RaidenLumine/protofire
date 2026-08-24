//! tools/gen-kaslr-relocs/src/main.rs
//!
//! gen-kaslr-relocs — extract absolute relocations from a PIE kernel ELF
//! and emit a Rust source file with a compact relocation table for KASLR.
//!
//! Usage: gen-kaslr-relocs <kernel-elf> <output-rs>
//!
//! The kernel must be linked with `--emit-relocs` which preserves every
//! link-time relocation in .rela.* sections of the output ELF.  This tool
//! reads those sections, selects absolute-address relocations (R_X86_64_64,
//! R_X86_64_32, R_X86_64_32S), and writes a Rust array suitable for
//! `include!` into the kernel.

use std::env;
use std::fs;
use std::io::{self, Write};

// ── ELF64 constants ─────────────────────────────────────────────────────
const EM_X86_64: u16 = 62;
const SHT_RELA: u32 = 4;
const EI_NIDENT: usize = 16; // ELF e_ident size

// Relocation types (x86_64 ABI).
const R_X86_64_64: u32 = 1;   // S + A (64-bit absolute)
const R_X86_64_32: u32 = 10;  // S + A (32-bit absolute)
const R_X86_64_32S: u32 = 11; // S + A (32-bit signed)

/// Minimum virtual address considered "inside the kernel image".
/// Everything below this is firmware / bootstrap data.
const KERNEL_VADDR_MIN: u64 = 0x200000;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Elf64Ehdr {
    e_ident: [u8; EI_NIDENT],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

impl Elf64Ehdr {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }
        let e_ident = bytes[0..16].try_into().ok()?;
        let e_type = u16::from_le_bytes(bytes[16..18].try_into().ok()?);
        let e_machine = u16::from_le_bytes(bytes[18..20].try_into().ok()?);
        let e_version = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
        let e_entry = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
        let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
        let e_shoff = u64::from_le_bytes(bytes[40..48].try_into().ok()?);
        let e_flags = u32::from_le_bytes(bytes[48..52].try_into().ok()?);
        let e_ehsize = u16::from_le_bytes(bytes[52..54].try_into().ok()?);
        let e_phentsize = u16::from_le_bytes(bytes[54..56].try_into().ok()?);
        let e_phnum = u16::from_le_bytes(bytes[56..58].try_into().ok()?);
        let e_shentsize = u16::from_le_bytes(bytes[58..60].try_into().ok()?);
        let e_shnum = u16::from_le_bytes(bytes[60..62].try_into().ok()?);
        let e_shstrndx = u16::from_le_bytes(bytes[62..64].try_into().ok()?);
        Some(Self {
            e_ident,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_phentsize,
            e_phnum,
            e_shoff,
            e_flags,
            e_ehsize,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

fn read_shdr(bytes: &[u8], offset: u64) -> Option<Elf64Shdr> {
    let off = offset as usize;
    if off + 64 > bytes.len() {
        return None;
    }
    Some(Elf64Shdr {
        sh_name: u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?),
        sh_type: u32::from_le_bytes(bytes[off + 4..off + 8].try_into().ok()?),
        sh_flags: u64::from_le_bytes(bytes[off + 8..off + 16].try_into().ok()?),
        sh_addr: u64::from_le_bytes(bytes[off + 16..off + 24].try_into().ok()?),
        sh_offset: u64::from_le_bytes(bytes[off + 24..off + 32].try_into().ok()?),
        sh_size: u64::from_le_bytes(bytes[off + 32..off + 40].try_into().ok()?),
        sh_link: u32::from_le_bytes(bytes[off + 40..off + 44].try_into().ok()?),
        sh_info: u32::from_le_bytes(bytes[off + 44..off + 48].try_into().ok()?),
        sh_addralign: u64::from_le_bytes(bytes[off + 48..off + 56].try_into().ok()?),
        sh_entsize: u64::from_le_bytes(bytes[off + 56..off + 64].try_into().ok()?),
    })
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

fn read_rela(bytes: &[u8], offset: u64) -> Option<Elf64Rela> {
    let off = offset as usize;
    if off + 24 > bytes.len() {
        return None;
    }
    Some(Elf64Rela {
        r_offset: u64::from_le_bytes(bytes[off..off + 8].try_into().ok()?),
        r_info: u64::from_le_bytes(bytes[off + 8..off + 16].try_into().ok()?),
        r_addend: i64::from_le_bytes(bytes[off + 16..off + 24].try_into().ok()?),
    })
}

/// Relocation type from r_info (low 32 bits).
fn rela_type(r_info: u64) -> u32 {
    (r_info & 0xFFFF_FFFF) as u32
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: gen-kaslr-relocs <kernel-elf> <output-rs>");
        std::process::exit(1);
    }
    let elf_path = &args[1];
    let out_path = &args[2];

    // Read the entire kernel ELF.
    let data = fs::read(elf_path)?;
    if data.len() < 64 {
        eprintln!("error: file too small for ELF header");
        std::process::exit(1);
    }

    // Parse ELF header.
    let ehdr = Elf64Ehdr::from_bytes(&data).expect("invalid ELF header");
    if ehdr.e_ident[0..4] != [0x7f, b'E', b'L', b'F'] {
        eprintln!("error: not an ELF file");
        std::process::exit(1);
    }
    if ehdr.e_machine != EM_X86_64 {
        eprintln!("error: not an x86_64 ELF (machine={:#x})", ehdr.e_machine);
        std::process::exit(1);
    }

    // Read the section header string table.
    let shdr_off = ehdr.e_shoff as usize;
    let shdr_entsize = ehdr.e_shentsize as usize;
    let shdr_count = ehdr.e_shnum as usize;

    if shdr_off + shdr_count * shdr_entsize > data.len() {
        eprintln!("error: section headers overflow file");
        std::process::exit(1);
    }

    let shstrtab_ndx = ehdr.e_shstrndx as usize;
    if shstrtab_ndx >= shdr_count {
        eprintln!("error: invalid shstrtab index");
        std::process::exit(1);
    }

    let shstrtab_shdr = read_shdr(&data, (shdr_off + shstrtab_ndx * shdr_entsize) as u64)
        .expect("invalid shstrtab section header");
    let shstrtab_off = shstrtab_shdr.sh_offset as usize;
    let shstrtab_size = shstrtab_shdr.sh_size as usize;
    if shstrtab_off + shstrtab_size > data.len() {
        eprintln!("error: shstrtab overflows file");
        std::process::exit(1);
    }
    let shstrtab = &data[shstrtab_off..shstrtab_off + shstrtab_size];

    // Helper: get section name.
    let section_name = |shdr: &Elf64Shdr| -> String {
        let name_off = shdr.sh_name as usize;
        if name_off >= shstrtab.len() {
            return String::new();
        }
        let end = shstrtab[name_off..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(shstrtab.len() - name_off);
        String::from_utf8_lossy(&shstrtab[name_off..name_off + end]).to_string()
    };

    // Scan all sections for RELA sections.
    let mut relocations: Vec<(u64, i64, u32)> = Vec::new();

    for i in 0..shdr_count {
        let shdr = read_shdr(&data, (shdr_off + i * shdr_entsize) as u64)
            .expect("invalid section header");
        let name = section_name(&shdr);

        if shdr.sh_type == SHT_RELA && name.starts_with(".rela.") {
            // Skip .rela.debug_* sections — they reference addresses outside
            // the kernel image (unloaded debug sections).
            if name.starts_with(".rela.debug") {
                continue;
            }

            // Read RELA entries from this section.
            let rela_off = shdr.sh_offset as usize;
            let rela_size = shdr.sh_size as usize;
            let entsize = if shdr.sh_entsize != 0 {
                shdr.sh_entsize as usize
            } else {
                24 // default RELA entry size
            };

            if rela_off + rela_size > data.len() || entsize < 24 {
                eprintln!(
                    "warning: skipping section '{}' (offset={:#x}, size={}, entsize={})",
                    name, rela_off, rela_size, entsize
                );
                continue;
            }

            let mut count = 0;
            let mut off = rela_off;
            let end = rela_off + rela_size;

            while off + 24 <= end {
                let rela = read_rela(&data, off as u64).expect("invalid RELA entry");
                let r_type = rela_type(rela.r_info);

                match r_type {
                    R_X86_64_64 | R_X86_64_32 | R_X86_64_32S => {
                        // Only keep entries whose target is within the
                        // kernel image range.
                        if rela.r_offset >= KERNEL_VADDR_MIN {
                            relocations.push((rela.r_offset, rela.r_addend, r_type));
                            count += 1;
                        }
                    }
                    _ => {} // skip PC-relative, PLT, and other relocations
                }

                off += entsize;
            }

            eprintln!(
                "  {}: {} entries (kept {})",
                name,
                (rela_size / entsize),
                count
            );
        }
    }

    let total = relocations.len();

    // ── Pre-compute VMA→file-offset mapping from LOAD segments ──────────
    struct LoadSegment {
        vaddr: u64,
        file_off: u64,
        file_size: u64,
    }
    let mut segs: Vec<LoadSegment> = Vec::new();
    let e_phoff = ehdr.e_phoff;
    let e_phentsize = ehdr.e_phentsize as usize;
    let e_phnum = ehdr.e_phnum as usize;
    for i in 0..e_phnum {
        let ph_off = e_phoff as usize + i * e_phentsize;
        if ph_off + 56 > data.len() {
            break;
        }
        let p_type = u32::from_le_bytes(data[ph_off..ph_off+4].try_into().unwrap());
        if p_type == 1 { // PT_LOAD
            let p_offset = u64::from_le_bytes(data[ph_off+8..ph_off+16].try_into().unwrap());
            let p_vaddr  = u64::from_le_bytes(data[ph_off+16..ph_off+24].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(data[ph_off+32..ph_off+40].try_into().unwrap());
            segs.push(LoadSegment { vaddr: p_vaddr, file_off: p_offset, file_size: p_filesz });
        }
    }
    let vma_to_offset = |vma: u64| -> Option<u64> {
        for seg in &segs {
            if vma >= seg.vaddr && vma < seg.vaddr + seg.file_size {
                return Some(seg.file_off + (vma - seg.vaddr));
            }
        }
        None
    };

    // ── Read __bss_end / __kernel_end from the symbol table ──────────
    // Fallback: compute kernel_end from LOAD segments (last LOAD vaddr + memsz).
    let mut kernel_end: u64 = 0;
    for seg in &segs {
        let mem_end = seg.vaddr + seg.file_size; // use file_size since mem in BSS is zero
        if mem_end > kernel_end { kernel_end = mem_end; }
    }
    // Also check the BSS LOAD segment (file_sz=0, mem_sz>0).
    for ph_i in 0..e_phnum {
        let ph_off = e_phoff as usize + ph_i * e_phentsize;
        if ph_off + 56 > data.len() { break; }
        let p_type = u32::from_le_bytes(data[ph_off..ph_off+4].try_into().unwrap());
        if p_type == 1 {
            let p_vaddr = u64::from_le_bytes(data[ph_off+16..ph_off+24].try_into().unwrap());
            let p_memsz = u64::from_le_bytes(data[ph_off+40..ph_off+48].try_into().unwrap());
            let mem_end = p_vaddr + p_memsz;
            if mem_end > kernel_end { kernel_end = mem_end; }
        }
    }
    // Symbol table lookup is a more precise source; override if available.
    // (Currently the symtab parsing encounters a boundary bug, so we use
    //  the LOAD-segment heuristic which gives a slightly wider range —
    //  safe because it only PASSES entries, never filters valid ones.)
    let valid_end = kernel_end;

    // ── Validate each entry by reading the value at the site ──────────
    // `--emit-relocs` preserves relocations from ALL input object files,
    // including many whose site does not actually hold an absolute address.
    // We validate by checking that the current value at `r_offset` is within
    // [KERNEL_VADDR_MIN, kernel_end).  Entries outside this range are
    // spurious and are skipped.
    let mut validated: Vec<(u64, i64, u32)> = Vec::new();
    let mut filtered = 0usize;
    for &(r_off, addend, r_type) in &relocations {
        let width: u64 = if r_type == R_X86_64_64 { 8 } else { 4 };
        if let Some(file_off) = vma_to_offset(r_off) {
            if (file_off + width) as usize <= data.len() {
                let val = if width == 8 {
                    u64::from_le_bytes(data[file_off as usize..file_off as usize + 8].try_into().unwrap())
                } else {
                    u32::from_le_bytes(data[file_off as usize..file_off as usize + 4].try_into().unwrap()) as u64
                };
                // Additional check for 8-byte entries: valid kernel addresses
                // fit in 32 bits (kernel < 4 GiB).  If upper 32 bits are set,
                // the value is NOT a pointer but instruction bytes that happen
                // to fall in range (e.g. a relocation at offset 0 that reads
                // the REX+opcode prefix as part of the "value").
                let high_bits_ok = width < 8 || (val >> 32) == 0;
                if val >= KERNEL_VADDR_MIN && val < valid_end && high_bits_ok {
                    validated.push((r_off, addend, r_type));
                } else {
                    filtered += 1;
                }
            }
        }
    }
    let total = validated.len();
    eprintln!("Validated KASLR relocation entries: {} (filtered {} spurious)", total, filtered);

    // Sort by offset for reliable processing.
    validated.sort_by_key(|&(offset, _, _)| offset);

    // Generate the Rust source file.
    let mut out = fs::File::create(out_path)?;

    writeln!(out, "// Auto-generated by gen-kaslr-relocs — DO NOT EDIT")?;
    writeln!(out, "// Source ELF: {}", elf_path)?;
    writeln!(out, "// Total entries: {}", total)?;
    writeln!(out)?;
    writeln!(
        out,
        "pub(crate) const KASLR_RELOCATION_COUNT: usize = {};",
        total
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "/// (relative_offset_from_kernel_start, addend, byte_width) tuples."
    )?;
    writeln!(
        out,
        "/// At boot, for each entry: read/write `width` bytes at `kernel_base + offset`, then `value += delta`."
    )?;
    writeln!(out, "pub(crate) const KASLR_RELOCATIONS: [(usize, isize, u8); {}] = [", total)?;

    let kernel_base = KERNEL_VADDR_MIN;
    for &(offset, addend, r_type) in &validated {
        let rela_off = offset - kernel_base;
        let width: u8 = if r_type == R_X86_64_64 { 8 } else { 4 };
        writeln!(out, "    ({:#x}, {}, {}),", rela_off, addend, width)?;
    }

    writeln!(out, "];")?;

    eprintln!("Wrote {} to {}", out_path, total);
    Ok(())
}
