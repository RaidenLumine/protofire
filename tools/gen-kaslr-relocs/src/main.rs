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
use std::io::Write;
use std::io::{self};

// ── ELF64 constants ─────────────────────────────────────────────────────
const EM_X86_64: u16 = 62;
const SHT_RELA: u32 = 4;
const SHT_SYMTAB: u32 = 2;
const EI_NIDENT: usize = 16; // ELF e_ident size

// Relocation types (x86_64 ABI).
const R_X86_64_64: u32 = 1; // S + A (64-bit absolute)
const R_X86_64_32: u32 = 10; // S + A (32-bit absolute)
const R_X86_64_32S: u32 = 11; // S + A (32-bit signed)

/// Minimum virtual address considered "inside the kernel image".
/// Everything below this is firmware / bootstrap data.
const KERNEL_VADDR_MIN: u64 = 0x200000;

/// The array's length in the generated file, whatever the entry count is.
///
/// It is fixed so that the table's *size* does not depend on how many entries
/// it holds, and that is what makes a KASLR build reach a fixed point in two
/// passes.  The table is compiled in, so compiling it moves every site that
/// comes after it in the image; if the array's length changed with the count
/// — and compiling the table in changes the count, because the code that
/// reads the table has address relocations of its own — every pass would move
/// the sites, the next table would describe the previous layout, and no pass
/// would ever describe the image that carries it.  With a fixed length the
/// layout is stable from the first pass that compiles the table in, and the
/// second pass's table describes the image it is compiled into.  Unused slots
/// are `(0, 0, 0)` and are never applied (`KASLR_RELOCATION_COUNT` bounds the
/// loop).
const RELOCATION_CAPACITY: usize = 40000;

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

/// Symbol index from r_info (high 32 bits).
fn rela_symbol(r_info: u64) -> u64 {
    r_info >> 32
}

/// The `st_value` of symbol `sym_index` in the symbol table section at
/// `symtab_index`, and the section the symbol is defined in, or `None` when
/// any index or offset is out of bounds.
fn symbol_value(
    data: &[u8],
    shdr_off: usize,
    shdr_entsize: usize,
    shdr_count: usize,
    symtab_index: u64,
    sym_index: u64,
) -> Option<(u64, u16)> {
    let symtab_index = symtab_index as usize;
    if symtab_index >= shdr_count {
        return None;
    }
    let symtab = read_shdr(data, (shdr_off + symtab_index * shdr_entsize) as u64)?;
    let entsize = if symtab.sh_entsize != 0 {
        symtab.sh_entsize as usize
    } else {
        24 // Elf64_Sym
    };
    if entsize < 24 {
        return None;
    }
    let off =
        (symtab.sh_offset as usize).checked_add((sym_index as usize).checked_mul(entsize)?)?;
    let symtab_end = symtab.sh_offset as usize + symtab.sh_size as usize;
    if off + 24 > data.len() || off + 24 > symtab_end {
        return None;
    }
    let st_shndx = u16::from_le_bytes(data[off + 6..off + 8].try_into().ok()?);
    let st_value = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?);
    Some((st_value, st_shndx))
}

/// Whether the section `shndx` is one a relocation may name: allocated
/// (loaded into the image) or an absolute constant.
///
/// This is the filter that keeps the proof from being vacuous.  A record
/// against an unallocated section — a `.debug_*` section symbol, whose
/// `st_value` is zero — would otherwise "prove" trivially wherever the site
/// happens to hold zero, which is a coincidence rather than an applied
/// relocation: the kernel loads no debug section, so it can hold no
/// reference into one.  `SHN_ABS` (0xfff1) passes because an absolute symbol
/// is an address the kernel may legitimately store; any other special index
/// and any out-of-range index does not.
fn symbol_is_loadable(
    data: &[u8],
    shdr_off: usize,
    shdr_entsize: usize,
    shdr_count: usize,
    shndx: u16,
) -> Option<bool> {
    const SHN_ABS: u16 = 0xfff1;
    const SHF_ALLOC: u64 = 0x2;
    if shndx == SHN_ABS {
        return Some(true);
    }
    let index = shndx as usize;
    if index == 0 || index >= shdr_count {
        return None;
    }
    let shdr = read_shdr(data, (shdr_off + index * shdr_entsize) as u64)?;
    Some(shdr.sh_flags & SHF_ALLOC != 0)
}

/// Whether the ELF carries a symbol table at all.
///
/// The proof of a relocation compares a `st_value` from `.symtab` against the
/// bytes at the site; with no table there is nothing to compare against, and
/// a run over a stripped ELF would "drop" every record as unresolved and
/// report a table of zero entries.  The tool refuses that file instead.
fn symbol_table_present(
    data: &[u8],
    shdr_off: usize,
    shdr_entsize: usize,
    shdr_count: usize,
) -> bool {
    for i in 0..shdr_count {
        let Some(shdr) = read_shdr(data, (shdr_off + i * shdr_entsize) as u64) else {
            continue;
        };
        if shdr.sh_type == SHT_SYMTAB {
            return true;
        }
    }
    false
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

    // Scan all sections for RELA sections.  Each entry carries the value of
    // the symbol it names, resolved through the section's own symbol table —
    // that value is what the validation below proves the entry against.
    struct Relocation {
        /// Where the record applies, a virtual address in the image.
        site: u64,
        /// The record's addend.
        addend: i64,
        /// `R_X86_64_64`, `_32` or `_32S`.
        r_type: u32,
        /// The named symbol's `st_value` and section index, when it resolves.
        symbol: Option<(u64, u16)>,
    }
    let mut relocations: Vec<Relocation> = Vec::new();

    for i in 0..shdr_count {
        let shdr =
            read_shdr(&data, (shdr_off + i * shdr_entsize) as u64).expect("invalid section header");
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
                    // Keep the absolute kinds; whether an entry is real is
                    // decided below, where its symbol value is known.
                    R_X86_64_64 | R_X86_64_32 | R_X86_64_32S
                        if rela.r_offset >= KERNEL_VADDR_MIN =>
                    {
                        let sym_value = symbol_value(
                            &data,
                            shdr_off,
                            shdr_entsize,
                            shdr_count,
                            u64::from(shdr.sh_link),
                            rela_symbol(rela.r_info),
                        );
                        relocations.push(Relocation {
                            site: rela.r_offset,
                            addend: rela.r_addend,
                            r_type,
                            symbol: sym_value,
                        });
                        count += 1;
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
    eprintln!("Collected {total} absolute relocation entries");

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
        let p_type = u32::from_le_bytes(data[ph_off..ph_off + 4].try_into().unwrap());
        if p_type == 1 {
            // PT_LOAD
            let p_offset = u64::from_le_bytes(data[ph_off + 8..ph_off + 16].try_into().unwrap());
            let p_vaddr = u64::from_le_bytes(data[ph_off + 16..ph_off + 24].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(data[ph_off + 32..ph_off + 40].try_into().unwrap());
            segs.push(LoadSegment {
                vaddr: p_vaddr,
                file_off: p_offset,
                file_size: p_filesz,
            });
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
        if mem_end > kernel_end {
            kernel_end = mem_end;
        }
    }
    // Also check the BSS LOAD segment (file_sz=0, mem_sz>0).
    for ph_i in 0..e_phnum {
        let ph_off = e_phoff as usize + ph_i * e_phentsize;
        if ph_off + 56 > data.len() {
            break;
        }
        let p_type = u32::from_le_bytes(data[ph_off..ph_off + 4].try_into().unwrap());
        if p_type == 1 {
            let p_vaddr = u64::from_le_bytes(data[ph_off + 16..ph_off + 24].try_into().unwrap());
            let p_memsz = u64::from_le_bytes(data[ph_off + 40..ph_off + 48].try_into().unwrap());
            let mem_end = p_vaddr + p_memsz;
            if mem_end > kernel_end {
                kernel_end = mem_end;
            }
        }
    }
    // ── The kernel's end, from the linker's own symbols ───────────────
    // The window below needs the kernel's *end*, and the LOAD segments no
    // longer have it: the frame pool is reserved address space, outside
    // every segment, so the segment walk stops at `__image_end` while the
    // addresses the kernel stores run on to `__kernel_end` (= `__bss_end`,
    // both after the pool).  A site holding `__pool_start`, `__pool_end`
    // or `__image_end` would then be filtered as spurious, and the tool
    // would write a table that never relocates the pool's own bounds —
    // silently, because a missing entry changes nothing until KASLR is
    // enabled and the relocated kernel computes a stale pool.  So read
    // `st_value` from the symbol table (`.symtab`); the segment walk above
    // stays as the fallback for a stripped ELF.
    let mut symtab_end: u64 = 0;
    let mut symtab_end_name = "";

    // The symbols the kernel's address space cannot lose: the pool's two ends
    // and the image's end.  The kernel stores each of them as a value, so a
    // relocation over each of them has to be in the table — and when the pool
    // moved out of the load segments, 45 such entries were dropped with no
    // line saying so.  They are counted and reported below, and the
    // `check-kaslr-relocs` gate requires each count to stay non-zero.
    const BOUNDARY_SYMBOLS: [&[u8]; 3] = [b"__pool_start", b"__pool_end", b"__image_end"];
    let mut boundary_values: [Option<u64>; 3] = [None; 3];

    for i in 0..shdr_count {
        let shdr =
            read_shdr(&data, (shdr_off + i * shdr_entsize) as u64).expect("invalid section header");
        if shdr.sh_type != SHT_SYMTAB {
            continue;
        }
        let strtab_ndx = shdr.sh_link as usize;
        if strtab_ndx >= shdr_count {
            continue;
        }
        let strtab_shdr = read_shdr(&data, (shdr_off + strtab_ndx * shdr_entsize) as u64)
            .expect("invalid section header");
        let strtab_off = strtab_shdr.sh_offset as usize;
        let strtab_size = strtab_shdr.sh_size as usize;
        if strtab_off + strtab_size > data.len() {
            continue;
        }
        let strtab = &data[strtab_off..strtab_off + strtab_size];

        let sym_off = shdr.sh_offset as usize;
        let sym_size = shdr.sh_size as usize;
        let entsize = if shdr.sh_entsize != 0 {
            shdr.sh_entsize as usize
        } else {
            24 // Elf64_Sym
        };
        if entsize < 24 || sym_off + sym_size > data.len() {
            continue;
        }

        let mut off = sym_off;
        while off + 24 <= sym_off + sym_size {
            let name_off = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            let st_value = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
            let name: &[u8] = if name_off < strtab.len() {
                let end = strtab[name_off..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|position| name_off + position)
                    .unwrap_or(strtab.len());
                &strtab[name_off..end]
            } else {
                &[]
            };
            let named = if name == b"__kernel_end" {
                Some("__kernel_end")
            } else if name == b"__bss_end" {
                Some("__bss_end")
            } else {
                None
            };
            if let Some(named) = named {
                if st_value > symtab_end {
                    symtab_end = st_value;
                    symtab_end_name = named;
                }
            }
            for (slot, boundary) in BOUNDARY_SYMBOLS.iter().enumerate() {
                if name == *boundary && boundary_values[slot].is_none() {
                    boundary_values[slot] = Some(st_value);
                }
            }
            off += entsize;
        }
    }

    // The wider of the two sources: the segment walk cannot exceed the
    // linker's end, so taking the max keeps the window at least as wide as
    // the image and exactly as wide as the kernel when the symbols exist.
    let valid_end = kernel_end.max(symtab_end);
    if symtab_end != 0 {
        eprintln!("Kernel extent end: {:#x} ({})", valid_end, symtab_end_name);
    } else {
        eprintln!(
            "Kernel extent end: {:#x} (LOAD segments; no linker end symbol)",
            valid_end
        );
    }

    // ── Validate each entry against the symbol it names ───────────────
    // `--emit-relocs` preserves relocations from ALL input object files, and
    // not every record is a reference the link actually applied: the site can
    // hold instruction bytes that merely look like an address.  The filter
    // used to guess — "the value at the site is a plausible kernel address" —
    // which cannot tell an applied relocation from a coincidence, and its
    // own comment admitted that false positives could remain.  With the
    // symbol value in hand the question has a proof: a record is a real
    // relocation exactly when the symbol it names links to the value at its
    // site, `site == (st_value + addend) mod 2^width`.  A record that fails
    // is one the linker did not apply, and each drop is counted by reason so
    // the numbers can be read rather than trusted.
    let mut validated: Vec<(u64, i64, u32)> = Vec::new();
    let mut unresolved = 0usize;
    let mut unreadable = 0usize;
    let mut not_loadable = 0usize;
    let mut mismatch = 0usize;
    let mut out_of_extent = 0usize;
    let mut boundary_kept = [0usize; BOUNDARY_SYMBOLS.len()];
    // `KASLR_RELOCS_EXPLAIN=1` reports what was dropped and why: a count
    // alone cannot be acted on, and the failure paths of the check that runs
    // this tool need the entries, not just the totals.
    let explain = std::env::var_os("KASLR_RELOCS_EXPLAIN").is_some();
    let mut explained = 0usize;
    for relocation in &relocations {
        let Relocation {
            site: r_off,
            addend,
            r_type,
            symbol,
        } = *relocation;
        let width: u64 = if r_type == R_X86_64_64 { 8 } else { 4 };
        // The symbol the record names has to resolve: without it the entry
        // cannot be proven, and an unprovable entry is not emitted.
        let Some((sym_value, sym_shndx)) = symbol else {
            unresolved += 1;
            if explain && explained < 20 {
                explained += 1;
                eprintln!("  dropped unresolved: site={:#x} addend={}", r_off, addend);
            }
            continue;
        };
        // A record into a section the kernel never loads — a `.debug_*`
        // section symbol, whose value is zero — proves nothing: the site
        // holding zero would "match" by coincidence, and the kernel stores
        // no reference into a section it does not have.
        match symbol_is_loadable(&data, shdr_off, shdr_entsize, shdr_count, sym_shndx) {
            Some(true) => {}
            Some(false) => {
                not_loadable += 1;
                if explain && explained < 20 {
                    explained += 1;
                    eprintln!(
                        "  dropped not-loadable: site={:#x} symbol-shndx={} value={:#x}",
                        r_off, sym_shndx, sym_value
                    );
                }
                continue;
            }
            None => {
                unresolved += 1;
                if explain && explained < 20 {
                    explained += 1;
                    eprintln!(
                        "  dropped unresolved section: site={:#x} symbol-shndx={}",
                        r_off, sym_shndx
                    );
                }
                continue;
            }
        }
        // The measurement itself: the applied value and the recorded symbol
        // address have to be the same number at the site's width.
        let Some(file_off) = vma_to_offset(r_off) else {
            unreadable += 1;
            if explain && explained < 20 {
                explained += 1;
                eprintln!("  dropped unreadable site: site={:#x}", r_off);
            }
            continue;
        };
        if (file_off + width) as usize > data.len() {
            unreadable += 1;
            if explain && explained < 20 {
                explained += 1;
                eprintln!("  dropped unreadable site (past EOF): site={:#x}", r_off);
            }
            continue;
        }
        let val = if width == 8 {
            u64::from_le_bytes(
                data[file_off as usize..file_off as usize + 8]
                    .try_into()
                    .unwrap(),
            )
        } else {
            u32::from_le_bytes(
                data[file_off as usize..file_off as usize + 4]
                    .try_into()
                    .unwrap(),
            ) as u64
        };
        let mask: u64 = if width == 8 { u64::MAX } else { 0xffff_ffff };
        let expected = sym_value.wrapping_add(addend as u64) & mask;
        if val != expected {
            mismatch += 1;
            if explain && explained < 20 {
                explained += 1;
                eprintln!(
                    "  dropped value mismatch: site={:#x} holds {:#x}, symbol {:#x} + {} expects {:#x}",
                    r_off, val, sym_value, addend, expected
                );
            }
            continue;
        }
        // The symbol is the anchor: a record the kernel applies names an
        // address inside the kernel's extent, and the extent's end is
        // inclusive because the linker's end label is itself a value the
        // kernel stores (`__pool_end` and `__bss_end` equal `__kernel_end`).
        // The value at the site is *not* checked against the extent: it is
        // `symbol + addend`, and the addend legitimately points past the end —
        // the kernel stores `__bss_end + 0xfff` (page-align-up's operand) and
        // `__bss_end + 0x1000` (the heap's rounded end), and both have to
        // move with the kernel.  An earlier version of this check compared
        // the site value too and dropped exactly those records, which is the
        // same class of loss the segment-derived bound had.
        let in_extent = |address: u64| (KERNEL_VADDR_MIN..=valid_end).contains(&address);
        if !in_extent(sym_value) {
            out_of_extent += 1;
            if explain && explained < 20 {
                explained += 1;
                eprintln!(
                    "  dropped out of extent: site={:#x} symbol-value={:#x} (shndx {}) site-value={:#x}",
                    r_off, sym_value, sym_shndx, val
                );
            }
            continue;
        }
        for (slot, boundary_value) in boundary_values.iter().enumerate() {
            if *boundary_value == Some(sym_value) {
                boundary_kept[slot] += 1;
            }
        }
        validated.push((r_off, addend, r_type));
    }

    // A stripped ELF has no symbol table, and without it no record can be
    // proven — every one of them would come out "unresolved" and the tool
    // would write an empty table and report success.  The table's whole value
    // is that it is complete, so refuse instead: a caller that stripped the
    // ELF passed the wrong file.
    if !symbol_table_present(&data, shdr_off, shdr_entsize, shdr_count) {
        eprintln!(
            "error: {elf_path} has no symbol table; the relocation table cannot be proven against it"
        );
        std::process::exit(1);
    }

    let total = validated.len();
    eprintln!(
        "KASLR relocs: {} kept, {} dropped ({} unresolved symbol, {} unreadable site, {} not loadable, {} value mismatch, {} out of extent)",
        total,
        unresolved + unreadable + not_loadable + mismatch + out_of_extent,
        unresolved,
        unreadable,
        not_loadable,
        mismatch,
        out_of_extent
    );
    for (slot, boundary) in BOUNDARY_SYMBOLS.iter().enumerate() {
        let name = String::from_utf8_lossy(boundary);
        match boundary_values[slot] {
            Some(_) => eprintln!("boundary {}: {} kept", name, boundary_kept[slot]),
            None => eprintln!("boundary {}: not in the symbol table", name),
        }
    }

    // ── Pointers the linker resolved without leaving a record ──────────
    // The copy has to be patched everywhere the loaded image holds an
    // address, and "everywhere" is not the same set as "everywhere a
    // relocation record exists": a `.data` dispatch slot the linker resolved
    // to a code address can have no record in any `.rela.*` section
    // (measured: the fmt/alloc dispatch slots, called through with `call
    // *0x603078(%rip)` — forty-eight code pointers, and not one `.rela.data`
    // record among them).  A table built only from records leaves those
    // naming the abandoned image, and the first indirect call through one
    // faults at the link-time address — measured, with a reclaimed IP of
    // `Formatter::pad` before any shell.
    //
    // So the proven records are the table's spine and this scan is its
    // complement: every aligned pointer-sized value in an allocated,
    // **writable** section (`.data`; `.bss` is NOBITS and holds nothing to
    // scan) that lands inside a section marked executable and is not already
    // covered by a proven record.  The range test is what keeps it honest —
    // a `.data` word that names code is a code pointer on this image, which
    // has no ASLR-independent encodings — and each addition is counted and
    // named so the gate's log shows exactly what the scan added.
    let mut scanned = 0usize;
    {
        use std::collections::HashSet;
        let mut covered: HashSet<u64> = HashSet::new();
        for &(offset, _, r_type) in &validated {
            let width: u64 = if r_type == R_X86_64_64 { 8 } else { 4 };
            for byte in 0..width {
                covered.insert(offset + byte);
            }
        }

        let mut executable: Vec<(u64, u64)> = Vec::new();
        let mut writable_data: Vec<(u64, u64, u64, u64)> = Vec::new();
        for i in 0..shdr_count {
            let shdr = read_shdr(&data, (shdr_off + i * shdr_entsize) as u64)
                .expect("invalid section header");
            const SHF_WRITE: u64 = 0x1;
            const SHF_ALLOC: u64 = 0x2;
            const SHF_EXECINSTR: u64 = 0x4;
            if shdr.sh_flags & SHF_ALLOC == 0 || shdr.sh_type != 1 {
                continue;
            }
            if shdr.sh_flags & SHF_EXECINSTR != 0 {
                executable.push((shdr.sh_addr, shdr.sh_addr + shdr.sh_size));
            } else if shdr.sh_flags & SHF_WRITE != 0 {
                writable_data.push((
                    shdr.sh_addr,
                    shdr.sh_offset,
                    shdr.sh_size,
                    shdr.sh_addralign,
                ));
            }
        }

        for &(addr, offset, size, _) in &writable_data {
            let mut at = 0u64;
            while at + 8 <= size {
                let site = addr + at;
                // Aligned, inside the kernel, and not already an entry.
                if site.is_multiple_of(8)
                    && site >= KERNEL_VADDR_MIN
                    && site <= valid_end
                    && !covered.contains(&site)
                {
                    let file_at = (offset + at) as usize;
                    if file_at + 8 <= data.len() {
                        let value =
                            u64::from_le_bytes(data[file_at..file_at + 8].try_into().unwrap());
                        if executable
                            .iter()
                            .any(|&(start, end)| start <= value && value < end)
                        {
                            scanned += 1;
                            if explain && scanned <= 20 {
                                eprintln!(
                                    "  scanned pointer: site={:#x} -> code {:#x}",
                                    site, value
                                );
                            }
                            validated.push((site, 0, R_X86_64_64));
                        }
                    }
                }
                at += 8;
            }
        }
    }
    let total = validated.len();
    eprintln!(
        "scanned: {} absolute pointer(s) with no relocation record in writable data",
        scanned
    );

    // The generated array has a fixed length; a count past it is a table the
    // tool cannot represent, and silently writing a shorter one would be the
    // same class of loss this file exists to prevent.
    if total > RELOCATION_CAPACITY {
        eprintln!(
            "error: {} entries do not fit the table's fixed capacity of {}; raise RELOCATION_CAPACITY",
            total, RELOCATION_CAPACITY
        );
        std::process::exit(1);
    }

    // Sort by offset for reliable processing.
    validated.sort_by_key(|&(offset, _, _)| offset);

    // Generate the Rust source file.
    let mut out = fs::File::create(out_path)?;

    writeln!(out, "// Auto-generated by gen-kaslr-relocs — DO NOT EDIT")?;
    writeln!(out, "// Source ELF: {}", elf_path)?;
    writeln!(out, "// Total entries: {}", total)?;
    writeln!(
        out,
        "// Capacity: {} (fixed, so compiling the table in does not move the sites after it)",
        RELOCATION_CAPACITY
    )?;
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
    writeln!(
        out,
        "/// The first KASLR_RELOCATION_COUNT are real; the rest are padding."
    )?;
    // A `static` rather than a `const`: the table is a megabyte by the time
    // it is padded to the fixed capacity, and `const` would have the compiler
    // inline a value that large at its one use.  The table holds offsets
    // relative to the kernel's start, so it needs no relocation of its own.
    writeln!(
        out,
        "pub(crate) static KASLR_RELOCATIONS: [(usize, isize, u8); {}] = [",
        RELOCATION_CAPACITY
    )?;

    let kernel_base = KERNEL_VADDR_MIN;
    for &(offset, addend, r_type) in &validated {
        let rela_off = offset - kernel_base;
        let width: u8 = if r_type == R_X86_64_64 { 8 } else { 4 };
        writeln!(out, "    ({:#x}, {}, {}),", rela_off, addend, width)?;
    }
    for _ in total..RELOCATION_CAPACITY {
        writeln!(out, "    (0, 0, 0),")?;
    }

    writeln!(out, "];")?;

    eprintln!("Wrote {} to {}", out_path, total);
    Ok(())
}
