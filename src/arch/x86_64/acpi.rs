//! src/arch/x86_64/acpi.rs
//!
//! The ACPI tables this architecture is told about at boot: the MADT, which
//! names the processors, and the SRAT/SLIT pair, which says how far apart they
//! and their memory are.
//!
//! Parsed through the RSDP that the boot hand-off carries, before the runtime
//! page tables replace the bootstrap identity map — the tables live at physical
//! addresses the identity map covers and the runtime map may not.

use alloc::vec::Vec;

// ── ACPI structures (minimal — only what MADT parsing needs) ────────────

#[cfg(target_os = "none")]
#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

#[cfg(target_os = "none")]
#[repr(C, packed)]
#[allow(dead_code)]
struct RsdpV2 {
    base: Rsdp,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    _reserved: [u8; 3],
}

#[cfg(any(target_os = "none", test))]
#[repr(C, packed)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

#[cfg(target_os = "none")]
#[repr(C, packed)]
struct Madt {
    header: SdtHeader,
    local_apic_address: u32,
    flags: u32,
    // entries follow
}

// The two statements of the same layout have to agree.
#[cfg(target_os = "none")]
const _: () = assert!(core::mem::size_of::<Madt>() == MADT_HEADER_BYTES);

// And the header's two statements, wherever the struct is compiled.
#[cfg(any(target_os = "none", test))]
const _: () = assert!(core::mem::size_of::<SdtHeader>() == ACPI_SDT_HEADER_BYTES);

/// Parsed local APIC entry from the MADT.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct LocalApicEntry {
    pub acpi_processor_id: u8,
    pub apic_id: u8,
    pub enabled: bool,
}

// ── RSDP discovery ─────────────────────────────────────────────────────

/// Find the ACPI RSDP.
///
/// First checks the Multiboot2 info for ACPI tags (type 14 = old RSDP,
/// type 15 = new RSDP).  Falls back to scanning the BIOS read-only memory
/// area (0xE0000–0xFFFFF) for the "RSD PTR " signature.
#[cfg(target_os = "none")]
unsafe fn find_rsdp(multiboot_info: usize) -> Option<*const Rsdp> {
    // SAFETY: the caller is early boot with the loader's info block, which is
    // what both paths below expect; neither does anything else.
    unsafe {
        // Try Multiboot2 tags first.
        if let Some(rsdp) = find_rsdp_via_multiboot2(multiboot_info) {
            return Some(rsdp);
        }
        // Fall back to BIOS area scan.
        find_rsdp_via_bios_scan()
    }
}

/// Search Multiboot2 info tags for ACPI RSDP (type 14 or 15).
#[cfg(target_os = "none")]
unsafe fn find_rsdp_via_multiboot2(multiboot_info: usize) -> Option<*const Rsdp> {
    if multiboot_info == 0 {
        return None;
    }

    // SAFETY: `multiboot_info` is the loader's info block (checked non-zero
    // above), whose first u32 is the block's total size by the Multiboot2
    // specification.
    let total_size = unsafe { *(multiboot_info as *const u32) };
    let mut offset: usize = 8; // skip total_size (u32) + reserved (u32)

    while offset + 8 <= total_size as usize {
        // SAFETY: the loop condition keeps 8 bytes from `offset`, so both the
        // type at +0 and the size at +4 are inside the block.
        let tag_type = unsafe { *((multiboot_info + offset) as *const u32) };
        // SAFETY: as above — the same 8 bytes cover the size field.
        let tag_size = unsafe { *((multiboot_info + offset + 4) as *const u32) } as usize;

        if tag_type == 0 {
            break; // end tag
        }

        // An RSDP copy is only there if the tag is long enough to hold one;
        // the reads below are bounded by this.
        let rsdp_copy_fits = tag_size >= 8 + core::mem::size_of::<Rsdp>();

        match tag_type {
            14 if rsdp_copy_fits => {
                // ACPI old RSDP — the tag contains a copy of the RSDP
                // starting at offset 8.  Verify the signature.
                let rsdp_ptr = (multiboot_info + offset + 8) as *const Rsdp;
                // SAFETY: the tag's own size covers a full RSDP copy, which
                // the check above establishes before the pointer is formed.
                let sig = unsafe { core::ptr::read_volatile(&(*rsdp_ptr).signature) };
                if &sig == b"RSD PTR " {
                    return Some(rsdp_ptr);
                }
            }
            15 if rsdp_copy_fits => {
                // ACPI new RSDP — same layout, tag contains a copy.
                let rsdp_ptr = (multiboot_info + offset + 8) as *const Rsdp;
                // SAFETY: as for tag 14 — the length check above says the copy
                // is there.
                let sig = unsafe { core::ptr::read_volatile(&(*rsdp_ptr).signature) };
                if &sig == b"RSD PTR " {
                    return Some(rsdp_ptr);
                }
            }
            _ => {}
        }

        // Tags are 8-byte aligned.
        let aligned_size = (tag_size + 7) & !7;
        offset += aligned_size;
    }

    None
}

/// Scan the BIOS memory area (0xE0000–0xFFFFF) for the "RSD PTR " signature
/// on a 16-byte boundary.
#[cfg(target_os = "none")]
unsafe fn find_rsdp_via_bios_scan() -> Option<*const Rsdp> {
    let start: usize = 0xE0000;
    let end: usize = 0x100000;

    let mut addr = start;
    while addr < end {
        let ptr = addr as *const Rsdp;
        // SAFETY: these addresses are in the BIOS ROM area, which is
        // identity-mapped and readable; the scan never leaves it (`addr <
        // 0x100000`), so the whole RSDP this signature lives in is mapped.
        let sig = unsafe { core::ptr::read_volatile(&(*ptr).signature) };
        if &sig == b"RSD PTR " {
            // Verify checksum.
            // SAFETY: as above — the candidate address is inside the BIOS
            // ROM area, and the RSDP structure is what a signature match says
            // starts there.
            let bytes = unsafe {
                core::slice::from_raw_parts(ptr as *const u8, core::mem::size_of::<Rsdp>())
            };
            let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
            if sum == 0 {
                return Some(ptr);
            }
        }
        addr += 16; // RSDP is 16-byte aligned
    }

    None
}

// ── MADT parsing ───────────────────────────────────────────────────────

/// Read a physical address' contents via identity mapping.
///
/// # Safety
///
/// `addr` must be a valid physical address within the identity-mapped region.
#[cfg(target_os = "none")]
unsafe fn read_phys_u8(addr: usize) -> u8 {
    // SAFETY: the caller's contract above says `addr` is a valid physical
    // address in the identity-mapped region.
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// Read a little-endian u32 from a potentially unaligned physical address.
///
/// Uses volatile byte-by-byte reads to avoid alignment requirements while
/// still preventing the compiler from reordering or eliding the access.
#[cfg(target_os = "none")]
unsafe fn read_phys_u32(addr: usize) -> u32 {
    // SAFETY: the caller's contract covers the four addresses; each is a byte
    // of the same word.
    let b0 = unsafe { read_phys_u8(addr) } as u32;
    // SAFETY: as above.
    let b1 = unsafe { read_phys_u8(addr + 1) } as u32;
    // SAFETY: as above.
    let b2 = unsafe { read_phys_u8(addr + 2) } as u32;
    // SAFETY: as above.
    let b3 = unsafe { read_phys_u8(addr + 3) } as u32;
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

/// Bytes of an ACPI system description table header.
///
/// The layout is the specification's fixed one — signature (4), length (4),
/// revision, checksum, six-byte OEM ID, eight-byte table ID and two
/// revisions — and [`SdtHeader`] states the same layout where that struct is
/// compiled.  The walker uses this number so the tests' host build, which
/// does not compile the struct, still has it; the assert below ties the two
/// statements together wherever both exist.
#[cfg(any(target_os = "none", test))]
const ACPI_SDT_HEADER_BYTES: usize = 36;

/// The most bytes any ACPI table the walker follows may span.
///
/// Every table this tree reads is small — the captured real-firmware MADT is
/// 476 bytes, and even a machine with sixty-five thousand processors needs
/// only one megabyte of `x2APIC` entries — so a table whose header declares
/// more is a header not to trust.  The bound exists because the header's
/// length field is 32 bits of firmware data and every reader of a table
/// forms a slice from it: a wild length is how a read runs off the map.
#[cfg(any(target_os = "none", test))]
const ACPI_TABLE_MAX_BYTES: usize = 0x10_0000;

/// The most bytes a MADT may span before the boot distrusts it.
///
/// The header's length field is 32 bits, so firmware can claim a table of
/// four gigabytes.  A real MADT is a few hundred bytes — the fixture in this
/// tree, from a laptop's own firmware, is 476 — and even a machine with
/// sixty-five thousand processors would need one megabyte of sixteen-byte
/// `x2APIC` entries to outgrow this bound, so a length past it is a length
/// not to trust.  The number is deliberately far above what any machine
/// describes: the bound exists to bound the slice, not to model a machine.
const MADT_MAX_BYTES: usize = 0x10_0000;

/// Bytes before a MADT's entry list: an SDT header (36) plus the local-APIC
/// address and the flags word.  The `Madt` struct states the same layout for
/// the bare-metal path; this is the number the byte parser uses, because it
/// has to be the same on a host build that never defines that struct.
const MADT_HEADER_BYTES: usize = 44;

/// Parse a MADT out of its own bytes, and answer its local APIC entries.
///
/// Pure over the table's bytes so the parse is host-testable: the capture in
/// `fixtures/acpi/APIC` is a real firmware's MADT (a laptop's, with the
/// processor IDs, the disabled `0xff` entries and the interrupt-source
/// overrides QEMU's machines never describe), and
/// `real_firmware_madt_parses` walks it.  Entry types other than the
/// processor local APIC's are skipped by their length, which is what keeps
/// the walk landing on entry boundaries whatever a firmware puts between
/// them.
pub fn parse_madt_bytes(table: &[u8]) -> Vec<LocalApicEntry> {
    let mut entries = Vec::new();
    if !(MADT_HEADER_BYTES..=MADT_MAX_BYTES).contains(&table.len()) {
        return entries;
    }

    let mut offset = MADT_HEADER_BYTES;
    while offset + 2 <= table.len() {
        let entry_type = table[offset];
        let entry_len = table[offset + 1] as usize;
        if entry_len < 2 || offset + entry_len > table.len() {
            break;
        }
        if entry_type == 0 && entry_len >= 8 {
            let acpi_processor_id = table[offset + 2];
            let apic_id = table[offset + 3];
            let flags = table[offset + 4] as u32 | ((table[offset + 5] as u32) << 8);
            entries.push(LocalApicEntry {
                acpi_processor_id,
                apic_id,
                enabled: (flags & 0x1) != 0,
            });
        }
        offset += entry_len;
    }

    entries
}

/// Parse the MADT at a physical address and return its enabled local APIC
/// entries.
///
/// The address comes from the RSDT walk, which read the table's own header;
/// the table is mapped because every ACPI table is in the identity-mapped
/// region at boot.  The read is a byte slice over that mapping rather than a
/// copy, which is why the wrapper checks the header's length first: the
/// slice exists before the parser can re-check it.
#[cfg(target_os = "none")]
unsafe fn parse_madt(madt_addr: usize) -> Vec<LocalApicEntry> {
    // SAFETY: the MADT address comes from the RSDT walk, which read the
    // table's own header, and byte 4 of an SDT header is the length field's
    // first byte — inside the mapped table.
    let length = unsafe { read_phys_u32(madt_addr + 4) } as usize;
    if !(MADT_HEADER_BYTES..=MADT_MAX_BYTES).contains(&length) {
        return Vec::new();
    }
    // SAFETY: `length` is the length the table's own header declares, bounded
    // above by `MADT_MAX_BYTES`, and the table is the mapped range the RSDT
    // named — so the slice covers exactly that table.  Nothing writes
    // through it, and ACPI tables are never written by software.
    let table = unsafe { core::slice::from_raw_parts(madt_addr as *const u8, length) };
    parse_madt_bytes(table)
}

/// Discover AP LAPIC IDs from the ACPI MADT.
///
/// Returns a vector of (logical_cpu_id, lapic_id) pairs for all enabled
/// processors except the BSP.
#[cfg(target_os = "none")]
pub fn discover_aps(multiboot_info: usize) -> Vec<(u32, u8)> {
    // SAFETY: this runs at boot with the loader's info block, which is the
    // contract of the discovery helper.
    let rsdp = match unsafe { find_rsdp(multiboot_info) } {
        Some(rsdp) => rsdp,
        None => {
            crate::println!("[smp   ] ACPI RSDP not found, SMP disabled");
            return Vec::new();
        }
    };

    // Read RSDP fields via raw pointers — the struct is #[repr(C, packed)]
    // so creating references to its fields is UB.
    let rsdp_ptr = rsdp as *const u8;
    // SAFETY: offset 15 is the RSDP's revision field, and the RSDP was found by
    // signature in mapped memory.
    let revision = unsafe { core::ptr::read_volatile(rsdp_ptr.add(15)) };
    // OEM ID is 6 bytes at offset 9.
    let mut oem_buf = [0u8; 6];
    // SAFETY: the OEM ID is six bytes at offset 9 of the same RSDP; the
    // destination is a six-byte array that does not overlap it.
    unsafe {
        core::ptr::copy_nonoverlapping(rsdp_ptr.add(9), oem_buf.as_mut_ptr(), 6);
    }
    crate::println!(
        "[smp   ] ACPI RSDP found revision={} oem={}",
        revision,
        core::str::from_utf8(&oem_buf).unwrap_or("?")
    );

    // Read RSDT address at offset 16 (u32, little-endian, potentially
    // unaligned).  Use byte-by-byte volatile reads.
    // SAFETY: offset 16 is the RSDP's RSDT address field, in the mapped RSDP
    // the signature search found.
    let rsdt_addr = unsafe { read_phys_u32(rsdp as usize + 16) } as usize;
    crate::println!("[smp   ] RSDT at {:#010x}", rsdt_addr);
    if rsdt_addr == 0 {
        crate::println!("[smp   ] RSDT address is null, SMP disabled");
        return Vec::new();
    }

    // Find MADT within RSDT.
    // SAFETY: `rsdt_addr` came out of the RSDP; the helper reads the RSDT
    // header and its entries from mapped memory.
    let madt_addr = match unsafe { find_table_in_rsdt(rsdt_addr, b"APIC") } {
        Some(addr) => addr,
        None => {
            crate::println!("[smp   ] MADT not found in RSDT, SMP disabled");
            return Vec::new();
        }
    };

    // SAFETY: `madt_addr` is a table the RSDT named and whose checksum was
    // verified there.
    let all_entries = unsafe { parse_madt(madt_addr) };
    crate::println!(
        "[smp   ] MADT at {:#010x}: {} local APIC entries",
        madt_addr,
        all_entries.len()
    );

    // Assign logical CPU IDs.  BSP = 0, APs = 1, 2, ...
    let mut cpu_id: u32 = 0;
    let mut aps = Vec::new();

    for entry in &all_entries {
        if !entry.enabled {
            crate::println!("[smp   ]   APIC ID {} disabled, skipping", entry.apic_id);
            continue;
        }
        if cpu_id == 0 {
            // BSP — we are already running here.
            crate::println!("[smp   ]   BSP cpu_id={} apic_id={}", cpu_id, entry.apic_id);
        } else {
            aps.push((cpu_id, entry.apic_id));
            crate::println!("[smp   ]   AP  cpu_id={} apic_id={}", cpu_id, entry.apic_id);
        }
        cpu_id += 1;
    }

    aps
}

/// The RSDT walk, over an address space the caller answers for.
///
/// `space(addr, len)` names the `len` bytes at `addr`, or `None` when that
/// address is outside the space — and that one question is the whole of the
/// addressing: the walk itself is policy over whatever window the caller
/// hands it.  Two callers do: the boot passes the identity-mapped physical
/// space (every in-range read answers; the length bounds below are what
/// bound the reads), and
/// `rsdt_walk_finds_the_valid_table_behind_a_decoy` passes its own buffer
/// with *offsets as addresses*, so the whole walk — the entry-array bounds,
/// the candidate length gate, the signature and the checksum — runs on a
/// host over the captured firmware table's own bytes.
///
/// The walk distrusts everything it reads, because all of it is firmware
/// data:
///
/// * an RSDT whose header is too short to hold an entry array — or longer than
///   any real one — is refused rather than believed (`length - 36` underflowing
///   is how a wild length becomes a wild loop);
/// * a candidate whose own header declares a length outside the same bounds is
///   stepped over without its body being read;
/// * only then is the signature matched and the checksum verified over the
///   table's declared length, which is what keeps "a table the firmware meant"
///   distinct from "bytes that happen to spell APIC".
#[cfg(any(target_os = "none", test))]
fn walk_rsdt<'a, S>(rsdt_addr: usize, signature: &[u8; 4], space: &S) -> Option<usize>
where
    S: Fn(usize, usize) -> Option<&'a [u8]>,
{
    let header_size = ACPI_SDT_HEADER_BYTES;
    let u32_at = |addr: usize| -> Option<usize> {
        let bytes = space(addr, 4)?;
        let word: [u8; 4] = bytes.try_into().ok()?;
        Some(u32::from_le_bytes(word) as usize)
    };

    let rsdt_length = u32_at(rsdt_addr + 4)?;
    if !(header_size..=ACPI_TABLE_MAX_BYTES).contains(&rsdt_length) {
        return None;
    }
    let entry_count = (rsdt_length - header_size) / 4;

    for i in 0..entry_count {
        let table_addr = match u32_at(rsdt_addr + header_size + i * 4) {
            Some(0) | None => continue,
            Some(addr) => addr,
        };
        let table_length = match u32_at(table_addr + 4) {
            Some(length) if (header_size..=ACPI_TABLE_MAX_BYTES).contains(&length) => length,
            _ => continue,
        };
        let Some(bytes) = space(table_addr, table_length) else {
            continue;
        };
        if &bytes[0..4] != signature {
            continue;
        }
        let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if sum == 0 {
            return Some(table_addr);
        }
    }

    None
}

/// Search the RSDT for a table with the given 4-byte signature.
///
/// Answers the table's physical address.  The walk is [`walk_rsdt`]; this is
/// the identity-mapped space it runs over at boot, and the closure is where
/// the one addressing fact lives: a range has to lie inside the bootstrap
/// identity map, because every address in the walk comes out of firmware
/// data — a 32-bit table field puts a range's *start* below four gigabytes,
/// but its end can cross the map's, and a range that crosses is one to
/// refuse rather than to read.
#[cfg(target_os = "none")]
unsafe fn find_table_in_rsdt(rsdt_addr: usize, signature: &[u8; 4]) -> Option<usize> {
    use crate::arch::x86_64::paging::BOOTSTRAP_IDENTITY_MAP_END;

    walk_rsdt(rsdt_addr, signature, &|addr: usize, len: usize| {
        // The map is four gigabytes and the addresses are firmware data, so
        // this is the bound that turns "the firmware named it" into "the
        // boot can read it".
        if addr.checked_add(len)? > BOOTSTRAP_IDENTITY_MAP_END {
            return None;
        }
        // SAFETY: the caller passes the RSDT address the RSDP named, and the
        // check above just bounded the whole range inside the bootstrap
        // identity map the discovery path runs under — so naming those
        // bytes is sound for as long as that map is active, which is the
        // whole of this path.
        Some(unsafe { core::slice::from_raw_parts(addr as *const u8, len) })
    })
}

// ── Early-discovered AP list ───────────────────────────────────────────

/// Stores the AP list discovered before the page-table switch so it can be
/// used later during bring-up.  See [`store_early_aps`] and [`take_early_aps`].
#[cfg(target_os = "none")]
static EARLY_APS: crate::util::sync_unsafe_cell::SyncUnsafeCell<
    Option<alloc::vec::Vec<(u32, u8)>>,
> = crate::util::sync_unsafe_cell::SyncUnsafeCell::new(None);

/// Store the AP list discovered during early boot (before the page-table
/// switch).  Must be called at most once.
#[cfg(target_os = "none")]
pub fn store_early_aps(aps: alloc::vec::Vec<(u32, u8)>) {
    // SAFETY: the doc above says this runs at most once, before any reader
    // (`take_early_aps`) exists; the cell has no other writer.
    unsafe {
        *EARLY_APS.get() = Some(aps);
    }
}

/// Retrieve the early-discovered AP list (if any).
#[cfg(target_os = "none")]
pub fn take_early_aps() -> Option<alloc::vec::Vec<(u32, u8)>> {
    // SAFETY: as `store_early_aps` — this is the only reader, and it runs
    // after the single store.
    unsafe { (*EARLY_APS.get()).take() }
}

// ── Early-discovered NUMA data ─────────────────────────────────────────

/// A single processor-local APIC affinity record parsed from the ACPI SRAT.
/// Only compiled on x86_64 bare-metal where `discover_numa`/SRAT parsing runs.
#[cfg(target_os = "none")]
#[derive(Debug, Clone)]
pub struct CpuAffinity {
    /// Whether this processor is enabled (SRAT flags bit 0).
    pub enabled: bool,
    /// Local APIC ID of the processor.
    pub apic_id: u8,
    /// Proximity domain (NUMA node) this processor belongs to.
    pub node_id: u8,
}

/// A single x2APIC affinity record parsed from the ACPI SRAT.
/// Only compiled on x86_64 bare-metal where `discover_numa`/SRAT parsing runs.
#[cfg(target_os = "none")]
#[derive(Debug, Clone)]
pub struct X2ApicAffinity {
    /// Whether this processor is enabled (SRAT flags bit 0).
    pub enabled: bool,
    /// x2APIC ID of the processor.
    pub x2apic_id: u32,
    /// Proximity domain (NUMA node) this processor belongs to.
    pub node_id: u32,
}

/// A single memory affinity record parsed from the ACPI SRAT.
/// Only compiled on x86_64 bare-metal where `discover_numa`/SRAT parsing runs.
#[cfg(target_os = "none")]
#[derive(Debug, Clone)]
pub struct MemoryAffinity {
    /// Whether this memory region is enabled (SRAT flags bit 0).
    pub enabled: bool,
    /// Proximity domain (NUMA node) this memory range belongs to.
    pub node_id: u32,
    /// Base physical address of the memory range.
    pub base_addr: u64,
    /// Length in bytes of the memory range.
    pub length: u64,
}

/// NUMA topology data discovered during early boot, consumed later by
/// [`take_early_numa`].  When the boot handoff carries no usable SRAT/SLIT
/// data, nothing is stored and the kernel falls back to a single-node
/// topology.  Only compiled on x86_64 bare-metal where SRAT/SLIT parsing runs
/// and `build_numa_topology_from_srat` consumes the records.
#[cfg(target_os = "none")]
#[derive(Debug, Clone)]
pub struct EarlyNumaData {
    /// `(logical_cpu_id, apic_id)` for every enabled processor, in the same
    /// order assigned by MADT parsing (BSP first).
    pub cpu_apic_ids: alloc::vec::Vec<(u32, u8)>,
    /// Processor-local APIC affinity records from the SRAT.
    pub cpu_affinities: alloc::vec::Vec<CpuAffinity>,
    /// x2APIC affinity records from the SRAT.
    pub x2apic_affinities: alloc::vec::Vec<X2ApicAffinity>,
    /// Memory affinity records from the SRAT.
    pub memory_affinities: alloc::vec::Vec<MemoryAffinity>,
    /// Optional SLIT distance matrix (row-major, N x N) when a SLIT table
    /// was found; `None` otherwise.
    pub slit_matrix: Option<alloc::vec::Vec<alloc::vec::Vec<u8>>>,
}

/// Stores the NUMA data discovered before the page-table switch so it can be
/// consumed later during topology initialisation.
#[cfg(target_os = "none")]
static EARLY_NUMA: crate::util::sync_unsafe_cell::SyncUnsafeCell<Option<EarlyNumaData>> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new(None);

/// Locate an ACPI table with the given 4-byte signature via the RSDP/RSDT.
#[cfg(target_os = "none")]
unsafe fn find_acpi_table(rsdp: *const Rsdp, signature: &[u8; 4]) -> Option<usize> {
    // SAFETY: the caller passes the RSDP the signature search found; offset 16
    // is its RSDT address field.
    let rsdt_addr = unsafe { read_phys_u32(rsdp as usize + 16) } as usize;
    if rsdt_addr == 0 {
        return None;
    }
    // SAFETY: the address is the RSDT the RSDP named, which is what the walker
    // expects.
    unsafe { find_table_in_rsdt(rsdt_addr, signature) }
}

/// Read a little-endian u64 from a potentially unaligned physical address.
#[cfg(target_os = "none")]
unsafe fn read_phys_u64(addr: usize) -> u64 {
    // SAFETY: the caller's contract covers the eight addresses; this reads the
    // low half.
    let lo = unsafe { read_phys_u32(addr) } as u64;
    // SAFETY: as above — the high half, four bytes on.
    let hi = unsafe { read_phys_u32(addr + 4) } as u64;
    lo | (hi << 32)
}

/// Parse the ACPI SRAT and return the affinity records.
#[cfg(target_os = "none")]
unsafe fn parse_srat(
    srat_addr: usize,
) -> (Vec<CpuAffinity>, Vec<MemoryAffinity>, Vec<X2ApicAffinity>) {
    let mut cpu = Vec::new();
    let mut mem = Vec::new();
    let mut x2apic = Vec::new();

    // SAFETY: `srat_addr` is a table the RSDT named and whose checksum was
    // verified; its header is the first structure in it.
    let header = unsafe { &*(srat_addr as *const SdtHeader) };
    let table_end = srat_addr + header.length as usize;

    // SRAT: 36-byte SDT header + 12 reserved bytes, then affinity records.
    let mut offset = srat_addr + core::mem::size_of::<SdtHeader>() + 12;

    while offset + 2 <= table_end {
        // SAFETY: the loop condition keeps two bytes from `offset`, both
        // inside the table.
        let entry_type = unsafe { read_phys_u8(offset) };
        // SAFETY: as above — the length byte.
        let entry_len = unsafe { read_phys_u8(offset + 1) } as usize;
        if entry_len < 2 || offset + entry_len > table_end {
            break;
        }

        match entry_type {
            0 if entry_len >= 16 => {
                // Processor Local APIC/SAPIC Affinity (v1: 16 bytes).
                // SAFETY: the arm's `entry_len >= 16` guard covers the bytes
                // read here, and the length check above keeps the entry inside
                // the table.
                let proximity_domain = unsafe { read_phys_u32(offset + 2) };
                // SAFETY: as above.
                let apic_id = unsafe { read_phys_u8(offset + 6) };
                // SAFETY: as above.
                let flags = unsafe { read_phys_u32(offset + 7) };
                cpu.push(CpuAffinity {
                    enabled: (flags & 0x1) != 0,
                    apic_id,
                    node_id: proximity_domain as u8,
                });
            }
            1 if entry_len >= 40 => {
                // Memory Affinity (40 bytes).
                // SAFETY: the arm's `entry_len >= 40` guard covers every byte
                // read here, and the entry is inside the table.
                let proximity_domain = unsafe { read_phys_u32(offset + 2) };
                // SAFETY: as above.
                let base_addr = unsafe { read_phys_u64(offset + 8) };
                // SAFETY: as above.
                let length = unsafe { read_phys_u64(offset + 16) };
                // SAFETY: as above.
                let flags = unsafe { read_phys_u32(offset + 28) };
                mem.push(MemoryAffinity {
                    enabled: (flags & 0x1) != 0,
                    node_id: proximity_domain,
                    base_addr,
                    length,
                });
            }
            2 if entry_len >= 24 => {
                // x2APIC Affinity (24 bytes).
                // SAFETY: the arm's `entry_len >= 24` guard covers every byte
                // read here, and the entry is inside the table.
                let proximity_domain = unsafe { read_phys_u32(offset + 6) };
                // SAFETY: as above.
                let x2apic_id = unsafe { read_phys_u32(offset + 10) };
                // SAFETY: as above.
                let flags = unsafe { read_phys_u32(offset + 14) };
                x2apic.push(X2ApicAffinity {
                    enabled: (flags & 0x1) != 0,
                    x2apic_id,
                    node_id: proximity_domain,
                });
            }
            _ => {}
        }

        offset += entry_len;
    }

    (cpu, mem, x2apic)
}

/// Parse the ACPI SLIT distance matrix.
///
/// Returns `None` when the matrix is absent or out of bounds.
#[cfg(target_os = "none")]
unsafe fn parse_slit(slit_addr: usize) -> Option<Vec<Vec<u8>>> {
    // SAFETY: `slit_addr` is a table the RSDT named and whose checksum was
    // verified; its header is the first structure in it.
    let header = unsafe { &*(slit_addr as *const SdtHeader) };
    let table_end = slit_addr + header.length as usize;

    // SLIT: 36-byte SDT header + 8-byte locality count, then the matrix.
    // SAFETY: offset 36 is the SLIT's locality count, inside the table whose
    // length the header above gave.
    let locality_count = unsafe { read_phys_u64(slit_addr + 36) };
    if locality_count == 0 || locality_count > 64 {
        return None;
    }
    let locality_count = locality_count as usize;
    let matrix_offset = slit_addr + 36 + 8;
    if matrix_offset + locality_count * locality_count > table_end {
        return None;
    }

    let mut matrix = Vec::with_capacity(locality_count);
    for i in 0..locality_count {
        let mut row = Vec::with_capacity(locality_count);
        for j in 0..locality_count {
            let idx = i * locality_count + j;
            // SAFETY: the `matrix_offset + count² <= table_end` check above
            // keeps every index of the matrix inside the table.
            let dist = unsafe { read_phys_u8(matrix_offset + idx) };
            row.push(dist);
        }
        matrix.push(row);
    }

    Some(matrix)
}

/// Discover NUMA topology from ACPI SRAT/SLIT tables and store the result.
///
/// Must be called while the bootstrap identity map is still active (before
/// the page-table switch), because ACPI tables reside in physical memory.
/// The parsed data is stored in a static slot so it can be consumed later by
/// the kernel's NUMA topology initialisation.  When the handoff carries no
/// usable SRAT data, nothing is stored and the kernel falls back to a
/// single-node topology.
#[cfg(target_os = "none")]
pub fn discover_numa(multiboot_info: usize) {
    // SAFETY: this runs at boot with the loader's info block, which is what
    // discovery expects.
    let rsdp = match unsafe { find_rsdp(multiboot_info) } {
        Some(rsdp) => rsdp,
        None => return,
    };

    // Find and parse SRAT.
    // SAFETY: the RSDP came from the signature search; the helper reads only
    // the RSDT it names.
    let srat_addr = match unsafe { find_acpi_table(rsdp, b"SRAT") } {
        Some(addr) => addr,
        None => {
            crate::println!("[numa  ] SRAT not found, NUMA disabled");
            return;
        }
    };
    crate::println!("[numa  ] SRAT at {:#010x}", srat_addr);

    // SAFETY: `srat_addr` is a checksum-verified table the RSDT named.
    let (cpu_affs, mem_affs, x2apic_affs) = unsafe { parse_srat(srat_addr) };

    // Find and parse SLIT (optional).
    // SAFETY: as for the SRAT — the same RSDP, the same walk.
    let slit_matrix = match unsafe { find_acpi_table(rsdp, b"SLIT") } {
        Some(slit_addr) => {
            crate::println!("[numa  ] SLIT at {:#010x}", slit_addr);
            // SAFETY: `slit_addr` is a checksum-verified table the RSDT named.
            unsafe { parse_slit(slit_addr) }
        }
        None => None,
    };

    // Build the APIC-to-logical-CPU mapping from the MADT.
    // SAFETY: as above — the same RSDP, the same walk.
    let madt_addr = match unsafe { find_acpi_table(rsdp, b"APIC") } {
        Some(addr) => addr,
        None => return,
    };
    // SAFETY: `madt_addr` is a checksum-verified table the RSDT named.
    let madt_entries = unsafe { parse_madt(madt_addr) };
    let mut cpu_apic_ids = Vec::with_capacity(madt_entries.len());
    let mut cpu_id: u32 = 0;
    for entry in &madt_entries {
        if entry.enabled {
            cpu_apic_ids.push((cpu_id, entry.apic_id));
            cpu_id += 1;
        }
    }

    crate::println!(
        "[numa  ] {} CPU affinities, {} x2APIC affinities, {} memory ranges, {} enabled CPUs",
        cpu_affs.len(),
        x2apic_affs.len(),
        mem_affs.len(),
        cpu_apic_ids.len()
    );

    // SAFETY: this runs once at boot, before the consumer (`take_early_numa`)
    // exists; the cell has no other writer.
    unsafe {
        *EARLY_NUMA.get() = Some(EarlyNumaData {
            cpu_apic_ids,
            cpu_affinities: cpu_affs,
            x2apic_affinities: x2apic_affs,
            memory_affinities: mem_affs,
            slit_matrix,
        });
    }
}

/// Retrieve the early-discovered NUMA data (if any).
#[cfg(target_os = "none")]
pub fn take_early_numa() -> Option<EarlyNumaData> {
    // SAFETY: the only reader of the cell, after the single store in
    // `discover_numa`.
    unsafe { (*EARLY_NUMA.get()).take() }
}

#[cfg(test)]
mod tests {
    use super::parse_madt_bytes;
    use super::walk_rsdt;
    use alloc::vec::Vec;

    /// A laptop's own firmware's MADT, captured once from
    /// `/sys/firmware/acpi/tables/APIC` and checked in under
    /// `fixtures/acpi/` (the recipe is its README).  Every other MADT this
    /// tree has ever parsed was QEMU's; this is the first one the parse runs
    /// on that no part of this tree produced.
    const REAL_MADT: &[u8] = include_bytes!("../../../fixtures/acpi/APIC");

    /// The real firmware's table, parsed whole.
    ///
    /// A Raptor Lake-P machine's MADT: 32 processor local APIC entries of
    /// which 12 are enabled — the enabled APIC IDs are the real hybrid
    /// topology (`0/1`, `8/9`, `16/17`, `24/25` are the SMT pairs, `40/42/`
    /// `44/46` the efficiency cores) and the other 20 are the disabled
    /// placeholders real firmware writes with APIC ID `0xff`.  QEMU's MADTs
    /// have neither placeholders nor this many entries, so a parse that
    /// mistook a placeholder for a processor, or stopped at the first entry
    /// type it did not know, would have gone unnoticed until a board.
    #[test]
    fn real_firmware_madt_parses() {
        let entries = parse_madt_bytes(REAL_MADT);

        assert_eq!(entries.len(), 32, "the table's processor entries, in order");

        let enabled: Vec<u8> = entries
            .iter()
            .filter(|entry| entry.enabled)
            .map(|entry| entry.apic_id)
            .collect();
        assert_eq!(
            enabled,
            [0, 1, 8, 9, 16, 17, 24, 25, 40, 42, 44, 46],
            "the enabled APIC IDs are the machine's real topology"
        );

        let disabled = entries.iter().filter(|entry| !entry.enabled).count();
        assert_eq!(disabled, 20, "the firmware's disabled placeholders");
        assert!(
            entries
                .iter()
                .filter(|entry| !entry.enabled)
                .all(|entry| entry.apic_id == 0xff),
            "every disabled placeholder carries the 0xff APIC ID"
        );
    }

    /// The real table carries entry types the processor arm does not know —
    /// an IOAPIC, two interrupt-source overrides, 24 NMI entries — and the
    /// walk has to step over each by its length exactly: a misstep lands
    /// mid-entry and every later parse is noise.  The last processor entry
    /// being the 32nd and the disabled ones still reading as `0xff` says the
    /// walk stayed on boundaries through all of them.
    #[test]
    fn the_walk_survives_entry_types_it_skips() {
        let entries = parse_madt_bytes(REAL_MADT);
        assert_eq!(entries.last().map(|entry| entry.apic_id), Some(0xff));
        // The processor IDs are contiguous 0..32 in the real table, which a
        // walk that misparsed an override as a processor would break.
        let processor_ids: Vec<u8> = entries
            .iter()
            .map(|entry| entry.acpi_processor_id)
            .collect();
        assert_eq!(processor_ids, (0..32).collect::<Vec<u8>>());
    }

    /// The RSDT walk, over a synthetic root whose entries are the captured
    /// firmware table, a decoy that spells `APIC` with a broken checksum, a
    /// candidate whose header declares a wild length, and a slot past the
    /// end of the space.
    ///
    /// The addressing is the point: the walk's `space` answers `(addr, len)`
    /// with the bytes at that *offset* in the test's buffer, so the whole
    /// walk — the root's bounds, the candidate gate, the signature, the
    /// checksum — runs on a host over the real table's own bytes.  The
    /// firmware's RSDT itself is small (six entries in the measured image),
    /// so a synthetic one costs nothing and lets the decoys exist.
    #[test]
    fn rsdt_walk_finds_the_valid_table_behind_a_decoy() {
        // Layout: root at 0x20, decoy at 0x200, wild-length candidate at
        // 0x400, the real table at 0x1000.
        const ROOT: usize = 0x20;
        const DECOY: usize = 0x200;
        const WILD: usize = 0x400;
        const REAL: usize = 0x1000;

        let real = REAL_MADT;
        let mut buf: Vec<u8> = alloc::vec![0u8; REAL + real.len()];

        // The decoy: the real table's bytes with its checksum field broken,
        // so it spells APIC and fails the sum.
        buf[DECOY..DECOY + real.len()].copy_from_slice(real);
        buf[DECOY + 9] = buf[DECOY + 9].wrapping_add(1);

        // The wild candidate: a header whose declared length is 4 GiB - 1.
        buf[WILD..WILD + 4].copy_from_slice(b"APIC");
        buf[WILD + 4..WILD + 8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        buf[WILD + 9] = 0; // make-believe checksum byte

        // The real table.
        buf[REAL..REAL + real.len()].copy_from_slice(real);

        // The root: four entries — the decoy, the wild candidate, a null
        // slot, and the real table.
        buf[ROOT..ROOT + 4].copy_from_slice(b"RSDT");
        // Four entries: 36-byte header plus 16 bytes of addresses.
        buf[ROOT + 4..ROOT + 8].copy_from_slice(&52u32.to_le_bytes());
        for (i, entry) in [DECOY as u32, WILD as u32, 0, REAL as u32]
            .iter()
            .enumerate()
        {
            let at = ROOT + 36 + i * 4;
            buf[at..at + 4].copy_from_slice(&entry.to_le_bytes());
        }

        let space =
            |addr: usize, len: usize| -> Option<&[u8]> { buf.get(addr..addr.checked_add(len)?) };
        let found = walk_rsdt(ROOT, b"APIC", &space);
        assert_eq!(
            found,
            Some(REAL),
            "the only candidate left standing is the one the firmware wrote"
        );
    }

    /// A root shorter than its own header is refused, not believed.
    ///
    /// A 32-bit length of 20 leaves `length - 36` underflowing to nearly
    /// `usize::MAX`, and an entry count derived from that is a walk off the
    /// end of every map — this is the branch that keeps a wild length a
    /// refusal rather than a fault.
    #[test]
    fn rsdt_walk_refuses_a_root_shorter_than_its_header() {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(b"RSDT");
        for length in [0u32, 20, 35] {
            buf[4..8].copy_from_slice(&length.to_le_bytes());
            let space = |addr: usize, len: usize| -> Option<&[u8]> { buf.get(addr..addr + len) };
            assert_eq!(
                walk_rsdt(0, b"APIC", &space),
                None,
                "a root of {length} bytes holds no entry array"
            );
        }
    }

    /// And a root that claims more than any real one is refused too — the
    /// same bound the candidates get, applied to the root itself.
    #[test]
    fn rsdt_walk_refuses_an_unbelievably_long_root() {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(b"RSDT");
        buf[4..8].copy_from_slice(&0x10_0001u32.to_le_bytes());
        let space = |addr: usize, len: usize| -> Option<&[u8]> { buf.get(addr..addr + len) };
        assert_eq!(walk_rsdt(0, b"APIC", &space), None);
    }

    /// A candidate whose bytes are not reachable at all — the entry points
    /// past the space the caller answers for — is stepped over, and the walk
    /// goes on to a later, valid entry.
    #[test]
    fn rsdt_walk_steps_over_an_unreachable_candidate() {
        const ROOT: usize = 0x20;
        const REAL: usize = 0x200;

        let real = REAL_MADT;
        let mut buf: Vec<u8> = alloc::vec![0u8; REAL + real.len()];
        buf[REAL..REAL + real.len()].copy_from_slice(real);

        buf[ROOT..ROOT + 4].copy_from_slice(b"RSDT");
        buf[ROOT + 4..ROOT + 8].copy_from_slice(&44u32.to_le_bytes());
        // One entry far outside the buffer, then the real table.
        buf[ROOT + 36..ROOT + 40].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        buf[ROOT + 40..ROOT + 44].copy_from_slice(&(REAL as u32).to_le_bytes());

        let space =
            |addr: usize, len: usize| -> Option<&[u8]> { buf.get(addr..addr.checked_add(len)?) };
        assert_eq!(walk_rsdt(ROOT, b"APIC", &space), Some(REAL));
    }

    /// Bytes that are not a table: short, truncated, or with an entry length
    /// that leaves the table.  None may panic, and none may read past its
    /// slice.
    #[test]
    fn malformed_madts_answer_nothing_and_never_panic() {
        // Shorter than a MADT header.
        assert!(parse_madt_bytes(&[]).is_empty());
        assert!(parse_madt_bytes(&[0u8; 43]).is_empty());
        // A header with a truncated entry: type 0, length 8, one byte
        // missing.
        let mut table = alloc::vec![0u8; 44];
        table[0..4].copy_from_slice(b"APIC");
        table.extend_from_slice(&[0, 8, 1, 2, 1, 0, 0]);
        assert!(parse_madt_bytes(&table).is_empty());
        // An entry length below the two header bytes stops the walk rather
        // than looping in place.
        let mut table = alloc::vec![0u8; 44];
        table[0..4].copy_from_slice(b"APIC");
        table.extend_from_slice(&[0, 1]);
        assert!(parse_madt_bytes(&table).is_empty());
        // An entry that claims to run past the table is dropped.
        let mut table = alloc::vec![0u8; 44];
        table[0..4].copy_from_slice(b"APIC");
        table.extend_from_slice(&[0, 255, 1, 2, 1, 0, 0, 0]);
        assert!(parse_madt_bytes(&table).is_empty());
    }
}
