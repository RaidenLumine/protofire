//! src/arch/x86_64/acpi.rs
//!
//! The ACPI tables this architecture is told about at boot: the MADT, which
//! names the processors, and the SRAT/SLIT pair, which says how far apart they
//! and their memory are.
//!
//! Parsed through the RSDP that the boot hand-off carries, before the runtime
//! page tables replace the bootstrap identity map — the tables live at physical
//! addresses the identity map covers and the runtime map may not.

#[cfg(target_os = "none")]
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

#[cfg(target_os = "none")]
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

/// Parse the MADT and return a list of enabled local APIC entries.
#[cfg(target_os = "none")]
unsafe fn parse_madt(madt_addr: usize) -> Vec<LocalApicEntry> {
    let mut entries = Vec::new();

    // SAFETY: the MADT address comes from the RSDT walk, which read the table's
    // own header; the header is what this line reads, and it is mapped because
    // every ACPI table is in the identity-mapped region at boot.
    let header = unsafe { &*(madt_addr as *const Madt) };
    let table_end = madt_addr + header.header.length as usize;

    // Entries start right after the flags field.
    let mut offset = madt_addr + core::mem::size_of::<Madt>();

    while offset + 2 <= table_end {
        // SAFETY: the loop condition keeps two bytes from `offset`, and both
        // are inside the table because `offset + 2 <= table_end`.
        let entry_type = unsafe { read_phys_u8(offset) };
        // SAFETY: as above — the second of those two bytes.
        let entry_len = unsafe { read_phys_u8(offset + 1) } as usize;

        if entry_len < 2 || offset + entry_len > table_end {
            break;
        }

        match entry_type {
            0 if entry_len >= 8 => {
                // Processor Local APIC
                // SAFETY: the arm's `entry_len >= 8` guard says the entry
                // covers the six bytes read here, and the length check above
                // says the entry is inside the table.
                let acpi_processor_id = unsafe { read_phys_u8(offset + 2) };
                // SAFETY: as above.
                let apic_id = unsafe { read_phys_u8(offset + 3) };
                // SAFETY: as above — the flags pair is the last of the six
                // bytes the arm's guard covers.
                let flags = unsafe {
                    let lo = read_phys_u8(offset + 4) as u32;
                    let hi = read_phys_u8(offset + 5) as u32;
                    lo | (hi << 8)
                };
                let enabled = (flags & 0x1) != 0;
                entries.push(LocalApicEntry {
                    acpi_processor_id,
                    apic_id,
                    enabled,
                });
            }
            _ => {
                // Skip other entry types or entries that are too short.
            }
        }

        offset += entry_len;
    }

    entries
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

/// Search the RSDT for a table with the given 4-byte signature.
#[cfg(target_os = "none")]
unsafe fn find_table_in_rsdt(rsdt_addr: usize, signature: &[u8; 4]) -> Option<usize> {
    // SAFETY: the caller passes the RSDT address the RSDP named; its header is
    // the first structure in the table and the table is mapped at boot.
    let header = unsafe { &*(rsdt_addr as *const SdtHeader) };
    let entry_count = (header.length as usize - core::mem::size_of::<SdtHeader>()) / 4;
    let entry_base = rsdt_addr + core::mem::size_of::<SdtHeader>();

    for i in 0..entry_count {
        // SAFETY: `entry_count` is derived from the RSDT's own length, so index
        // `i` is inside the entry array the header describes.
        let table_addr = unsafe { read_phys_u32(entry_base + i * 4) } as usize;
        if table_addr == 0 {
            continue;
        }
        // SAFETY: the entry is a physical address of a table whose first
        // structure is an SDT header; the header is what is read here.
        let table_header = unsafe { &*(table_addr as *const SdtHeader) };
        if &table_header.signature == signature {
            // Verify checksum.
            // SAFETY: the checksum covers the table's own declared length,
            // starting at the table's first byte.
            let bytes = unsafe {
                core::slice::from_raw_parts(table_addr as *const u8, table_header.length as usize)
            };
            let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
            if sum == 0 {
                return Some(table_addr);
            }
        }
    }

    None
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
