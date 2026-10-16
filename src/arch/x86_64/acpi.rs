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

/// A MADT interrupt-source override (ACPI 6.x § 5.2.9, type 2): a statement
/// that an ISA IRQ does **not** reach the I/O APIC on the pin its number
/// suggests.
///
/// A machine that puts ISA IRQ 0 on GSI 2 — which every PC and QEMU's own
/// firmware does — says so here rather than by the IRQ number, so a kernel
/// that routes by IRQ number instead of by the override sends the timer to a
/// pin with nothing attached.  The flags carry the polarity and trigger mode
/// the ISA bus does not imply (a PCI link is level-triggered and active-low;
/// an ISA line is edge-triggered and active-high), which is why an override's
/// absence and its identity mapping are not the same statement.
#[cfg(any(target_os = "none", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptOverride {
    /// The bus the source IRQ is on: 0 is ISA.
    pub bus: u8,
    /// The bus-relative IRQ the override is about.
    pub source_irq: u8,
    /// The global system interrupt (I/O APIC pin) it reaches instead.
    pub gsi: u32,
    /// Bits 0-1 polarity (3 = active low), bits 2-3 trigger (1 = level).
    pub flags: u16,
}

/// Parse a MADT out of its own bytes and answer its interrupt-source
/// overrides.
///
/// Pure over the table's bytes so the parse is host-testable, the way
/// [`parse_madt_bytes`] is.  An entry is stepped over by its own length, so a
/// record type the walk does not read lands the next read on a boundary — the
/// same rule the processor walk follows.
#[cfg(any(target_os = "none", test))]
pub fn parse_madt_interrupt_overrides(table: &[u8]) -> Vec<InterruptOverride> {
    let mut overrides = Vec::new();
    if !(MADT_HEADER_BYTES..=MADT_MAX_BYTES).contains(&table.len()) {
        return overrides;
    }

    let mut offset = MADT_HEADER_BYTES;
    while offset + 2 <= table.len() {
        let entry_type = table[offset];
        let entry_len = table[offset + 1] as usize;
        if entry_len < 2 || offset + entry_len > table.len() {
            break;
        }
        if entry_type == 2 && entry_len >= 10 {
            overrides.push(InterruptOverride {
                bus: table[offset + 2],
                source_irq: table[offset + 3],
                gsi: le_u32(table, offset + 4),
                // The flags are a **16-bit** field at the record's tail, not a
                // word: reading four bytes here would take two from whatever
                // follows the entry.
                flags: u16::from_le_bytes([table[offset + 8], table[offset + 9]]),
            });
        }
        offset += entry_len;
    }

    overrides
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

/// Parse the interrupt-source overrides of the MADT at a physical address.
///
/// As [`parse_madt`]: the same table, bounded by its own declared length and
/// handed to the pure parser.
#[cfg(target_os = "none")]
unsafe fn parse_madt_interrupt_overrides_at(madt_addr: usize) -> Vec<InterruptOverride> {
    // SAFETY: the MADT address comes from the RSDT walk, which read the
    // table's own header; the length field's bytes are inside it.
    let length = unsafe { read_phys_u32(madt_addr + 4) } as usize;
    if !(MADT_HEADER_BYTES..=MADT_MAX_BYTES).contains(&length) {
        return Vec::new();
    }
    // SAFETY: as `parse_madt` — the declared length, capped, over the mapped
    // table the RSDT named.
    let table = unsafe { core::slice::from_raw_parts(madt_addr as *const u8, length) };
    parse_madt_interrupt_overrides(table)
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

    // The same table's interrupt-source overrides.  A machine that remaps an
    // ISA IRQ (QEMU's own firmware puts IRQ 0 on GSI 2) states it here, and
    // the IOAPIC setup reads these to route by GSI rather than by IRQ number.
    // SAFETY: `madt_addr` is the same checksum-verified table the parse above
    // read; the wrapper bounds the slice by the header's own length.
    let overrides = unsafe { parse_madt_interrupt_overrides_at(madt_addr) };
    if !overrides.is_empty() {
        crate::println!("[smp   ] {} interrupt-source override(s)", overrides.len());
    }
    store_early_interrupt_overrides(overrides);

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

// ── Early-discovered ISA IRQ overrides ─────────────────────────────────

/// The MADT interrupt-source overrides discovered before the page-table
/// switch, so the I/O APIC setup (which runs later) routes by the machine's
/// GSI map rather than by IRQ number.  See [`store_early_interrupt_overrides`]
/// and [`take_early_interrupt_overrides`].
#[cfg(target_os = "none")]
static EARLY_ISA_OVERRIDES: crate::util::sync_unsafe_cell::SyncUnsafeCell<
    Option<alloc::vec::Vec<InterruptOverride>>,
> = crate::util::sync_unsafe_cell::SyncUnsafeCell::new(None);

/// Store the interrupt-source overrides discovered during early boot.  Must be
/// called at most once, before any reader.
#[cfg(target_os = "none")]
pub fn store_early_interrupt_overrides(overrides: alloc::vec::Vec<InterruptOverride>) {
    // SAFETY: the doc above says this runs at most once, before any reader
    // (`take_early_interrupt_overrides`) exists; the cell has no other writer.
    unsafe {
        *EARLY_ISA_OVERRIDES.get() = Some(overrides);
    }
}

/// The global system interrupt a bus-relative ISA IRQ reaches, from a set of
/// overrides: the override's GSI when the machine gave one for bus 0, and the
/// IRQ number itself otherwise — the identity map a machine that names no
/// override is read as, which is what this driver assumed before overrides
/// existed.  Pure, so the choice is host-tested rather than only reachable
/// through a boot.
#[cfg(any(target_os = "none", test))]
pub fn isa_irq_gsi_from(overrides: &[InterruptOverride], irq: u8) -> u32 {
    overrides
        .iter()
        .find(|entry| entry.bus == 0 && entry.source_irq == irq)
        .map_or(u32::from(irq), |entry| entry.gsi)
}

/// The global system interrupt a bus-relative ISA IRQ reaches, from the stored
/// overrides — [`isa_irq_gsi_from`] over what the boot parsed.
#[cfg(target_os = "none")]
pub fn isa_irq_gsi(irq: u8) -> u32 {
    // SAFETY: the cell was written once at boot before this reader runs; the
    // read borrows it without taking it, so later reads answer too.
    let stored = unsafe { (*EARLY_ISA_OVERRIDES.get()).as_ref() };
    match stored {
        Some(overrides) => isa_irq_gsi_from(overrides, irq),
        None => u32::from(irq),
    }
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
/// Only compiled on x86_64 bare-metal where `discover_numa`/SRAT parsing runs,
/// and on a host for the parser tests.
#[cfg(any(target_os = "none", test))]
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
/// Only compiled on x86_64 bare-metal where `discover_numa`/SRAT parsing runs,
/// and on a host for the parser tests.
#[cfg(any(target_os = "none", test))]
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
/// Only compiled on x86_64 bare-metal where `discover_numa`/SRAT parsing runs,
/// and on a host for the parser tests.
#[cfg(any(target_os = "none", test))]
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

/// Bytes before a SRAT's entry list: an SDT header (36) plus its twelve
/// reserved bytes.
#[cfg(any(target_os = "none", test))]
const SRAT_ENTRIES_OFFSET: usize = 48;

/// The bound on a table's declared length, shared by the NUMA parsers.
///
/// A machine's SRAT is a few kilobytes — every processor and every usable
/// memory range — so a length past a megabyte is a length not to trust: the
/// bound exists to bound the slice, not to model a machine, which is the same
/// rule [`MADT_MAX_BYTES`] follows.
#[cfg(any(target_os = "none", test))]
const NUMA_TABLE_MAX_BYTES: usize = 0x10_0000;

/// Bytes before a SLIT's distance matrix: an SDT header (36) plus the
/// eight-byte locality count.
#[cfg(any(target_os = "none", test))]
const SLIT_MATRIX_OFFSET: usize = 44;

/// Little-endian readers over a table's own bytes: the pure parsers below use
/// these rather than the physical-address readers, which exist only on
/// bare-metal.
#[cfg(any(target_os = "none", test))]
fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[cfg(any(target_os = "none", test))]
fn le_u64(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

/// Parse an ACPI SRAT out of its own bytes and answer its affinity records.
///
/// Pure over the table's bytes so the parse is host-testable, the way
/// [`parse_madt_bytes`] is: a real board's SRAT is a table no QEMU machine
/// describes — several proximity domains, memory ranges at addresses a
/// `virt` machine has no reason to use, and entry types this kernel has no
/// name for sitting between the ones it reads.  An entry is skipped by its
/// own length, and an entry whose length would leave the table ends the walk,
/// which is what keeps a malformed table from steering the parse.
#[cfg(any(target_os = "none", test))]
pub fn parse_srat_bytes(
    table: &[u8],
) -> (Vec<CpuAffinity>, Vec<MemoryAffinity>, Vec<X2ApicAffinity>) {
    let mut cpu = Vec::new();
    let mut mem = Vec::new();
    let mut x2apic = Vec::new();
    if table.len() < SRAT_ENTRIES_OFFSET || table.len() > NUMA_TABLE_MAX_BYTES {
        return (cpu, mem, x2apic);
    }

    let mut offset = SRAT_ENTRIES_OFFSET;
    while offset + 2 <= table.len() {
        let entry_type = table[offset];
        let entry_len = table[offset + 1] as usize;
        if entry_len < 2 || offset + entry_len > table.len() {
            break;
        }

        match entry_type {
            0 if entry_len >= 16 => {
                // Processor Local APIC/SAPIC Affinity (16 bytes).  The
                // proximity domain is **split**: its low byte sits right after
                // the two-byte subtable header, its high three bytes after the
                // local SAPIC EID — the layout QEMU writes and the ACPI spec
                // states, and not a single 32-bit field.  This record's node id
                // is a `u8`, so the low byte is the whole of it for any machine
                // this kernel can name.
                let node_lo = table[offset + 2];
                let apic_id = table[offset + 3];
                let flags = le_u32(table, offset + 4);
                cpu.push(CpuAffinity {
                    enabled: (flags & 0x1) != 0,
                    apic_id,
                    node_id: node_lo,
                });
            }
            1 if entry_len >= 40 => {
                // Memory Affinity (40 bytes).
                let node_id = le_u32(table, offset + 2);
                let base_addr = le_u64(table, offset + 8);
                let length = le_u64(table, offset + 16);
                let flags = le_u32(table, offset + 28);
                mem.push(MemoryAffinity {
                    enabled: (flags & 0x1) != 0,
                    node_id,
                    base_addr,
                    length,
                });
            }
            2 if entry_len >= 24 => {
                // Processor Local x2APIC Affinity (24 bytes): a two-byte
                // reserved field after the subtable header, then the proximity
                // domain — the layout QEMU writes for a processor whose APIC ID
                // does not fit a byte.
                let node_id = le_u32(table, offset + 4);
                let x2apic_id = le_u32(table, offset + 8);
                let flags = le_u32(table, offset + 12);
                x2apic.push(X2ApicAffinity {
                    enabled: (flags & 0x1) != 0,
                    x2apic_id,
                    node_id,
                });
            }
            _ => {}
        }

        offset += entry_len;
    }

    (cpu, mem, x2apic)
}

/// Parse an ACPI SLIT out of its own bytes and answer its distance matrix.
///
/// Pure over the table's bytes for the same reason the SRAT parser is.  A
/// locality count that is zero, past the format's own maximum of 64, or whose
/// matrix does not fit the table is refused (`None`) rather than read past —
/// a malformed SLIT is a table to decline, not one to trust.
#[cfg(any(target_os = "none", test))]
pub fn parse_slit_bytes(table: &[u8]) -> Option<Vec<Vec<u8>>> {
    if table.len() < SLIT_MATRIX_OFFSET || table.len() > NUMA_TABLE_MAX_BYTES {
        return None;
    }
    let locality_count = le_u64(table, 36);
    if locality_count == 0 || locality_count > 64 {
        return None;
    }
    let locality_count = locality_count as usize;
    let matrix_offset = SLIT_MATRIX_OFFSET;
    let end = matrix_offset.checked_add(locality_count.checked_mul(locality_count)?)?;
    if end > table.len() {
        return None;
    }

    let mut matrix = Vec::with_capacity(locality_count);
    for i in 0..locality_count {
        let row = matrix_offset + i * locality_count;
        matrix.push(table[row..row + locality_count].to_vec());
    }
    Some(matrix)
}

/// Parse the ACPI SRAT at a physical address and return the affinity records.
///
/// The address comes from the RSDT walk, which read the table's own header;
/// the table is mapped because every ACPI table is in the identity-mapped
/// region at boot.  The wrapper bounds the slice by the header's own length —
/// capped, because a firmware that lies about it must not describe a slice
/// past the mapping — and hands it to [`parse_srat_bytes`].
#[cfg(target_os = "none")]
unsafe fn parse_srat(
    srat_addr: usize,
) -> (Vec<CpuAffinity>, Vec<MemoryAffinity>, Vec<X2ApicAffinity>) {
    // SAFETY: `srat_addr` is a table the RSDT named and whose checksum was
    // verified; byte 4 of an SDT header is the length field's first byte.
    let length = unsafe { read_phys_u32(srat_addr + 4) } as usize;
    if !(SRAT_ENTRIES_OFFSET..=NUMA_TABLE_MAX_BYTES).contains(&length) {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    // SAFETY: `length` is the length the table's own header declares, bounded
    // above by `NUMA_TABLE_MAX_BYTES`, and the table is the mapped range the
    // RSDT named — so the slice covers exactly that table.  Nothing writes
    // through it, and ACPI tables are never written by software.
    let table = unsafe { core::slice::from_raw_parts(srat_addr as *const u8, length) };
    parse_srat_bytes(table)
}

/// Parse the ACPI SLIT at a physical address and return its distance matrix.
///
/// As [`parse_srat`]: a bounded slice over the mapped table, handed to the
/// pure parser.
#[cfg(target_os = "none")]
unsafe fn parse_slit(slit_addr: usize) -> Option<Vec<Vec<u8>>> {
    // SAFETY: `slit_addr` is a table the RSDT named and whose checksum was
    // verified; the length field's bytes are inside it.
    let length = unsafe { read_phys_u32(slit_addr + 4) } as usize;
    if !(SLIT_MATRIX_OFFSET..=NUMA_TABLE_MAX_BYTES).contains(&length) {
        return None;
    }
    // SAFETY: as for the SRAT — the declared length, capped, over the mapped
    // table the RSDT named.
    let table = unsafe { core::slice::from_raw_parts(slit_addr as *const u8, length) };
    parse_slit_bytes(table)
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

    /// Build a SRAT whose bytes are exactly what **QEMU** writes, so the
    /// parser is held against the layout a machine produces rather than
    /// against one this tree invented.
    ///
    /// The subtable offsets are the ones `hw/i386/acpi-build.c`'s
    /// `build_srat` appends (ACPI 6.x § 5.2.16): a type-0 record puts the
    /// proximity domain's low byte at +2, the APIC ID at +3 and a 32-bit
    /// flags word at +4; a type-2 record has two reserved bytes, the domain at
    /// +4, the x2APIC ID at +8 and flags at +12.  A parser that read the
    /// domain as one 32-bit field, or the APIC ID at the record's tail, would
    /// pass on a table this tree built and fail on every real machine — which
    /// is what the field-offset defect here was.
    fn qemu_srat() -> alloc::vec::Vec<u8> {
        let mut table = alloc::vec![0u8; 48]; // 36-byte SDT header + 12 reserved
        table[0..4].copy_from_slice(b"SRAT");
        // Two processors on node 0 (a type-0 record each): APIC IDs 0 and 1.
        for apic_id in [0u8, 1u8] {
            table.push(0); // type 0
            table.push(16); // length
            table.push(0); // proximity domain low
            table.push(apic_id);
            table.extend_from_slice(&1u32.to_le_bytes()); // flags: enabled
            table.push(0); // local SAPIC EID
            table.extend_from_slice(&[0, 0, 0]); // proximity domain high
            table.extend_from_slice(&0u32.to_le_bytes()); // reserved
        }
        // And two on node 1: one more type-0 record, and a type-2 record for
        // an APIC ID past a byte (QEMU's split), so both layouts are covered.
        table.push(0);
        table.push(16);
        table.push(1); // node 1
        table.push(2);
        table.extend_from_slice(&1u32.to_le_bytes());
        table.push(0);
        table.extend_from_slice(&[0, 0, 0]);
        table.extend_from_slice(&0u32.to_le_bytes());
        table.push(2); // type 2
        table.push(24);
        table.extend_from_slice(&0u16.to_le_bytes()); // reserved
        table.extend_from_slice(&1u32.to_le_bytes()); // node 1
        table.extend_from_slice(&300u32.to_le_bytes()); // x2APIC ID
        table.extend_from_slice(&1u32.to_le_bytes()); // enabled
        table.extend_from_slice(&0u32.to_le_bytes()); // clock domain
        table.extend_from_slice(&0u32.to_le_bytes()); // reserved
                                                      // One memory range: node 1 owns [1 GiB, 2 GiB).
        table.push(1); // type 1
        table.push(40);
        table.extend_from_slice(&1u32.to_le_bytes()); // node 1
        table.extend_from_slice(&0u16.to_le_bytes()); // reserved
        table.extend_from_slice(&(1u64 << 30).to_le_bytes()); // base
        table.extend_from_slice(&(1u64 << 30).to_le_bytes()); // length
        table.extend_from_slice(&0u32.to_le_bytes()); // reserved
        table.extend_from_slice(&1u32.to_le_bytes()); // enabled
        table.extend_from_slice(&0u64.to_le_bytes()); // reserved
        table
    }

    /// The CPU affinity records are read at the offsets a real machine writes.
    ///
    /// This is the gate the field-offset defect needed: with the domain read
    /// as one 32-bit field and the APIC ID from the record's tail, every
    /// QEMU-emitted type-0 record parsed as APIC ID 0 and flags 0 — so the
    /// boot saw no enabled processor on any node and a two-node machine
    /// collapsed to one, silently, because no gate asserted the node count.
    #[test]
    fn srat_cpu_affinities_are_read_at_the_offsets_qemu_writes() {
        let (cpu, mem, x2apic) = super::parse_srat_bytes(&qemu_srat());

        let got: Vec<(bool, u8, u8)> = cpu
            .iter()
            .map(|aff| (aff.enabled, aff.apic_id, aff.node_id))
            .collect();
        assert_eq!(
            got,
            [(true, 0, 0), (true, 1, 0), (true, 2, 1)],
            "each type-0 record's enabled flag, APIC ID and node, in order"
        );
        assert_eq!(
            x2apic.len(),
            1,
            "the type-2 record a processor past a byte needs"
        );
        assert!(x2apic[0].enabled);
        assert_eq!(x2apic[0].x2apic_id, 300, "the x2APIC ID at its own offset");
        assert_eq!(x2apic[0].node_id, 1, "and the domain at its own offset");
        assert_eq!(mem.len(), 1);
        assert_eq!(mem[0].node_id, 1);
        assert_eq!(mem[0].base_addr, 1 << 30);
        assert_eq!(mem[0].length, 1 << 30);
        assert!(mem[0].enabled);
    }

    /// A malformed SRAT is declined rather than read past: a truncated table,
    /// an entry length that leaves the table, and an entry below the two
    /// header bytes each stop the walk with what was read so far.
    #[test]
    fn a_malformed_srat_stops_the_walk_rather_than_reading_past() {
        assert!(super::parse_srat_bytes(&[]).0.is_empty());
        assert!(super::parse_srat_bytes(&[0u8; 47]).0.is_empty());

        let mut truncated = alloc::vec![0u8; 48];
        truncated[0..4].copy_from_slice(b"SRAT");
        truncated.extend_from_slice(&[0, 16, 0, 5, 1, 0, 0, 0]); // one byte short
        assert!(super::parse_srat_bytes(&truncated).0.is_empty());

        let mut overrun = alloc::vec![0u8; 48];
        overrun[0..4].copy_from_slice(b"SRAT");
        overrun.extend_from_slice(&[0, 200, 0, 5, 1, 0, 0, 0]);
        assert!(super::parse_srat_bytes(&overrun).0.is_empty());

        // An entry length below the header size must not loop in place.
        let mut tiny = alloc::vec![0u8; 48];
        tiny[0..4].copy_from_slice(b"SRAT");
        tiny.extend_from_slice(&[0, 1]);
        assert!(super::parse_srat_bytes(&tiny).0.is_empty());
    }

    /// The SLIT's distance matrix is read by row, and a locality count whose
    /// matrix does not fit — or is zero or past the format's maximum — is
    /// declined rather than read past.
    #[test]
    fn a_slit_matrix_reads_by_row_and_a_lying_count_is_declined() {
        let mut slit = alloc::vec![0u8; 44]; // 36-byte header + 8-byte count
        slit[0..4].copy_from_slice(b"SLIT");
        slit[36..44].copy_from_slice(&2u64.to_le_bytes());
        slit.extend_from_slice(&[10, 20, 20, 10]); // row-major 2x2
        assert_eq!(
            super::parse_slit_bytes(&slit),
            Some(alloc::vec![alloc::vec![10, 20], alloc::vec![20, 10]])
        );

        // A count of 3 whose matrix is only 4 bytes long is refused.
        let mut lying = alloc::vec![0u8; 44];
        lying[0..4].copy_from_slice(b"SLIT");
        lying[36..44].copy_from_slice(&3u64.to_le_bytes());
        lying.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(super::parse_slit_bytes(&lying), None);

        // Zero localities, and a count past the format's maximum of 64.
        let mut zero = alloc::vec![0u8; 44];
        zero[0..4].copy_from_slice(b"SLIT");
        assert_eq!(super::parse_slit_bytes(&zero), None);
        let mut huge = alloc::vec![0u8; 44];
        huge[0..4].copy_from_slice(b"SLIT");
        huge[36..44].copy_from_slice(&65u64.to_le_bytes());
        assert_eq!(super::parse_slit_bytes(&huge), None);
    }

    /// The interrupt-source overrides are read from the table's own bytes at
    /// the offsets a real machine writes, and the ISA IRQ 0 -> GSI 2 remap
    /// every PC states is answered.
    ///
    /// This is the gate for the defect that prompted the parser: routing by
    /// IRQ number instead of by the override sends the timer to a pin with
    /// nothing on it on every machine that remaps IRQ 0 — which every PC and
    /// both of QEMU's x86 machines do.  The record is built the way the ACPI
    /// spec and QEMU's MADT builder lay it out: type 2, length 10, the bus,
    /// the source IRQ, a 32-bit GSI, and a two-byte flags field.
    #[test]
    fn madt_interrupt_overrides_are_read_at_their_offsets() {
        let mut table = alloc::vec![0u8; 44]; // MADT header: 36 + 4 + 4
        table[0..4].copy_from_slice(b"APIC");
        // The canonical PC remap: ISA IRQ 0 reaches GSI 2.
        table.push(2);
        table.push(10);
        table.push(0); // bus 0 (ISA)
        table.push(0); // source IRQ 0
        table.extend_from_slice(&2u32.to_le_bytes()); // GSI 2
        table.extend_from_slice(&0u16.to_le_bytes()); // flags: edge, active high
                                                      // A PCI link: IRQ 9 on GSI 9, level-triggered active-low (flags 0xd).
        table.push(2);
        table.push(10);
        table.push(0);
        table.push(9);
        table.extend_from_slice(&9u32.to_le_bytes());
        table.extend_from_slice(&0x000du16.to_le_bytes());

        let overrides = super::parse_madt_interrupt_overrides(&table);
        assert_eq!(overrides.len(), 2);
        assert_eq!(
            (overrides[0].bus, overrides[0].source_irq, overrides[0].gsi),
            (0, 0, 2),
            "ISA IRQ 0 reaches GSI 2, not pin 0"
        );
        assert_eq!(overrides[0].flags, 0x0000);
        assert_eq!(
            (
                overrides[1].source_irq,
                overrides[1].gsi,
                overrides[1].flags
            ),
            (9, 9, 0x000d),
            "a level-triggered active-low PCI link keeps its flags"
        );
    }

    /// The walk steps over the entry types between overrides by their own
    /// length, and a malformed override does not steer the parse: the captured
    /// laptop MADT has two overrides among 24 NMI entries and two IOAPICs, and
    /// a walk that mis-stepped would land mid-entry.
    #[test]
    fn madt_interrupt_overrides_walk_real_layouts() {
        let overrides = super::parse_madt_interrupt_overrides(REAL_MADT);
        // The captured table's two overrides, ISA IRQ 0 -> GSI 2 and IRQ 9 ->
        // GSI 9, read out of a walk that crossed 32 processors, an IOAPIC and
        // 24 NMI entries to reach them.
        assert_eq!(
            overrides
                .iter()
                .map(|o| (o.bus, o.source_irq, o.gsi))
                .collect::<Vec<_>>(),
            [(0, 0, 2), (0, 9, 9)],
            "the real firmware's two overrides, in order"
        );

        // A table with no overrides answers none, and a truncated one is
        // declined rather than read past.
        assert!(super::parse_madt_interrupt_overrides(&[0u8; 43]).is_empty());
        let mut truncated = alloc::vec![0u8; 44];
        truncated.extend_from_slice(&[2, 10, 0, 0, 2, 0, 0, 0]); // one byte short
        assert!(super::parse_madt_interrupt_overrides(&truncated).is_empty());
    }

    /// The GSI a route uses is the override's when the machine gave one and
    /// the IRQ number otherwise: a machine that remaps IRQ 0 to GSI 2 must not
    /// have the timer routed to pin 0, and one that names no override keeps
    /// the identity map it had before overrides were read.
    #[test]
    fn a_route_uses_the_machines_gsi_or_the_identity_map() {
        let overrides = alloc::vec![
            super::InterruptOverride {
                bus: 0,
                source_irq: 0,
                gsi: 2,
                flags: 0,
            },
            super::InterruptOverride {
                bus: 0,
                source_irq: 9,
                gsi: 9,
                flags: 0xd,
            },
        ];
        assert_eq!(super::isa_irq_gsi_from(&overrides, 0), 2, "IRQ 0 -> GSI 2");
        assert_eq!(super::isa_irq_gsi_from(&overrides, 9), 9);
        assert_eq!(
            super::isa_irq_gsi_from(&overrides, 1),
            1,
            "an IRQ the machine did not remap keeps its own number"
        );
        assert_eq!(
            super::isa_irq_gsi_from(&[], 0),
            0,
            "no overrides is the identity map"
        );
    }
}
