//! src/arch/boot.rs
//!
//! Architecture-neutral boot protocol and handoff descriptors.

use alloc::string::String;
#[cfg(target_arch = "x86_64")]
use alloc::vec::Vec;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// Stores the Multiboot2 info address (or equivalent) for later use by SMP
/// bring-up and other late-boot subsystems.
static BOOT_HANDOFF_ADDR: AtomicUsize = AtomicUsize::new(0);

/// Store the boot handoff address.  Called once during early boot.
pub fn store_handoff_address(addr: usize) {
    BOOT_HANDOFF_ADDR.store(addr, Ordering::Release);
}

/// Retrieve the stored boot handoff address, or 0 if not set.
pub fn handoff_address() -> usize {
    BOOT_HANDOFF_ADDR.load(Ordering::Acquire)
}

// Multiboot2 tag types.
#[cfg(target_arch = "x86_64")]
const MULTIBOOT2_TAG_END: u32 = 0;
#[cfg(target_arch = "x86_64")]
const MULTIBOOT2_TAG_CMDLINE: u32 = 1;
#[cfg(target_arch = "x86_64")]
const MULTIBOOT2_TAG_MMAP: u32 = 6;

/// Memory-map entry type: available RAM.
#[cfg(target_arch = "x86_64")]
/// The tag a loader that set a graphics mode passes.
#[cfg(target_arch = "x86_64")]
const MULTIBOOT2_TAG_FRAMEBUFFER: u32 = 8;

/// Parse the kernel command line from the Multiboot2 info structure.
///
/// Returns `None` if no boot handoff address is available or the command-line
/// The command line the loader passed, read while its block was reachable.
///
/// x86_64's runtime page tables do not map the loader's info block — the
/// bootstrap identity map did — so a read of it after the switch faults.  The
/// boot captures the command line in `capture_early_state`, which runs while
/// the bootstrap map is still active, and the late caller reads this copy
/// ([RFC 0019](../../docs/rfcs/0019-what-a-frame-is.md)'s boot, where a real
/// loader and its info block first existed).
static BOOT_COMMAND_LINE: crate::kernel::sync::SpinLock<Option<String>> =
    crate::kernel::sync::SpinLock::new(None);

/// The framebuffer the loader described, captured while its block was
/// reachable — the same rule the command line follows, for the same reason:
/// x86_64's runtime tables do not map the loader's block, so it is read once,
/// early, and never again.
static LOADER_FRAMEBUFFER: crate::kernel::sync::SpinLock<Option<LoaderFramebuffer>> =
    crate::kernel::sync::SpinLock::new(None);

/// Record the loader's framebuffer, once, before its block becomes
/// unreachable.
pub fn store_framebuffer(framebuffer: Option<LoaderFramebuffer>) {
    *LOADER_FRAMEBUFFER.lock() = framebuffer;
}

/// The loader's framebuffer, as captured at boot.
pub fn loader_framebuffer() -> Option<LoaderFramebuffer> {
    *LOADER_FRAMEBUFFER.lock()
}

/// Record the command line, once, before the info block becomes unreachable.
pub fn store_command_line(line: Option<String>) {
    *BOOT_COMMAND_LINE.lock() = line;
}

/// The command line the loader passed, as captured at boot.
pub fn boot_command_line() -> Option<String> {
    BOOT_COMMAND_LINE.lock().clone()
}

/// The command line from the Multiboot2 tag block, if there is one.
///
/// Returns `None` when no boot hand-off address is available or the tag is not
/// present in the Multiboot2 info.
///
/// On non-x86_64 architectures the handoff address holds a device-tree blob
/// (aarch64/riscv64 QEMU direct boot) rather than a Multiboot2 info structure,
/// so this function always returns `None` there.
pub fn multiboot2_command_line() -> Option<String> {
    // Multiboot2 is x86_64-specific.  On aarch64/riscv64 QEMU direct boot
    // the handoff address is a device-tree blob, not a Multiboot2 header.
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }

    #[cfg(target_arch = "x86_64")]
    {
        let addr = handoff_address();
        if addr == 0 {
            return None;
        }

        // Multiboot2 info structure starts with total_size (u32) and reserved (u32).
        // Tags follow immediately after the 8-byte header.
        // SAFETY: the bootloader hands over a Multiboot2 info structure, and
        // its first word is `total_size`; every read below is bounded by that
        // size, starting with the loop condition on the line after this.
        let total_size = unsafe { *(addr as *const u32) } as usize;
        let mut offset = 8;

        while offset + 8 <= total_size {
            // SAFETY: the loop condition keeps `offset + 8` within
            // `total_size`, so this word and the size word after it are inside
            // the structure.
            let tag_type = unsafe { *((addr + offset) as *const u32) };
            // SAFETY: as the tag-type read above — the same eight bytes the
            // loop condition bounds cover both words.
            let tag_size = unsafe { *((addr + offset + 4) as *const u32) } as usize;

            if tag_type == MULTIBOOT2_TAG_END {
                break;
            }

            if tag_size < 8 {
                break; // malformed tag
            }

            if tag_type == MULTIBOOT2_TAG_CMDLINE {
                // Command line is a NUL-terminated string after the tag header.
                let string_ptr = (addr + offset + 8) as *const u8;
                let max_len = tag_size.saturating_sub(8);
                let mut cmdline = String::new();
                for i in 0..max_len {
                    // SAFETY: the byte loop is bounded by `max_len`, which is
                    // `tag_size` minus the tag header, so it stays inside the
                    // string tag.
                    let byte = unsafe { *string_ptr.add(i) };
                    if byte == 0 {
                        break;
                    }
                    cmdline.push(byte as char);
                }
                return Some(cmdline);
            }

            // Tags are 8-byte aligned.
            let aligned_size = (tag_size + 7) & !7;
            offset += aligned_size;
        }

        None
    }
}

/// One memory region a Multiboot2 map describes.
///
/// The **kind** is the map's own word about the memory — the format's types —
/// and it is kept because a correct map reserves the memory the loader loaded
/// the image into, so "inside a region" and "inside an *available* region" are
/// different questions ([RFC
/// 0020](../../docs/rfcs/0020-what-the-memory-map-may-refuse-on.md)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base: usize,
    pub length: usize,
    /// The Multiboot2 type: 1 available, 2 reserved, 3 ACPI reclaimable,
    /// 4 preserved across hibernation, 5 defective.
    pub kind: u32,
}

impl MemoryRegion {
    pub const fn end(&self) -> usize {
        self.base.saturating_add(self.length)
    }
}

/// The format's first type: RAM free for the taking.
pub const MEMORY_REGION_AVAILABLE: u32 = 1;
/// Memory the firmware or the loader keeps.  A kernel image lives here.
pub const MEMORY_REGION_RESERVED: u32 = 2;
/// The format's worst type: memory the firmware has declared broken.
pub const MEMORY_REGION_DEFECTIVE: u32 = 5;

/// The machine's memory, as a Multiboot2 memory map describes it: one entry per
/// range the map has, with the kind it gives it.
///
/// The hand-off address is a parameter rather than a read of the global so that
/// a test can drive this walk over a tag block it built
/// ([RFC 0019](../../docs/rfcs/0019-what-a-frame-is.md));
/// [`multiboot2_usable_regions`] is the wrapper that reads what the loader
/// recorded.  `None` means the machine described no map at all, which is not
/// the same as describing an empty one.
#[cfg(target_arch = "x86_64")]
pub fn multiboot2_memory_regions_at(addr: usize) -> Option<Vec<MemoryRegion>> {
    if addr == 0 {
        return None;
    }

    // SAFETY: the first word of the hand-off structure, as in the parse above;
    // the loop condition bounds every later read by it.
    let total_size = unsafe { *(addr as *const u32) } as usize;
    let mut offset = 8;
    let mut regions: Vec<MemoryRegion> = Vec::new();

    while offset + 8 <= total_size {
        // SAFETY: bounded by the loop condition above, as in the first pass
        // over these tags.
        let tag_type = unsafe { *((addr + offset) as *const u32) };
        // SAFETY: as the tag-type read — both words are inside the eight bytes
        // the loop condition bounds.
        let tag_size = unsafe { *((addr + offset + 4) as *const u32) } as usize;

        if tag_type == MULTIBOOT2_TAG_END {
            break;
        }

        if tag_size < 8 {
            break;
        }

        if tag_type == MULTIBOOT2_TAG_MMAP {
            // The mmap tag has: type(4) + size(4) + entry_size(4) + entry_version(4)
            // followed by at least one entry.
            if tag_size < 16 {
                break;
            }
            // SAFETY: `tag_size` was checked to be at least 16 above, so this
            // word and the entry-version word after it are inside the
            // memory-map tag.
            let entry_size = unsafe { *((addr + offset + 8) as *const u32) } as usize;
            // An entry carries `base_addr`, `length`, `type`, and a reserved
            // word — 24 bytes of fields, which is what the reads below cover.
            // A bootloader that claims a smaller entry is refused rather than
            // trusted: the tag is bounded, so the type read would otherwise
            // take bytes from whatever follows.
            if entry_size < 24 {
                break;
            }
            // SAFETY: the loop the comment above describes has already bounded the entry,
            // so this reads the entry's version word inside the tag.
            let _entry_version = unsafe { *((addr + offset + 12) as *const u32) };

            let entries_start = offset + 16;
            let entries_end = offset + tag_size;

            let mut entry_off = entries_start;
            while entry_off + entry_size <= entries_end {
                // SAFETY: `entry_off + entry_size` is still inside the tag (the loop
                // condition), so each word below is a byte of the blob.
                let base = unsafe { *((addr + entry_off) as *const u64) };
                // SAFETY: as above — the length word of the same entry.
                let length = unsafe { *((addr + entry_off + 8) as *const u64) };
                // SAFETY: as above — the type word of the same entry.
                let entry_type = unsafe { *((addr + entry_off + 16) as *const u32) };

                if length > 0 {
                    regions.push(MemoryRegion {
                        base: base as usize,
                        length: length as usize,
                        kind: entry_type,
                    });
                }

                entry_off += entry_size;
            }
            return Some(regions);
        }

        // Tags are 8-byte aligned.
        let aligned_size = (tag_size + 7) & !7;
        offset += aligned_size;
    }

    None
}

// ── The PVH hand-off ────────────────────────────────────────────────────
//
// A direct QEMU boot on the PC (`-kernel`, the PVH protocol) hands over a
// different block through the same entry symbol: Xen's `hvm_start_info`,
// which *does* describe the machine's memory — as an E820-shaped table the
// struct points at — and whose fields are emphatically not Multiboot2 tags.
// It is kept in a slot of its own for that reason: the tag readers (the
// command line, the framebuffer, ACPI's RSDP lookup) read the Multiboot2
// slot, and only the memory-map walk reads this one ([RFC
// 0020](../../docs/rfcs/0020-what-the-memory-map-may-refuse-on.md): reading
// the wrong block as tags is the defect that put a framebuffer over bytes
// that were never a display).

/// The magic a PVH start-of-day block begins with (Xen's `hvm_start_info`).
#[cfg(target_arch = "x86_64")]
const PVH_START_MAGIC: u32 = 0x336e_c578;

/// Fields past `cmdline_paddr` — the RSDP, the memory map — exist only from
/// this version of the struct on.
#[cfg(target_arch = "x86_64")]
const PVH_MMAP_VERSION: u32 = 1;

/// One memory-map entry: address, size, type and a word Xen reserves, which
/// is E820's shape — and E820's *types*, deliberately: 1 available, 2
/// reserved, 3 ACPI, 4 NVS, 5 unusable.  The kinds pass through unchanged.
#[cfg(target_arch = "x86_64")]
const PVH_MEMMAP_ENTRY_SIZE: usize = 24;

/// The most entries this walk will read from a loader's table.
///
/// The struct gives a count and no length, so the count is the only bound
/// there is; a number past this one is a block this kernel refuses rather
/// than walks.  Real tables are two orders of magnitude smaller (QEMU writes
/// nine entries on `q35`).
#[cfg(target_arch = "x86_64")]
const PVH_MEMMAP_MAX_ENTRIES: usize = 128;

/// How much of the machine the bootstrap identity map covers.
///
/// `boot.asm` builds 512 two-megabyte entries before Rust runs, and the
/// loader's own block is read through that map — the runtime tables do not
/// map it, which is why the command line and the framebuffer are captured
/// before the switch.  An address outside this window cannot be read at all,
/// so this is what turns a wild hand-off into "the machine described
/// nothing" instead of a fault with no console behind it.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn bootstrap_map_limit() -> usize {
    1 << 30
}

/// A host build has no identity map: a test drives these walks over blocks in
/// its own address space, where nothing bounds them but the blocks.  The
/// limit is "everything", and it is a value rather than a constant so the
/// comparison reads the same in both builds.
#[cfg(all(target_arch = "x86_64", not(target_os = "none")))]
fn bootstrap_map_limit() -> usize {
    usize::MAX
}

/// The PVH `hvm_start_info` block the loader handed over, if it handed one.
///
/// Stored apart from [`handoff_address`] because it is not a tag block: the
/// readers of *that* address walk Multiboot2 tags, and this struct's first
/// word happens to be a magic rather than a total size — a walk over it is
/// how a framebuffer ends up reading bytes that were never a display.
///
/// x86_64-only, like everything that reads or writes it: the other machines'
/// hand-off is a device-tree blob, and there is no such block for them to
/// store or ask about.
#[cfg(target_arch = "x86_64")]
static PVH_START_INFO: AtomicUsize = AtomicUsize::new(0);

/// Record the PVH block, once, from the entry path that recognised it.
#[cfg(target_arch = "x86_64")]
pub fn store_pvh_start_info(addr: usize) {
    PVH_START_INFO.store(addr, Ordering::Release);
}

/// The PVH block's address, or 0 when the loader did not hand one over.
#[cfg(target_arch = "x86_64")]
pub fn pvh_start_info_address() -> usize {
    PVH_START_INFO.load(Ordering::Acquire)
}

/// The machine's memory, as a PVH start-of-day block describes it.
///
/// The block points at an E820-shaped table (`memmap_paddr`, `memmap_entries`)
/// whose types are E820's, so the regions come out in the same shape the
/// Multiboot2 walk answers with and the memory layer asks one question
/// ([RFC 0019](../../docs/rfcs/0019-what-a-frame-is.md)).
///
/// `None` means this block is not a start-of-day block, is too old to carry a
/// map, or carries one too long to trust — all of which are "the machine
/// described nothing" rather than a guess.
#[cfg(target_arch = "x86_64")]
pub fn pvh_memory_regions_at(addr: usize) -> Option<Vec<MemoryRegion>> {
    // A block outside the bootstrap map cannot be read; a pointer the loader
    // left behind is not one to fault on.
    if addr == 0 || addr >= bootstrap_map_limit() {
        return None;
    }

    // SAFETY: `addr` is inside the bootstrap identity map, which covers the
    // first gigabyte while the boot runs; the struct is read as the fixed
    // record Xen defines, and the two fields below are read only after the
    // version says they exist.
    let magic = unsafe { *(addr as *const u32) };
    if magic != PVH_START_MAGIC {
        return None;
    }
    // SAFETY: the version word is the second word of the same struct.
    let version = unsafe { *((addr + 4) as *const u32) };
    if version < PVH_MMAP_VERSION {
        return None;
    }
    // SAFETY: from version 1 on, `memmap_paddr` and `memmap_entries` are
    // present at their fixed offsets.
    let memmap_paddr = unsafe { *((addr + 0x28) as *const u64) } as usize;
    // SAFETY: as above — the count word of the same field pair.
    let entries = unsafe { *((addr + 0x30) as *const u32) } as usize;

    if memmap_paddr == 0 || entries == 0 || entries > PVH_MEMMAP_MAX_ENTRIES {
        return None;
    }
    // The table must be readable through the same map as the struct it comes
    // from: a table that runs past the window is not one to walk.
    let table_bytes = entries.checked_mul(PVH_MEMMAP_ENTRY_SIZE)?;
    if memmap_paddr.checked_add(table_bytes)? > bootstrap_map_limit() {
        return None;
    }

    let mut regions: Vec<MemoryRegion> = Vec::new();
    for index in 0..entries {
        let entry = memmap_paddr + index * PVH_MEMMAP_ENTRY_SIZE;
        // SAFETY: every byte read below lies inside `entries` records of
        // `PVH_MEMMAP_ENTRY_SIZE`, and the bound above checked that whole
        // range against the map this code runs under.
        let base = unsafe { *(entry as *const u64) };
        // SAFETY: as above — the size word of the same entry.
        let length = unsafe { *((entry + 8) as *const u64) };
        // SAFETY: as above — the type word of the same entry.
        let kind = unsafe { *((entry + 16) as *const u32) };

        if length > 0 {
            regions.push(MemoryRegion {
                base: base as usize,
                length: length as usize,
                kind,
            });
        }
    }

    Some(regions)
}

/// The PVH block's memory map, read from the address the entry path stored.
#[cfg(target_arch = "x86_64")]
pub fn pvh_memory_regions() -> Option<Vec<MemoryRegion>> {
    pvh_memory_regions_at(pvh_start_info_address())
}

/// The linear framebuffer a loader handed over, as its tag describes it.
///
/// A loader that set a graphics mode passes the mode it set — address, pitch,
/// size and depth — which is the one framebuffer on a machine this kernel did
/// not have to switch on itself: a real PC's display comes from the firmware,
/// and until this tag was read the only framebuffers this tree knew how to use
/// were the ones its own device drivers (virtio-gpu, bochs-display) owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoaderFramebuffer {
    /// Where the framebuffer is, in the machine's own address space.
    pub address: usize,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bits_per_pixel: u8,
    /// The format's own kind byte: 1 is a direct RGB colour framebuffer.
    pub kind: u8,
}

/// The framebuffer tag of a Multiboot2 map, if it has one.
///
/// The address is a parameter for the same reason the memory map's is: a test
/// drives the walk over a block it built.
#[cfg(target_arch = "x86_64")]
pub fn multiboot2_framebuffer_at(addr: usize) -> Option<LoaderFramebuffer> {
    if addr == 0 {
        return None;
    }

    // SAFETY: the first word of the hand-off structure, as in the walks above;
    // the loop condition bounds every later read by it.
    let total_size = unsafe { *(addr as *const u32) } as usize;
    let mut offset = 8;

    while offset + 8 <= total_size {
        // SAFETY: the loop condition keeps these two words inside the block.
        let tag_type = unsafe { *((addr + offset) as *const u32) };
        // SAFETY: as above — the tag's size word.
        let tag_size = unsafe { *((addr + offset + 4) as *const u32) } as usize;

        if tag_type == MULTIBOOT2_TAG_END {
            break;
        }
        if tag_size < 8 {
            break;
        }

        if tag_type == MULTIBOOT2_TAG_FRAMEBUFFER {
            // The tag is a fixed 32 bytes: the address, the pitch, the two
            // dimensions, the depth, the kind and a reserved word.
            if tag_size < 32 {
                break;
            }
            // SAFETY: `tag_size` was checked to be at least the tag's own
            // fields, so every read below is inside the block's tag.
            let address = unsafe { *((addr + offset + 8) as *const u64) } as usize;
            // SAFETY: as above — the pitch word of the same tag.
            let pitch = unsafe { *((addr + offset + 16) as *const u32) };
            // SAFETY: as above — the width word of the same tag.
            let width = unsafe { *((addr + offset + 20) as *const u32) };
            // SAFETY: as above — the height word of the same tag.
            let height = unsafe { *((addr + offset + 24) as *const u32) };
            // SAFETY: as above — the depth byte of the same tag.
            let bits_per_pixel = unsafe { *((addr + offset + 28) as *const u8) };
            // SAFETY: as above — the kind byte of the same tag.
            let kind = unsafe { *((addr + offset + 29) as *const u8) };
            if address == 0 || pitch == 0 || width == 0 || height == 0 {
                return None;
            }
            return Some(LoaderFramebuffer {
                address,
                pitch,
                width,
                height,
                bits_per_pixel,
                kind,
            });
        }

        offset += (tag_size + 7) & !7;
    }

    None
}

/// The framebuffer the loader described, read from the block it handed over.
#[cfg(target_arch = "x86_64")]
pub fn multiboot2_framebuffer() -> Option<LoaderFramebuffer> {
    multiboot2_framebuffer_at(handoff_address())
}

/// The memory regions a Multiboot2 map describes, from the block the loader
/// handed over.
#[cfg(target_arch = "x86_64")]
pub fn multiboot2_memory_regions() -> Option<Vec<MemoryRegion>> {
    multiboot2_memory_regions_at(handoff_address())
}

/// The RAM a map calls available, in bytes.
///
/// This is the number the boot reports as the machine's own; everything else a
/// map describes is memory that is not free for the taking, which is why the
/// regions above carry their kind rather than being filtered here.
#[cfg(target_arch = "x86_64")]
pub fn available_bytes(regions: &[MemoryRegion]) -> usize {
    regions
        .iter()
        .filter(|region| region.kind == MEMORY_REGION_AVAILABLE)
        .fold(0usize, |total, region| total.saturating_add(region.length))
}

/// Parse the Multiboot2 memory-map tag and return total usable RAM in bytes.
///
/// Sums the entries [`multiboot2_usable_regions`] answers with.  Returns `None`
/// if no memory-map tag is present or the hand-off address is not set.
#[cfg(target_arch = "x86_64")]
pub fn multiboot2_memory_map() -> Option<usize> {
    let regions = multiboot2_memory_regions()?;
    Some(available_bytes(&regions))
}

/// Extract the `init=<path>` value from a kernel command line.
///
/// Returns the init path if found, otherwise returns `default_path`.
pub fn init_path_from_command_line<'a>(command_line: &'a str, default_path: &'a str) -> &'a str {
    for token in command_line.split_whitespace() {
        if let Some(path) = token.strip_prefix("init=") {
            if !path.is_empty() {
                return path;
            }
        }
    }
    default_path
}

/// Boot protocol tags recognized by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootProtocol {
    Unknown,    // Unknown boot protocol
    Multiboot2, // Multiboot2 boot protocol (used by GRUB)
    QemuDirect, // Direct QEMU boot (for aarch64)
}

impl BootProtocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Multiboot2 => "multiboot2",
            Self::QemuDirect => "qemu-direct",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInfo {
    architecture: &'static str,
    protocol: BootProtocol,
    loader_magic: u32,
    handoff_address: usize,
}

impl BootInfo {
    pub const fn new(
        architecture: &'static str,
        protocol: BootProtocol,
        loader_magic: u32,
        handoff_address: usize,
    ) -> Self {
        Self {
            architecture,
            protocol,
            loader_magic,
            handoff_address,
        }
    }

    pub const fn architecture(self) -> &'static str {
        self.architecture
    }

    pub const fn protocol(self) -> BootProtocol {
        self.protocol
    }

    pub const fn loader_magic(self) -> u32 {
        self.loader_magic
    }

    pub const fn handoff_address(self) -> usize {
        self.handoff_address
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CURRENT_ARCHITECTURE: &str = "x86_64";

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const CURRENT_ARCHITECTURE: &str = "aarch64";

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
const CURRENT_ARCHITECTURE: &str = "riscv64";

#[cfg(not(target_os = "none"))]
const CURRENT_ARCHITECTURE: &str = "host";

pub const fn current_architecture() -> &'static str {
    CURRENT_ARCHITECTURE
}

#[cfg(all(
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ),
    target_os = "none"
))]
const fn current_arch_boot_info(
    protocol: BootProtocol,
    loader_magic: u32,
    handoff_address: usize,
) -> BootInfo {
    BootInfo::new(
        current_architecture(),
        protocol,
        loader_magic,
        handoff_address,
    )
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const MULTIBOOT2_BOOT_MAGIC: u32 = 0x36D7_6289;

/// The PC's hand-off, whichever of the two it is.
///
/// The same entry symbol serves both: a Multiboot2 loader leaves its magic and
/// a tag block, and a direct QEMU boot (the PVH protocol) leaves theirs — a
/// pointer to **Xen's start_info**, whose fields are not tags at all.  So the
/// magic decides what the block is, and **only a Multiboot2 block is recorded
/// as the one to read tags from**: a boot that stores the other one hands every
/// reader — the memory map, the command line, the framebuffer, and the ACPI
/// discovery that looks for the RSDP in a tag before falling back to a BIOS
/// scan — a struct that merely looks like tags, and a framebuffer read out of
/// bytes that mean something else is a range mapped and drawn on that was never
/// a display ([RFC
/// 0020](../../docs/rfcs/0020-what-the-memory-map-may-refuse-on.md):
/// this is the defect that made the x86_64 runtime gate's shell die in ring 3
/// while every Multiboot2 boot was fine).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn from_x86_64_multiboot2(multiboot_magic: u32, multiboot_info: u32) -> BootInfo {
    let multiboot2 = multiboot_magic == MULTIBOOT2_BOOT_MAGIC;
    if multiboot2 {
        store_handoff_address(multiboot_info as usize);
    } else if multiboot_info != 0 {
        // The other hand-off this entry serves is PVH's: `%ebx` points at
        // Xen's `hvm_start_info`, which describes the machine's memory and
        // whose fields are not tags.  It goes in its own slot so that a tag
        // reader cannot be handed it ([the comment on `store_handoff_address`'s
        // readers above](Self::from_x86_64_multiboot2)); the walk that reads
        // it checks the magic before trusting a byte of it.
        store_pvh_start_info(multiboot_info as usize);
    }
    current_arch_boot_info(
        if multiboot2 {
            BootProtocol::Multiboot2
        } else {
            BootProtocol::QemuDirect
        },
        multiboot_magic,
        multiboot_info as usize,
    )
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub const fn from_aarch64_qemu_direct(device_tree_blob: usize) -> BootInfo {
    current_arch_boot_info(BootProtocol::QemuDirect, 0, device_tree_blob)
}

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub const fn from_riscv64_qemu_direct(device_tree_blob: usize) -> BootInfo {
    current_arch_boot_info(BootProtocol::QemuDirect, 0, device_tree_blob)
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use alloc::vec;
    #[cfg(target_arch = "x86_64")]
    use alloc::vec::Vec;

    #[cfg(target_arch = "x86_64")]
    use super::available_bytes;
    use super::current_architecture;
    #[cfg(target_arch = "x86_64")]
    use super::multiboot2_framebuffer_at;
    #[cfg(target_arch = "x86_64")]
    use super::multiboot2_memory_regions_at;
    #[cfg(target_arch = "x86_64")]
    use super::pvh_memory_regions_at;
    use super::BootInfo;
    use super::BootProtocol;
    #[cfg(target_arch = "x86_64")]
    use super::LoaderFramebuffer;
    #[cfg(target_arch = "x86_64")]
    use super::MemoryRegion;
    #[cfg(target_arch = "x86_64")]
    use super::MEMORY_REGION_AVAILABLE;
    #[cfg(target_arch = "x86_64")]
    use super::MEMORY_REGION_RESERVED;
    #[cfg(target_arch = "x86_64")]
    use super::PVH_MEMMAP_MAX_ENTRIES;
    #[cfg(target_arch = "x86_64")]
    use super::PVH_MMAP_VERSION;

    #[test]
    fn boot_protocol_labels_are_stable() {
        assert_eq!(BootProtocol::Unknown.as_str(), "unknown");
        assert_eq!(BootProtocol::Multiboot2.as_str(), "multiboot2");
        assert_eq!(BootProtocol::QemuDirect.as_str(), "qemu-direct");
    }

    #[test]
    fn boot_info_accessors_preserve_constructor_fields() {
        let info = BootInfo::new("host", BootProtocol::Unknown, 0x36d7_6289, 0x1234_5678);

        assert_eq!(info.architecture(), "host");
        assert_eq!(info.protocol(), BootProtocol::Unknown);
        assert_eq!(info.loader_magic(), 0x36d7_6289);
        assert_eq!(info.handoff_address(), 0x1234_5678);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn current_architecture_reports_host_for_host_targets() {
        assert_eq!(current_architecture(), "host");
    }

    /// The Multiboot2 walk, over a block built the way the protocol lays one
    /// out: the header, one memory-map tag, and the entries in it.  The
    /// answer is the regions the machine calls usable
    /// ([RFC 0019](../../docs/rfcs/0019-what-a-frame-is.md)); an entry that is
    /// reserved is not one of them.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_multiboot_map_answers_the_regions_it_calls_usable() {
        let entries: [(u64, u64, u32); 3] = [
            (0x1000, 0x9_f000, 1),
            (0x10_0000, 0x1000_0000, 1),
            (0x2000_0000, 0x1000, 2),
        ];
        let tag_size = 16 + entries.len() * 24;
        let total = 8 + tag_size + 8;

        let mut block: Vec<u8> = Vec::new();
        block.extend_from_slice(&(total as u32).to_le_bytes());
        block.extend_from_slice(&0_u32.to_le_bytes());
        block.extend_from_slice(&6_u32.to_le_bytes());
        block.extend_from_slice(&(tag_size as u32).to_le_bytes());
        block.extend_from_slice(&24_u32.to_le_bytes());
        block.extend_from_slice(&0_u32.to_le_bytes());
        for (base, length, kind) in entries {
            block.extend_from_slice(&base.to_le_bytes());
            block.extend_from_slice(&length.to_le_bytes());
            block.extend_from_slice(&kind.to_le_bytes());
            block.extend_from_slice(&0_u32.to_le_bytes());
        }
        block.extend_from_slice(&0_u32.to_le_bytes());
        block.extend_from_slice(&8_u32.to_le_bytes());

        let at = block.as_ptr() as usize;
        let regions = multiboot2_memory_regions_at(at).expect("a map");
        assert_eq!(
            regions,
            vec![
                MemoryRegion {
                    base: 0x1000,
                    length: 0x9_f000,
                    kind: MEMORY_REGION_AVAILABLE,
                },
                MemoryRegion {
                    base: 0x10_0000,
                    length: 0x1000_0000,
                    kind: MEMORY_REGION_AVAILABLE,
                },
                MemoryRegion {
                    base: 0x2000_0000,
                    length: 0x1000,
                    kind: MEMORY_REGION_RESERVED,
                },
            ],
            "every entry the map has, with the kind it gives it"
        );
        assert_eq!(
            available_bytes(&regions),
            0x9_f000 + 0x1000_0000,
            "only the available entry counts as the machine's RAM"
        );
        assert_eq!(
            multiboot2_memory_regions_at(0),
            None,
            "no hand-off address is no map, which is not an empty one"
        );
    }

    /// The framebuffer tag: the mode a loader set, which is the only display a
    /// machine with no driver of this kernel's own has ([RFC
    /// 0019](../../docs/rfcs/0019-what-a-frame-is.md)'s list, first item).
    ///
    /// The parser's job is to say what the loader said — including the kinds
    /// the console does not draw in, which the *caller* refuses — and to say
    /// nothing about a block that does not carry the tag.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_loader_framebuffer_answers_the_mode_it_set() {
        // type(4) size(4) address(8) pitch(4) width(4) height(4) bpp(1) kind(1)
        // reserved(2)
        fn block(address: u64, pitch: u32, width: u32, height: u32, bpp: u8, kind: u8) -> Vec<u8> {
            let tag_size = 32usize;
            let total = 8 + tag_size + 8;
            let mut block: Vec<u8> = Vec::new();
            block.extend_from_slice(&(total as u32).to_le_bytes());
            block.extend_from_slice(&0_u32.to_le_bytes());
            block.extend_from_slice(&8_u32.to_le_bytes());
            block.extend_from_slice(&(tag_size as u32).to_le_bytes());
            block.extend_from_slice(&address.to_le_bytes());
            block.extend_from_slice(&pitch.to_le_bytes());
            block.extend_from_slice(&width.to_le_bytes());
            block.extend_from_slice(&height.to_le_bytes());
            block.push(bpp);
            block.push(kind);
            block.extend_from_slice(&0_u16.to_le_bytes());
            block.extend_from_slice(&0_u32.to_le_bytes());
            block.extend_from_slice(&8_u32.to_le_bytes());
            block
        }

        let graphics = block(0x8000_0000, 4096, 1024, 768, 32, 1);
        let at = graphics.as_ptr() as usize;
        assert_eq!(
            multiboot2_framebuffer_at(at),
            Some(LoaderFramebuffer {
                address: 0x8000_0000,
                pitch: 4096,
                width: 1024,
                height: 768,
                bits_per_pixel: 32,
                kind: 1,
            })
        );

        // A text mode is answered too, and by its own kind: what the loader set
        // is the parser's to report, and the console's to refuse.
        let text = block(0x000b_8000, 160, 80, 25, 16, 2);
        assert_eq!(
            multiboot2_framebuffer_at(text.as_ptr() as usize).map(|fb| fb.kind),
            Some(2)
        );

        // No address, no framebuffer: a loader that described a mode of nothing
        // described nothing.
        let empty = block(0, 4096, 1024, 768, 32, 1);
        assert_eq!(multiboot2_framebuffer_at(empty.as_ptr() as usize), None);

        // And a block with no tag at all, or no block, answers nothing.
        assert_eq!(multiboot2_framebuffer_at(0), None);
        let mut bare: Vec<u8> = Vec::new();
        bare.extend_from_slice(&8_u32.to_le_bytes());
        assert_eq!(multiboot2_framebuffer_at(bare.as_ptr() as usize), None);
    }

    /// A total size the block does not have bounds every read: the walk stops
    /// rather than reading whatever follows.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_truncated_map_answers_nothing() {
        let mut block: Vec<u8> = Vec::new();
        block.extend_from_slice(&8_u32.to_le_bytes());
        let at = block.as_ptr() as usize;
        assert_eq!(multiboot2_memory_regions_at(at), None);
    }

    /// The PVH walk, over a block built the way QEMU lays one out: Xen's
    /// `hvm_start_info` (magic, version, and the field pair that points at
    /// the map) followed by an E820-shaped table.
    ///
    /// The answer is the same shape the Multiboot2 walk gives — the map's own
    /// types, in the order the machine wrote them — because the memory layer
    /// asks one question of either protocol ([RFC
    /// 0019](../../docs/rfcs/0019-what-a-frame-is.md)).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_pvh_start_of_day_block_answers_its_memory_map() {
        // The entries QEMU writes on `q35` with 1 GiB: low RAM available, two
        // reserved holes, RAM again above 1 MiB, and a reserved hole where the
        // 32-bit device window is.
        fn block(version: u32) -> Vec<u8> {
            let entries: [(u64, u64, u32); 4] = [
                (0x0, 0x9_fc00, 1),
                (0x9_fc00, 0x400, 2),
                (0x10_0000, 0x3ff0_0000, 1),
                (0xb000_0000, 0x1000_0000, 2),
            ];

            let mut block: Vec<u8> = Vec::with_capacity(0x38 + entries.len() * 24);
            block.extend_from_slice(&0x336e_c578_u32.to_le_bytes()); // magic
            block.extend_from_slice(&version.to_le_bytes()); // version
            block.extend_from_slice(&0_u32.to_le_bytes()); // flags
            block.extend_from_slice(&0_u32.to_le_bytes()); // nr_modules
            block.extend_from_slice(&0_u64.to_le_bytes()); // modlist_paddr
            block.extend_from_slice(&0_u64.to_le_bytes()); // cmdline_paddr
            block.extend_from_slice(&0_u64.to_le_bytes()); // rsdp_paddr
                                                           // The table lives right after the 0x38-byte struct; the two
                                                           // halves of the pointer are written once the buffer stops moving.
            let memmap_paddr_offset = block.len();
            block.extend_from_slice(&0_u64.to_le_bytes());
            block.extend_from_slice(&(entries.len() as u32).to_le_bytes());
            block.extend_from_slice(&0_u32.to_le_bytes()); // reserved
            assert_eq!(memmap_paddr_offset, 0x28, "the field pair's offset");
            assert_eq!(block.len(), 0x38, "the struct's size");

            for (base, length, kind) in entries {
                block.extend_from_slice(&base.to_le_bytes());
                block.extend_from_slice(&length.to_le_bytes());
                block.extend_from_slice(&kind.to_le_bytes());
                block.extend_from_slice(&0_u32.to_le_bytes()); // reserved
            }

            let table = block.as_ptr() as usize + 0x38;
            block[memmap_paddr_offset..memmap_paddr_offset + 8]
                .copy_from_slice(&(table as u64).to_le_bytes());
            block
        }

        let built = block(PVH_MMAP_VERSION);
        let regions = pvh_memory_regions_at(built.as_ptr() as usize).expect("a map");
        assert_eq!(
            regions,
            vec![
                MemoryRegion {
                    base: 0x0,
                    length: 0x9_fc00,
                    kind: MEMORY_REGION_AVAILABLE,
                },
                MemoryRegion {
                    base: 0x9_fc00,
                    length: 0x400,
                    kind: MEMORY_REGION_RESERVED,
                },
                MemoryRegion {
                    base: 0x10_0000,
                    length: 0x3ff0_0000,
                    kind: MEMORY_REGION_AVAILABLE,
                },
                MemoryRegion {
                    base: 0xb000_0000,
                    length: 0x1000_0000,
                    kind: MEMORY_REGION_RESERVED,
                },
            ],
            "the PVH table's entries, with the kinds it gives them"
        );
        assert_eq!(
            available_bytes(&regions),
            0x9_fc00 + 0x3ff0_0000,
            "the same count the Multiboot2 walk would give for this machine"
        );

        // A struct older than the map field pair answers nothing: the bytes
        // after `rsdp_paddr` are not a pointer on a version-0 block.
        let mut old = block(0);
        old.truncate(0x38);
        assert_eq!(pvh_memory_regions_at(old.as_ptr() as usize), None);

        // A block that is not one — another protocol's hand-off, a null
        // pointer — answers nothing rather than being read.
        let mut foreign: Vec<u8> = Vec::new();
        foreign.extend_from_slice(&8_u32.to_le_bytes());
        assert_eq!(pvh_memory_regions_at(foreign.as_ptr() as usize), None);
        assert_eq!(pvh_memory_regions_at(0), None);

        // And a map longer than the walk will trust is refused whole: the
        // struct gives a count and no length, so the count is the only bound
        // there is, and a wild one is not a map to read.
        let mut wild = block(PVH_MMAP_VERSION);
        wild[0x30..0x34].copy_from_slice(&((PVH_MEMMAP_MAX_ENTRIES + 1) as u32).to_le_bytes());
        assert_eq!(pvh_memory_regions_at(wild.as_ptr() as usize), None);
    }
}
