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
const MULTIBOOT2_MMAP_AVAILABLE: u32 = 1;
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

/// tag is not present in the Multiboot2 info.
///
/// On non-x86_64 architectures the handoff address holds a device-tree blob
/// (aarch64/riscv64 QEMU direct boot) rather than a Multiboot2 info structure,
/// so this function always returns `None`.
pub fn multiboot2_command_line() -> Option<String> {
    // Multiboot2 is x86_64-specific.  On aarch64/riscv64 QEMU direct boot
    // the handoff address is a device-tree blob, not a Multiboot2 header.
    #[cfg(not(target_arch = "x86_64"))]
    {
        // PVH direct boot (magic=0) does not provide a Multiboot2 memory map.
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

/// The machine's usable RAM, as a Multiboot2 memory map describes it: one
/// `(base, length)` per entry whose type says the region is available.
///
/// The hand-off address is a parameter rather than a read of the global so that
/// a test can drive this walk over a tag block it built
/// ([RFC 0019](../../docs/rfcs/0019-what-a-frame-is.md));
/// [`multiboot2_usable_regions`] is the wrapper that reads what the loader
/// recorded.  `None` means the machine described no map at all, which is not
/// the same as describing an empty one.
#[cfg(target_arch = "x86_64")]
pub fn multiboot2_usable_regions_at(addr: usize) -> Option<Vec<(usize, usize)>> {
    if addr == 0 {
        return None;
    }

    // SAFETY: the first word of the hand-off structure, as in the parse above;
    // the loop condition bounds every later read by it.
    let total_size = unsafe { *(addr as *const u32) } as usize;
    let mut offset = 8;
    let mut regions: Vec<(usize, usize)> = Vec::new();

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

                if entry_type == MULTIBOOT2_MMAP_AVAILABLE && length > 0 {
                    regions.push((base as usize, length as usize));
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

/// The machine's usable RAM, from the block the loader handed over.
#[cfg(target_arch = "x86_64")]
pub fn multiboot2_usable_regions() -> Option<Vec<(usize, usize)>> {
    multiboot2_usable_regions_at(handoff_address())
}

/// Parse the Multiboot2 memory-map tag and return total usable RAM in bytes.
///
/// Sums the entries [`multiboot2_usable_regions`] answers with.  Returns `None`
/// if no memory-map tag is present or the hand-off address is not set.
#[cfg(target_arch = "x86_64")]
pub fn multiboot2_memory_map() -> Option<usize> {
    let regions = multiboot2_usable_regions()?;
    Some(
        regions
            .iter()
            .fold(0usize, |total, (_, length)| total.saturating_add(*length)),
    )
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
pub fn from_x86_64_multiboot2(multiboot_magic: u32, multiboot_info: u32) -> BootInfo {
    // The loader's info block is recorded here, the way the device-tree
    // machines record their blob: everything that reads a Multiboot2 tag —
    // the memory map, `multiboot2_usable_regions`, and the ACPI discovery that
    // looks for the RSDP in a tag before falling back to a BIOS scan — reads
    // it through `handoff_address`, and on x86_64 nothing had ever stored it.
    // ACPI's BIOS scan covered the loss, which is why it went unnoticed
    // ([RFC 0019](../../docs/rfcs/0019-what-a-frame-is.md)).
    store_handoff_address(multiboot_info as usize);
    current_arch_boot_info(
        BootProtocol::Multiboot2,
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

    use super::current_architecture;
    #[cfg(target_arch = "x86_64")]
    use super::multiboot2_usable_regions_at;
    use super::BootInfo;
    use super::BootProtocol;

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
        assert_eq!(
            multiboot2_usable_regions_at(at),
            Some(vec![(0x1000, 0x9_f000), (0x10_0000, 0x1000_0000)]),
            "the reserved entry is not a region to place a kernel in"
        );
        assert_eq!(
            multiboot2_usable_regions_at(0),
            None,
            "no hand-off address is no map, which is not an empty one"
        );
    }

    /// A total size the block does not have bounds every read: the walk stops
    /// rather than reading whatever follows.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_truncated_map_answers_nothing() {
        let mut block: Vec<u8> = Vec::new();
        block.extend_from_slice(&8_u32.to_le_bytes());
        let at = block.as_ptr() as usize;
        assert_eq!(multiboot2_usable_regions_at(at), None);
    }
}
