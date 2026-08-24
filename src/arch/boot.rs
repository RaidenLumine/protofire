//! src/arch/boot.rs
//!
//! Architecture-neutral boot protocol and handoff descriptors.

use alloc::string::String;
use core::sync::atomic::{AtomicUsize, Ordering};

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

/// Parse the kernel command line from the Multiboot2 info structure.
///
/// Returns `None` if no boot handoff address is available or the command-line
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
        let total_size = unsafe { *(addr as *const u32) } as usize;
        let mut offset = 8;

        while offset + 8 <= total_size {
            let tag_type = unsafe { *((addr + offset) as *const u32) };
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

/// Parse the Multiboot2 memory-map tag and return total usable RAM in bytes.
///
/// Sums entries with `type == 1` (available RAM).  Returns `None` if no
/// memory-map tag is present or the handoff address is not set.
#[cfg(target_arch = "x86_64")]
pub fn multiboot2_memory_map() -> Option<usize> {
    let addr = handoff_address();
    if addr == 0 {
        return None;
    }

    let total_size = unsafe { *(addr as *const u32) } as usize;
    let mut offset = 8;
    let mut total_ram: usize = 0;

    while offset + 8 <= total_size {
        let tag_type = unsafe { *((addr + offset) as *const u32) };
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
            let entry_size = unsafe { *((addr + offset + 8) as *const u32) } as usize;
            if entry_size < 16 {
                break;
            }
            let _entry_version = unsafe { *((addr + offset + 12) as *const u32) };
            let entries_start = offset + 16;
            let entries_end = offset + tag_size;

            let mut entry_off = entries_start;
            while entry_off + entry_size <= entries_end {
                let _base = unsafe { *((addr + entry_off) as *const u64) };
                let length = unsafe { *((addr + entry_off + 8) as *const u64) };
                let entry_type = unsafe { *((addr + entry_off + 16) as *const u32) };

                if entry_type == MULTIBOOT2_MMAP_AVAILABLE {
                    total_ram = total_ram.saturating_add(length as usize);
                }

                entry_off += entry_size;
            }
            return Some(total_ram);
        }

        // Tags are 8-byte aligned.
        let aligned_size = (tag_size + 7) & !7;
        offset += aligned_size;
    }

    None
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
pub const fn from_x86_64_multiboot2(multiboot_magic: u32, multiboot_info: u32) -> BootInfo {
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
    use super::{current_architecture, BootInfo, BootProtocol};

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
}
