//! src/kernel/device.rs
//!
//! Shared virtual-device registry that keeps names, paths, access masks, I/O dispatch, and devfs visibility in one place.

use alloc::string::String;

use crate::kernel::{
    console,
    drivers::{keyboard, serial},
    fs::{DirectoryEntry, FileMetadata, NodeKind},
    process::{HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE},
};
use crate::util::debug;
use crate::{Error, Result};

pub const CONSOLE_DEVICE_NAME: &str = "console";
pub const DEBUG_DEVICE_NAME: &str = "debug";
pub const KEYBOARD_DEVICE_NAME: &str = "keyboard";
pub const KEYBOARD_RAW_DEVICE_NAME: &str = "keyboard-raw";
pub const NULL_DEVICE_NAME: &str = "null";
pub const SERIAL0_DEVICE_NAME: &str = "serial0";
pub const ZERO_DEVICE_NAME: &str = "zero";

pub const CONSOLE_DEVICE_PATH: &str = "/system/dev/console";
pub const DEBUG_DEVICE_PATH: &str = "/system/dev/debug";
pub const STDIN_DEVICE_PATH: &str = "/system/dev/stdin";
pub const STDOUT_DEVICE_PATH: &str = "/system/dev/stdout";
pub const STDERR_DEVICE_PATH: &str = "/system/dev/stderr";
pub const KEYBOARD_DEVICE_PATH: &str = "/system/dev/keyboard";
pub const KEYBOARD_RAW_DEVICE_PATH: &str = "/system/dev/keyboard-raw";
pub const NULL_DEVICE_PATH: &str = "/system/dev/null";
pub const SERIAL0_DEVICE_PATH: &str = "/system/dev/serial0";
pub const ZERO_DEVICE_PATH: &str = "/system/dev/zero";
pub const VIRTUAL_DEVICE_DIRECTORY_PATH: &str = "/system/dev";

type DeviceReadHandler = fn(&mut [u8], u64) -> Result<usize>;
type DeviceWriteHandler = fn(&[u8]) -> Result<usize>;

#[derive(Debug, Clone, Copy)]
pub struct DeviceDescriptor {
    pub name: &'static str,
    pub supported_rights: u32,
    read: DeviceReadHandler,
    write: DeviceWriteHandler,
    stat_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualDeviceNode {
    pub full_path: &'static str,
    pub mount_path: &'static str,
    pub target_name: &'static str,
    alias_supported_rights: Option<u32>,
    visible_in_directory: bool,
}

impl DeviceDescriptor {
    pub fn metadata(self) -> FileMetadata {
        FileMetadata::new(NodeKind::Device, self.stat_size)
    }

    pub fn read(self, buffer: &mut [u8], timeout_ticks: u64) -> Result<usize> {
        (self.read)(buffer, timeout_ticks)
    }

    pub fn write(self, buffer: &[u8]) -> Result<usize> {
        (self.write)(buffer)
    }
}

impl VirtualDeviceNode {
    pub fn supported_rights(self) -> u32 {
        self.alias_supported_rights
            .unwrap_or_else(|| supported_device_rights(self.target_name).unwrap_or(0))
    }

    pub fn metadata(self) -> FileMetadata {
        device_metadata(self.target_name).unwrap_or_else(default_device_metadata)
    }

    pub const fn visible_in_directory(self) -> bool {
        self.visible_in_directory
    }

    fn directory_entry_name(self) -> &'static str {
        self.mount_path.strip_prefix('/').unwrap_or(self.mount_path)
    }

    fn directory_entry(self) -> Option<DirectoryEntry> {
        if !self.visible_in_directory {
            return None;
        }

        let metadata = self.metadata();
        Some(DirectoryEntry::new(
            metadata.kind,
            metadata.size,
            String::from(self.directory_entry_name()),
        ))
    }
}

const DEVICE_DESCRIPTORS: [DeviceDescriptor; 7] = [
    DeviceDescriptor {
        name: CONSOLE_DEVICE_NAME,
        supported_rights: HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        read: read_console_bytes,
        write: write_console_bytes,
        stat_size: 0,
    },
    DeviceDescriptor {
        name: DEBUG_DEVICE_NAME,
        supported_rights: HANDLE_RIGHT_WRITE,
        read: unsupported_device_read,
        write: write_debug_bytes,
        stat_size: 0,
    },
    DeviceDescriptor {
        name: KEYBOARD_DEVICE_NAME,
        supported_rights: HANDLE_RIGHT_READ,
        read: read_keyboard_char_bytes,
        write: unsupported_device_write,
        stat_size: 0,
    },
    DeviceDescriptor {
        name: KEYBOARD_RAW_DEVICE_NAME,
        supported_rights: HANDLE_RIGHT_READ,
        read: read_keyboard_scancode_bytes,
        write: unsupported_device_write,
        stat_size: 0,
    },
    DeviceDescriptor {
        name: NULL_DEVICE_NAME,
        supported_rights: HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        read: read_null_bytes,
        write: write_discard_bytes,
        stat_size: 0,
    },
    DeviceDescriptor {
        name: SERIAL0_DEVICE_NAME,
        supported_rights: HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        read: read_serial_bytes,
        write: write_serial_bytes,
        stat_size: 0,
    },
    DeviceDescriptor {
        name: ZERO_DEVICE_NAME,
        supported_rights: HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        read: read_zero_bytes,
        write: write_accept_bytes,
        stat_size: 0,
    },
];

const VIRTUAL_DEVICE_NODES: [VirtualDeviceNode; 10] = [
    VirtualDeviceNode {
        full_path: CONSOLE_DEVICE_PATH,
        mount_path: "/console",
        target_name: CONSOLE_DEVICE_NAME,
        alias_supported_rights: None,
        visible_in_directory: true,
    },
    VirtualDeviceNode {
        full_path: DEBUG_DEVICE_PATH,
        mount_path: "/debug",
        target_name: DEBUG_DEVICE_NAME,
        alias_supported_rights: None,
        visible_in_directory: true,
    },
    VirtualDeviceNode {
        full_path: KEYBOARD_DEVICE_PATH,
        mount_path: "/keyboard",
        target_name: KEYBOARD_DEVICE_NAME,
        alias_supported_rights: None,
        visible_in_directory: true,
    },
    VirtualDeviceNode {
        full_path: KEYBOARD_RAW_DEVICE_PATH,
        mount_path: "/keyboard-raw",
        target_name: KEYBOARD_RAW_DEVICE_NAME,
        alias_supported_rights: None,
        visible_in_directory: true,
    },
    VirtualDeviceNode {
        full_path: NULL_DEVICE_PATH,
        mount_path: "/null",
        target_name: NULL_DEVICE_NAME,
        alias_supported_rights: None,
        visible_in_directory: true,
    },
    VirtualDeviceNode {
        full_path: SERIAL0_DEVICE_PATH,
        mount_path: "/serial0",
        target_name: SERIAL0_DEVICE_NAME,
        alias_supported_rights: None,
        visible_in_directory: true,
    },
    VirtualDeviceNode {
        full_path: STDERR_DEVICE_PATH,
        mount_path: "/stderr",
        target_name: DEBUG_DEVICE_NAME,
        alias_supported_rights: Some(HANDLE_RIGHT_WRITE),
        visible_in_directory: true,
    },
    VirtualDeviceNode {
        full_path: STDIN_DEVICE_PATH,
        mount_path: "/stdin",
        target_name: CONSOLE_DEVICE_NAME,
        alias_supported_rights: Some(HANDLE_RIGHT_READ),
        visible_in_directory: true,
    },
    VirtualDeviceNode {
        full_path: STDOUT_DEVICE_PATH,
        mount_path: "/stdout",
        target_name: DEBUG_DEVICE_NAME,
        alias_supported_rights: Some(HANDLE_RIGHT_WRITE),
        visible_in_directory: true,
    },
    VirtualDeviceNode {
        full_path: ZERO_DEVICE_PATH,
        mount_path: "/zero",
        target_name: ZERO_DEVICE_NAME,
        alias_supported_rights: None,
        visible_in_directory: true,
    },
];

fn unsupported_device_read(_buffer: &mut [u8], _timeout_ticks: u64) -> Result<usize> {
    Err(Error::Unsupported)
}

fn unsupported_device_write(_buffer: &[u8]) -> Result<usize> {
    Err(Error::Unsupported)
}

fn default_device_metadata() -> FileMetadata {
    FileMetadata::new(NodeKind::Device, 0)
}

fn read_console_bytes(buffer: &mut [u8], timeout_ticks: u64) -> Result<usize> {
    console::init_global()
        .read_bytes_timeout(buffer, timeout_ticks)
        .ok_or(Error::TimedOut)
}

fn write_console_bytes(buffer: &[u8]) -> Result<usize> {
    Ok(console::write_bytes(buffer))
}

fn write_debug_bytes(buffer: &[u8]) -> Result<usize> {
    debug::write_bytes(buffer);
    Ok(buffer.len())
}

fn read_keyboard_char_bytes(buffer: &mut [u8], timeout_ticks: u64) -> Result<usize> {
    if buffer.is_empty() {
        return Ok(0);
    }

    let first = keyboard::read_char_timeout(timeout_ticks).ok_or(Error::TimedOut)?;
    // The current keyboard decoder emits ASCII-only chars, so the cooked device
    // can surface them directly as a byte stream without a richer event ABI.
    debug_assert!(first.is_ascii());
    buffer[0] = first as u8;

    let mut count = 1;
    while count < buffer.len() {
        let Some(character) = keyboard::try_read_char() else {
            break;
        };
        debug_assert!(character.is_ascii());
        buffer[count] = character as u8;
        count += 1;
    }

    Ok(count)
}

fn read_keyboard_scancode_bytes(buffer: &mut [u8], timeout_ticks: u64) -> Result<usize> {
    if buffer.is_empty() {
        return Ok(0);
    }

    let first = keyboard::read_scancode_timeout(timeout_ticks).ok_or(Error::TimedOut)?;
    buffer[0] = first;

    let mut count = 1;
    while count < buffer.len() {
        let Some(scancode) = keyboard::try_read_scancode() else {
            break;
        };
        buffer[count] = scancode;
        count += 1;
    }

    Ok(count)
}

fn read_null_bytes(_buffer: &mut [u8], _timeout_ticks: u64) -> Result<usize> {
    Ok(0)
}

fn write_discard_bytes(buffer: &[u8]) -> Result<usize> {
    Ok(buffer.len())
}

fn read_serial_bytes(buffer: &mut [u8], timeout_ticks: u64) -> Result<usize> {
    serial::read_bytes_timeout(buffer, timeout_ticks).ok_or(Error::TimedOut)
}

fn write_serial_bytes(buffer: &[u8]) -> Result<usize> {
    Ok(serial::write_bytes(buffer))
}

fn read_zero_bytes(buffer: &mut [u8], _timeout_ticks: u64) -> Result<usize> {
    buffer.fill(0);
    Ok(buffer.len())
}

fn write_accept_bytes(buffer: &[u8]) -> Result<usize> {
    Ok(buffer.len())
}

pub fn device_descriptor(name: &str) -> Option<&'static DeviceDescriptor> {
    DEVICE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.name == name)
}

pub fn supported_device_rights(name: &str) -> Option<u32> {
    device_descriptor(name).map(|descriptor| descriptor.supported_rights)
}

pub fn device_metadata(name: &str) -> Option<FileMetadata> {
    device_descriptor(name).map(|descriptor| descriptor.metadata())
}

pub fn dispatch_device_read(name: &str, buffer: &mut [u8], timeout_ticks: u64) -> Result<usize> {
    match device_descriptor(name) {
        Some(descriptor) => descriptor.read(buffer, timeout_ticks),
        None => Err(Error::Unsupported),
    }
}

pub fn dispatch_device_write(name: &str, buffer: &[u8]) -> Result<usize> {
    match device_descriptor(name) {
        Some(descriptor) => descriptor.write(buffer),
        None => Err(Error::Unsupported),
    }
}

pub fn virtual_device_node(path: &str) -> Option<&'static VirtualDeviceNode> {
    VIRTUAL_DEVICE_NODES
        .iter()
        .find(|descriptor| descriptor.full_path == path)
}

pub fn virtual_device_nodes() -> &'static [VirtualDeviceNode] {
    &VIRTUAL_DEVICE_NODES
}

pub fn is_virtual_device_directory(path: &str) -> bool {
    path == VIRTUAL_DEVICE_DIRECTORY_PATH
}

pub fn virtual_device_metadata(path: &str) -> Option<FileMetadata> {
    if is_virtual_device_directory(path) {
        return Some(FileMetadata::new(
            NodeKind::Directory,
            VIRTUAL_DEVICE_NODES
                .iter()
                .filter(|node| node.visible_in_directory())
                .count(),
        ));
    }

    virtual_device_node(path).map(|node| node.metadata())
}

pub fn virtual_device_directory_entry(index: usize) -> Option<DirectoryEntry> {
    VIRTUAL_DEVICE_NODES
        .iter()
        .filter(|node| node.visible_in_directory())
        .nth(index)
        .and_then(|node| node.directory_entry())
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::kernel::fs::{FileMetadata, NodeKind};

    use super::{
        supported_device_rights, virtual_device_directory_entry, virtual_device_metadata,
        virtual_device_nodes, VIRTUAL_DEVICE_DIRECTORY_PATH,
    };

    #[test]
    fn virtual_device_nodes_have_unique_paths_and_supported_targets() {
        let nodes = virtual_device_nodes();

        for (index, node) in nodes.iter().enumerate() {
            assert!(
                supported_device_rights(node.target_name).is_some(),
                "unknown device target {}",
                node.target_name
            );
            assert!(
                nodes[index + 1..]
                    .iter()
                    .all(|other| other.full_path != node.full_path),
                "duplicate full path {}",
                node.full_path
            );
            assert!(
                nodes[index + 1..]
                    .iter()
                    .all(|other| other.mount_path != node.mount_path),
                "duplicate mount path {}",
                node.mount_path
            );
        }
    }

    #[test]
    fn direct_virtual_nodes_reuse_target_rights() {
        for node in virtual_device_nodes() {
            if node.full_path.ends_with("/stdin")
                || node.full_path.ends_with("/stdout")
                || node.full_path.ends_with("/stderr")
            {
                continue;
            }

            assert_eq!(
                Some(node.supported_rights()),
                supported_device_rights(node.target_name)
            );
        }
    }

    #[test]
    fn virtual_device_directory_metadata_matches_visible_nodes() {
        assert_eq!(
            virtual_device_metadata(VIRTUAL_DEVICE_DIRECTORY_PATH),
            Some(FileMetadata::new(NodeKind::Directory, 10))
        );
    }

    #[test]
    fn virtual_device_directory_entries_follow_registry_order() {
        let mut names = Vec::new();
        let mut index = 0;
        while let Some(entry) = virtual_device_directory_entry(index) {
            names.push(entry.name);
            index += 1;
        }

        assert_eq!(
            names,
            vec![
                "console",
                "debug",
                "keyboard",
                "keyboard-raw",
                "null",
                "serial0",
                "stderr",
                "stdin",
                "stdout",
                "zero",
            ]
        );
    }
}
