//! src/fs/devfs.rs
//!
//! Device filesystem (devfs): exposes the kernel device registry as VFS nodes.
//!
//! Two kinds of device live here, and they are shaped by what the kernel can
//! actually do with them:
//!
//! * The kernel's own devices — `console`, `null`, `serial0`, … — have a name
//!   fixed at compile time and a read/write handler to go with it, so each is a
//!   node a program can open and use.
//! * Devices a probe *found* and a driver claimed are recorded with what the
//!   machine knows about them (who owns it, what kind, where it was found) and
//!   nothing else yet: there is no I/O interface to serve.  Each is a directory
//!   of those facts instead, in the same shape `/service` reports a service —
//!   when a device gains an interface, the interface becomes the node.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::vfs::DirectoryEntry;
use crate::fs::vfs::FileSystem;
use crate::fs::vfs::Metadata;
use crate::fs::vfs::NodeKind;
use crate::fs::vfs::SecurityDescriptor;
use crate::fs::vfs::VNode;
use crate::kernel::device;
use crate::Error;
use crate::Result;

/// Device filesystem.
pub struct DevFs;

/// A directory node for the devfs root.
pub struct DevDirVNode;

/// A VNode backed by a registered device descriptor.
pub struct DevVNode {
    name: String,
}

/// A directory node for a device a driver bound: `/dev/<name>/`.
pub struct DevRecordDirVNode {
    name: String,
}

/// One file inside a recorded device's directory.
pub struct DevRecordFileVNode {
    device: String,
    file: DeviceRecordFile,
}

/// The files that describe one recorded device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceRecordFile {
    Driver,
    Category,
    Bus,
    Describe,
}

impl DeviceRecordFile {
    /// Every file, in the order `ls /dev/<name>` reports them.
    const ALL: [Self; 4] = [Self::Driver, Self::Category, Self::Bus, Self::Describe];

    /// Map a path component to a file type.
    fn parse(name: &str) -> Option<Self> {
        match name {
            "driver" => Some(Self::Driver),
            "category" => Some(Self::Category),
            "bus" => Some(Self::Bus),
            "describe" => Some(Self::Describe),
            _ => None,
        }
    }

    /// Return the filename this variant is reachable as.
    fn name(self) -> &'static str {
        match self {
            Self::Driver => "driver",
            Self::Category => "category",
            Self::Bus => "bus",
            Self::Describe => "describe",
        }
    }

    /// Render this file's contents for `record`.
    ///
    /// Single-value files end with a newline so that `cat` produces a
    /// well-formed line, matching the `/proc` and `/service` conventions.
    fn produce(self, record: &device::DeviceRecord) -> Vec<u8> {
        match self {
            Self::Driver => format!("{}\n", driver_of(record)).into_bytes(),
            Self::Category => format!("{}\n", record.category).into_bytes(),
            Self::Bus => format!("{}\n", bus_of(record)).into_bytes(),
            Self::Describe => describe_data(record),
        }
    }
}

/// The driver that owns a recorded device, or `(none)`.
///
/// A device with no owner is one a probe found and nobody claimed.  Saying so
/// beats an empty file, which reads as a fact rather than as its absence.
fn driver_of(record: &device::DeviceRecord) -> &str {
    record.driver.as_deref().unwrap_or("(none)")
}

/// The bus address a recorded device was found at, or `(none)`.
fn bus_of(record: &device::DeviceRecord) -> String {
    match record.bus {
        Some(address) => format!("{:#x}", address),
        None => String::from("(none)"),
    }
}

/// Render a whole record as `key: value` lines.
fn describe_data(record: &device::DeviceRecord) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |key: &str, value: &str| {
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(b":\t");
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    };

    field("Device", &record.device);
    field("Driver", driver_of(record));
    field("Category", record.category);
    field("Bus", &bus_of(record));

    out
}

impl VNode for DevDirVNode {
    fn name(&self) -> &str {
        "/"
    }

    fn kind(&self) -> NodeKind {
        NodeKind::Directory
    }

    fn size(&self) -> usize {
        0
    }

    fn read(&self, _offset: u64, _buffer: &mut [u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
}

impl VNode for DevVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        NodeKind::Device
    }

    fn size(&self) -> usize {
        device::device_metadata(&self.name)
            .map(|meta| meta.size)
            .unwrap_or(0)
    }

    fn metadata(&self) -> Result<Metadata> {
        match device::device_metadata(&self.name) {
            Some(meta) => Ok(Metadata {
                kind: NodeKind::Device,
                size: meta.size,
                security: SecurityDescriptor::root_for_kind(NodeKind::Device),
                created: 0,
                modified: 0,
                accessed: 0,
            }),
            None => Err(Error::NotFound),
        }
    }

    fn read(&self, _offset: u64, buffer: &mut [u8]) -> Result<usize> {
        device::dispatch_device_read(&self.name, buffer, 0)
    }

    fn write(&self, _offset: u64, buffer: &[u8]) -> Result<usize> {
        device::dispatch_device_write(&self.name, buffer)
    }

    fn device_id(&self) -> Result<(u32, u32)> {
        // Device nodes are addressed by name through the registry; report a
        // stable (0, 0) major/minor pair since devfs has no block numbering.
        Ok((0, 0))
    }
}

impl VNode for DevRecordDirVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        NodeKind::Directory
    }

    fn size(&self) -> usize {
        0
    }

    fn metadata(&self) -> Result<Metadata> {
        // A directory whose device is gone is gone with it, the same way a
        // `/service` directory follows its record.
        if device::device_record(&self.name).is_none() {
            return Err(Error::NotFound);
        }
        Ok(Metadata {
            kind: NodeKind::Directory,
            size: 0,
            security: SecurityDescriptor::root_for_kind(NodeKind::Directory),
            created: 0,
            modified: 0,
            accessed: 0,
        })
    }

    fn read(&self, _offset: u64, _buffer: &mut [u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
}

impl VNode for DevRecordFileVNode {
    fn name(&self) -> &str {
        self.file.name()
    }

    fn kind(&self) -> NodeKind {
        NodeKind::File
    }

    fn size(&self) -> usize {
        self.record()
            .map(|record| self.file.produce(&record).len())
            .unwrap_or(0)
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            kind: NodeKind::File,
            size: self.size(),
            security: SecurityDescriptor::root_for_kind(NodeKind::File),
            created: 0,
            modified: 0,
            accessed: 0,
        })
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let data = self.file.produce(&self.record()?);
        let start = (offset as usize).min(data.len());
        let end = (start + buffer.len()).min(data.len());
        let count = end - start;
        buffer[..count].copy_from_slice(&data[start..end]);
        Ok(count)
    }
}

impl DevRecordFileVNode {
    /// Read the record this file renders, failing if the device is gone.
    fn record(&self) -> Result<device::DeviceRecord> {
        device::device_record(&self.device).ok_or(Error::NotFound)
    }
}

impl FileSystem for DevFs {
    fn name(&self) -> &str {
        "devfs"
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        if path == "/" || path.is_empty() || device::is_virtual_device_directory(path) {
            return Ok(Arc::new(DevDirVNode));
        }
        if device::virtual_device_node(path).is_some() {
            return Ok(Arc::new(DevVNode {
                name: path.to_string(),
            }));
        }

        let trimmed = path.strip_prefix('/').unwrap_or(path);

        // A path inside a recorded device's directory: `/dev/<name>/<file>`.
        if let Some((head, tail)) = trimmed.split_once('/') {
            return match DeviceRecordFile::parse(tail) {
                Some(file) if device::device_record(head).is_some() => {
                    Ok(Arc::new(DevRecordFileVNode {
                        device: head.to_string(),
                        file,
                    }))
                }
                _ => Err(Error::NotFound),
            };
        }

        // A recorded device itself.
        if device::device_record(trimmed).is_some() {
            return Ok(Arc::new(DevRecordDirVNode {
                name: trimmed.to_string(),
            }));
        }

        // Allow lookup by bare device name (mount-relative, e.g. "console").
        if device::device_descriptor(trimmed).is_some() {
            return Ok(Arc::new(DevVNode {
                name: trimmed.to_string(),
            }));
        }
        Err(Error::NotFound)
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        self.lookup(path).and_then(|vnode| vnode.metadata())
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        // `/dev` lists the device registry.  Running past the end is the end of
        // the listing, which the caller detects by `NotFound` — reporting it as
        // an invalid argument is what made an empty or exhausted directory look
        // like a broken one.
        if path == "/" || path.is_empty() {
            // The kernel's own devices first, then the ones a driver bound:
            // an entry a program can open, then an entry it can ask about.
            let descriptors = device::device_descriptors();
            if let Some(descriptor) = descriptors.get(index) {
                let metadata = descriptor.metadata();
                return Ok(DirectoryEntry::new(
                    metadata.kind,
                    metadata.size,
                    String::from(descriptor.name),
                ));
            }

            let record = device::device_records()
                .into_iter()
                .nth(index - descriptors.len())
                .ok_or(Error::NotFound)?;
            return Ok(DirectoryEntry::new(NodeKind::Directory, 0, record.name));
        }

        // One recorded device's directory: its own facts, or nothing.
        let name = path.strip_prefix('/').unwrap_or(path);
        if device::device_record(name).is_some() {
            let file = DeviceRecordFile::ALL.get(index).ok_or(Error::NotFound)?;
            return Ok(DirectoryEntry::new(
                NodeKind::File,
                0,
                file.name().to_string(),
            ));
        }

        Err(Error::NotFound)
    }

    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn create_file(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::Unsupported)
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn remove_path(&self, _path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }
}

/// Register and mount devfs at `mount_path`.
pub fn mount_devfs(mount_path: &str) -> Result<()> {
    let fs = crate::fs::global().ok_or(Error::InternalError)?;
    let mut fs_guard = fs.lock();
    fs_guard.register(crate::fs::DEVFS_FS_NAME, Arc::new(DevFs));
    fs_guard.mount(
        crate::fs::DEVFS_MOUNT_DEVICE,
        mount_path,
        crate::fs::DEVFS_FS_NAME,
        0,
    )
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    /// Collect a directory listing through the filesystem.
    fn list(fs: &DevFs, path: &str) -> Vec<String> {
        let mut names = Vec::new();
        for index in 0..64 {
            match fs.read_dir(path, index) {
                Ok(entry) => names.push(entry.name),
                Err(_) => break,
            }
        }
        names
    }

    /// Read a whole file through the filesystem.
    fn read(fs: &DevFs, path: &str) -> String {
        let vnode = fs.lookup(path).expect("lookup");
        let mut buffer = vec![0_u8; 512];
        let count = vnode.read(0, &mut buffer).expect("read");
        String::from_utf8(buffer[..count].to_vec()).expect("utf8")
    }

    #[test]
    fn the_ledger_disambiguates_two_devices_that_report_one_name() {
        let _guard = device::lock_device_records_for_tests();

        assert_eq!(
            device::record_device("virtio-blk", Some("virtio"), "storage", None),
            "virtio-blk"
        );
        // A second disk of the same kind: a path has to be unique, and the
        // device's own name is all the driver gave it.
        assert_eq!(
            device::record_device("virtio-blk", Some("virtio"), "storage", None),
            "virtio-blk-2"
        );
        assert_eq!(
            device::record_device("virtio-blk", Some("virtio"), "storage", None),
            "virtio-blk-3"
        );

        let names: Vec<String> = device::device_records()
            .into_iter()
            .map(|record| record.name)
            .collect();
        assert_eq!(names, ["virtio-blk", "virtio-blk-2", "virtio-blk-3"]);
    }

    #[test]
    fn a_recorded_device_is_a_directory_of_the_facts_the_machine_has() {
        let _guard = device::lock_device_records_for_tests();
        device::record_device("nvme0", Some("nvme"), "storage", Some(0xE000_0000));

        let fs = DevFs;

        // It appears in the listing next to the kernel's own devices.
        let root = list(&fs, "/");
        assert!(root.contains(&String::from("nvme0")), "{root:?}");
        assert!(root.contains(&String::from("console")), "{root:?}");

        // And it is a directory of facts, not a node nothing can serve.
        assert_eq!(
            list(&fs, "/nvme0"),
            vec!["driver", "category", "bus", "describe"]
        );
        assert_eq!(read(&fs, "/nvme0/driver"), "nvme\n");
        assert_eq!(read(&fs, "/nvme0/category"), "storage\n");
        assert_eq!(read(&fs, "/nvme0/bus"), "0xe0000000\n");

        let describe = read(&fs, "/nvme0/describe");
        assert!(describe.contains("Device:\tnvme0\n"), "{describe}");
        assert!(describe.contains("Driver:\tnvme\n"), "{describe}");
        assert!(describe.contains("Category:\tstorage\n"), "{describe}");
        assert!(describe.contains("Bus:\t0xe0000000\n"), "{describe}");
    }

    #[test]
    fn a_device_nobody_owns_says_so_rather_than_nothing() {
        let _guard = device::lock_device_records_for_tests();
        device::record_device("mystery", None, "bus", None);

        let fs = DevFs;

        assert_eq!(read(&fs, "/mystery/driver"), "(none)\n");
        assert_eq!(read(&fs, "/mystery/bus"), "(none)\n");
    }

    #[test]
    fn a_device_that_is_not_recorded_has_no_directory() {
        let _guard = device::lock_device_records_for_tests();

        let fs = DevFs;

        assert!(fs.lookup("/not-a-device").is_err());
        assert!(fs.lookup("/not-a-device/driver").is_err());
        // A file the shape does not have is refused as a path, not answered
        // with an empty one.
        assert!(fs.lookup("/console/driver").is_err());
    }
}
