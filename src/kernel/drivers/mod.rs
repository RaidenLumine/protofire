//! src/kernel/drivers/mod.rs
//! Driver manager that initializes hardware drivers and exposes boot-time devices.

pub mod ahci;
pub mod ata;
pub mod framebuffer;
pub mod framebuffer_console;
pub mod hda;
pub mod keyboard;
pub mod nvme;
pub mod serial;
pub mod usb_hid;
pub mod virtio;
pub mod virtio_gpu;
pub mod virtio_net;
pub mod virtio_pci;
pub mod virtio_pci_modern;
pub mod virtio_pci_msix;
pub mod xhci;

/// PC speaker driver (PIT channel 2 tone generation).
pub mod pcspkr;

/// USB mass storage class driver (BOT + SCSI).
pub mod usb_msd;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::network::link::device::NetworkDevice;
use crate::println;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverCategory {
    Bus,
    Storage,
    Input,
    Console,
    Network,
    Audio,
}

impl DriverCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bus => "bus",
            Self::Storage => "storage",
            Self::Input => "input",
            Self::Console => "console",
            Self::Network => "network",
            Self::Audio => "audio",
        }
    }
}

pub trait Driver: Send + Sync {
    fn name(&self) -> &'static str;
    fn category(&self) -> DriverCategory;
    fn init(&self) -> Result<()>;

    /// Probe to see if this driver can handle the given device.
    /// Returns `Ok(true)` if the driver claims the device.
    fn probe(&self, _device_id: usize) -> Result<bool> {
        Ok(false)
    }

    /// Remove/unbind a device from this driver.
    fn remove(&self, _device_id: usize) -> Result<()> {
        Ok(())
    }

    /// Suspend a device.
    fn suspend(&self, _device_id: usize) -> Result<()> {
        Ok(())
    }

    /// Resume a device.
    fn resume(&self, _device_id: usize) -> Result<()> {
        Ok(())
    }

    /// Device-tree compatible strings this driver can bind to.
    ///
    /// Empty (the default) means the driver does not participate in
    /// device-tree-driven probing.  Present only on targets with an FDT
    /// (AArch64/RISC-V, and host tests).
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
    fn compatible_strings(&self) -> &'static [&'static str] {
        &[]
    }

    /// Probe a device-tree node.
    ///
    /// `node_idx` is the index into the FDT node table and `node` carries the
    /// compatible string, MMIO `reg`, and interrupt specifier parsed from the
    /// device tree.  Returns `Ok(true)` when the driver claims the node.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
    fn probe_dt(&self, _node_idx: usize, _node: &crate::arch::fdt::DtNode) -> Result<bool> {
        Ok(false)
    }
}

/// A discovered hardware device tracked by the device manager.
#[derive(Debug, Clone)]
pub struct DeviceNode {
    /// Unique device identifier.
    pub device_id: usize,
    /// Human-readable name.
    pub name: &'static str,
    /// Driver category hint.
    pub category: DriverCategory,
    /// Name of the bound driver, if any.
    pub driver_name: Option<&'static str>,
    /// Bus-specific data (e.g. PCI address).
    pub bus_data: Option<usize>,
}

/// Manager for discovered hardware devices and their driver bindings.
pub struct DeviceManager {
    devices: Vec<DeviceNode>,
    next_device_id: usize,
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceManager {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            next_device_id: 1,
        }
    }

    /// Register a newly discovered device and try to bind a driver to it.
    pub fn register_device(
        &mut self,
        name: &'static str,
        category: DriverCategory,
        bus_data: Option<usize>,
        drivers: &[Arc<dyn Driver>],
    ) -> usize {
        let device_id = self.next_device_id;
        self.next_device_id += 1;

        let mut driver_name = None;
        for drv in drivers {
            if drv.probe(device_id).unwrap_or(false) {
                driver_name = Some(drv.name());
                break;
            }
        }

        self.devices.push(DeviceNode {
            device_id,
            name,
            category,
            driver_name,
            bus_data,
        });
        device_id
    }

    /// Remove a device (e.g. on hot-unplug).
    pub fn remove_device(&mut self, device_id: usize) -> Result<()> {
        if let Some(pos) = self.devices.iter().position(|d| d.device_id == device_id) {
            self.devices.remove(pos);
        }
        Ok(())
    }

    /// Return a reference to all tracked devices.
    pub fn devices(&self) -> &[DeviceNode] {
        &self.devices
    }
}

pub struct DriverManager {
    drivers: Vec<Arc<dyn Driver>>,
    device_manager: DeviceManager,
    boot_disk: Option<Arc<dyn BlockDevice>>,
    boot_net_device: Option<Arc<dyn NetworkDevice>>,
    initialized: bool,
}

impl Default for DriverManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DriverManager {
    pub fn new() -> Self {
        Self {
            drivers: Vec::new(),
            device_manager: DeviceManager::new(),
            boot_disk: None,
            boot_net_device: None,
            initialized: false,
        }
    }

    /// Access the device manager.
    pub fn device_manager(&self) -> &DeviceManager {
        &self.device_manager
    }

    /// Access the device manager mutably.
    pub fn device_manager_mut(&mut self) -> &mut DeviceManager {
        &mut self.device_manager
    }

    pub fn init(&mut self) {
        if self.initialized {
            return;
        }

        self.register(serial::driver());
        self.register(keyboard::driver());
        self.register(ata::driver());
        // AHCI/SATA driver: discovers controllers via PCI enumeration
        // (class=0x01/subclass=0x06).  Registers after ATA PIO so both
        // legacy-IDE and AHCI-mode controllers are discovered.
        self.register(ahci::driver());
        self.register(virtio::driver());
        self.register(virtio_net::driver());

        // Priority 6 drivers: NVMe, virtio-gpu, framebuffer, xHCI.
        // VirtIO GPU is probed before bochs-display so it takes precedence
        // when a virtio-gpu-pci device is present on the PCI bus.
        // MMIO BAR mapping is available via map_device_mmio.
        // NVMe/xHCI full BlockDevice/ring activation is deferred.
        self.register(nvme::driver());
        self.register(virtio_gpu::driver());
        self.register(framebuffer::driver());
        self.register(xhci::driver());
        // HDA audio driver: provides audio subsystem via Intel HD Audio.
        // Discovers HDA controllers via PCI (class=0x04/subclass=0x03).
        self.register(hda::driver());
        // USB HID driver: provides scancode mapping and report processing.
        // Actual device discovery is done by the xHCI controller driver.
        self.register(usb_hid::driver());

        #[cfg(target_arch = "x86_64")]
        self.register(pcspkr::driver());

        // Device-tree-driven probe: bind registered drivers to FDT nodes
        // (AArch64/RISC-V).  Runs before the init loop so a DT-bound device
        // (e.g. virtio-gpu) is ready when its driver's `init()` runs.
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
        self.probe_dt_devices();

        let mut ata_initialized = true;
        for driver in &self.drivers {
            match driver.init() {
                Ok(()) => {
                    println!(
                        "[driver] initialized {} ({})",
                        driver.name(),
                        driver.category().as_str()
                    );
                }
                Err(error) => {
                    println!(
                        "[driver] init failed {} ({}) error={}",
                        driver.name(),
                        driver.category().as_str(),
                        error.as_str()
                    );
                    if driver.name() == "ata" {
                        ata_initialized = false;
                    }
                }
            }
        }

        // Prefer ATA for boot-disk discovery; fall back to AHCI (real hardware
        // SATA), then VirtIO (QEMU virt machines), then NVMe (modern PCIe SSD).
        self.boot_disk = if ata_initialized {
            ata::probe_boot_disk()
        } else {
            println!("[driver] skipping ATA boot-disk probe because ATA init failed");
            None
        };
        if self.boot_disk.is_none() {
            self.boot_disk = ahci::probe_boot_disk();
        }
        if self.boot_disk.is_none() {
            self.boot_disk = virtio::probe_boot_disk();
        }
        if self.boot_disk.is_none() {
            self.boot_disk = nvme::probe_boot_disk();
        }
        if let Some(disk) = &self.boot_disk {
            println!(
                "[driver] detected boot disk: {} ({} blocks)",
                disk.name(),
                disk.block_count()
            );
        } else {
            println!("[driver] no boot disk detected; using in-memory demo volumes");
        }

        // Probe for a VirtIO network device so the native network stack can
        // be brought up during the rest of kernel initialisation.
        self.boot_net_device = virtio_net::probe_boot_net();
        if self.boot_net_device.is_some() {
            println!("[driver] detected boot network device");
        }

        self.initialized = true;
    }

    pub fn register(&mut self, driver: Arc<dyn Driver>) {
        self.drivers.push(driver);
    }

    pub fn count(&self) -> usize {
        self.drivers.len()
    }

    pub fn drivers(&self) -> &[Arc<dyn Driver>] {
        &self.drivers
    }

    pub fn boot_disk(&self) -> Option<Arc<dyn BlockDevice>> {
        self.boot_disk.clone()
    }

    pub fn boot_net_device(&self) -> Option<Arc<dyn NetworkDevice>> {
        self.boot_net_device.clone()
    }

    /// Register a discovered device and attempt driver binding.
    pub fn register_device(
        &mut self,
        name: &'static str,
        category: DriverCategory,
        bus_data: Option<usize>,
    ) -> usize {
        self.device_manager
            .register_device(name, category, bus_data, &self.drivers)
    }

    /// Remove a device (hot-unplug).
    pub fn remove_device(&mut self, device_id: usize) -> Result<()> {
        // Notify the bound driver before removing the device node.
        let driver_name = {
            let devices = self.device_manager.devices();
            devices
                .iter()
                .find(|d| d.device_id == device_id)
                .and_then(|d| d.driver_name)
                .map(|n| n as &str)
        };
        if let Some(name) = driver_name {
            for drv in &self.drivers {
                if drv.name() == name {
                    let _ = drv.remove(device_id);
                    break;
                }
            }
        }
        self.device_manager.remove_device(device_id)
    }

    /// Probe devices discovered in the device tree, binding each node to the
    /// first registered driver whose `compatible_strings()` matches the node's
    /// compatible string.
    ///
    /// This is the device-tree-driven half of driver probing, used on
    /// AArch64/RISC-V where hardware is described by the FDT rather than PCI
    /// enumeration.  Runs during `init()` before the per-driver init loop so a
    /// DT-bound device (e.g. virtio-gpu) is ready before its driver's `init`
    /// runs.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
    fn probe_dt_devices(&mut self) {
        let table = crate::arch::fdt::dt_node_table();
        self.probe_dt_devices_from_table(&table);
    }

    /// Pure variant of [`probe_dt_devices`] that takes an explicit node table
    /// (used by tests to avoid the global table).
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
    fn probe_dt_devices_from_table(&mut self, table: &crate::arch::fdt::DtNodeTable) {
        for (idx, node) in table.nodes[..table.count].iter().enumerate() {
            if node.disabled {
                continue;
            }
            let compatible = node.compatible_str();
            if compatible.is_empty() {
                continue;
            }
            for drv in &self.drivers {
                if drv.compatible_strings().contains(&compatible)
                    && drv.probe_dt(idx, node).unwrap_or(false)
                {
                    println!(
                        "[driver] {} bound to DT node {} ({})",
                        drv.name(),
                        node.name_str(),
                        compatible
                    );
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::fdt::{DtNode, DtNodeTable, DtRegEntry};
    use crate::kernel::sync::Mutex;

    /// A fake driver that claims `virtio,mmio` nodes and records which MMIO
    /// bases it was asked to probe.
    struct TestDtDriver {
        probed: Mutex<alloc::vec::Vec<usize>>,
    }

    impl Driver for TestDtDriver {
        fn name(&self) -> &'static str {
            "test-dt"
        }

        fn category(&self) -> DriverCategory {
            DriverCategory::Bus
        }

        fn init(&self) -> Result<()> {
            Ok(())
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
        fn compatible_strings(&self) -> &'static [&'static str] {
            &["virtio,mmio"]
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
        fn probe_dt(&self, _node_idx: usize, node: &crate::arch::fdt::DtNode) -> Result<bool> {
            if let Some(base) = node.mmio_base() {
                self.probed.lock().push(base);
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    /// Build a `virtio,mmio` DT node with a single reg entry.
    fn make_virtio_node(base: usize, disabled: bool) -> DtNode {
        let mut node = DtNode {
            name: [0; 24],
            name_len: 0,
            compatible: [0; 64],
            compatible_len: 0,
            reg: [DtRegEntry { base: 0, size: 0 }; 2],
            reg_count: 0,
            irq: None,
            phandle: None,
            disabled,
            depth: 1,
        };
        let unit = b"virtio";
        node.name[..unit.len()].copy_from_slice(unit);
        node.name_len = unit.len() as u8;
        let compat = b"virtio,mmio";
        node.compatible[..compat.len()].copy_from_slice(compat);
        node.compatible_len = compat.len() as u8;
        node.reg[0] = DtRegEntry {
            base: base as u64,
            size: 0x200,
        };
        node.reg_count = 1;
        node
    }

    #[test]
    fn probe_dt_devices_binds_matching_driver_and_skips_disabled() {
        let mut manager = DriverManager::new();
        let driver = Arc::new(TestDtDriver {
            probed: Mutex::new(alloc::vec::Vec::new()),
        });
        manager.register(driver.clone());

        // Two virtio nodes (one disabled) plus an unmatched device node.
        let mut table = DtNodeTable::empty();
        table.nodes[0] = make_virtio_node(0x0A00_0000, false);
        table.nodes[1] = make_virtio_node(0x0A00_0200, true); // disabled → skipped
        table.nodes[2] = {
            let mut node = make_virtio_node(0x0A00_0400, false);
            node.compatible[..4].copy_from_slice(b"pl01");
            node.compatible_len = 4;
            node
        };
        table.count = 3;

        manager.probe_dt_devices_from_table(&table);

        // Only the enabled, matching node was probed.
        assert_eq!(driver.probed.lock().as_slice(), &[0x0A00_0000]);
    }

    #[test]
    fn probe_dt_devices_ignores_unmatched_and_empty() {
        let mut manager = DriverManager::new();
        let driver = Arc::new(TestDtDriver {
            probed: Mutex::new(alloc::vec::Vec::new()),
        });
        manager.register(driver.clone());

        // A node whose compatible does not match any registered driver.
        let mut table = DtNodeTable::empty();
        table.nodes[0] = make_virtio_node(0x0A00_0000, false);
        table.nodes[0].compatible[..4].copy_from_slice(b"pl01");
        table.nodes[0].compatible_len = 4;
        table.count = 1;
        manager.probe_dt_devices_from_table(&table);
        assert_eq!(driver.probed.lock().as_slice(), &[]);

        // An empty table must not panic and must not probe anything.
        manager.probe_dt_devices_from_table(&DtNodeTable::empty());
        assert_eq!(driver.probed.lock().as_slice(), &[]);
    }
}
