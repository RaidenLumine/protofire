//! src/kernel/drivers/ata.rs
//!
//! ATA disk driver (block I/O).
//! ATA PIO block-device driver with transfer mode selection and sector I/O
//! routines.

use alloc::sync::Arc;

use crate::kernel::fs::block::BlockDevice;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::fs::block::DeviceHealth;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::memory::DmaBuffer;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
use crate::Error;
use crate::Result;

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
use crate::kernel::fs::block::BLOCK_SIZE;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::sync::Mutex;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::Result as KernelResult;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use alloc::string::{String, ToString};

use super::{Driver, DriverCategory};

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::port::Port;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PRIMARY_IO_BASE: u16 = 0x1F0;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PRIMARY_CONTROL_BASE: u16 = 0x3F6;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const SECONDARY_IO_BASE: u16 = 0x170;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const SECONDARY_CONTROL_BASE: u16 = 0x376;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_CMD_IDENTIFY: u8 = 0xEC;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_CMD_READ_SECTORS: u8 = 0x20;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_CMD_READ_SECTORS_EXT: u8 = 0x24;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_CMD_WRITE_SECTORS_EXT: u8 = 0x34;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const ATA_CMD_CACHE_FLUSH_EXT: u8 = 0xEA;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const STATUS_ERR: u8 = 0x01;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const STATUS_DRQ: u8 = 0x08;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const STATUS_DF: u8 = 0x20;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const STATUS_DRDY: u8 = 0x40;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const STATUS_BSY: u8 = 0x80;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const POLL_LIMIT: usize = 1_000_000;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const ATA_LBA28_MAX: u64 = 0x0FFF_FFFF;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const ATA_LBA48_MAX: u64 = 0x0000_FFFF_FFFF_FFFF;

// Drive/head register values for CHS/LBA addressing.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const DRIVE_HEAD_PRIMARY_MASTER: u8 = 0xA0;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const DRIVE_HEAD_PRIMARY_SLAVE: u8 = 0xB0;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const LBA_HEAD_PRIMARY_MASTER: u8 = 0xE0;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const LBA_HEAD_PRIMARY_SLAVE: u8 = 0xF0;

// Device Control register bits.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CTRL_SRST: u8 = 0x04;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CTRL_NORMAL: u8 = 0x00;

// Status register special values for floating-bus detection.
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const STATUS_FLOATING_BUS: u8 = 0xFF;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const STATUS_NONE: u8 = 0x00;

// LBA28 addressing mask.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const LBA28_HEAD_MASK: u8 = 0x0F;

// IDENTIFY command constants.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const IDENTIFY_WORD_COUNT: usize = 256;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const IDENTIFY_LBA48_BIT: usize = 10;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const IDENTIFY_MODEL_START: usize = 27;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const IDENTIFY_MODEL_END: usize = 47;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const SECTOR_COUNT_1: u8 = 1;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const IO_WAIT_READS: usize = 4;

// ── Bus Master IDE (BMIDE) DMA constants ─────────────────────────────
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_CMD_READ_DMA: u8 = 0xC8;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_CMD_WRITE_DMA: u8 = 0xCA;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;

// BMIDE Command Register (offset 0x00) bits.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const BM_CMD_START_STOP: u8 = 0x01;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const BM_CMD_READ: u8 = 0x08; // 1 = read from device, 0 = write to device

// BMIDE Status Register (offset 0x02) bits.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const BM_STATUS_ACTIVE: u8 = 0x01;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const BM_STATUS_ERROR: u8 = 0x02;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const BM_STATUS_INTERRUPT: u8 = 0x04;

// PRDT entry: bit 31 of the byte-count field marks the end of the table.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PRD_END_OF_TABLE: u32 = 1 << 31;

/// BMIDE register block for a single ATA channel.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
struct BmideRegs {
    command: Port<u8>,
    status: Port<u8>,
    prdt_ptr: Port<u32>,
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtaTransferMode {
    Lba28(u32),
    Lba48(u64),
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtaStatusDecision {
    DeviceMissing,
    Busy,
    Error,
    DataRequest,
    NotReady,
    Waiting,
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
fn transfer_mode_for_lba(lba: u64) -> Result<AtaTransferMode> {
    if lba <= ATA_LBA28_MAX {
        return Ok(AtaTransferMode::Lba28(lba as u32));
    }

    if lba <= ATA_LBA48_MAX {
        return Ok(AtaTransferMode::Lba48(lba));
    }

    Err(Error::Unsupported)
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
fn classify_ata_status(status: u8) -> AtaStatusDecision {
    if status == STATUS_NONE || status == STATUS_FLOATING_BUS {
        return AtaStatusDecision::DeviceMissing;
    }

    if status & STATUS_BSY != 0 {
        return AtaStatusDecision::Busy;
    }

    if status & (STATUS_ERR | STATUS_DF) != 0 {
        return AtaStatusDecision::Error;
    }

    if status & STATUS_DRQ != 0 {
        return AtaStatusDecision::DataRequest;
    }

    if status & STATUS_DRDY == 0 {
        return AtaStatusDecision::NotReady;
    }

    AtaStatusDecision::Waiting
}

#[inline]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
fn lba_byte(lba: u64, byte_index: usize) -> u8 {
    ((lba >> (byte_index * 8)) & 0xFF) as u8
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
fn validate_block_io_range(block_count: u64, lba: u64, byte_len: usize) -> Result<()> {
    if !byte_len.is_multiple_of(BLOCK_SIZE) {
        return Err(Error::InvalidArgument);
    }

    let blocks = (byte_len / BLOCK_SIZE) as u64;
    let end = lba.checked_add(blocks).ok_or(Error::InvalidArgument)?;
    if end > block_count {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

struct AtaDriver;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
struct AtaPorts {
    data: Port<u16>,
    sector_count: Port<u8>,
    lba_low: Port<u8>,
    lba_mid: Port<u8>,
    lba_high: Port<u8>,
    drive_head: Port<u8>,
    status_command: Port<u8>,
    alt_status: Port<u8>,
    control: Port<u8>,
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl AtaPorts {
    fn new(io_base: u16, control_base: u16) -> Self {
        Self {
            data: Port::new(io_base),
            sector_count: Port::new(io_base + 2),
            lba_low: Port::new(io_base + 3),
            lba_mid: Port::new(io_base + 4),
            lba_high: Port::new(io_base + 5),
            drive_head: Port::new(io_base + 6),
            status_command: Port::new(io_base + 7),
            alt_status: Port::new(control_base),
            control: Port::new(control_base),
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[derive(Clone, Copy)]
struct AtaProbeTarget {
    io_base: u16,
    control_base: u16,
    identify_drive_head: u8,
    lba_drive_head: u8,
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl AtaProbeTarget {
    const fn new(
        io_base: u16,
        control_base: u16,
        identify_drive_head: u8,
        lba_drive_head: u8,
    ) -> Self {
        Self {
            io_base,
            control_base,
            identify_drive_head,
            lba_drive_head,
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_PROBE_ORDER: [AtaProbeTarget; 4] = [
    AtaProbeTarget::new(
        PRIMARY_IO_BASE,
        PRIMARY_CONTROL_BASE,
        DRIVE_HEAD_PRIMARY_MASTER,
        LBA_HEAD_PRIMARY_MASTER,
    ),
    AtaProbeTarget::new(
        PRIMARY_IO_BASE,
        PRIMARY_CONTROL_BASE,
        DRIVE_HEAD_PRIMARY_SLAVE,
        LBA_HEAD_PRIMARY_SLAVE,
    ),
    AtaProbeTarget::new(
        SECONDARY_IO_BASE,
        SECONDARY_CONTROL_BASE,
        DRIVE_HEAD_PRIMARY_MASTER,
        LBA_HEAD_PRIMARY_MASTER,
    ),
    AtaProbeTarget::new(
        SECONDARY_IO_BASE,
        SECONDARY_CONTROL_BASE,
        DRIVE_HEAD_PRIMARY_SLAVE,
        LBA_HEAD_PRIMARY_SLAVE,
    ),
];

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub struct AtaDisk {
    name: &'static str,
    model: String,
    target: AtaProbeTarget,
    ports: Mutex<AtaPorts>,
    block_count: u64,
    read_only: bool,
    health: Mutex<DeviceHealth>,
    /// Optional BMIDE register base for DMA transfers.
    /// `None` means DMA is unavailable; fall back to PIO.
    bmide_base: Option<u16>,
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl AtaDisk {
    fn new(
        name: &'static str,
        model: String,
        block_count: u64,
        read_only: bool,
        target: AtaProbeTarget,
        bmide_base: Option<u16>,
    ) -> Arc<Self> {
        Arc::new(Self {
            name,
            model,
            target,
            ports: Mutex::new(AtaPorts::new(target.io_base, target.control_base)),
            block_count,
            read_only,
            health: Mutex::new(DeviceHealth::Healthy),
            bmide_base,
        })
    }

    fn read_sector_locked(
        &self,
        ports: &mut AtaPorts,
        lba: u64,
        sector: &mut [u8],
    ) -> KernelResult<()> {
        if sector.len() != BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Try DMA first; fall back to PIO on failure.
        if self.bmide_base.is_some() && try_dma_read_sector(self, ports, lba, sector).is_ok() {
            return Ok(());
        }

        let transfer_mode = transfer_mode_for_lba(lba)?;
        program_read_sector(ports, self.target, transfer_mode)?;

        for word in sector.as_chunks_mut::<2>().0 {
            let value = unsafe { ports.data.read() };
            word.copy_from_slice(&value.to_le_bytes());
        }

        io_wait(ports);
        Ok(())
    }

    fn write_sector_locked(
        &self,
        ports: &mut AtaPorts,
        lba: u64,
        sector: &[u8],
    ) -> KernelResult<()> {
        if sector.len() != BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Try DMA first; fall back to PIO on failure.
        if self.bmide_base.is_some() && try_dma_write_sector(self, ports, lba, sector).is_ok() {
            return Ok(());
        }

        let transfer_mode = transfer_mode_for_lba(lba)?;
        program_write_sector(ports, self.target, transfer_mode)?;

        for word in sector.as_chunks::<2>().0 {
            let value = u16::from_le_bytes([word[0], word[1]]);
            unsafe { ports.data.write(value) };
        }

        unsafe {
            ports
                .status_command
                .write(cache_flush_command_for_mode(transfer_mode));
        }
        wait_for_not_busy(ports)?;
        io_wait(ports);
        Ok(())
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Downgrade device health on I/O error.
    /// Healthy → Degraded; Degraded or Failed stays as-is.
    fn downgrade_health_on_error(&self) {
        let mut health = self.health.lock();
        if *health == DeviceHealth::Healthy {
            *health = DeviceHealth::Degraded;
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl BlockDevice for AtaDisk {
    fn name(&self) -> &str {
        self.name
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn device_health(&self) -> DeviceHealth {
        *self.health.lock()
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> KernelResult<()> {
        validate_block_io_range(self.block_count, lba, buffer.len())?;

        let mut ports = self.ports.lock();
        for (index, sector) in buffer
            .as_chunks_mut::<BLOCK_SIZE>()
            .0
            .iter_mut()
            .enumerate()
        {
            if let Err(e) = self.read_sector_locked(&mut ports, lba + index as u64, sector) {
                self.downgrade_health_on_error();
                return Err(e);
            }
        }

        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> KernelResult<()> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }

        validate_block_io_range(self.block_count, lba, data.len())?;

        let mut ports = self.ports.lock();
        for (index, sector) in data.as_chunks::<BLOCK_SIZE>().0.iter().enumerate() {
            if let Err(e) = self.write_sector_locked(&mut ports, lba + index as u64, sector) {
                self.downgrade_health_on_error();
                return Err(e);
            }
        }

        Ok(())
    }

    fn flush(&self) -> KernelResult<()> {
        if self.read_only {
            return Ok(());
        }

        let mut ports = self.ports.lock();
        // Use EXT variant for large disks, standard for smaller ones.
        let flush_cmd = if self.block_count > ATA_LBA28_MAX {
            ATA_CMD_CACHE_FLUSH_EXT
        } else {
            ATA_CMD_CACHE_FLUSH
        };

        unsafe {
            ports.status_command.write(flush_cmd);
        }
        if let Err(e) = wait_for_not_busy(&mut ports) {
            self.downgrade_health_on_error();
            return Err(e);
        }
        io_wait(&mut ports);
        Ok(())
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn probe_boot_disk() -> Option<Arc<dyn BlockDevice>> {
    let bmide_base = discover_bmide_base();
    ATA_PROBE_ORDER
        .iter()
        .copied()
        .find_map(|target| probe_target(target, bmide_base))
        .map(|disk| disk as Arc<dyn BlockDevice>)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn probe_boot_disk() -> Option<Arc<dyn BlockDevice>> {
    None
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn probe_primary_master() -> Option<Arc<AtaDisk>> {
    let bmide_base = discover_bmide_base();
    probe_target(ATA_PROBE_ORDER[0], bmide_base)
}

/// Try to discover the Bus Master IDE base address from PCI configuration
/// space.  Returns the I/O base (bit 0 cleared) if a PIIX4/ICH IDE
/// controller is found at the expected bus/device/function.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn discover_bmide_base() -> Option<u16> {
    use crate::arch::x86_64::pci::raw;

    // PCI IDE controllers at common b/d/f locations.
    // 00:01.1 = PIIX4/PIIX3 IDE (QEMU q35 and pc)
    // 00:1f.1 = ICH IDE (non-AHCI mode)
    let candidates: &[(u8, u8, u8)] = &[(0, 1, 1), (0, 31, 1)];
    for &(bus, dev, func) in candidates {
        let addr = raw::PciAddress::new(bus, dev, func);
        let vendor_device = unsafe { raw::pci_config_read_u32(addr, 0) };
        if vendor_device == 0xFFFF_FFFF {
            continue;
        }
        // Read the class/subclass/prog-if/revision register.
        // At offset CLASS (0x0B), the u32 contains:
        //   bits 31:24 = class, bits 23:16 = subclass,
        //   bits 15:8  = prog-if, bits 7:0 = revision.
        let cc = unsafe { raw::pci_config_read_u32(addr, raw::CLASS) };
        let class = (cc >> 24) as u8;
        let subclass = (cc >> 16) as u8;
        // class 0x01 = mass storage, subclass 0x01 = IDE
        if class != 0x01 || subclass != 0x01 {
            continue;
        }
        // BAR4 holds the BMIDE base address (I/O space).
        let bar4 = unsafe { raw::pci_config_read_u32(addr, raw::BAR4) };
        if bar4 == 0 || bar4 == 0xFFFF_FFFF {
            continue;
        }
        // I/O BARs have bit 0 set.
        if bar4 & 1 == 0 {
            continue;
        }
        return Some((bar4 & !1) as u16);
    }
    None
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn probe_target(target: AtaProbeTarget, bmide_base: Option<u16>) -> Option<Arc<AtaDisk>> {
    let mut ports = AtaPorts::new(target.io_base, target.control_base);

    unsafe {
        ports.control.write(CTRL_SRST);
        io_wait(&mut ports);
        ports.control.write(CTRL_NORMAL);
    }

    wait_for_status_presence(&mut ports)?;

    unsafe {
        ports.drive_head.write(target.identify_drive_head);
        io_wait(&mut ports);
        ports.sector_count.write(0);
        ports.lba_low.write(0);
        ports.lba_mid.write(0);
        ports.lba_high.write(0);
        ports.status_command.write(ATA_CMD_IDENTIFY);
        io_wait(&mut ports);
    }

    let _ = wait_for_status_presence(&mut ports)?;

    if wait_for_not_busy(&mut ports).is_err() {
        return None;
    }

    let signature_mid = unsafe { ports.lba_mid.read() };
    let signature_high = unsafe { ports.lba_high.read() };
    if signature_mid != 0 || signature_high != 0 {
        return None;
    }

    if wait_for_data_request(&mut ports).is_err() {
        return None;
    }

    let mut identify = [0_u16; IDENTIFY_WORD_COUNT];
    for word in &mut identify {
        *word = unsafe { ports.data.read() };
    }

    let block_count = identify_capacity(&identify)?;
    let model = parse_model(&identify);
    Some(AtaDisk::new(
        "ata0",
        model,
        block_count,
        false,
        target,
        bmide_base,
    ))
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn identify_capacity(words: &[u16; IDENTIFY_WORD_COUNT]) -> Option<u64> {
    let lba48_supported = words[83] & (1 << IDENTIFY_LBA48_BIT) != 0;
    if lba48_supported {
        let capacity = (words[100] as u64)
            | ((words[101] as u64) << 16)
            | ((words[102] as u64) << 32)
            | ((words[103] as u64) << 48);
        if capacity != 0 {
            return Some(capacity);
        }
    }

    let capacity = (words[60] as u64) | ((words[61] as u64) << 16);
    if capacity != 0 {
        Some(capacity)
    } else {
        None
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn parse_model(words: &[u16; IDENTIFY_WORD_COUNT]) -> String {
    let mut bytes = [0_u8; 40];

    for (index, word) in words[IDENTIFY_MODEL_START..IDENTIFY_MODEL_END]
        .iter()
        .copied()
        .enumerate()
    {
        let [high, low] = word.to_be_bytes();
        bytes[index * 2] = high;
        bytes[index * 2 + 1] = low;
    }

    core::str::from_utf8(&bytes)
        .unwrap_or("ATA")
        .trim_matches(char::from(0))
        .trim()
        .to_string()
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn program_read_sector(
    ports: &mut AtaPorts,
    target: AtaProbeTarget,
    lba: AtaTransferMode,
) -> KernelResult<()> {
    program_sector_io(
        ports,
        target,
        lba,
        ATA_CMD_READ_SECTORS,
        ATA_CMD_READ_SECTORS_EXT,
    )
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn program_write_sector(
    ports: &mut AtaPorts,
    target: AtaProbeTarget,
    lba: AtaTransferMode,
) -> KernelResult<()> {
    program_sector_io(
        ports,
        target,
        lba,
        ATA_CMD_WRITE_SECTORS,
        ATA_CMD_WRITE_SECTORS_EXT,
    )
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn program_sector_io(
    ports: &mut AtaPorts,
    target: AtaProbeTarget,
    lba: AtaTransferMode,
    lba28_command: u8,
    lba48_command: u8,
) -> KernelResult<()> {
    wait_for_not_busy(ports)?;

    unsafe {
        match lba {
            AtaTransferMode::Lba28(lba) => {
                ports
                    .drive_head
                    .write(target.lba_drive_head | ((lba >> 24) as u8 & LBA28_HEAD_MASK));
                io_wait(ports);
                ports.sector_count.write(SECTOR_COUNT_1);
                ports.lba_low.write(lba as u8);
                ports.lba_mid.write((lba >> 8) as u8);
                ports.lba_high.write((lba >> 16) as u8);
                ports.status_command.write(lba28_command);
            }
            AtaTransferMode::Lba48(lba) => {
                ports.drive_head.write(target.lba_drive_head);
                io_wait(ports);

                ports.sector_count.write(0);
                ports.lba_low.write(lba_byte(lba, 3));
                ports.lba_mid.write(lba_byte(lba, 4));
                ports.lba_high.write(lba_byte(lba, 5));

                ports.sector_count.write(SECTOR_COUNT_1);
                ports.lba_low.write(lba_byte(lba, 0));
                ports.lba_mid.write(lba_byte(lba, 1));
                ports.lba_high.write(lba_byte(lba, 2));
                ports.status_command.write(lba48_command);
            }
        }
    }

    wait_for_data_request(ports)
}

// ── BMIDE DMA sector I/O ───────────────────────────────────────────────

/// Try a single-sector DMA read on `disk`.  Returns `Ok(())` on success, or
/// an error if DMA is unavailable or the transfer fails (caller falls back to
/// PIO).  The data is placed in `sector`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn try_dma_read_sector(
    disk: &AtaDisk,
    ports: &mut AtaPorts,
    lba: u64,
    sector: &mut [u8],
) -> KernelResult<()> {
    let bmide_base = disk.bmide_base.ok_or(Error::Unsupported)?;
    let mut bmide = bmide_regs_for_target(bmide_base, disk.target);
    let transfer_mode = transfer_mode_for_lba(lba)?;

    // Allocate DMA buffers.
    let dma_buf = DmaBuffer::allocate(1).ok_or(Error::OutOfMemory)?;
    let prdt_buf = DmaBuffer::allocate(1).ok_or(Error::OutOfMemory)?;
    let prdt_phys = prdt_buf.phys_addr();
    let data_phys = dma_buf.phys_addr();

    // Build a single-entry PRDT: one 512-byte region, end-of-table.
    unsafe {
        core::ptr::write_volatile(prdt_buf.as_ptr() as *mut u32, data_phys as u32);
        core::ptr::write_volatile(
            (prdt_buf.as_ptr() as *mut u32).add(1),
            (BLOCK_SIZE as u32) | PRD_END_OF_TABLE,
        );
    }

    // Program the ATA DMA read command.
    program_dma_sector(ports, disk.target, transfer_mode, true)?;

    // Set PRDT pointer and clear status.
    unsafe {
        bmide.prdt_ptr.write(prdt_phys as u32);
        bmide.status.write(BM_STATUS_INTERRUPT | BM_STATUS_ERROR);
        bmide.command.write(BM_CMD_READ | BM_CMD_START_STOP);
    }

    // Wait for DMA completion.
    wait_bmide_done(&mut bmide)?;

    // Copy data from DMA buffer to caller's sector buffer.
    sector.copy_from_slice(&dma_buf.as_slice()[..BLOCK_SIZE]);

    Ok(())
}

/// Try a single-sector DMA write on `disk`.  Returns `Ok(())` on success, or
/// an error if DMA is unavailable or the transfer fails.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn try_dma_write_sector(
    disk: &AtaDisk,
    ports: &mut AtaPorts,
    lba: u64,
    sector: &[u8],
) -> KernelResult<()> {
    let bmide_base = disk.bmide_base.ok_or(Error::Unsupported)?;
    let mut bmide = bmide_regs_for_target(bmide_base, disk.target);
    let transfer_mode = transfer_mode_for_lba(lba)?;

    let mut dma_buf = DmaBuffer::allocate(1).ok_or(Error::OutOfMemory)?;
    let prdt_buf = DmaBuffer::allocate(1).ok_or(Error::OutOfMemory)?;
    let prdt_phys = prdt_buf.phys_addr();
    let data_phys = dma_buf.phys_addr();

    // Copy caller's data into DMA buffer.
    dma_buf.as_mut_slice()[..BLOCK_SIZE].copy_from_slice(sector);

    // Build PRDT.
    unsafe {
        core::ptr::write_volatile(prdt_buf.as_ptr() as *mut u32, data_phys as u32);
        core::ptr::write_volatile(
            (prdt_buf.as_ptr() as *mut u32).add(1),
            (BLOCK_SIZE as u32) | PRD_END_OF_TABLE,
        );
    }

    // Program ATA DMA write command.
    program_dma_sector(ports, disk.target, transfer_mode, false)?;

    unsafe {
        bmide.prdt_ptr.write(prdt_phys as u32);
        bmide.status.write(BM_STATUS_INTERRUPT | BM_STATUS_ERROR);
        // Start DMA (write: memory → device, READ bit = 0).
        bmide.command.write(BM_CMD_START_STOP);
    }

    wait_bmide_done(&mut bmide)?;

    Ok(())
}

/// Program the ATA registers for a DMA read or write and wait for DRQ.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn program_dma_sector(
    ports: &mut AtaPorts,
    target: AtaProbeTarget,
    lba: AtaTransferMode,
    is_read: bool,
) -> KernelResult<()> {
    let (lba28_cmd, lba48_cmd) = if is_read {
        (ATA_CMD_READ_DMA, ATA_CMD_READ_DMA_EXT)
    } else {
        (ATA_CMD_WRITE_DMA, ATA_CMD_WRITE_DMA_EXT)
    };
    program_sector_io(ports, target, lba, lba28_cmd, lba48_cmd)
}

/// Poll the BMIDE status register until the transfer completes or an error
/// occurs.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn wait_bmide_done(bmide: &mut BmideRegs) -> KernelResult<()> {
    for _ in 0..POLL_LIMIT {
        let status = unsafe { bmide.status.read() };
        if status & BM_STATUS_ERROR != 0 {
            // Stop the DMA engine on error.
            unsafe { bmide.command.write(0) };
            return Err(Error::DeviceError);
        }
        if status & BM_STATUS_ACTIVE == 0 {
            // Transfer complete — stop the engine.
            unsafe { bmide.command.write(0) };
            return Ok(());
        }
    }
    // Timeout — stop DMA.
    unsafe { bmide.command.write(0) };
    Err(Error::Busy)
}

/// Construct BMIDE registers for a given probe target.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn bmide_regs_for_target(bmide_base: u16, target: AtaProbeTarget) -> BmideRegs {
    let channel_offset = if target.io_base == PRIMARY_IO_BASE {
        0_u16
    } else {
        8_u16
    };
    let base = bmide_base + channel_offset;
    BmideRegs {
        command: Port::new(base),
        status: Port::new(base + 2),
        prdt_ptr: Port::new(base + 4),
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
fn cache_flush_command_for_mode(mode: AtaTransferMode) -> u8 {
    match mode {
        AtaTransferMode::Lba28(_) => ATA_CMD_CACHE_FLUSH,
        AtaTransferMode::Lba48(_) => ATA_CMD_CACHE_FLUSH_EXT,
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn wait_for_not_busy(ports: &mut AtaPorts) -> KernelResult<u8> {
    for _ in 0..POLL_LIMIT {
        let status = unsafe { ports.status_command.read() };
        match classify_ata_status(status) {
            AtaStatusDecision::DeviceMissing => return Err(Error::DeviceError),
            AtaStatusDecision::Busy => {}
            _ => return Ok(status),
        }
    }

    Err(Error::Busy)
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn wait_for_status_presence(ports: &mut AtaPorts) -> Option<u8> {
    for _ in 0..POLL_LIMIT {
        let status = unsafe { ports.status_command.read() };
        if status == STATUS_FLOATING_BUS {
            return None;
        }

        if status != STATUS_NONE {
            return Some(status);
        }

        io_wait(ports);
    }

    None
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn wait_for_data_request(ports: &mut AtaPorts) -> KernelResult<()> {
    for _ in 0..POLL_LIMIT {
        let status = wait_for_not_busy(ports)?;

        match classify_ata_status(status) {
            AtaStatusDecision::DeviceMissing | AtaStatusDecision::Error => {
                return Err(Error::DeviceError);
            }
            AtaStatusDecision::DataRequest => return Ok(()),
            AtaStatusDecision::Busy | AtaStatusDecision::NotReady | AtaStatusDecision::Waiting => {}
        }
    }

    Err(Error::Busy)
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn io_wait(ports: &mut AtaPorts) {
    for _ in 0..IO_WAIT_READS {
        let _ = unsafe { ports.alt_status.read() };
    }
}

impl Driver for AtaDriver {
    fn name(&self) -> &'static str {
        "ata"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Storage
    }

    fn init(&self) -> Result<()> {
        // Keep driver registration cheap and side-effect light. Real hardware
        // discovery is deferred to `probe_boot_disk()` so boot can continue on
        // machines that simply do not expose an ATA device.
        Ok(())
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(AtaDriver)
}

#[cfg(test)]
mod tests {
    use super::{
        cache_flush_command_for_mode, classify_ata_status, lba_byte, transfer_mode_for_lba,
        validate_block_io_range, AtaStatusDecision, AtaTransferMode, ATA_CMD_CACHE_FLUSH,
        ATA_CMD_CACHE_FLUSH_EXT, ATA_LBA28_MAX, ATA_LBA48_MAX, STATUS_BSY, STATUS_DF, STATUS_DRDY,
        STATUS_DRQ, STATUS_ERR, STATUS_FLOATING_BUS, STATUS_NONE,
    };
    use crate::kernel::fs::block::BLOCK_SIZE;
    use crate::Error;

    #[test]
    fn transfer_mode_uses_lba28_up_to_legacy_limit() {
        assert_eq!(transfer_mode_for_lba(0), Ok(AtaTransferMode::Lba28(0)));
        assert_eq!(
            transfer_mode_for_lba(ATA_LBA28_MAX),
            Ok(AtaTransferMode::Lba28(ATA_LBA28_MAX as u32))
        );
    }

    #[test]
    fn transfer_mode_promotes_to_lba48_above_lba28_limit() {
        let lba = ATA_LBA28_MAX + 1;
        assert_eq!(transfer_mode_for_lba(lba), Ok(AtaTransferMode::Lba48(lba)));
    }

    #[test]
    fn transfer_mode_rejects_values_above_lba48_limit() {
        assert_eq!(
            transfer_mode_for_lba(ATA_LBA48_MAX + 1),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn transfer_mode_accepts_lba48_upper_boundary() {
        assert_eq!(
            transfer_mode_for_lba(ATA_LBA48_MAX),
            Ok(AtaTransferMode::Lba48(ATA_LBA48_MAX))
        );
    }

    #[test]
    fn cache_flush_command_matches_transfer_mode() {
        assert_eq!(
            cache_flush_command_for_mode(AtaTransferMode::Lba28(ATA_LBA28_MAX as u32)),
            ATA_CMD_CACHE_FLUSH
        );
        assert_eq!(
            cache_flush_command_for_mode(AtaTransferMode::Lba48(ATA_LBA28_MAX + 1)),
            ATA_CMD_CACHE_FLUSH_EXT
        );
    }

    #[test]
    fn status_classification_preserves_polling_priority() {
        assert_eq!(
            classify_ata_status(STATUS_NONE),
            AtaStatusDecision::DeviceMissing
        );
        assert_eq!(
            classify_ata_status(STATUS_FLOATING_BUS),
            AtaStatusDecision::DeviceMissing
        );
        assert_eq!(
            classify_ata_status(STATUS_BSY | STATUS_ERR),
            AtaStatusDecision::Busy
        );
        assert_eq!(classify_ata_status(STATUS_ERR), AtaStatusDecision::Error);
        assert_eq!(classify_ata_status(STATUS_DF), AtaStatusDecision::Error);
        assert_eq!(
            classify_ata_status(STATUS_DRQ),
            AtaStatusDecision::DataRequest
        );
        assert_eq!(classify_ata_status(0x02), AtaStatusDecision::NotReady);
        assert_eq!(classify_ata_status(STATUS_DRDY), AtaStatusDecision::Waiting);
    }

    #[test]
    fn lba_byte_extracts_expected_byte_positions() {
        let lba = 0x11_22_33_44_55_66_u64;
        assert_eq!(lba_byte(lba, 0), 0x66);
        assert_eq!(lba_byte(lba, 1), 0x55);
        assert_eq!(lba_byte(lba, 2), 0x44);
        assert_eq!(lba_byte(lba, 3), 0x33);
        assert_eq!(lba_byte(lba, 4), 0x22);
        assert_eq!(lba_byte(lba, 5), 0x11);
    }

    #[test]
    fn validate_block_io_range_accepts_in_bounds_sector_aligned_requests() {
        assert_eq!(validate_block_io_range(16, 0, 0), Ok(()));
        assert_eq!(validate_block_io_range(16, 0, BLOCK_SIZE), Ok(()));
        assert_eq!(validate_block_io_range(16, 15, BLOCK_SIZE), Ok(()));
    }

    #[test]
    fn validate_block_io_range_rejects_unaligned_or_out_of_bounds_requests() {
        assert_eq!(
            validate_block_io_range(16, 0, BLOCK_SIZE - 1),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            validate_block_io_range(16, 16, BLOCK_SIZE),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            validate_block_io_range(u64::MAX, u64::MAX, BLOCK_SIZE),
            Err(Error::InvalidArgument)
        );
    }
}
