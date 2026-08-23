//! src/kernel/drivers/usb_msd.rs
//! USB Mass Storage class driver — Bulk-Only Transport (BOT) + SCSI + BlockDevice.
//!
//! Implements the USB mass storage class (class 0x08, subclass 0x06 SCSI,
//! protocol 0x50 BOT) on top of the xHCI bulk endpoint support.

#![cfg(all(target_arch = "x86_64", target_os = "none"))]

use crate::kernel::drivers::xhci::with_controller;
use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::block::DeviceHealth;
use crate::kernel::sync::Mutex;
use crate::println;
use crate::{Error, Result};

// ── USB class constants ──────────────────────────────────────────────────

/// USB mass storage class code.
pub const USB_CLASS_MSC: u8 = 0x08;
/// SCSI transparent command set subclass.
pub const USB_SUBCLASS_SCSI: u8 = 0x06;
/// Bulk-Only Transport protocol.
pub const USB_PROTOCOL_BOT: u8 = 0x50;

// ── BOT protocol constants ───────────────────────────────────────────────

/// Bulk-Only Transport: Command Block Wrapper signature.
const CBW_SIGNATURE: u32 = 0x43425355; // "USBC"
/// Bulk-Only Transport: Command Status Wrapper signature.
const CSW_SIGNATURE: u32 = 0x53425355; // "USBS"

/// CBW flags: direction is device-to-host (IN).
const CBW_DIR_IN: u8 = 0x80;
/// CBW flags: direction is host-to-device (OUT).
const CBW_DIR_OUT: u8 = 0x00;

/// CSW status: command passed.
const CSW_STATUS_PASSED: u8 = 0;
/// CSW status: command failed.
const CSW_STATUS_FAILED: u8 = 1;
/// CSW status: phase error.
const CSW_STATUS_PHASE_ERROR: u8 = 2;

// ── SCSI command constants ───────────────────────────────────────────────

const SCSI_INQUIRY: u8 = 0x12;
const SCSI_TEST_UNIT_READY: u8 = 0x00;
const SCSI_READ_CAPACITY_10: u8 = 0x25;
const SCSI_READ_10: u8 = 0x28;
const SCSI_WRITE_10: u8 = 0x2A;
const SCSI_REQUEST_SENSE: u8 = 0x03;

// ── CBW / CSW structures ─────────────────────────────────────────────────

/// Command Block Wrapper (31 bytes, little-endian).
#[repr(C, packed)]
struct Cbw {
    signature: u32,
    tag: u32,
    data_transfer_length: u32,
    flags: u8,
    lun: u8,
    command_length: u8,
    command: [u8; 16],
}

/// Command Status Wrapper (13 bytes, little-endian).
#[repr(C, packed)]
struct Csw {
    signature: u32,
    tag: u32,
    data_residue: u32,
    status: u8,
}

// ── SCSI command structures ──────────────────────────────────────────────

/// SCSI READ CAPACITY(10) response (8 bytes).
#[repr(C, packed)]
struct ScsiReadCapacity10 {
    returned_lba: u32, // last logical block address
    block_length: u32, // bytes per block
}

/// SCSI READ(10) / WRITE(10) command descriptor block (10 bytes).
#[repr(C, packed)]
struct ScsiRw10Cdb {
    opcode: u8,
    flags: u8,
    lba: u32, // big-endian
    group: u8,
    length: u16, // transfer length in blocks, big-endian
    control: u8,
}

// ── Bulk endpoint info ───────────────────────────────────────────────────

/// Information about a USB mass storage device's bulk endpoints.
#[derive(Debug, Clone, Copy)]
pub struct MsdBulkEndpoints {
    pub slot_id: u8,
    pub ep_out_addr: u8, // bulk OUT endpoint address
    pub ep_in_addr: u8,  // bulk IN endpoint address
    pub max_packet_size: u16,
}

// ── MSD state (global singleton) ─────────────────────────────────────────

static MSD_DEVICE: Mutex<Option<MsdDevice>> = Mutex::new(None);

struct MsdDevice {
    endpoints: MsdBulkEndpoints,
    block_size: usize,
    block_count: u64,
    tag: u32, // CBW tag counter
}

// ── BlockDevice implementation ───────────────────────────────────────────

/// The USB mass storage block device.
pub struct UsbMsdBlockDevice;

impl BlockDevice for UsbMsdBlockDevice {
    fn name(&self) -> &str {
        "usb-msd"
    }

    fn block_size(&self) -> usize {
        MSD_DEVICE
            .lock()
            .as_ref()
            .map(|d| d.block_size)
            .unwrap_or(BLOCK_SIZE)
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn block_count(&self) -> u64 {
        MSD_DEVICE
            .lock()
            .as_ref()
            .map(|d| d.block_count)
            .unwrap_or(0)
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        let nblocks = buffer.len() / BLOCK_SIZE;
        for i in 0..nblocks {
            let offset = i * BLOCK_SIZE;
            let block_buf = &mut buffer[offset..offset + BLOCK_SIZE];
            scsi_read_10(lba + i as u64, block_buf)?;
        }
        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        let nblocks = data.len() / BLOCK_SIZE;
        for i in 0..nblocks {
            let offset = i * BLOCK_SIZE;
            let block_data = &data[offset..offset + BLOCK_SIZE];
            scsi_write_10(lba + i as u64, block_data)?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn device_health(&self) -> DeviceHealth {
        DeviceHealth::Healthy
    }
}

const BLOCK_SIZE: usize = 512;

// ── SCSI commands ────────────────────────────────────────────────────────

fn scsi_read_10(lba: u64, buffer: &mut [u8]) -> Result<()> {
    let cdb = ScsiRw10Cdb {
        opcode: SCSI_READ_10,
        flags: 0,
        lba: (lba as u32).to_be(),
        group: 0,
        length: 1u16.to_be(), // transfer length = 1 block
        control: 0,
    };
    let cdb_bytes = unsafe { core::mem::transmute::<ScsiRw10Cdb, [u8; 10]>(cdb) };
    bot_transfer(&cdb_bytes, Some(buffer), CBW_DIR_IN)
}

fn scsi_write_10(lba: u64, data: &[u8]) -> Result<()> {
    let cdb = ScsiRw10Cdb {
        opcode: SCSI_WRITE_10,
        flags: 0,
        lba: (lba as u32).to_be(),
        group: 0,
        length: 1u16.to_be(), // transfer length = 1 block
        control: 0,
    };
    let cdb_bytes = unsafe { core::mem::transmute::<ScsiRw10Cdb, [u8; 10]>(cdb) };
    // BOT write: data is immutable from BlockDevice but we need mutable for
    // the bot_transfer interface. Since this is an OUT transfer, bulk_send
    // only reads the data — it doesn't modify it.
    let mut write_buf = [0u8; BLOCK_SIZE];
    let len = data.len().min(BLOCK_SIZE);
    write_buf[..len].copy_from_slice(&data[..len]);
    bot_transfer(&cdb_bytes, Some(&mut write_buf[..len]), CBW_DIR_OUT)
}

fn scsi_test_unit_ready() -> Result<()> {
    let cdb = [SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut dummy = [0u8; 1];
    bot_transfer(&cdb, Some(&mut dummy), CBW_DIR_IN)
}

fn scsi_read_capacity() -> Result<(u64, usize)> {
    let cdb = [SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut resp = [0u8; 8];
    bot_transfer(&cdb, Some(&mut resp), CBW_DIR_IN)?;
    // Response is big-endian.
    let cap = unsafe { core::ptr::read_unaligned(resp.as_ptr() as *const ScsiReadCapacity10) };
    let lba = u32::from_be(cap.returned_lba);
    let block_len = u32::from_be(cap.block_length);
    Ok((lba as u64 + 1, block_len as usize))
}

/// SCSI INQUIRY — fetch the standard inquiry data (36 bytes).
///
/// Bytes 8..16 carry the vendor ID, 16..32 the product ID, 32..36 the
/// product revision.  Used during init for a one-line identity diagnostic.
fn scsi_inquiry() -> Result<[u8; 36]> {
    let cdb = [SCSI_INQUIRY, 0, 0, 0, 0, 36, 0, 0, 0, 0]; // allocation length = 36
    let mut resp = [0u8; 36];
    bot_transfer(&cdb, Some(&mut resp), CBW_DIR_IN)?;
    Ok(resp)
}

/// SCSI REQUEST SENSE — return the current sense key (lower 4 bits of
/// byte 2 in the fixed-format sense data).  Used to diagnose why a
/// TEST UNIT READY keeps failing.
fn scsi_request_sense() -> Result<u8> {
    let cdb = [SCSI_REQUEST_SENSE, 0, 0, 0, 0, 18, 0, 0, 0, 0]; // allocation length = 18
    let mut resp = [0u8; 18];
    bot_transfer(&cdb, Some(&mut resp), CBW_DIR_IN)?;
    Ok(resp[2] & 0x0F)
}

// ── BOT protocol ─────────────────────────────────────────────────────────

/// Perform a BOT transfer: send CBW, transfer data, receive CSW.
fn bot_transfer(cdb: &[u8], data: Option<&mut [u8]>, direction: u8) -> Result<()> {
    let mut device = MSD_DEVICE.lock();
    let dev = device.as_mut().ok_or(Error::InvalidArgument)?;
    let data_len = data.as_ref().map(|d| d.len() as u32).unwrap_or(0);

    dev.tag = dev.tag.wrapping_add(1);

    // Build CBW.
    let mut command = [0u8; 16];
    let cmd_len = cdb.len().min(16) as u8;
    command[..cmd_len as usize].copy_from_slice(&cdb[..cmd_len as usize]);
    let cbw = Cbw {
        signature: CBW_SIGNATURE.to_le(),
        tag: dev.tag,
        data_transfer_length: data_len,
        flags: direction,
        lun: 0, // LUN
        command_length: cmd_len,
        command,
    };
    let cbw_bytes = unsafe { core::mem::transmute::<Cbw, [u8; 31]>(cbw) };

    // Send CBW on bulk OUT.
    let ep_out = dev.endpoints.ep_out_addr;
    with_controller(|ctrl| unsafe { ctrl.bulk_send(ep_out, &cbw_bytes) })
        .ok_or(Error::DeviceError)??;

    // Transfer data if any.
    if let Some(buf) = data {
        if direction == CBW_DIR_IN {
            with_controller(|ctrl| unsafe { ctrl.bulk_recv(dev.endpoints.ep_in_addr, buf) })
                .ok_or(Error::DeviceError)??;
        } else {
            with_controller(|ctrl| unsafe { ctrl.bulk_send(ep_out, buf) })
                .ok_or(Error::DeviceError)??;
        }
    }

    // Receive CSW on bulk IN.
    let mut csw_bytes = [0u8; 13];
    with_controller(|ctrl| unsafe { ctrl.bulk_recv(dev.endpoints.ep_in_addr, &mut csw_bytes) })
        .ok_or(Error::DeviceError)??;

    let csw = unsafe { core::ptr::read(csw_bytes.as_ptr() as *const Csw) };
    if csw.signature.to_le() != CSW_SIGNATURE {
        return Err(Error::DeviceError);
    }
    if csw.status != CSW_STATUS_PASSED {
        crate::println!(
            "[usbmsd] BOT command failed: status {} ({}), residue {}",
            csw.status,
            match csw.status {
                CSW_STATUS_FAILED => "FAILED",
                CSW_STATUS_PHASE_ERROR => "PHASE ERROR",
                _ => "UNKNOWN",
            },
            csw.data_residue.to_le(),
        );
        return Err(Error::DeviceError);
    }

    Ok(())
}

// ── Initialisation ───────────────────────────────────────────────────────

/// Initialise the USB mass storage device at the given xHCI slot.
///
/// # Safety
///
/// Called from `probe_xhci` when a MSC BOT device is detected.
pub unsafe fn init_msd(endpoints: MsdBulkEndpoints) -> Result<()> {
    // Register the endpoints first so the BOT transfers below can run.
    *MSD_DEVICE.lock() = Some(MsdDevice {
        endpoints,
        block_size: BLOCK_SIZE,
        block_count: 0,
        tag: 0,
    });

    // Query the device identity (INQUIRY) for a one-line diagnostic.
    if let Ok(inq) = scsi_inquiry() {
        let vendor = core::str::from_utf8(&inq[8..16]).unwrap_or("").trim();
        let product = core::str::from_utf8(&inq[16..32]).unwrap_or("").trim();
        println!(
            "[usbmsd] INQUIRY: vendor='{}' product='{}'",
            vendor, product
        );
    }

    // Wait for the device to become ready.
    let mut last_sense: Option<u8> = None;
    for _ in 0..100 {
        if scsi_test_unit_ready().is_ok() {
            break;
        }
        // Record the sense key for the diagnostic below.
        last_sense = scsi_request_sense().ok();
    }
    if let Some(sense) = last_sense {
        println!(
            "[usbmsd] device was slow to become ready (last sense key 0x{:x})",
            sense
        );
    }

    // Read capacity.
    let (block_count, block_size) = scsi_read_capacity()?;
    println!(
        "[usbmsd] USB mass storage: {} blocks x {} bytes = {} MiB",
        block_count,
        block_size,
        (block_count * block_size as u64) / (1024 * 1024)
    );

    // Fill in the real geometry now that READ CAPACITY has completed.
    let mut device = MSD_DEVICE.lock();
    let dev = device.as_mut().ok_or(Error::InvalidArgument)?;
    dev.block_size = block_size;
    dev.block_count = block_count;
    drop(device);

    // Register with the filesystem as a block device.
    if let Some(fs) = crate::kernel::fs::global() {
        let mut fs_lock = fs.lock();
        fs_lock.register_block_device("usb-msd", alloc::sync::Arc::new(UsbMsdBlockDevice));
        println!("[usbmsd] Registered as block device 'usb-msd'");
    }

    Ok(())
}
