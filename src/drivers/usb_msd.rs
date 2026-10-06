//! src/drivers/usb_msd.rs
//!
//! USB Mass Storage class driver.
//! USB Mass Storage class driver — Bulk-Only Transport (BOT) + SCSI +
//! BlockDevice.
//!
//! Implements the USB mass storage class (class 0x08, subclass 0x06 SCSI,
//! protocol 0x50 BOT) on top of the xHCI bulk endpoint support.

#![cfg(all(target_arch = "x86_64", target_os = "none"))]

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use alloc::sync::Arc;

use crate::drivers::xhci::with_controller;
use crate::kernel::block::BlockDevice;
use crate::kernel::block::DeviceHealth;
use crate::kernel::sync::Mutex;
use crate::println;
use crate::Error;
use crate::Result;

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
        // Use the real READ CAPACITY block size, not the 512-byte fallback.
        let block_size = self.block_size();
        let nblocks = buffer.len() / block_size;
        let usable = nblocks * block_size;
        scsi_read_10(lba, &mut buffer[..usable])
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        let block_size = self.block_size();
        let nblocks = data.len() / block_size;
        let usable = nblocks * block_size;
        scsi_write_10(lba, &data[..usable])
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn device_health(&self) -> DeviceHealth {
        DeviceHealth::Healthy
    }
}

/// Fallback block size (512 bytes) used before READ CAPACITY has run.
const BLOCK_SIZE: usize = 512;

/// Maximum number of blocks per READ(10)/WRITE(10) CDB.  The transfer-length
/// field is 16 bits, so a single command covers at most 65535 blocks.
const MAX_SCSI_BLOCKS_PER_CDB: usize = 65535;

/// Maximum bytes moved per BOT data-phase transfer.  The xHCI Normal TRB
/// transfer-length field is 17 bits (max 0x1FFFF), so a bulk data stage is
/// chunked below that ceiling.
const MAX_BOT_DATA_CHUNK: usize = 0xFF00;

/// The device's real block size (READ CAPACITY result), or the 512-byte
/// fallback before geometry has been queried.
fn device_block_size() -> usize {
    MSD_DEVICE
        .lock()
        .as_ref()
        .map(|d| d.block_size)
        .unwrap_or(BLOCK_SIZE)
}

// ── SCSI commands ────────────────────────────────────────────────────────

fn scsi_read_10(lba: u64, buffer: &mut [u8]) -> Result<()> {
    let block_size = device_block_size();
    let total_blocks = buffer.len() / block_size;
    let mut done = 0usize;
    while done < total_blocks {
        // Chunk at the CDB block-count limit (u16 transfer length).
        let chunk = core::cmp::min(MAX_SCSI_BLOCKS_PER_CDB, total_blocks - done);
        let offset = done * block_size;
        let chunk_buf = &mut buffer[offset..offset + chunk * block_size];
        let cdb = ScsiRw10Cdb {
            opcode: SCSI_READ_10,
            flags: 0,
            lba: ((lba + done as u64) as u32).to_be(),
            group: 0,
            length: (chunk as u16).to_be(),
            control: 0,
        };
        // SAFETY: `ScsiRw10Cdb` is `repr(C, packed)` and ten bytes wide, so the
        // transmute to the wire form is the same ten bytes; the compiler checks
        // the sizes agree.
        let cdb_bytes = unsafe { core::mem::transmute::<ScsiRw10Cdb, [u8; 10]>(cdb) };
        bot_transfer(&cdb_bytes, Some(BotData::In(chunk_buf)))?;
        done += chunk;
    }
    Ok(())
}

fn scsi_write_10(lba: u64, data: &[u8]) -> Result<()> {
    let block_size = device_block_size();
    let total_blocks = data.len() / block_size;
    let mut done = 0usize;
    while done < total_blocks {
        let chunk = core::cmp::min(MAX_SCSI_BLOCKS_PER_CDB, total_blocks - done);
        let offset = done * block_size;
        let chunk_data = &data[offset..offset + chunk * block_size];
        let cdb = ScsiRw10Cdb {
            opcode: SCSI_WRITE_10,
            flags: 0,
            lba: ((lba + done as u64) as u32).to_be(),
            group: 0,
            length: (chunk as u16).to_be(),
            control: 0,
        };
        // SAFETY: as `scsi_read_10` — the same ten-byte packed descriptor.
        let cdb_bytes = unsafe { core::mem::transmute::<ScsiRw10Cdb, [u8; 10]>(cdb) };
        bot_transfer(&cdb_bytes, Some(BotData::Out(chunk_data)))?;
        done += chunk;
    }
    Ok(())
}

fn scsi_test_unit_ready() -> Result<()> {
    // TEST UNIT READY has no data stage.  Asking for a byte here — which this
    // did — leaves the device reporting a residue of one for a transfer that
    // should not exist, and relies on the device tolerating the extra phase.
    // The command status wrapper is the whole answer.
    let cdb = [SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    bot_transfer(&cdb, None)
}

fn scsi_read_capacity() -> Result<(u64, usize)> {
    let cdb = [SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut resp = [0u8; 8];
    bot_transfer(&cdb, Some(BotData::In(&mut resp)))?;
    // Response is big-endian.
    // SAFETY: the device wrote the 8 bytes of a READ CAPACITY response into
    // `resp`, the buffer `bot_transfer` filled; the copy is what keeps the read
    // independent of the record's alignment.
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
    // The allocation length is the *two* bytes at 3..5 — byte 3 its high half,
    // byte 4 its low half — and byte 5 is the control byte.  This array used to
    // carry the 36 one byte too far right, so the device was asked for zero
    // bytes and answered with status PASSED and a residue of all thirty-six:
    // the thirty-six zeros that the identity line printed as an empty vendor.
    let cdb = [SCSI_INQUIRY, 0, 0, 0, 36, 0, 0, 0, 0, 0];
    let mut resp = [0u8; 36];
    bot_transfer(&cdb, Some(BotData::In(&mut resp)))?;
    Ok(resp)
}

/// SCSI REQUEST SENSE — return the current sense key (lower 4 bits of
/// byte 2 in the fixed-format sense data).  Used to diagnose why a
/// TEST UNIT READY keeps failing.
fn scsi_request_sense() -> Result<u8> {
    // REQUEST SENSE's allocation length is the single byte 4 — byte 3 is
    // reserved — and it had the same one-byte error as INQUIRY above.
    let cdb = [SCSI_REQUEST_SENSE, 0, 0, 0, 18, 0, 0, 0, 0, 0];
    let mut resp = [0u8; 18];
    bot_transfer(&cdb, Some(BotData::In(&mut resp)))?;
    Ok(resp[2] & 0x0F)
}

// ── Boot-disk probe ──────────────────────────────────────────────────────

/// Return the USB mass storage block device as a boot disk candidate.
///
/// `probe_xhci` registers the device (via [`init_msd`]) before the driver
/// manager walks the boot-disk fallback chain, so this just checks whether
/// a USB mass storage device was initialised.
pub fn probe_boot_disk() -> Option<Arc<dyn BlockDevice>> {
    // Kick the deferred SCSI geometry probe now that the xHCI controller is
    // globally reachable.  Idempotent, so this is also the fallback trigger
    // for when probe_xhci's own trigger races ahead of it.
    probe_geometry();
    if MSD_DEVICE.lock().is_some() {
        Some(Arc::new(UsbMsdBlockDevice))
    } else {
        None
    }
}

// ── BOT protocol ─────────────────────────────────────────────────────────

/// Perform a BOT transfer: send CBW, transfer data, receive CSW.
///
/// The data stage's direction is carried by the value rather than by a separate
/// flag, so the CBW's direction byte and the transfer cannot disagree — and an
/// OUT transfer never has to invent a mutable view of the block device's
/// immutable buffer.
enum BotData<'a> {
    /// The device writes into this buffer (CBW flags = IN).
    In(&'a mut [u8]),
    /// The device reads from this buffer (CBW flags = OUT).
    Out(&'a [u8]),
}

fn bot_transfer(cdb: &[u8], data: Option<BotData<'_>>) -> Result<()> {
    let mut device = MSD_DEVICE.lock();
    let dev = device.as_mut().ok_or(Error::InvalidArgument)?;
    let (data_len, direction) = match &data {
        Some(BotData::In(buf)) => (buf.len() as u32, CBW_DIR_IN),
        Some(BotData::Out(buf)) => (buf.len() as u32, CBW_DIR_OUT),
        None => (0, CBW_DIR_OUT),
    };

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
    // SAFETY: `Cbw` is `repr(C, packed)` with fixed byte fields, and the
    // compiler checks that its size is the 31 bytes the wire form needs.
    let cbw_bytes = unsafe { core::mem::transmute::<Cbw, [u8; 31]>(cbw) };

    // Send CBW on bulk OUT.
    let ep_out = dev.endpoints.ep_out_addr;
    // SAFETY: the endpoint belongs to a slot this controller configured, and the
    // CBW is a local array `bulk_send` copies into its own buffer.
    with_controller(|ctrl| unsafe { ctrl.bulk_send(ep_out, &cbw_bytes) })
        .ok_or(Error::DeviceError)??;

    // Transfer data if any, chunking so no single bulk transfer exceeds the
    // xHCI TRB transfer-length ceiling (17 bits).
    match data {
        Some(BotData::In(buf)) => {
            for chunk in buf.chunks_mut(MAX_BOT_DATA_CHUNK) {
                // SAFETY: the endpoint is one this controller's device
                // configured for bulk IN, and the chunk is part of the caller's
                // buffer, which outlives the transfer.
                with_controller(|ctrl| unsafe { ctrl.bulk_recv(dev.endpoints.ep_in_addr, chunk) })
                    .ok_or(Error::DeviceError)??;
            }
        }
        Some(BotData::Out(buf)) => {
            for chunk in buf.chunks(MAX_BOT_DATA_CHUNK) {
                // SAFETY: as above, on the OUT endpoint — `bulk_send` copies the
                // chunk into its own DMA buffer and keeps no reference.
                with_controller(|ctrl| unsafe { ctrl.bulk_send(ep_out, chunk) })
                    .ok_or(Error::DeviceError)??;
            }
        }
        None => {}
    }

    // Receive CSW on bulk IN.
    let mut csw_bytes = [0u8; 13];
    // SAFETY: as above, on the IN endpoint — the buffer is this function's own
    // and outlives the transfer.
    with_controller(|ctrl| unsafe { ctrl.bulk_recv(dev.endpoints.ep_in_addr, &mut csw_bytes) })
        .ok_or(Error::DeviceError)??;

    // SAFETY: the device wrote exactly the 13 bytes of a CSW into the buffer
    // `bulk_recv` filled, and the copy is what keeps the read independent of
    // the record's alignment.
    let csw = unsafe { core::ptr::read_unaligned(csw_bytes.as_ptr() as *const Csw) };
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

/// Register a newly detected USB mass storage device at the given xHCI slot.
///
/// This only records the bulk endpoints and the geometry defaults (512-byte
/// blocks, unknown count); the SCSI geometry probe is deferred to
/// [`probe_geometry`] because it needs the xHCI controller to be published
/// in the global registry, which `probe_xhci` does only after its port scan
/// completes.
///
/// # Safety
///
/// Called from `probe_xhci` when a MSC BOT device is detected.
pub unsafe fn register_msd(endpoints: MsdBulkEndpoints) {
    *MSD_DEVICE.lock() = Some(MsdDevice {
        endpoints,
        block_size: BLOCK_SIZE,
        block_count: 0,
        tag: 0,
    });
}

/// Whether [`probe_geometry`] has already run (idempotence guard).
static GEOMETRY_PROBED: AtomicBool = AtomicBool::new(false);

/// Run the SCSI geometry probe (INQUIRY, TEST UNIT READY, READ CAPACITY)
/// now that the xHCI controller is reachable through `with_controller`.
///
/// Deferred out of [`register_msd`] for that reason; safe to call
/// repeatedly.  No-ops when no USB mass storage device was registered.
pub fn probe_geometry() {
    if GEOMETRY_PROBED.swap(true, Ordering::AcqRel) {
        return;
    }
    if MSD_DEVICE.lock().is_none() {
        return;
    }

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
    let Ok((block_count, block_size)) = scsi_read_capacity() else {
        // Geometry probe failed; keep the 512-byte fallback and the zero
        // block count so the block device stays visible but unusable.
        return;
    };
    println!(
        "[usbmsd] USB mass storage: {} blocks x {} bytes = {} MiB",
        block_count,
        block_size,
        (block_count * block_size as u64) / (1024 * 1024)
    );

    // Read the first sector for a one-line identification: it is the read a
    // filesystem would do next, and it is the only thing in this driver that
    // shows a *block* came back rather than a capacity.
    let mut sector = [0u8; BLOCK_SIZE];
    match scsi_read_10(0, &mut sector) {
        Ok(()) => {
            println!("[usbmsd] sector 0: {:02x?}", &sector[..16]);
        }
        Err(_) => {
            println!("[usbmsd] sector 0: read failed");
        }
    }

    // Fill in the real geometry now that READ CAPACITY has completed.
    {
        let mut device = MSD_DEVICE.lock();
        if let Some(dev) = device.as_mut() {
            dev.block_size = block_size;
            dev.block_count = block_count;
        }
    }

    // Publish the device through the block layer.  Who consumes it is not this
    // driver's business — the filesystem owns the device map and installs
    // itself as the sink at boot.
    let device: alloc::sync::Arc<dyn crate::kernel::block::BlockDevice> =
        alloc::sync::Arc::new(UsbMsdBlockDevice);
    if crate::kernel::block::publish_device("usb-msd", device) {
        println!("[usbmsd] Registered as block device 'usb-msd'");
        crate::drivers::record_bound_device(
            "usb-msd",
            "usb-msd",
            crate::drivers::DriverCategory::Storage,
            None,
        );
    } else {
        println!("[usbmsd] No block-device sink installed; 'usb-msd' was not registered");
    }
}
