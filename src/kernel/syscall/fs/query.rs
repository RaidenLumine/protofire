//! src/kernel/syscall/fs/query.rs
//! Filesystem query syscall handlers: mount/block-device enumeration and
//! security descriptor updates.

use alloc::vec::Vec;

use crate::abi::fs::{self, BlockDeviceInfoRecord, MountInfoRecord};
use crate::{Error, Result};

use super::user_memory::{copy_user_bytes, user_string};
use super::{validate_zeroed_args, SyscallContext, SyscallDispatch};

// ── ListMounts (slot 86) ──────────────────────────────────────────────────

pub(super) fn list_mounts(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let buffer_ptr = context.arg(0) as *mut u8;
    let buffer_len = context.arg(1);
    validate_zeroed_args(context, 2)?;

    let Some(fs_guard) = crate::kernel::fs::global() else {
        return Err(Error::InternalError);
    };
    let fs = fs_guard.lock();
    let mounts = fs.mount_points();

    let records: Vec<MountInfoRecord> = mounts
        .into_iter()
        .map(|m| {
            // Zero-init the record so `#[repr(C)]` padding bytes are not
            // leaked to user space when the record is serialized.
            let mut record: MountInfoRecord = unsafe { core::mem::zeroed() };

            fill_fixed_str(&mut record.path, &m.path);
            fill_fixed_str(&mut record.fs_name, &m.fs_name);
            fill_fixed_str(&mut record.device, &m.device);
            record.flags = m.flags as u64;
            record.reserved = 0;

            record
        })
        .collect();

    drop(fs);
    write_record_slice_to_user(&records, buffer_ptr, buffer_len)
}

// ── ListBlockDevices (slot 87) ────────────────────────────────────────────

pub(super) fn list_block_devices(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let buffer_ptr = context.arg(0) as *mut u8;
    let buffer_len = context.arg(1);
    validate_zeroed_args(context, 2)?;

    let Some(fs_guard) = crate::kernel::fs::global() else {
        return Err(Error::InternalError);
    };
    let fs = fs_guard.lock();
    let devices = fs.block_devices();

    let records: Vec<BlockDeviceInfoRecord> = devices
        .into_iter()
        .map(|d| {
            // Zero-init the record so `#[repr(C)]` padding bytes are not
            // leaked to user space when the record is serialized.
            let mut record: BlockDeviceInfoRecord = unsafe { core::mem::zeroed() };

            fill_fixed_str(&mut record.name, &d.name);
            record.block_size = d.block_size as u64;
            record.block_count = d.block_count;
            record.read_only = d.read_only as u64;

            record
        })
        .collect();

    drop(fs);
    write_record_slice_to_user(&records, buffer_ptr, buffer_len)
}

// ── SetSecurityDescriptor (slot 88) ───────────────────────────────────────

pub(super) fn set_security_descriptor(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let path_ptr = context.arg(0) as *const u8;
    let path_len = context.arg(1);
    let update_flags = context.arg(2) as u32;
    let mode = context.arg(3) as u16;
    let owner_uid = context.arg(4) as u32;
    let owner_gid = context.arg(5) as u32;

    // Validate flag bits.
    let known_flags = fs::SECURITY_DESCRIPTOR_UPDATE_KNOWN_FLAGS as u32;
    if update_flags & !known_flags != 0 {
        return Err(Error::InvalidArgument);
    }

    // Read the path from user memory.
    let path = user_string(path_ptr, path_len)?;

    // Build the security descriptor update from flags.
    let mut update = crate::kernel::fs::vfs::SecurityDescriptorUpdate::default();
    if update_flags & (fs::SECURITY_DESCRIPTOR_UPDATE_MODE as u32) != 0 {
        update = update.mode(mode);
    }
    if update_flags & (fs::SECURITY_DESCRIPTOR_UPDATE_OWNER_UID as u32) != 0 {
        update = update.owner_uid(owner_uid);
    }
    if update_flags & (fs::SECURITY_DESCRIPTOR_UPDATE_OWNER_GID as u32) != 0 {
        update = update.owner_gid(owner_gid);
    }

    // Authorize the update against the caller's security token so the
    // filesystem's permission-mutation policy gates the operation.
    super::runtime::with_current_process_security_token_fs(|token, fs| {
        let normalized = fs.normalize_path(&path)?;
        fs.update_persistent_security_descriptor_for_normalized_path(&normalized, update, token)?;
        Ok(SyscallDispatch::complete(0))
    })
}

// ── RepairVolume (slot 94) ───────────────────────────────────────────────

/// Volume check-and-repair report packed for user-space consumption.
#[repr(C)]
#[allow(dead_code)]
struct VolumeRepairReportRaw {
    issues_detected: u64,
    repairs_applied: u64,
    orphan_data_blocks: u64,
    checksum_failures: u64,
    staging_orphans_cleaned: u64,
    orphan_blocks_cleaned: u64,
    interrupted_commits: u64,
}

impl From<crate::kernel::fs::vfs::VolumeCheckReport> for VolumeRepairReportRaw {
    fn from(report: crate::kernel::fs::vfs::VolumeCheckReport) -> Self {
        Self {
            issues_detected: report.issues_detected as u64,
            repairs_applied: report.repairs_applied as u64,
            orphan_data_blocks: report.orphan_data_blocks as u64,
            checksum_failures: report.checksum_failures as u64,
            staging_orphans_cleaned: report.staging_orphans_cleaned as u64,
            orphan_blocks_cleaned: report.orphan_blocks_cleaned as u64,
            interrupted_commits: report.interrupted_commits as u64,
        }
    }
}

#[allow(dead_code)]
pub(super) fn repair_volume(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let path_ptr = context.arg(0) as *const u8;
    let path_len = context.arg(1);
    let report_buffer_ptr = context.arg(2) as *mut u8;
    let report_buffer_len = context.arg(3);
    validate_zeroed_args(context, 4)?;

    let report_size = core::mem::size_of::<VolumeRepairReportRaw>();
    if report_buffer_len < report_size {
        return Err(Error::InvalidArgument);
    }

    // Read the path from user memory.
    let path = user_string(path_ptr, path_len)?;

    let Some(fs_guard) = crate::kernel::fs::global() else {
        return Err(Error::InternalError);
    };
    let fs = fs_guard.lock();
    let report = fs.check_and_repair_volume_normalized(&path)?;
    let raw = VolumeRepairReportRaw::from(report);

    // Write the report to user memory.
    let raw_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &raw as *const VolumeRepairReportRaw as *const u8,
            report_size,
        )
    };
    copy_user_bytes(raw_bytes, report_buffer_ptr, report_size)?;

    Ok(SyscallDispatch::complete(report_size))
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Copy bytes from `src` into each fixed-size field, truncating or
/// zero-padding as needed.
fn fill_fixed_str(dest: &mut [u8], src: &str) {
    let bytes = src.as_bytes();
    let copy_len = bytes.len().min(dest.len());
    dest[..copy_len].copy_from_slice(&bytes[..copy_len]);
}

/// Write a slice of fixed-size records to a user buffer.
///
/// Returns the number of records written.  If `buffer_len == 0` (probe),
/// returns the total byte size needed for all records.
fn write_record_slice_to_user<T>(
    records: &[T],
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<SyscallDispatch> {
    let record_size = core::mem::size_of::<T>();

    // Probe mode: return required buffer size.
    if buffer_len == 0 {
        return Ok(SyscallDispatch::complete(core::mem::size_of_val(records)));
    }

    // Determine how many records fit.
    let count = (buffer_len / record_size).min(records.len());
    let byte_count = count * record_size;

    if count == 0 && !records.is_empty() {
        return Err(Error::InvalidArgument);
    }

    // Build contiguous byte slice from records into a zero-initialized
    // buffer so `#[repr(C)]` padding bytes are not leaked to user space.
    let mut bytes = alloc::vec![0u8; byte_count];
    for (slot, record) in bytes
        .chunks_exact_mut(record_size)
        .zip(records[..count].iter())
    {
        let ptr = (record as *const T).cast::<u8>();
        let slice = unsafe { core::slice::from_raw_parts(ptr, record_size) };
        slot.copy_from_slice(slice);
    }

    copy_user_bytes(&bytes, buffer_ptr, byte_count).map(|_| SyscallDispatch::complete(count))
}
