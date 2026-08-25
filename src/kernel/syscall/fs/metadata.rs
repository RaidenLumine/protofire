//! src/kernel/syscall/fs/metadata.rs
//!
//! Filesystem metadata syscalls: stat/read_dir, access queries, and permission
//! metadata records.

use crate::abi::fs as fs_abi;
use crate::kernel::device;
use crate::kernel::fs;
use crate::kernel::process::{HandleEntry, KernelObject};
use crate::{Error, Result};

pub(super) fn stat_at(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let source = super::fs_path::context_path_source_at_after_reserved(context, 0, 1, 2, 5)?;
    dispatch_stat_path_source(context, source, 3, 4)
}

pub(super) fn stat(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let source = super::fs_path::context_path_source_after_reserved(context, 0, 1, 4)?;
    dispatch_stat_path_source(context, source, 2, 3)
}

pub(super) fn read_dir(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 5)?;
    let output = directory_entry_output_after_validation(context, 2, 3, 4)?;
    let source = super::fs_path::context_path_source(context, 0, 1)?;
    dispatch_read_dir_path_source(source, output)
}

pub(super) fn access_query(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let source = super::fs_path::context_path_source_after_reserved(context, 0, 1, 5)?;
    dispatch_access_query_path_source(context, source, 2, 3, 4)
}

pub(super) fn access_query_at(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    dispatch_access_query_path_source(
        context,
        super::fs_path::context_path_source_at(context, 0, 1, 2)?,
        3,
        4,
        5,
    )
}

pub(super) fn rename(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let old_source = super::fs_path::context_path_source_after_reserved(context, 0, 1, 4)?;
    let new_source = super::fs_path::context_path_source(context, 2, 3)?;
    super::fs_path::dispatch_path_pair_sources(
        old_source,
        new_source,
        |normalized_old, normalized_new| rename_normalized_paths(&normalized_old, &normalized_new),
    )
}

pub(super) fn rename_at(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let old_source = super::fs_path::context_path_source_at(context, 0, 1, 2)?;
    let new_source = super::fs_path::context_path_source_at(context, 3, 4, 5)?;
    super::fs_path::dispatch_path_pair_sources(
        old_source,
        new_source,
        |normalized_old, normalized_new| rename_normalized_paths(&normalized_old, &normalized_new),
    )
}

pub(super) fn stat_fd(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    super::validate_zeroed_args(context, 3)?;
    dispatch_fd_fixed_record(context, fd, 1, 2, stat_record_for_handle)
}

pub(super) fn read_dir_fd(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    super::validate_zeroed_args(context, 4)?;
    let output = directory_entry_output_after_validation(context, 1, 2, 3)?;

    with_current_process_fd_entry(fd, |entry| {
        copy_directory_entry_result(
            read_dir_entry_for_handle(&entry, output.index),
            output.buffer_ptr,
            output.buffer_len,
        )
    })
}

pub(super) fn access_query_fd(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let required_access = access_query_required_access_arg(context.arg(1))?;
    super::validate_zeroed_args(context, 4)?;
    dispatch_fd_fixed_record(context, fd, 2, 3, |entry| {
        access_query_record_for_handle(entry, required_access)
    })
}

pub(super) fn permission_metadata(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let source = super::fs_path::context_path_source_after_reserved(context, 0, 1, 4)?;
    dispatch_permission_metadata_path_source(context, source, 2, 3)
}

pub(super) fn permission_metadata_at(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let source = super::fs_path::context_path_source_at_after_reserved(context, 0, 1, 2, 5)?;
    dispatch_permission_metadata_path_source(context, source, 3, 4)
}

pub(super) fn permission_metadata_fd(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    super::validate_zeroed_args(context, 3)?;
    dispatch_fd_fixed_record(context, fd, 1, 2, permission_metadata_record_for_handle)
}

fn with_current_process_fd_entry<T>(
    fd: usize,
    f: impl FnOnce(HandleEntry) -> Result<T>,
) -> Result<T> {
    super::runtime::current_process_fd_entry(fd).and_then(f)
}

fn dispatch_fd_fixed_record<T: super::user_memory::PaddingFree>(
    context: &super::SyscallContext,
    fd: usize,
    record_ptr_arg: usize,
    record_len_arg: usize,
    record_for_entry: impl FnOnce(&HandleEntry) -> Result<T>,
) -> Result<super::SyscallDispatch> {
    let record_buffer =
        super::user_memory::fixed_output_buffer_arg::<T>(context, record_ptr_arg, record_len_arg)?;
    with_current_process_fd_entry(fd, |entry| {
        record_buffer.finish_with(|| record_for_entry(&entry))
    })
}

fn rename_normalized_paths(old_path: &str, new_path: &str) -> Result<super::SyscallDispatch> {
    super::runtime::with_current_process_security_token_fs(|security_token, fs| {
        fs.rename_normalized_paths_with_security_token(old_path, new_path, security_token)
    })?;
    Ok(super::SyscallDispatch::complete(0))
}

fn dispatch_stat_path_source(
    context: &super::SyscallContext,
    source: super::fs_path::PathSource<'_>,
    record_ptr_arg: usize,
    record_len_arg: usize,
) -> Result<super::SyscallDispatch> {
    let record_buffer = super::user_memory::fixed_output_buffer_arg::<fs_abi::FileStat>(
        context,
        record_ptr_arg,
        record_len_arg,
    )?;
    super::fs_path::dispatch_path_source(source, |normalized_path| {
        record_buffer.finish_with(|| stat_record_for_normalized_path(&normalized_path))
    })
}

fn dispatch_read_dir_path_source(
    source: super::fs_path::PathSource<'_>,
    output: DirectoryEntryOutput,
) -> Result<super::SyscallDispatch> {
    super::fs_path::dispatch_path_source(source, |normalized_path| {
        copy_directory_entry_result(
            directory_entry_for_normalized_path(&normalized_path, output.index),
            output.buffer_ptr,
            output.buffer_len,
        )
    })
}

fn dispatch_access_query_path_source(
    context: &super::SyscallContext,
    source: super::fs_path::PathSource<'_>,
    required_access_arg: usize,
    record_ptr_arg: usize,
    record_len_arg: usize,
) -> Result<super::SyscallDispatch> {
    let required_access = access_query_required_access_arg(context.arg(required_access_arg))?;
    let record_buffer = super::user_memory::fixed_output_buffer_arg::<fs_abi::AccessQueryRecord>(
        context,
        record_ptr_arg,
        record_len_arg,
    )?;
    super::fs_path::dispatch_path_source(source, move |normalized_path| {
        record_buffer.finish_with(|| {
            access_query_record_for_normalized_path(&normalized_path, required_access)
        })
    })
}

fn dispatch_permission_metadata_path_source(
    context: &super::SyscallContext,
    source: super::fs_path::PathSource<'_>,
    record_ptr_arg: usize,
    record_len_arg: usize,
) -> Result<super::SyscallDispatch> {
    let record_buffer = super::user_memory::fixed_output_buffer_arg::<
        fs_abi::PermissionMetadataRecord,
    >(context, record_ptr_arg, record_len_arg)?;
    super::fs_path::dispatch_path_source(source, move |normalized_path| {
        record_buffer
            .finish_with(|| permission_metadata_record_for_normalized_path(&normalized_path))
    })
}

fn stat_record_for_normalized_path(normalized_path: &str) -> Result<fs_abi::FileStat> {
    if let Some(metadata) = device::virtual_device_metadata(normalized_path) {
        return Ok(encode_file_stat(metadata));
    }

    let metadata = super::runtime::with_global_fs(|fs| fs.stat_normalized_path(normalized_path))?;
    Ok(encode_file_stat(metadata))
}

fn directory_entry_for_normalized_path(
    normalized_path: &str,
    index: usize,
) -> Result<fs::DirectoryEntry> {
    if device::is_virtual_device_directory(normalized_path) {
        return device::virtual_device_directory_entry(index).ok_or(Error::NotFound);
    }

    super::runtime::with_global_fs(|fs| fs.read_dir_normalized(normalized_path, index))
}

fn access_query_record_for_normalized_path(
    normalized_path: &str,
    required_access: u16,
) -> Result<fs_abi::AccessQueryRecord> {
    super::runtime::with_current_process_security_token_fs(|security_token, fs| {
        Ok(fs
            .access_query_context_for_normalized_path_with_security_token(
                normalized_path,
                required_access,
                security_token,
            )?
            .public_access_query_record())
    })
}

fn permission_metadata_record_for_normalized_path(
    normalized_path: &str,
) -> Result<fs_abi::PermissionMetadataRecord> {
    let permission_metadata = super::runtime::with_global_fs(|fs| {
        fs.permission_metadata_for_normalized_path(normalized_path)
    })?;
    Ok(encode_permission_metadata_record(permission_metadata))
}

fn stat_record_for_handle(entry: &HandleEntry) -> Result<fs_abi::FileStat> {
    entry.public_file_stat_record(stat_record_for_normalized_path)
}

fn read_dir_entry_for_handle(entry: &HandleEntry, index: usize) -> Result<fs::DirectoryEntry> {
    directory_entry_for_normalized_path(entry.directory_backing_path()?, index)
}

fn access_query_record_for_handle(
    entry: &HandleEntry,
    required_access: u16,
) -> Result<fs_abi::AccessQueryRecord> {
    if let KernelObject::File(file) = &entry.object {
        return super::runtime::with_current_process(|process| {
            Ok(file
                .access_query_context_for(required_access, process.security_token())?
                .public_access_query_record())
        });
    }

    access_query_record_for_normalized_path(entry.metadata_backing_path()?, required_access)
}

fn permission_metadata_record_for_handle(
    entry: &HandleEntry,
) -> Result<fs_abi::PermissionMetadataRecord> {
    if let KernelObject::File(file) = &entry.object {
        return Ok(encode_permission_metadata_record(
            file.permission_metadata_record()?,
        ));
    }

    permission_metadata_record_for_normalized_path(entry.metadata_backing_path()?)
}

#[derive(Clone, Copy)]
struct DirectoryEntryOutput {
    index: usize,
    buffer_ptr: *mut u8,
    buffer_len: usize,
}

fn directory_entry_output_after_validation(
    context: &super::SyscallContext,
    index_arg: usize,
    buffer_ptr_arg: usize,
    buffer_len_arg: usize,
) -> Result<DirectoryEntryOutput> {
    let output = DirectoryEntryOutput {
        index: context.arg(index_arg),
        buffer_ptr: context.arg(buffer_ptr_arg) as *mut u8,
        buffer_len: context.arg(buffer_len_arg),
    };
    validate_directory_entry_output_buffer(output.buffer_ptr, output.buffer_len)?;
    Ok(output)
}

fn validate_directory_entry_output_buffer(buffer_ptr: *mut u8, buffer_len: usize) -> Result<()> {
    if buffer_len == 0 {
        return Ok(());
    }

    super::user_memory::validate_current_process_user_output_buffer(
        buffer_ptr,
        buffer_len,
        fs_abi::DIRECTORY_ENTRY_RECORD_SIZE,
    )
}

fn copy_directory_entry_value(
    entry: &fs::DirectoryEntry,
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    let record = encode_directory_entry_record(entry);
    super::user_memory::copy_user_value_with_trailing_bytes(
        &record,
        entry.name.as_bytes(),
        buffer_ptr,
        buffer_len,
    )
    .map(super::SyscallDispatch::complete)
}

fn copy_directory_entry_result(
    entry: Result<fs::DirectoryEntry>,
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    let entry = entry?;
    copy_directory_entry_value(&entry, buffer_ptr, buffer_len)
}

fn encode_file_stat(metadata: fs::FileMetadata) -> fs_abi::FileStat {
    // Syscall metadata encoding stays pinned to the current public exposure
    // policy even though the internal candidate view already tracks
    // owner/group/mode for future ABI work.
    metadata.public_stat_record()
}

fn encode_directory_entry_record(entry: &fs::DirectoryEntry) -> fs_abi::DirectoryEntryRecord {
    // `read_dir` shares the same explicit public-exposure policy as `stat`.
    entry.public_record()
}

fn encode_permission_metadata_record(
    record: fs::vfs::PermissionMetadataRecord,
) -> fs_abi::PermissionMetadataRecord {
    // Permission metadata is intentionally a separate public record so
    // ownership/mode can evolve without overloading `stat` or `read_dir`.
    fs_abi::PermissionMetadataRecord::new(record.owner_uid, record.owner_gid, record.mode)
}

fn access_query_required_access_arg(required_access: usize) -> Result<u16> {
    let required_access = u16::try_from(required_access).map_err(|_| Error::InvalidArgument)?;
    if required_access & !fs_abi::ACCESS_QUERY_KNOWN_ACCESS_MASK != 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(required_access)
}

#[cfg(test)]
mod tests {
    use super::{
        access_query_required_access_arg, encode_directory_entry_record, encode_file_stat,
        encode_permission_metadata_record,
    };
    use crate::abi::fs as fs_abi;
    use crate::kernel::fs::{
        self,
        vfs::{PermissionMetadataRecord as KernelPermissionMetadataRecord, SecurityDescriptor},
        NodeKind,
    };
    use crate::kernel::process::SecurityToken;
    use crate::Error;
    use alloc::string::String;

    #[test]
    fn encode_file_stat_keeps_public_shape_limited_to_kind_and_size() {
        let metadata = fs::FileMetadata::new(NodeKind::File, 123)
            .with_security(SecurityDescriptor::guest(0o600));
        let candidate = metadata.abi_candidate_view();

        let record = encode_file_stat(metadata);

        assert_eq!(record, fs_abi::FileStat::new(fs_abi::FILE_KIND_FILE, 123));
        assert_eq!(
            candidate.owner_uid,
            crate::kernel::process::DEFAULT_GUEST_USER_ID
        );
        assert_eq!(
            candidate.owner_gid,
            crate::kernel::process::DEFAULT_GUEST_GROUP_ID
        );
        assert_eq!(candidate.mode, 0o600);
    }

    #[test]
    fn encode_directory_entry_record_packs_name_bytes_after_header() {
        let entry = fs::DirectoryEntry::new(NodeKind::Directory, 7, String::from("guest"));

        let record = encode_directory_entry_record(&entry);

        assert_eq!(record.kind, fs_abi::FILE_KIND_DIRECTORY);
        assert_eq!(record.size, 7);
        assert_eq!(record.name_offset, fs_abi::DIRECTORY_ENTRY_RECORD_SIZE);
        assert_eq!(record.name_len, "guest".len());
    }

    #[test]
    fn syscall_metadata_encoding_follows_candidate_public_exposure_policy() {
        let metadata = fs::FileMetadata::new(NodeKind::File, 123)
            .with_security(SecurityDescriptor::guest(0o600));
        let entry = fs::DirectoryEntry::new(NodeKind::Directory, 7, String::from("guest"))
            .with_security(SecurityDescriptor::guest(0o700));

        assert_eq!(
            encode_file_stat(metadata.clone()),
            metadata.public_stat_record()
        );
        assert_eq!(encode_directory_entry_record(&entry), entry.public_record());
    }

    #[test]
    fn encode_file_stat_keeps_public_record_stable_across_internal_access_views() {
        let metadata = fs::FileMetadata::new(NodeKind::File, 123)
            .with_security(SecurityDescriptor::guest(0o600));

        let guest_context = metadata.access_query_context_for(0, SecurityToken::guest());
        let root_context =
            metadata.access_query_context_for(0, SecurityToken::root().with_authentication());
        let guest_record = encode_file_stat(metadata.clone());
        let root_record = encode_file_stat(metadata);

        assert_eq!(guest_context.metadata.mode, 0o600);
        assert_eq!(guest_context.access.granted_mode_bits, 0b110);
        assert!(!guest_context.access.bypasses_discretionary_permissions);
        assert_eq!(root_context.metadata.mode, 0o600);
        assert_eq!(root_context.access.granted_mode_bits, 0b111);
        assert!(root_context.access.bypasses_discretionary_permissions);
        assert_eq!(guest_record, root_record);
        assert_eq!(
            guest_record,
            fs_abi::FileStat::new(fs_abi::FILE_KIND_FILE, 123)
        );
    }

    #[test]
    fn encode_directory_entry_keeps_public_record_stable_across_internal_access_views() {
        let entry = fs::DirectoryEntry::new(NodeKind::Directory, 7, String::from("guest"))
            .with_security(SecurityDescriptor::guest(0o700));

        let guest_context = entry.access_query_context_for(0, SecurityToken::guest());
        let root_context =
            entry.access_query_context_for(0, SecurityToken::root().with_authentication());
        let guest_record = encode_directory_entry_record(&entry);
        let root_record = encode_directory_entry_record(&entry);

        assert_eq!(guest_context.metadata.mode, 0o700);
        assert_eq!(guest_context.access.granted_mode_bits, 0b111);
        assert!(!guest_context.access.bypasses_discretionary_permissions);
        assert_eq!(root_context.metadata.mode, 0o700);
        assert_eq!(root_context.access.granted_mode_bits, 0b111);
        assert!(root_context.access.bypasses_discretionary_permissions);
        assert_eq!(guest_record, root_record);
        assert_eq!(
            guest_record,
            fs_abi::DirectoryEntryRecord::new(fs_abi::FILE_KIND_DIRECTORY, 7, "guest".len())
        );
    }

    #[test]
    fn access_query_record_keeps_effective_access_flags_and_grants() {
        let metadata = fs::FileMetadata::new(NodeKind::File, 123)
            .with_security(SecurityDescriptor::guest(0o600));

        let guest_record = metadata
            .access_query_context_for(
                fs_abi::ACCESS_READ_BIT | fs_abi::ACCESS_WRITE_BIT,
                SecurityToken::guest(),
            )
            .public_access_query_record();
        let root_record = metadata
            .access_query_context_for(
                fs_abi::ACCESS_READ_BIT | fs_abi::ACCESS_WRITE_BIT | fs_abi::ACCESS_EXECUTE_BIT,
                SecurityToken::root().with_authentication(),
            )
            .public_access_query_record();

        assert_eq!(
            guest_record,
            fs_abi::AccessQueryRecord::new(
                fs_abi::ACCESS_READ_BIT | fs_abi::ACCESS_WRITE_BIT,
                fs_abi::ACCESS_READ_BIT | fs_abi::ACCESS_WRITE_BIT,
                fs_abi::ACCESS_QUERY_FLAG_ALLOWED
                    | fs_abi::ACCESS_QUERY_FLAG_CAN_READ
                    | fs_abi::ACCESS_QUERY_FLAG_CAN_WRITE
            )
        );
        assert_eq!(
            root_record,
            fs_abi::AccessQueryRecord::new(
                fs_abi::ACCESS_READ_BIT | fs_abi::ACCESS_WRITE_BIT | fs_abi::ACCESS_EXECUTE_BIT,
                fs_abi::ACCESS_READ_BIT | fs_abi::ACCESS_WRITE_BIT | fs_abi::ACCESS_EXECUTE_BIT,
                fs_abi::ACCESS_QUERY_FLAG_ALLOWED
                    | fs_abi::ACCESS_QUERY_FLAG_CAN_READ
                    | fs_abi::ACCESS_QUERY_FLAG_CAN_WRITE
                    | fs_abi::ACCESS_QUERY_FLAG_CAN_EXECUTE
                    | fs_abi::ACCESS_QUERY_FLAG_BYPASSES_DISCRETIONARY_PERMISSIONS
            )
        );
    }

    #[test]
    fn encode_permission_metadata_record_exposes_owner_group_and_mode_without_access_flags() {
        let record = encode_permission_metadata_record(KernelPermissionMetadataRecord {
            owner_uid: crate::kernel::process::DEFAULT_GUEST_USER_ID,
            owner_gid: crate::kernel::process::DEFAULT_GUEST_GROUP_ID,
            mode: 0o664,
        });

        assert_eq!(
            record,
            fs_abi::PermissionMetadataRecord::new(
                crate::kernel::process::DEFAULT_GUEST_USER_ID,
                crate::kernel::process::DEFAULT_GUEST_GROUP_ID,
                0o664
            )
        );
    }

    #[test]
    fn permission_metadata_record_stays_stable_across_internal_access_views() {
        let metadata = fs::FileMetadata::new(NodeKind::File, 123)
            .with_security(SecurityDescriptor::guest(0o600));

        let guest_context = metadata.access_query_context_for(0, SecurityToken::guest());
        let root_context =
            metadata.access_query_context_for(0, SecurityToken::root().with_authentication());
        let guest_record = encode_permission_metadata_record(metadata.permission_metadata_record());
        let root_record = encode_permission_metadata_record(metadata.permission_metadata_record());

        assert_eq!(guest_context.metadata.mode, 0o600);
        assert_eq!(guest_context.access.granted_mode_bits, 0b110);
        assert!(!guest_context.access.bypasses_discretionary_permissions);
        assert_eq!(root_context.metadata.mode, 0o600);
        assert_eq!(root_context.access.granted_mode_bits, 0b111);
        assert!(root_context.access.bypasses_discretionary_permissions);
        assert_eq!(guest_record, root_record);
        assert_eq!(
            guest_record,
            fs_abi::PermissionMetadataRecord::new(
                crate::kernel::process::DEFAULT_GUEST_USER_ID,
                crate::kernel::process::DEFAULT_GUEST_GROUP_ID,
                0o600
            )
        );
    }

    #[test]
    fn access_query_required_access_arg_rejects_unknown_bits() {
        assert_eq!(
            access_query_required_access_arg(fs_abi::ACCESS_QUERY_KNOWN_ACCESS_MASK as usize),
            Ok(fs_abi::ACCESS_QUERY_KNOWN_ACCESS_MASK)
        );
        assert_eq!(
            access_query_required_access_arg(
                (fs_abi::ACCESS_QUERY_KNOWN_ACCESS_MASK | 0b1000) as usize
            ),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            access_query_required_access_arg(usize::from(u16::MAX) + 1),
            Err(Error::InvalidArgument)
        );
    }
}
