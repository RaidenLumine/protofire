//! src/kernel/syscall/fs/path_ops.rs
//!
//! Filesystem path operation syscalls: open/create/remove/rename flows.

use alloc::string::String;

use crate::abi::io as io_abi;
use crate::kernel::device;
use crate::kernel::fs;
use crate::kernel::process::Process;
use crate::kernel::process::SecurityToken;
use crate::kernel::process::HANDLE_RIGHT_READ;
use crate::kernel::process::HANDLE_RIGHT_WRITE;
use crate::Error;
use crate::Result;

type NamespaceMutation = fn(&fs::FileSystem, &str, SecurityToken) -> Result<()>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpenPathRequest {
    rights: u32,
    creation_disposition: u32,
}

impl OpenPathRequest {
    fn from_flags(open_flags: usize) -> Self {
        let rights = if open_flags & io_abi::OPEN_FLAG_WRITE != 0 {
            if open_flags & io_abi::OPEN_FLAG_READ != 0 {
                HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE
            } else {
                HANDLE_RIGHT_WRITE
            }
        } else {
            HANDLE_RIGHT_READ
        };
        let creation_disposition = if open_flags & io_abi::OPEN_FLAG_CREATE != 0 {
            fs::OPEN_ALWAYS
        } else {
            fs::OPEN_EXISTING
        };

        Self {
            rights,
            creation_disposition,
        }
    }

    const fn requests_create(self) -> bool {
        self.creation_disposition == fs::OPEN_ALWAYS
    }

    fn validate_directory_descriptor_rights(self) -> Result<()> {
        Process::validate_descriptor_rights_exact_request(self.rights, HANDLE_RIGHT_READ)
    }
}

pub(super) fn open(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let request = open_path_request_after_validation(context, 2, 3)?;
    dispatch_open_path_source(super::fs_path::context_path_source(context, 0, 1)?, request)
}

pub(super) fn open_at(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let request = open_path_request_after_validation(context, 3, 4)?;
    dispatch_open_path_source(
        super::fs_path::context_path_source_at(context, 0, 1, 2)?,
        request,
    )
}

pub(super) fn create_dir(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    dispatch_mutating_path_source(
        super::fs_path::context_path_source_after_reserved(context, 0, 1, 2)?,
        fs::FileSystem::create_dir_normalized_with_security_token,
    )
}

pub(super) fn create_dir_at(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    dispatch_mutating_path_source(
        super::fs_path::context_path_source_at_after_reserved(context, 0, 1, 2, 3)?,
        fs::FileSystem::create_dir_normalized_with_security_token,
    )
}

pub(super) fn remove_path(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    dispatch_mutating_path_source(
        super::fs_path::context_path_source_after_reserved(context, 0, 1, 2)?,
        fs::FileSystem::remove_normalized_path_with_security_token,
    )
}

pub(super) fn remove_path_at(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    dispatch_mutating_path_source(
        super::fs_path::context_path_source_at_after_reserved(context, 0, 1, 2, 3)?,
        fs::FileSystem::remove_normalized_path_with_security_token,
    )
}

fn open_path_request_after_validation(
    context: &super::SyscallContext,
    open_flags_arg: usize,
    reserved_arg: usize,
) -> Result<OpenPathRequest> {
    let open_flags = context.arg(open_flags_arg);
    // Keep ABI strict: reject unknown flags and non-zero trailing reserved slots
    // before decoding user path memory.
    super::validate_known_flags(open_flags, io_abi::OPEN_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, reserved_arg)?;
    Ok(OpenPathRequest::from_flags(open_flags))
}

fn dispatch_mutating_path_source(
    source: super::fs_path::PathSource<'_>,
    mutate: NamespaceMutation,
) -> Result<super::SyscallDispatch> {
    super::fs_path::dispatch_path_source(source, |normalized_path| {
        super::runtime::with_current_process_security_token_fs(|security_token, fs| {
            mutate(fs, &normalized_path, security_token)
        })?;
        Ok(super::SyscallDispatch::complete(0))
    })
}

fn dispatch_open_path_source(
    source: super::fs_path::PathSource<'_>,
    request: OpenPathRequest,
) -> Result<super::SyscallDispatch> {
    super::fs_path::with_current_process_path_source(source, |process, normalized_path| {
        open_normalized_path(process, normalized_path, request)
    })
}

fn open_named_device(
    process: &Process,
    normalized_path: &str,
    request: OpenPathRequest,
) -> Result<Option<usize>> {
    let Some(node) = device::virtual_device_node(normalized_path) else {
        return Ok(None);
    };
    let device_name = node.target_name;
    let supported_rights = node.supported_rights();

    if request.requests_create() {
        // Device aliases are virtual nodes and cannot be created.
        return Err(Error::InvalidArgument);
    }

    // Fixed-direction aliases (stdin/stdout/stderr/debug/keyboard) reject
    // incompatible access bits, while console/serial0 accept any non-zero
    // subset of their read/write capability masks.
    Process::validate_descriptor_rights_subset_request(request.rights, supported_rights)?;

    super::runtime::with_global_fs(|fs| {
        fs.authorize_open_normalized_path_with_security_token(
            normalized_path,
            request.rights,
            process.security_token(),
        )
    })?;

    let fd = process.open_device_descriptor(device_name, request.rights)?;
    Ok(Some(fd))
}

fn open_normalized_path(
    process: &Process,
    normalized_path: String,
    request: OpenPathRequest,
) -> Result<super::SyscallDispatch> {
    if let Some(fd) = open_named_device(process, &normalized_path, request)? {
        return Ok(super::SyscallDispatch::complete(fd));
    }

    let file = super::runtime::with_global_fs(|fs| {
        fs.create_file_normalized_with_security_token(
            &normalized_path,
            request.rights,
            0,
            request.creation_disposition,
            process.security_token(),
        )
    })?;
    if file.kind() == fs::NodeKind::Directory {
        // Directory descriptors are metadata-only and must remain read-only.
        request.validate_directory_descriptor_rights()?;

        let fd = process.open_directory_descriptor(&normalized_path, request.rights)?;
        return Ok(super::SyscallDispatch::complete(fd));
    }

    let fd = process.open_file_descriptor(&normalized_path, file, request.rights)?;
    Ok(super::SyscallDispatch::complete(fd))
}

pub(super) fn mount(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let flags = context.arg(4) as u32;
    super::validate_known_flags(
        flags as usize,
        crate::kernel::fs::layout::MOUNT_KNOWN_FLAGS as usize,
    )?;
    super::validate_zeroed_args(context, 5)?;

    let target_source = super::fs_path::context_path_source(context, 0, 1)?;
    let fstype = super::user_memory::user_path_arg(context, 2, 3)?;

    super::fs_path::dispatch_path_source(target_source, |normalized_target| {
        super::runtime::with_current_process_security_token_fs(|_security_token, fs| {
            let device = alloc::format!("/dev/adastra-{}", fstype);
            fs.mount(&device, &normalized_target, fstype, flags)
        })?;
        Ok(super::SyscallDispatch::complete(0))
    })
}

pub(super) fn umount(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 2)?;
    let target_source = super::fs_path::context_path_source_after_reserved(context, 0, 1, 2)?;
    super::fs_path::dispatch_path_source(target_source, |normalized_target| {
        super::runtime::with_current_process_security_token_fs(|_security_token, fs| {
            fs.unmount(&normalized_target)
        })?;
        Ok(super::SyscallDispatch::complete(0))
    })
}

#[cfg(test)]
mod tests {
    use super::OpenPathRequest;
    use crate::abi::io as io_abi;
    use crate::kernel::fs;
    use crate::kernel::process::HANDLE_RIGHT_READ;
    use crate::kernel::process::HANDLE_RIGHT_WRITE;
    use crate::Error;

    #[test]
    fn open_path_request_defaults_to_read_existing() {
        let request = OpenPathRequest::from_flags(io_abi::OPEN_FLAG_NONE);

        assert_eq!(request.rights, HANDLE_RIGHT_READ);
        assert_eq!(request.creation_disposition, fs::OPEN_EXISTING);
        assert!(!request.requests_create());
    }

    #[test]
    fn open_path_request_maps_write_and_create_combinations() {
        let write_create = OpenPathRequest::from_flags(io_abi::OPEN_FLAG_WRITE_CREATE);
        assert_eq!(write_create.rights, HANDLE_RIGHT_WRITE);
        assert_eq!(write_create.creation_disposition, fs::OPEN_ALWAYS);
        assert!(write_create.requests_create());

        let read_write_create = OpenPathRequest::from_flags(io_abi::OPEN_FLAG_READ_WRITE_CREATE);
        assert_eq!(
            read_write_create.rights,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE
        );
        assert_eq!(read_write_create.creation_disposition, fs::OPEN_ALWAYS);
        assert!(read_write_create.requests_create());
    }

    #[test]
    fn directory_descriptor_requests_remain_read_only() {
        let read_only = OpenPathRequest::from_flags(io_abi::OPEN_FLAG_READ);
        assert_eq!(read_only.validate_directory_descriptor_rights(), Ok(()));

        let read_write = OpenPathRequest::from_flags(io_abi::OPEN_FLAG_READ_WRITE);
        assert_eq!(
            read_write.validate_directory_descriptor_rights(),
            Err(Error::PermissionDenied)
        );

        let write_only = OpenPathRequest::from_flags(io_abi::OPEN_FLAG_WRITE);
        assert_eq!(
            write_only.validate_directory_descriptor_rights(),
            Err(Error::PermissionDenied)
        );
    }

    // -- mount / umount syscall tests -------------------------------

    use super::super::SyscallContext;
    use super::super::SyscallNumber;

    #[test]
    fn mount_syscall_rejects_unknown_flags() {
        let _guard = super::super::test_support::test_lock();
        let mut ctx = SyscallContext::new(
            SyscallNumber::Mount as usize,
            [
                0,      // target_ptr (invalid, but flags fail first)
                0,      // target_len
                0,      // fstype_ptr
                0,      // fstype_len
                0xFFFF, // flags (includes unknown bits)
                0,      // reserved
            ],
        );
        let result = super::mount(&mut ctx);
        assert!(result.is_err());
    }

    #[test]
    fn mount_syscall_rejects_nonzero_reserved_arg() {
        let _guard = super::super::test_support::test_lock();
        let mut ctx = SyscallContext::new(
            SyscallNumber::Mount as usize,
            [
                0, // target_ptr
                0, // target_len
                0, // fstype_ptr
                0, // fstype_len
                0, // flags
                1, // reserved (must be zero)
            ],
        );
        let result = super::mount(&mut ctx);
        assert!(result.is_err());
    }

    #[test]
    fn umount_syscall_rejects_nonzero_reserved_args() {
        let _guard = super::super::test_support::test_lock();
        let mut ctx = SyscallContext::new(
            SyscallNumber::Umount as usize,
            [
                0, // target_ptr
                0, // target_len
                1, // reserved (must be zero)
                0, 0, 0,
            ],
        );
        let result = super::umount(&mut ctx);
        assert!(result.is_err());
    }
}
