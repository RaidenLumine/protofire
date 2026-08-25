//! src/kernel/syscall/fs/fuse_mount.rs
//!
//! FuseMount syscall handler — creates a FUSE mount point.
//!
//! # Arguments
//!
//! | Arg | Type | Description |
//! |-----|------|-------------|
//! | 0   | `*const u8` | Mount path string pointer |
//! | 1   | `usize` | Mount path string length |
//! | 2   | `*const u8` | Filesystem name string pointer |
//! | 3   | `usize` | Filesystem name string length |
//! | 4   | `*mut [usize; 2]` | Output buffer for daemon-end FDs |
//! | 5   | `usize` | Output buffer length (must be 2 × sizeof(usize)) |
//!
//! # Returns
//!
//! 0 on success, or a negative errno on failure.

use alloc::string::ToString;
use alloc::sync::Arc;

use crate::kernel::fs::fuse::FuseConnection;
use crate::kernel::fs::fuse::FuseFileSystem;
use crate::kernel::fs::pipe;
use crate::kernel::fs::vfs::FileSystem as VfsTrait;
use crate::kernel::fs::vfs::SecurityDescriptor;
use crate::kernel::fs::vfs::SecurityDescriptorMutationSupport;
use crate::kernel::fs::FileHandle;
use crate::kernel::fs::NodeKind;
use crate::kernel::process::process::constants::HANDLE_RIGHT_READ;
use crate::kernel::process::process::constants::HANDLE_RIGHT_WRITE;
use crate::Result;

pub(super) fn fuse_mount(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    // ── 1. Read arguments ──────────────────────────────────────────────
    let mount_path = super::user_memory::user_path_arg(context, 0, 1)?.to_string();
    let fs_name = super::user_memory::user_path_arg(context, 2, 3)?.to_string();
    let buffer_ptr = context.arg(4) as *mut u8;
    let buffer_len = context.arg(5);

    super::validate_zeroed_args(context, 6)?;

    // ── 2. Create two pipe channels ─────────────────────────────────────
    let (req_daemon_read, req_kernel_write) = pipe::pipe_channel();
    let (resp_kernel_read, resp_daemon_write) = pipe::pipe_channel();

    // ── 3. Create FUSE connection ──────────────────────────────────────
    let conn = Arc::new(FuseConnection::new(req_kernel_write, resp_kernel_read));

    // ── 4. Create FUSE filesystem ──────────────────────────────────────
    let fs = Arc::new(FuseFileSystem::new(fs_name.clone(), conn));

    // ── 5. Register and mount in the global VFS ────────────────────────
    {
        let global_fs = crate::kernel::fs::global().ok_or(crate::Error::InternalError)?;
        let mut fs_guard = global_fs.lock();

        let device = alloc::format!("/dev/fuse/{}", fs_name);
        fs_guard.register(&fs_name, fs as Arc<dyn VfsTrait>);
        fs_guard.mount(&device, &mount_path, &fs_name, 0)?;
    }

    // ── 6. Convert daemon-end VNodes to FDs ────────────────────────────
    super::runtime::with_current_process(|process| {
        // Allocate two consecutive handle numbers from the global filesystem.
        let read_handle = crate::kernel::fs::global()
            .ok_or(crate::Error::InternalError)?
            .lock()
            .alloc_handles(2);
        let write_handle = read_handle + 1;

        let security = SecurityDescriptor::root_for_kind(NodeKind::File);
        let security_source = SecurityDescriptorMutationSupport::LayoutDerivedOnly;

        let req_file_handle =
            FileHandle::new(read_handle, req_daemon_read, security, security_source, 0);

        let resp_file_handle = FileHandle::new(
            write_handle,
            resp_daemon_write,
            security,
            security_source,
            0,
        );

        let req_fd = process.open_file_descriptor(
            &alloc::format!("fuse:{}:req", fs_name),
            req_file_handle,
            HANDLE_RIGHT_READ,
        )?;
        let resp_fd = process.open_file_descriptor(
            &alloc::format!("fuse:{}:resp", fs_name),
            resp_file_handle,
            HANDLE_RIGHT_WRITE,
        )?;

        // Write both FDs to the user-provided output buffer.
        let output =
            super::user_memory::FixedOutputBuffer::<[usize; 2]>::new(buffer_ptr, buffer_len)?;
        output.copy_value(&[req_fd, resp_fd])
    })?;

    Ok(super::SyscallDispatch::complete(0))
}
