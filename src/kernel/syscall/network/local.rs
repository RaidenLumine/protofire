//! src/kernel/syscall/network/local.rs
//!
//! Syscall handlers for Unix domain (local) socket operations
//! (BindLocal, ConnectLocal, AcceptLocal).

use crate::kernel::network::local;
use crate::kernel::process::HANDLE_RIGHT_READ;
use crate::kernel::process::HANDLE_RIGHT_WRITE;

pub(super) fn bind_local_socket(
    context: &mut super::SyscallContext,
) -> crate::Result<super::SyscallDispatch> {
    let path_ptr = context.arg(0);
    let path_len = context.arg(1);

    super::validate_zeroed_args(context, 2)?;

    let path = super::user_memory::user_string(path_ptr as *const u8, path_len)?;

    // Bind the local socket in the global registry.
    let socket = local::bind_local(&path)?;

    // Open an fd for the local socket (listener).  Only READ right is
    // required — accept is a read-like operation that returns a new
    // connected pipe VNode.
    super::runtime::with_current_process(|process| {
        let fd = process.open_local_socket_descriptor(&path, socket, HANDLE_RIGHT_READ)?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

pub(super) fn connect_local_socket(
    context: &mut super::SyscallContext,
) -> crate::Result<super::SyscallDispatch> {
    let path_ptr = context.arg(0);
    let path_len = context.arg(1);

    super::validate_zeroed_args(context, 2)?;

    let path = super::user_memory::user_string(path_ptr as *const u8, path_len)?;

    // Connect to the local socket.  Returns the client-side (write-end) VNode.
    let client_vnode = local::connect_local(&path)?;

    // Wrap the VNode in a pipe-backed FileHandle and open an fd.
    super::runtime::with_current_process(|process| {
        let fd = open_pipe_vnode_fd(process, client_vnode, HANDLE_RIGHT_WRITE)?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

pub(super) fn accept_local_socket(
    context: &mut super::SyscallContext,
) -> crate::Result<super::SyscallDispatch> {
    let listener_fd = context.arg(0);

    super::validate_zeroed_args(context, 1)?;

    super::runtime::with_current_process(|process| {
        let socket = process.get_local_socket(listener_fd)?;
        let server_vnode = local::accept_local(&socket)?;

        // Wrap the accepted VNode in a pipe-backed FileHandle.
        let fd = open_pipe_vnode_fd(process, server_vnode, HANDLE_RIGHT_READ)?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

/// Wrap a pipe VNode in a synthetic [`crate::kernel::fs::FileHandle`] and
/// open a file descriptor with the given rights.
fn open_pipe_vnode_fd(
    process: &crate::kernel::process::Process,
    vnode: alloc::sync::Arc<dyn crate::kernel::fs::vfs::VNode>,
    rights: u32,
) -> crate::Result<usize> {
    // Allocate a handle number from the global filesystem.
    let handle_num = crate::kernel::fs::global()
        .ok_or(crate::Error::InternalError)?
        .lock()
        .alloc_handles(1);

    let security = crate::kernel::fs::vfs::SecurityDescriptor::root_for_kind(
        crate::kernel::fs::NodeKind::File,
    );
    let security_source =
        crate::kernel::fs::vfs::SecurityDescriptorMutationSupport::LayoutDerivedOnly;

    let file_handle =
        crate::kernel::fs::FileHandle::new(handle_num, vnode, security, security_source, 0);

    process.open_file_descriptor("local-socket", file_handle, rights)
}
