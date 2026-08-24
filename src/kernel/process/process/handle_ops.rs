//! src/kernel/process/process/handle_ops.rs
//!
//! Process handle-table and file-descriptor operations: opening kernel
//! objects as handles and file descriptors, fd flags, standard-handle
//! bindings, and handle/fd duplication and redirection.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::kernel::device;
use crate::kernel::fs::FileHandle as FsFileHandle;
use crate::kernel::network::tls::TlsWrappedConnection;
use crate::kernel::network::{DccpSocket, TcpConnection};
use crate::{Error, Result};

use super::constants::*;
use super::types::*;
use super::Process;

impl Process {
    pub(crate) fn open_handle(&self, object: KernelObject, rights: u32) -> Result<Handle> {
        self.ensure_mutable()?;
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handle_table
            .lock()
            .insert(handle, HandleEntry { object, rights });
        Ok(handle)
    }

    pub(crate) fn install_fd_handle(&self, handle: Handle) -> Result<FileDescriptor> {
        self.ensure_mutable()?;
        let fd = self.next_fd.fetch_add(1, Ordering::Relaxed) as FileDescriptor;
        self.fd_table.lock().insert(fd, handle);
        Ok(fd)
    }

    /// Set or clear per-fd flags (e.g. `FdFlags::CLOEXEC`).
    ///
    /// The fd must already be bound; returns `NotFound` otherwise.
    pub fn set_fd_flags(&self, fd: FileDescriptor, set: FdFlags, clear: FdFlags) -> Result<()> {
        self.ensure_mutable()?;
        // Verify the fd exists before mutating flags.
        self.resolve_fd_handle(fd)?;
        let mut flags_map = self.fd_flags.lock();
        let flags = flags_map.entry(fd).or_default();
        flags.set(set);
        flags.clear(clear);
        if *flags == FdFlags::NONE {
            flags_map.remove(&fd);
        }
        Ok(())
    }

    /// Return the flags currently set on a file descriptor.
    pub fn get_fd_flags(&self, fd: FileDescriptor) -> Result<FdFlags> {
        self.resolve_fd_handle(fd)?;
        Ok(self
            .fd_flags
            .lock()
            .get(&fd)
            .copied()
            .unwrap_or(FdFlags::NONE))
    }

    /// Close every file descriptor whose `FdFlags::CLOEXEC` flag is set.
    ///
    /// This is called during `exec` so the new program image does not inherit
    /// descriptors that were explicitly marked close-on-exec.
    pub fn close_cloexec_fds(&self) {
        let cloexec_fds: Vec<FileDescriptor> = self
            .fd_flags
            .lock()
            .iter()
            .filter(|(_, flags)| flags.contains(FdFlags::CLOEXEC))
            .map(|(&fd, _)| fd)
            .collect();

        for fd in cloexec_fds {
            let _ = self.close_fd(fd);
        }
    }

    /// Copy every file descriptor that does *not* have `FdFlags::CLOEXEC` set
    /// from `source` into `self`, reopening each underlying handle so the child
    /// owns independent references.
    ///
    /// This is called during `spawn` when the caller sets
    /// `PROCESS_SPAWN_FLAG_INHERIT_FDS`.
    pub fn inherit_fds_from(&self, source: &Process) -> Result<()> {
        self.ensure_mutable()?;
        // Snapshot the source fd table and flags under one lock acquisition
        // window so we don't race with source-side mutations.
        let source_fd_table = source.fd_table.lock();
        let source_fd_flags = source.fd_flags.lock();

        // Collect (source_fd, handle, cloexec, other_flags) tuples.
        let inheritable: Vec<(FileDescriptor, Handle, bool, FdFlags)> = source_fd_table
            .iter()
            .map(|(&fd, &handle)| {
                let flags = source_fd_flags.get(&fd).copied().unwrap_or(FdFlags::NONE);
                let cloexec = flags.contains(FdFlags::CLOEXEC);
                let other_flags = FdFlags(flags.0 & !FdFlags::CLOEXEC.0);
                (fd, handle, cloexec, other_flags)
            })
            .collect();

        // Release source locks before acquiring child locks to avoid deadlocks.
        drop(source_fd_flags);
        drop(source_fd_table);

        for (_source_fd, source_handle, cloexec, other_flags) in inheritable {
            if cloexec {
                continue;
            }
            // Reopen the handle in the child so it gets its own reference.
            let entry = source.handle_entry(source_handle)?;
            let child_handle = entry.reopen_handle_in(self)?;
            // Install into the child fd table at a fresh fd number.
            let child_fd = self.install_fd_handle(child_handle)?;
            // Preserve any non-CLOEXEC flags the source fd had.
            if other_flags != FdFlags::NONE {
                self.fd_flags.lock().insert(child_fd, other_flags);
            }
            let _ = child_fd;
        }

        Ok(())
    }

    pub(crate) fn open_descriptor(
        &self,
        object: KernelObject,
        rights: u32,
    ) -> Result<FileDescriptor> {
        let handle = self.open_handle(object, rights)?;
        self.cleanup_on_error(&[handle], self.install_fd_handle(handle))
    }

    pub(crate) fn reopen_object_handle(&self, object: KernelObject, rights: u32) -> Result<Handle> {
        match object {
            KernelObject::File(file) => self.open_handle(KernelObject::File(file), rights),
            KernelObject::Directory(path) => self.open_directory_handle(&path, rights),
            KernelObject::Device(name) => self.open_device_handle(&name, rights),
            KernelObject::Network(connection) => {
                let endpoint = connection.endpoint().to_string();
                self.open_network_handle(&endpoint, connection, rights)
            }
            KernelObject::Process(pid) => self.open_handle(KernelObject::Process(pid), rights),
            KernelObject::Thread(tid) => self.open_handle(KernelObject::Thread(tid), rights),
            KernelObject::TcpListener(listener) => {
                let port = listener.port();
                self.open_listener_handle(port, listener, rights)
            }
            KernelObject::UdpSocket(socket) => {
                let port = socket.port();
                self.open_udp_handle(port, socket, rights)
            }
            KernelObject::DccpSocket(socket) => {
                let port = socket.local_port;
                self.open_dccp_handle(port, socket, rights)
            }
            KernelObject::RawSocket(handle) => self.open_raw_socket_handle(handle, rights),
            KernelObject::LocalSocket(socket) => {
                let path = socket.path.clone();
                self.open_local_socket_handle(&path, alloc::sync::Arc::clone(&socket), rights)
            }
            KernelObject::TlsConnection(connection) => {
                let endpoint = connection.endpoint().to_string();
                self.open_tls_handle(&endpoint, alloc::sync::Arc::clone(&connection), rights)
            }
            KernelObject::EventFd(state) => self.open_handle(
                KernelObject::EventFd(alloc::sync::Arc::clone(&state)),
                rights,
            ),
            KernelObject::SignalFd(state) => self.open_handle(
                KernelObject::SignalFd(alloc::sync::Arc::clone(&state)),
                rights,
            ),
            KernelObject::TimerFd(state) => self.open_handle(
                KernelObject::TimerFd(alloc::sync::Arc::clone(&state)),
                rights,
            ),
            KernelObject::Mqueue(state) => self.open_handle(
                KernelObject::Mqueue(alloc::sync::Arc::clone(&state)),
                rights,
            ),
            KernelObject::Epoll(state) => {
                self.open_handle(KernelObject::Epoll(alloc::sync::Arc::clone(&state)), rights)
            }
            KernelObject::IoUring(state) => self.open_handle(
                KernelObject::IoUring(alloc::sync::Arc::clone(&state)),
                rights,
            ),
        }
    }

    pub(crate) fn reopen_object_descriptor(
        &self,
        object: KernelObject,
        rights: u32,
    ) -> Result<FileDescriptor> {
        match object {
            KernelObject::File(file) => self.open_descriptor(KernelObject::File(file), rights),
            KernelObject::Directory(path) => self.open_directory_descriptor(&path, rights),
            KernelObject::Device(name) => self.open_device_descriptor(&name, rights),
            KernelObject::Network(connection) => {
                let endpoint = connection.endpoint().to_string();
                self.open_network_descriptor(&endpoint, connection, rights)
            }
            KernelObject::Process(pid) => self.open_descriptor(KernelObject::Process(pid), rights),
            KernelObject::Thread(tid) => self.open_descriptor(KernelObject::Thread(tid), rights),
            KernelObject::TcpListener(listener) => {
                let port = listener.port();
                self.open_listener_descriptor(port, listener, rights)
            }
            KernelObject::UdpSocket(socket) => {
                let port = socket.port();
                self.open_udp_descriptor(port, socket, rights)
            }
            KernelObject::DccpSocket(socket) => {
                let port = socket.local_port;
                self.open_dccp_descriptor(port, socket, rights)
            }
            KernelObject::RawSocket(handle) => self.open_raw_socket_descriptor(handle, rights),
            KernelObject::LocalSocket(socket) => {
                let path = socket.path.clone();
                self.open_local_socket_descriptor(&path, alloc::sync::Arc::clone(&socket), rights)
            }
            KernelObject::TlsConnection(connection) => {
                let endpoint = connection.endpoint().to_string();
                self.open_tls_descriptor(&endpoint, alloc::sync::Arc::clone(&connection), rights)
            }
            KernelObject::EventFd(state) => self.open_descriptor(
                KernelObject::EventFd(alloc::sync::Arc::clone(&state)),
                rights,
            ),
            KernelObject::SignalFd(state) => self.open_descriptor(
                KernelObject::SignalFd(alloc::sync::Arc::clone(&state)),
                rights,
            ),
            KernelObject::TimerFd(state) => self.open_descriptor(
                KernelObject::TimerFd(alloc::sync::Arc::clone(&state)),
                rights,
            ),
            KernelObject::Mqueue(state) => self.open_descriptor(
                KernelObject::Mqueue(alloc::sync::Arc::clone(&state)),
                rights,
            ),
            KernelObject::Epoll(state) => {
                self.open_descriptor(KernelObject::Epoll(alloc::sync::Arc::clone(&state)), rights)
            }
            KernelObject::IoUring(state) => self.open_descriptor(
                KernelObject::IoUring(alloc::sync::Arc::clone(&state)),
                rights,
            ),
        }
    }

    pub(crate) fn file_object(path: &str, file: FsFileHandle) -> KernelObject {
        KernelObject::File(OpenFile::new(path, file))
    }

    fn directory_object(path: &str) -> KernelObject {
        KernelObject::Directory(path.to_string())
    }

    fn device_object(name: &str) -> KernelObject {
        KernelObject::Device(name.to_string())
    }

    fn network_object(connection: TcpConnection) -> KernelObject {
        KernelObject::Network(connection)
    }

    /// Open a file object and return a kernel handle with the requested access rights.
    pub fn open_file_handle(&self, path: &str, file: FsFileHandle, rights: u32) -> Result<Handle> {
        self.open_handle(Self::file_object(path, file), rights)
    }

    /// Open a file object and return a file descriptor with the requested access rights.
    pub fn open_file_descriptor(
        &self,
        path: &str,
        file: FsFileHandle,
        rights: u32,
    ) -> Result<FileDescriptor> {
        self.open_descriptor(Self::file_object(path, file), rights)
    }

    /// Open a directory path and return a kernel handle with the requested access rights.
    pub fn open_directory_handle(&self, path: &str, rights: u32) -> Result<Handle> {
        self.open_handle(Self::directory_object(path), rights)
    }

    /// Open a directory path and return a file descriptor with the requested access rights.
    pub fn open_directory_descriptor(&self, path: &str, rights: u32) -> Result<FileDescriptor> {
        self.open_descriptor(Self::directory_object(path), rights)
    }

    /// Open a device by name and return a kernel handle with the requested access rights.
    pub fn open_device_handle(&self, name: &str, rights: u32) -> Result<Handle> {
        self.open_validated_object(
            Self::device_object(name),
            rights,
            Self::validate_device_descriptor_request(name, rights),
            Self::open_handle,
        )
    }

    /// Open a device by name and return a file descriptor with the requested access rights.
    pub fn open_device_descriptor(&self, name: &str, rights: u32) -> Result<FileDescriptor> {
        self.open_validated_object(
            Self::device_object(name),
            rights,
            Self::validate_device_descriptor_request(name, rights),
            Self::open_descriptor,
        )
    }

    /// Open a TCP connection and return a kernel handle with the requested access rights.
    pub fn open_network_handle(
        &self,
        endpoint: &str,
        connection: TcpConnection,
        rights: u32,
    ) -> Result<Handle> {
        self.open_validated_object(
            Self::network_object(connection),
            rights,
            Self::validate_network_descriptor_request(endpoint, rights),
            Self::open_handle,
        )
    }

    /// Open a TCP connection and return a file descriptor with the requested access rights.
    pub fn open_network_descriptor(
        &self,
        endpoint: &str,
        connection: TcpConnection,
        rights: u32,
    ) -> Result<FileDescriptor> {
        self.open_validated_object(
            Self::network_object(connection),
            rights,
            Self::validate_network_descriptor_request(endpoint, rights),
            Self::open_descriptor,
        )
    }

    /// Open a DCCP socket and return a kernel handle with the requested access rights.
    pub fn open_dccp_handle(&self, port: u16, socket: DccpSocket, rights: u32) -> Result<Handle> {
        self.open_validated_object(
            Self::dccp_socket_object(socket),
            rights,
            Self::validate_dccp_descriptor_request(port, rights),
            Self::open_handle,
        )
    }

    /// Open a DCCP socket and return a file descriptor with the requested access rights.
    pub fn open_dccp_descriptor(
        &self,
        port: u16,
        socket: DccpSocket,
        rights: u32,
    ) -> Result<FileDescriptor> {
        self.open_validated_object(
            Self::dccp_socket_object(socket),
            rights,
            Self::validate_dccp_descriptor_request(port, rights),
            Self::open_descriptor,
        )
    }

    /// Open a TLS connection and return a kernel handle with the requested access rights.
    pub fn open_tls_handle(
        &self,
        endpoint: &str,
        connection: Arc<TlsWrappedConnection>,
        rights: u32,
    ) -> Result<Handle> {
        self.open_validated_object(
            Self::tls_connection_object(connection),
            rights,
            Self::validate_tls_descriptor_request(endpoint, rights),
            Self::open_handle,
        )
    }

    /// Open a TLS connection and return a file descriptor with the requested access rights.
    pub fn open_tls_descriptor(
        &self,
        endpoint: &str,
        connection: Arc<TlsWrappedConnection>,
        rights: u32,
    ) -> Result<FileDescriptor> {
        self.open_validated_object(
            Self::tls_connection_object(connection),
            rights,
            Self::validate_tls_descriptor_request(endpoint, rights),
            Self::open_descriptor,
        )
    }

    /// Open an io_uring instance and return a file descriptor.
    ///
    /// The io_uring fd carries read+write rights so both submission and
    /// completion phases are permitted.
    pub fn open_io_uring_descriptor(&self, state: Arc<IoUringState>) -> Result<FileDescriptor> {
        self.open_descriptor(
            KernelObject::IoUring(Arc::clone(&state)),
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
    }

    fn dccp_socket_object(socket: DccpSocket) -> KernelObject {
        KernelObject::DccpSocket(socket)
    }

    fn validate_dccp_descriptor_request(port: u16, rights: u32) -> Result<()> {
        if port == 0 {
            return Err(Error::InvalidArgument);
        }
        // DCCP sockets need both READ and WRITE rights (send + recv).
        Self::validate_descriptor_rights_exact_request(
            rights,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
    }

    fn tls_connection_object(connection: Arc<TlsWrappedConnection>) -> KernelObject {
        KernelObject::TlsConnection(connection)
    }

    fn validate_tls_descriptor_request(endpoint: &str, rights: u32) -> Result<()> {
        if endpoint.trim().is_empty() {
            return Err(Error::PermissionDenied);
        }
        // TLS connections need both READ and WRITE rights (send + recv).
        Self::validate_descriptor_rights_exact_request(
            rights,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
    }

    /// Validate rights against the supported set, then open the object.
    pub(crate) fn open_validated_object<T>(
        &self,
        object: KernelObject,
        rights: u32,
        validation: Result<()>,
        open: impl FnOnce(&Self, KernelObject, u32) -> Result<T>,
    ) -> Result<T> {
        validation?;
        open(self, object, rights)
    }

    /// Reject requests whose rights include bits outside `supported_rights`,
    /// and reject the all-zero right set.
    pub(crate) fn validate_descriptor_rights_subset_request(
        rights: u32,
        supported_rights: u32,
    ) -> Result<()> {
        if rights == 0 || rights & !supported_rights != 0 {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Reject requests whose rights are anything other than exactly
    /// `required_rights`.
    pub(crate) fn validate_descriptor_rights_exact_request(
        rights: u32,
        required_rights: u32,
    ) -> Result<()> {
        Self::validate_descriptor_rights_subset_request(rights, required_rights)?;
        if rights != required_rights {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    fn validate_device_descriptor_request(name: &str, rights: u32) -> Result<()> {
        let supported_rights = device::supported_device_rights(name).ok_or(Error::NotFound)?;
        Self::validate_descriptor_rights_subset_request(rights, supported_rights)
    }

    fn validate_network_descriptor_request(endpoint: &str, rights: u32) -> Result<()> {
        if endpoint.trim().is_empty() {
            return Err(Error::PermissionDenied);
        }
        Self::validate_descriptor_rights_exact_request(
            rights,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
    }

    /// Return the [`HandleEntry`] bound to a kernel handle.
    pub fn handle_entry(&self, handle: Handle) -> Result<HandleEntry> {
        let handles = self.handle_table.lock();
        let entry = handles.get(&handle).ok_or(Error::NotFound)?;
        Ok(entry.clone())
    }

    /// Duplicate `fd`, allocating the lowest available descriptor
    /// (equivalent to `dup`).
    pub fn duplicate_fd(&self, fd: FileDescriptor) -> Result<FileDescriptor> {
        self.ensure_mutable()?;
        let entry = self.fd_entry(fd)?;
        entry.reopen_descriptor_in(self)
    }

    /// Duplicate `fd` onto `newfd`, closing `newfd` first if it was already
    /// open.  Returns `newfd` on success (POSIX `dup2` semantics).
    pub fn duplicate_fd_to(
        &self,
        fd: FileDescriptor,
        newfd: FileDescriptor,
    ) -> Result<FileDescriptor> {
        self.ensure_mutable()?;
        // If newfd is already open, close it first (POSIX dup2 semantics).
        if self.resolve_fd_handle(newfd).is_ok() {
            self.close_fd(newfd)?;
        }
        // Reopen the source fd's object with the target fd number.
        let entry = self.fd_entry(fd)?;
        let handle = entry.reopen_handle_in(self)?;
        self.fd_table.lock().insert(newfd, handle);
        Ok(newfd)
    }

    /// Duplicate `fd` onto the lowest available descriptor `>= min_fd`
    /// (POSIX `F_DUPFD` semantics).  Returns the new descriptor.
    pub fn duplicate_fd_from(
        &self,
        fd: FileDescriptor,
        min_fd: FileDescriptor,
    ) -> Result<FileDescriptor> {
        self.ensure_mutable()?;
        let entry = self.fd_entry(fd)?;
        let handle = entry.reopen_handle_in(self)?;
        let new_fd = self.allocate_fd_from(min_fd)?;
        self.fd_table.lock().insert(new_fd, handle);
        Ok(new_fd)
    }

    /// Allocate the lowest unused descriptor `>= min_fd`, never colliding
    /// with the reserved standard-handle slots.
    fn allocate_fd_from(&self, min_fd: FileDescriptor) -> Result<FileDescriptor> {
        let table = self.fd_table.lock();
        let mut fd = core::cmp::max(min_fd, FIRST_EXPLICIT_FD);
        loop {
            if !table.contains_key(&fd) {
                return Ok(fd);
            }
            fd = fd.checked_add(1).ok_or(Error::InvalidArgument)?;
        }
    }

    pub fn close_fd(&self, fd: FileDescriptor) -> Result<()> {
        self.ensure_mutable()?;
        let handle = self.take_fd_handle(fd)?;
        self.fd_flags.lock().remove(&fd);
        self.release_handle_if_unreferenced(handle);
        Ok(())
    }

    /// Resolve a descriptor to its backing handle and entry.
    pub fn resolve_fd(&self, fd: FileDescriptor) -> Result<(Handle, HandleEntry)> {
        let handle = self.resolve_fd_handle(fd)?;
        Ok((handle, self.handle_entry(handle)?))
    }

    /// Resolve a descriptor to its [`HandleEntry`].
    pub fn fd_entry(&self, fd: FileDescriptor) -> Result<HandleEntry> {
        let handle = self.resolve_fd_handle(fd)?;
        self.handle_entry(handle)
    }

    fn resolve_fd_handle(&self, fd: FileDescriptor) -> Result<Handle> {
        // Stdio fds resolve through the dedicated standard-handle slots first;
        // higher-numbered descriptors come from the regular fd table.
        if Self::is_standard_fd(fd) {
            self.standard_handle(fd)
        } else {
            self.fd_table
                .lock()
                .get(&fd)
                .copied()
                .ok_or(Error::NotFound)
        }
    }

    fn take_fd_handle(&self, fd: FileDescriptor) -> Result<Handle> {
        if Self::is_standard_fd(fd) {
            self.standard_handles.lock()[fd]
                .take()
                .ok_or(Error::NotFound)
        } else {
            self.fd_table.lock().remove(&fd).ok_or(Error::NotFound)
        }
    }

    fn release_handle_if_unreferenced(&self, handle: Handle) {
        if self.handle_is_referenced(handle) {
            return;
        }
        let _ = self.handle_table.lock().remove(&handle);
    }

    fn handle_is_referenced(&self, handle: Handle) -> bool {
        // A kernel object stays alive while referenced from either stdio slots
        // or normal file-descriptor bindings.
        self.standard_handles.lock().contains(&Some(handle))
            || self.fd_table.lock().values().any(|value| *value == handle)
    }

    fn release_handles_if_unreferenced(&self, handles: &[Handle]) {
        for &handle in handles {
            self.release_handle_if_unreferenced(handle);
        }
    }

    pub(crate) fn cleanup_on_error<T>(&self, cleanup: &[Handle], result: Result<T>) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                self.release_handles_if_unreferenced(cleanup);
                Err(error)
            }
        }
    }

    /// Redirect the standard-handle slot `from` to point at `to`'s current
    /// binding (POSIX `dup2` on stdio, used by shell redirection).
    pub fn redirect(&self, from: FileDescriptor, to: FileDescriptor) -> Result<()> {
        Self::ensure_standard_fd(from)?;
        Self::ensure_standard_fd(to)?;
        self.ensure_mutable()?;
        let source = self.standard_handle(from)?;
        self.replace_standard_handle_binding(to, source);
        Ok(())
    }

    fn ensure_standard_fd(fd: FileDescriptor) -> Result<()> {
        if Self::is_standard_fd(fd) {
            return Ok(());
        }
        Err(Error::InvalidArgument)
    }

    fn is_standard_fd(fd: FileDescriptor) -> bool {
        fd < STANDARD_FD_COUNT
    }

    /// Return the handle bound to a standard-handle slot (0/1/2).
    pub fn standard_handle(&self, fd: FileDescriptor) -> Result<Handle> {
        Self::ensure_standard_fd(fd)?;
        self.standard_handles.lock()[fd].ok_or(Error::NotFound)
    }

    /// Bind `handle` to a standard-handle slot, releasing the previous
    /// binding if it is no longer referenced.
    pub fn bind_standard_handle(&self, fd: FileDescriptor, handle: Handle) -> Result<()> {
        Self::ensure_standard_fd(fd)?;
        self.ensure_mutable()?;
        self.handle_entry(handle)?;
        self.replace_standard_handle_binding(fd, handle);
        Ok(())
    }

    /// Install a fresh owned handle for `entry` into a standard-handle slot,
    /// rather than sharing the raw numeric handle from another table.
    pub fn install_standard_handle_entry(
        &self,
        fd: FileDescriptor,
        entry: HandleEntry,
    ) -> Result<()> {
        Self::ensure_standard_fd(fd)?;
        let handle = entry.reopen_handle_in(self)?;
        self.replace_standard_handle_binding(fd, handle);
        Ok(())
    }

    /// Copy another process's standard-handle binding for `fd` into `self`.
    pub fn inherit_standard_handle_from(
        &self,
        process: &Process,
        fd: FileDescriptor,
    ) -> Result<()> {
        self.install_standard_handle_entry(fd, process.fd_entry(fd)?)
    }

    fn replace_standard_handle_binding(&self, fd: FileDescriptor, handle: Handle) {
        let previous = {
            let mut standard_handles = self.standard_handles.lock();
            standard_handles[fd].replace(handle)
        };
        if let Some(previous) = previous {
            self.release_handle_if_unreferenced(previous);
        }
    }
}
