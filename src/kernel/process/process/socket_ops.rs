//! src/kernel/process/process/socket_ops.rs
//!
//! TCP listener, UDP socket, raw socket, and local socket handle/descriptor
//! operations.
use alloc::sync::Arc;

use crate::kernel::network::{LocalSocket, TcpListener, UdpSocket};
use crate::kernel::process::RawSocketHandle;
use crate::{Error, Result};

use super::constants::*;
use super::types::*;
use super::Process;

impl Process {
    fn listener_object(listener: TcpListener) -> KernelObject {
        KernelObject::TcpListener(listener)
    }

    pub fn open_listener_handle(
        &self,
        port: u16,
        listener: TcpListener,
        rights: u32,
    ) -> Result<Handle> {
        self.open_validated_object(
            Self::listener_object(listener),
            rights,
            Self::validate_listener_descriptor_request(port, rights),
            Self::open_handle,
        )
    }

    pub fn open_listener_descriptor(
        &self,
        port: u16,
        listener: TcpListener,
        rights: u32,
    ) -> Result<FileDescriptor> {
        self.open_validated_object(
            Self::listener_object(listener),
            rights,
            Self::validate_listener_descriptor_request(port, rights),
            Self::open_descriptor,
        )
    }

    fn validate_listener_descriptor_request(port: u16, rights: u32) -> Result<()> {
        if port == 0 {
            return Err(Error::InvalidArgument);
        }
        // Listener fds need READ right (accept is a read-like operation).
        Self::validate_descriptor_rights_exact_request(rights, HANDLE_RIGHT_READ)
    }

    /// Retrieve the [`TcpListener`] bound to a file descriptor.
    pub fn get_listener(&self, fd: FileDescriptor) -> Result<TcpListener> {
        let entry = self.fd_entry(fd)?;
        match &entry.object {
            KernelObject::TcpListener(listener) => Ok(listener.clone()),
            _ => Err(Error::InvalidArgument),
        }
    }

    fn udp_socket_object(socket: UdpSocket) -> KernelObject {
        KernelObject::UdpSocket(socket)
    }

    pub fn open_udp_handle(&self, port: u16, socket: UdpSocket, rights: u32) -> Result<Handle> {
        self.open_validated_object(
            Self::udp_socket_object(socket),
            rights,
            Self::validate_udp_descriptor_request(port, rights),
            Self::open_handle,
        )
    }

    pub fn open_udp_descriptor(
        &self,
        port: u16,
        socket: UdpSocket,
        rights: u32,
    ) -> Result<FileDescriptor> {
        self.open_validated_object(
            Self::udp_socket_object(socket),
            rights,
            Self::validate_udp_descriptor_request(port, rights),
            Self::open_descriptor,
        )
    }

    fn validate_udp_descriptor_request(port: u16, rights: u32) -> Result<()> {
        if port == 0 {
            return Err(Error::InvalidArgument);
        }
        // UDP sockets need both READ and WRITE rights (send + recv).
        Self::validate_descriptor_rights_exact_request(
            rights,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
    }

    /// Retrieve the [`UdpSocket`] bound to a file descriptor.
    pub fn get_udp_socket(&self, fd: FileDescriptor) -> Result<UdpSocket> {
        let entry = self.fd_entry(fd)?;
        match &entry.object {
            KernelObject::UdpSocket(socket) => Ok(socket.clone()),
            _ => Err(Error::InvalidArgument),
        }
    }

    fn raw_socket_object(handle: RawSocketHandle) -> KernelObject {
        KernelObject::RawSocket(handle)
    }

    pub fn open_raw_socket_handle(&self, handle: RawSocketHandle, rights: u32) -> Result<Handle> {
        self.open_validated_object(
            Self::raw_socket_object(handle),
            rights,
            Self::validate_raw_socket_descriptor_request(handle.protocol, rights),
            Self::open_handle,
        )
    }

    pub fn open_raw_socket_descriptor(
        &self,
        handle: RawSocketHandle,
        rights: u32,
    ) -> Result<FileDescriptor> {
        self.open_validated_object(
            Self::raw_socket_object(handle),
            rights,
            Self::validate_raw_socket_descriptor_request(handle.protocol, rights),
            Self::open_descriptor,
        )
    }

    fn validate_raw_socket_descriptor_request(protocol: u8, rights: u32) -> Result<()> {
        if protocol == 0 {
            return Err(Error::InvalidArgument);
        }
        // Raw sockets need both READ and WRITE (send + recv).
        Self::validate_descriptor_rights_exact_request(
            rights,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
    }

    /// Retrieve the [`RawSocketHandle`] from a file descriptor.
    pub fn get_raw_socket(&self, fd: FileDescriptor) -> Result<RawSocketHandle> {
        let entry = self.fd_entry(fd)?;
        match &entry.object {
            KernelObject::RawSocket(handle) => Ok(*handle),
            _ => Err(Error::InvalidArgument),
        }
    }

    // ─── Local (Unix domain) socket operations ──────────────────────────

    fn local_socket_object(socket: Arc<LocalSocket>) -> KernelObject {
        KernelObject::LocalSocket(socket)
    }

    pub fn open_local_socket_handle(
        &self,
        path: &str,
        socket: Arc<LocalSocket>,
        rights: u32,
    ) -> Result<Handle> {
        self.open_validated_object(
            Self::local_socket_object(socket),
            rights,
            Self::validate_local_socket_descriptor_request(path, rights),
            Self::open_handle,
        )
    }

    pub fn open_local_socket_descriptor(
        &self,
        path: &str,
        socket: Arc<LocalSocket>,
        rights: u32,
    ) -> Result<FileDescriptor> {
        self.open_validated_object(
            Self::local_socket_object(socket),
            rights,
            Self::validate_local_socket_descriptor_request(path, rights),
            Self::open_descriptor,
        )
    }

    fn validate_local_socket_descriptor_request(path: &str, rights: u32) -> Result<()> {
        if path.is_empty() {
            return Err(Error::InvalidArgument);
        }
        // Local socket listener fds need READ right (accept is a read-like operation).
        Self::validate_descriptor_rights_exact_request(rights, HANDLE_RIGHT_READ)
    }

    /// Retrieve the [`LocalSocket`] bound to a file descriptor.
    pub fn get_local_socket(&self, fd: FileDescriptor) -> Result<Arc<LocalSocket>> {
        let entry = self.fd_entry(fd)?;
        match &entry.object {
            KernelObject::LocalSocket(socket) => Ok(Arc::clone(socket)),
            _ => Err(Error::InvalidArgument),
        }
    }
}
