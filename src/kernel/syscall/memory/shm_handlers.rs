//! src/kernel/syscall/memory/shm_handlers.rs
//!
//! Syscall handlers for SystV shared memory operations.

use crate::{Error, Result};

/// shmget(key, size, flags) → shmid
pub(super) fn shmget(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let key = context.arg(0);
    let size = context.arg(1);
    let flags = context.arg(2);

    let _ = key;
    let _ = size;
    let _ = flags;
    // shm operation requires a memory manager — not yet wired.
    Err(Error::Unsupported)
}

/// shmat(shmid, addr_hint, flags) → virtual_address
pub(super) fn shmat(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let _shmid = context.arg(0);
    let _addr_hint = context.arg(1);
    let _flags = context.arg(2);
    Err(Error::Unsupported)
}

/// shmdt(shmid) → 0 on success
pub(super) fn shmdt(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let _shmid = context.arg(0);
    Err(Error::Unsupported)
}

/// shmctl(shmid, cmd, buf) → 0 on success
pub(super) fn shmctl(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let _shmid = context.arg(0);
    let _cmd = context.arg(1);
    let _buf = context.arg(2);
    Err(Error::Unsupported)
}
