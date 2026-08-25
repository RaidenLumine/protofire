//! src/kernel/syscall/memory/map.rs
//!
//! mmap/munmap syscall handlers — anonymous memory mapping for user processes.

use crate::kernel::memory::paging::PagePermissions;
use crate::Error;
use crate::Result;

/// mmap protection flags (subset of POSIX PROT_*).
const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const PROT_EXEC: usize = 4;

/// mmap flag: anonymous memory (not backed by a file).
const MAP_ANONYMOUS: usize = 0x20;
const MAP_PRIVATE: usize = 0x02;

/// Known mmap flags mask.
const MAP_KNOWN_FLAGS: usize = MAP_ANONYMOUS | MAP_PRIVATE;

/// Page size for the platform (4 KiB on all supported architectures).
const PAGE_SIZE: usize = 4096;

pub(super) fn mmap(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 5)?;

    let addr_hint = context.arg(0);
    let length = context.arg(1);
    let prot = context.arg(2);
    let flags = context.arg(3);

    // Validate length.
    if length == 0 || length > 0x1000_0000 {
        // Reject zero-length and absurdly large (>256 MiB) mappings.
        return Err(Error::InvalidArgument);
    }

    // Only anonymous private mappings are supported.
    if flags & !MAP_KNOWN_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & MAP_ANONYMOUS == 0 {
        return Err(Error::InvalidArgument);
    }

    // Build permissions.
    let perms = translate_prot(prot)?;

    // Align address and length to page boundaries.
    let va = align_down(addr_hint, PAGE_SIZE);
    let len_aligned = align_up(length, PAGE_SIZE);

    // Reject address 0 for safety (null pointer guard).
    if va == 0 {
        return Err(Error::InvalidArgument);
    }

    // Perform the mapping.
    let mut memory = crate::kernel::memory::global_mut().ok_or(Error::InternalError)?;
    memory.map_region(va, len_aligned, perms)?;

    Ok(super::SyscallDispatch::complete(va))
}

pub(super) fn munmap(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 2)?;

    let addr = context.arg(0);
    let length = context.arg(1);

    if length == 0 {
        return Err(Error::InvalidArgument);
    }

    let va = align_down(addr, PAGE_SIZE);
    let len_aligned = align_up(length, PAGE_SIZE);

    if va == 0 {
        return Err(Error::InvalidArgument);
    }

    let mut memory = crate::kernel::memory::global_mut().ok_or(Error::InternalError)?;
    memory.unmap(va, len_aligned)?;

    Ok(super::SyscallDispatch::complete(0))
}

/// Translate POSIX-style protection flags to kernel [`PagePermissions`].
fn translate_prot(prot: usize) -> Result<PagePermissions> {
    let read = prot & PROT_READ != 0;
    let write = prot & PROT_WRITE != 0;
    let exec = prot & PROT_EXEC != 0;

    // W^X enforcement: writable and executable pages are not allowed.
    if write && exec {
        return Err(Error::InvalidArgument);
    }

    match (read, write, exec) {
        (true, false, false) => Ok(PagePermissions::READ),
        (true, true, false) => Ok(PagePermissions::READ_WRITE),
        (true, false, true) => Ok(PagePermissions::READ_EXECUTE),
        _ => Err(Error::InvalidArgument),
    }
}

#[inline]
const fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}

#[inline]
const fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}
