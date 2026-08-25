//! src/kernel/syscall/memory/mlock.rs
//!
//! mlock / munlock — lock/unlock memory pages (syscalls #131-132).
//! mlock locks a range of virtual pages into physical memory so they are
//! never swapped out.  munlock unlocks them.

use crate::kernel::memory::paging::MappingKind;
use crate::Error;
use crate::Result;

/// System-wide maximum locked pages (64 MiB / 4 KiB pages).
const MAX_LOCKED_PAGES: usize = 16384;

pub(super) fn mlock(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let addr = context.arg(0);
    let len = context.arg(1);

    super::validate_zeroed_args(context, 2)?;

    if len == 0 {
        return Err(Error::InvalidArgument);
    }

    let va = align_down(addr);
    let len_aligned = align_up(len);

    let mut memory = crate::kernel::memory::global_mut().ok_or(Error::InternalError)?;

    // Check against system-wide locked page limit.
    let pages_needed = len_aligned / 4096;
    if memory.locked_pages + pages_needed > MAX_LOCKED_PAGES {
        return Err(Error::OutOfMemory);
    }

    // Walk each page in the range and mark it as Locked.
    for offset in (0..len_aligned).step_by(4096) {
        let page_va = va + offset;
        if memory
            .page_table
            .replace_mapping_kind(page_va, MappingKind::Locked)
            .is_err()
        {
            // Page not mapped — that's fine, skip it.
            continue;
        }
        memory.locked_pages += 1;
    }

    Ok(super::SyscallDispatch::complete(0))
}

pub(super) fn munlock(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let addr = context.arg(0);
    let len = context.arg(1);

    super::validate_zeroed_args(context, 2)?;

    if len == 0 {
        return Err(Error::InvalidArgument);
    }

    let va = align_down(addr);
    let len_aligned = align_up(len);

    let mut memory = crate::kernel::memory::global_mut().ok_or(Error::InternalError)?;

    // Walk each page in the range and revert to Anonymous.
    for offset in (0..len_aligned).step_by(4096) {
        let page_va = va + offset;
        if memory
            .page_table
            .replace_mapping_kind(page_va, MappingKind::Anonymous)
            .is_ok()
        {
            // Only decrement if it was actually locked.
            if memory.locked_pages > 0 {
                memory.locked_pages -= 1;
            }
        }
    }

    Ok(super::SyscallDispatch::complete(0))
}

fn align_down(addr: usize) -> usize {
    addr & !0xFFF
}

fn align_up(len: usize) -> usize {
    (len + 0xFFF) & !0xFFF
}
