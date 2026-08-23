//! src/kernel/syscall/memory/madvise.rs
//! madvise — give advice about memory use (syscall #133).
//! Provides hints about memory usage patterns to the kernel.

use crate::kernel::memory::paging::{AdviceHint, MappingKind, PAGE_SIZE};
use crate::{Error, Result};

// ── Advice values ──────────────────────────────────────────────────────

const MADV_NORMAL: i32 = 0;
const MADV_RANDOM: i32 = 1;
const MADV_SEQUENTIAL: i32 = 2;
const MADV_WILLNEED: i32 = 3;
const MADV_DONTNEED: i32 = 4;
const MADV_REMOVE: i32 = 9;

pub(super) fn madvise(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let addr = context.arg(0);
    let len = context.arg(1);
    let advice = context.arg(2) as i32;

    super::validate_zeroed_args(context, 3)?;

    if len == 0 {
        return Err(Error::InvalidArgument);
    }

    let va = align_down(addr);
    let len_aligned = align_up(len);

    let mut memory = crate::kernel::memory::global_mut().ok_or(Error::InternalError)?;

    match advice {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL => {
            let hint = match advice {
                MADV_RANDOM => AdviceHint::Random,
                MADV_SEQUENTIAL => AdviceHint::Sequential,
                _ => AdviceHint::Normal,
            };
            for offset in (0..len_aligned).step_by(PAGE_SIZE) {
                let page_va = va + offset;
                let _ = memory.page_table.replace_mapping_advice(page_va, hint);
            }
            Ok(super::SyscallDispatch::complete(0))
        }
        MADV_WILLNEED => {
            // Pre-fault DemandPaged pages: trigger allocation for pages
            // that are mapped as DemandPaged but haven't been faulted yet.
            for offset in (0..len_aligned).step_by(PAGE_SIZE) {
                let page_va = va + offset;
                // Check if the mapping exists and is DemandPaged.
                let should_fault =
                    memory.page_table.mappings_snapshot().iter().any(|m| {
                        m.virtual_address == page_va && m.kind == MappingKind::DemandPaged
                    });
                if should_fault {
                    memory.resolve_page_fault(page_va, false);
                }
            }
            Ok(super::SyscallDispatch::complete(0))
        }
        MADV_DONTNEED | MADV_REMOVE => {
            // Deallocate frames for Anonymous pages.  The virtual mapping
            // is removed and the pages will fault in as zero-filled on
            // next access (DemandPaged semantics).
            for offset in (0..len_aligned).step_by(PAGE_SIZE) {
                let page_va = va + offset;
                // Unmap the physical frame from hardware and software.
                let _ = memory.page_table.unmap(page_va, PAGE_SIZE);
                // Re-map as DemandPaged so the next access triggers a
                // zero-fill fault.
                let perms = crate::kernel::memory::paging::PagePermissions::READ_WRITE;
                let _ = memory.map_region_with_kind(
                    page_va,
                    PAGE_SIZE,
                    perms,
                    MappingKind::DemandPaged,
                );
            }
            Ok(super::SyscallDispatch::complete(0))
        }
        _ => Err(Error::InvalidArgument),
    }
}

fn align_down(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

fn align_up(len: usize) -> usize {
    (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}
