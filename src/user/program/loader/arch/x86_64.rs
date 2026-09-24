//! src/user/program/loader/arch/x86_64.rs
//!
//! The x86_64 half of loading a program image: building its address space,
//! its stack, and the auxv a dynamically linked program would read.

use super::*;

pub(crate) fn prepare_arch_user_address_space(
    image_layout: Option<&UserImageLoadPlan>,
    image: &[u8],
    arguments: &[String],
    environment: &[String],
) -> Result<Option<ProcessUserAddressSpace>> {
    let Some(image_layout) = image_layout else {
        return Ok(None);
    };
    if !image_layout.has_consistent_runtime_layout() {
        return Err(Error::InvalidArgument);
    }
    let initial_stack = build_x86_64_initial_user_stack(image_layout, arguments, environment)?;

    if let Some(memory) = crate::kernel::memory::global() {
        // Real runtime builds merge user mappings into a prepared process page
        // table that already contains the kernel half.
        if let Some(mut prepared) = crate::arch::mmu::prepare_runtime_process_address_space(
            memory.heap_bounds(),
            image_layout,
            image,
        ) {
            prepared
                .write_user_bytes(initial_stack.stack_pointer, &initial_stack.bytes)
                .ok_or(Error::InvalidArgument)?;

            // Register user pages in the software page table so reclamation
            // and teardown can account for them.  All pages (code, data,
            // stack) stay resident and mapped in this process's prepared
            // hardware page tables.
            //
            // Code is deliberately NOT demand-paged: every user process loads
            // its image at the same fixed base virtual address, while the
            // software page table and the demand-paging content store are
            // keyed by virtual address alone.  Deferring code frames to that
            // global store would let the next spawn overwrite an earlier
            // process's image bytes, so later processes would fault on their
            // first instruction fetch — or, worse, execute the wrong program.
            // Keeping each process's own code frames resident (as the AArch64
            // and RISC-V prepare paths already do) preserves per-process
            // isolation.
            if let Some(mut memory_mut) = crate::kernel::memory::global_mut() {
                let entries: Vec<(usize, usize, PagePermissions, MappingKind)> = prepared
                    .user_page_entries()
                    .into_iter()
                    .map(|(va, pa, perms)| (va, pa, perms, MappingKind::Anonymous))
                    .collect();
                let code_count = entries
                    .iter()
                    .filter(|(_, _, perms, _)| {
                        perms.contains(PagePermissions::EXECUTE)
                            && !perms.contains(PagePermissions::WRITE)
                    })
                    .count();
                let registered = memory_mut.register_user_pages(&entries);
                crate::println!(
                    "[vm    ] registered {} user pages in software page table ({} code, {} data/stack)",
                    registered,
                    code_count,
                    registered.saturating_sub(code_count),
                );
            }

            return Ok(Some(ProcessUserAddressSpace::from_prepared_process(
                prepared,
            )));
        }

        return Err(Error::InvalidArgument);
    }

    // Host-side/unit-test execution can fall back to a user-only address-space
    // model because there is no live kernel page table to merge against.
    let mut prepared = crate::arch::mmu::materialize_user_address_space(image_layout, image)
        .ok_or(Error::InvalidArgument)?;
    prepared
        .write_bytes(initial_stack.stack_pointer, &initial_stack.bytes)
        .ok_or(Error::InvalidArgument)?;
    Ok(Some(ProcessUserAddressSpace::from_prepared_user(prepared)))
}

pub(crate) fn build_x86_64_initial_user_stack(
    image_layout: &UserImageLoadPlan,
    arguments: &[String],
    environment: &[String],
) -> Result<PreparedInitialUserStack> {
    build_initial_user_stack(
        image_layout.stack_bottom,
        image_layout.stack_top,
        arguments,
        environment,
        &x86_64_initial_auxv_entries(image_layout.entry_point),
    )
}

pub(crate) fn x86_64_initial_auxv_entries(entry_point: usize) -> [(u64, u64); 2] {
    [
        (
            constants::X86_64_AUXV_AT_PAGESZ,
            constants::USER_PAGE_SIZE as u64,
        ),
        (constants::X86_64_AUXV_AT_ENTRY, entry_point as u64),
    ]
}
