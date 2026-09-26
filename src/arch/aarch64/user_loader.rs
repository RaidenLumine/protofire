//! src/arch/aarch64/user_loader.rs
//!
//! The aarch64 half of loading a program image: building its address space,
//! its stack, and the argument registers an EL0 entry reads.

use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::user_loader::build_initial_user_stack;
use crate::arch::user_loader::PreparedInitialUserStack;
use crate::arch::user_loader::AUXV_AT_ENTRY;
use crate::arch::user_loader::AUXV_AT_PAGESZ;
use crate::kernel::process::ProcessUserAddressSpace;
use crate::kernel::process::UserThreadStart;
use crate::memory::paging::MappingKind;
use crate::memory::paging::PagePermissions;
use crate::user::program::UserImageLoadPlan;
use crate::user::program::USER_PAGE_SIZE;
use crate::Error;
use crate::Result;

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
    // The current AArch64 EL0 prototype uses one preallocated demo slot rather
    // than a fully general arbitrary-segment loader.
    if image_layout.segments.len() != 1 {
        return Err(Error::Unsupported);
    }

    let segment = &image_layout.segments[0];
    if !segment.permissions.contains(PagePermissions::EXECUTE) {
        return Err(Error::Unsupported);
    }

    let file_end = segment
        .file_offset
        .checked_add(segment.file_size)
        .ok_or(Error::InvalidArgument)?;
    let segment_bytes = image
        .get(segment.file_offset..file_end)
        .ok_or(Error::InvalidArgument)?;
    let entry_offset = image_layout
        .entry_point
        .checked_sub(segment.virtual_start)
        .ok_or(Error::InvalidArgument)?;
    let mut slot = crate::arch::mmu::allocate_demo_user_slot(segment_bytes, entry_offset)
        .ok_or(Error::OutOfMemory)?;
    let initial_stack = build_aarch64_initial_user_stack(&slot, arguments, environment)?;
    slot.write_bytes(initial_stack.stack_pointer, &initial_stack.bytes)
        .ok_or(Error::InvalidArgument)?;
    slot.set_stack_pointer(initial_stack.stack_pointer)
        .ok_or(Error::InvalidArgument)?;
    let prepared = crate::arch::mmu::prepare_runtime_process_address_space(slot)
        .ok_or(Error::InvalidArgument)?;

    // Register user pages in the software page table.
    if let Some(mut memory) = crate::memory::global_mut() {
        let entries: Vec<(usize, usize, PagePermissions, MappingKind)> = prepared
            .user_page_entries()
            .into_iter()
            .map(|(va, pa, perms)| (va, pa, perms, MappingKind::Anonymous))
            .collect();
        let registered = memory.register_user_pages(&entries);
        crate::println!(
            "[vm    ] registered {} AArch64 user pages in software page table",
            registered
        );
    }

    Ok(Some(ProcessUserAddressSpace::from_prepared(
        crate::arch::mmu::ProcessAddressSpace::from_prepared_process(prepared),
    )))
}

pub(crate) fn prepare_loaded_user_thread_start(
    prepared_user_address_space: Option<&ProcessUserAddressSpace>,
    _image_layout: Option<&UserImageLoadPlan>,
    _image: &[u8],
    arguments: &[String],
) -> Result<Option<UserThreadStart>> {
    let Some(start) =
        prepared_user_address_space.and_then(ProcessUserAddressSpace::user_thread_start)
    else {
        return Ok(None);
    };
    let argument_registers =
        build_aarch64_startup_argument_registers(start.stack_pointer, arguments.len())?;
    Ok(Some(start.with_startup_arguments(argument_registers)))
}

pub(crate) fn build_aarch64_startup_argument_registers(
    stack_pointer: usize,
    argument_count: usize,
) -> Result<[usize; 3]> {
    let argv_pointer = stack_pointer.checked_add(core::mem::size_of::<u64>());
    let envp_offset = argument_count
        .checked_add(2)
        .and_then(|slots| slots.checked_mul(core::mem::size_of::<u64>()));
    let envp_pointer = stack_pointer.checked_add(envp_offset.ok_or(Error::OutOfMemory)?);

    Ok([
        argument_count,
        argv_pointer.ok_or(Error::OutOfMemory)?,
        envp_pointer.ok_or(Error::OutOfMemory)?,
    ])
}

pub(crate) fn build_aarch64_initial_user_stack(
    slot: &crate::arch::mmu::PreparedDemoUserSlot,
    arguments: &[String],
    environment: &[String],
) -> Result<PreparedInitialUserStack> {
    build_initial_user_stack(
        slot.stack_bottom(),
        slot.stack_top(),
        arguments,
        environment,
        &aarch64_initial_auxv_entries(slot.entry_point()),
    )
}

pub(crate) fn aarch64_initial_auxv_entries(entry_point: usize) -> [(u64, u64); 2] {
    [
        (AUXV_AT_PAGESZ, USER_PAGE_SIZE as u64),
        (AUXV_AT_ENTRY, entry_point as u64),
    ]
}
