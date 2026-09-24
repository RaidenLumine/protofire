//! src/user/program/loader/arch/riscv64.rs
//!
//! The riscv64 half of loading a program image: building its address space,
//! its stack, and the two argument registers an S-mode entry reads.

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
    // The RISC-V U-mode prototype uses one preallocated demo slot.
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
    let initial_stack = build_riscv64_initial_user_stack(&slot, arguments, environment)?;
    slot.write_bytes(initial_stack.stack_pointer, &initial_stack.bytes)
        .ok_or(Error::InvalidArgument)?;
    slot.set_stack_pointer(initial_stack.stack_pointer)
        .ok_or(Error::InvalidArgument)?;
    let prepared = crate::arch::mmu::prepare_runtime_process_address_space(slot)
        .ok_or(Error::InvalidArgument)?;
    Ok(Some(ProcessUserAddressSpace::from_prepared_process(
        prepared,
    )))
}

pub(crate) fn prepare_loaded_user_thread_start(
    prepared_user_address_space: Option<&ProcessUserAddressSpace>,
    _image_layout: Option<&UserImageLoadPlan>,
    _image: &[u8],
    arguments: &[String],
) -> Result<Option<UserThreadStart>> {
    let Some(start) = prepared_user_address_space.map(ProcessUserAddressSpace::user_thread_start)
    else {
        return Ok(None);
    };
    let argument_registers =
        build_riscv64_startup_argument_registers(start.stack_pointer, arguments.len())?;
    Ok(Some(start.with_startup_arguments(argument_registers)))
}

pub(crate) fn build_riscv64_startup_argument_registers(
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

pub(crate) fn build_riscv64_initial_user_stack(
    slot: &crate::arch::mmu::PreparedDemoUserSlot,
    arguments: &[String],
    environment: &[String],
) -> Result<PreparedInitialUserStack> {
    build_initial_user_stack(
        slot.stack_bottom(),
        slot.stack_top(),
        arguments,
        environment,
        &riscv64_initial_auxv_entries(slot.entry_point()),
    )
}

pub(crate) fn riscv64_initial_auxv_entries(entry_point: usize) -> [(u64, u64); 3] {
    [
        (constants::AUXV_AT_PAGESZ, constants::USER_PAGE_SIZE as u64),
        (constants::AUXV_AT_ENTRY, entry_point as u64),
        (constants::AUXV_AT_NULL, 0),
    ]
}
