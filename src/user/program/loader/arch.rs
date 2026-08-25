//! src/user/program/loader/arch.rs
//!
//! Architecture-specific user-address-space preparation, initial-stack and
//! thread-start construction, and ELF segment planning.
use super::*;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::kernel::memory::paging::MappingKind;
use crate::kernel::memory::paging::PagePermissions;
use crate::kernel::process::{ProcessUserAddressSpace, UserThreadStart};
use crate::{Error, Result};

use super::super::constants;
use crate::user::elf::{ElfLoadSegment, ElfSegmentFlags};

// ── arch-specific address-space preparation ───────────────────────────

#[cfg(target_arch = "x86_64")]
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

            // Register user pages in the software page table so demand-paging
            // and page reclamation can operate on them.
            // Code pages (RX, no W) are registered as DemandPaged: their
            // frames are freed, the hardware PTE is cleared to NOT PRESENT,
            // and the ELF content is stored for later backfill on first
            // access.  Data and stack pages remain pre-allocated Anonymous.
            if let Some(mut memory_mut) = crate::kernel::memory::global_mut() {
                let user_entries = prepared.user_page_entries();
                let entries: Vec<(usize, usize, PagePermissions, MappingKind)> = user_entries
                    .iter()
                    .map(|&(va, pa, perms)| {
                        let kind = if perms.contains(PagePermissions::EXECUTE)
                            && !perms.contains(PagePermissions::WRITE)
                        {
                            MappingKind::DemandPaged
                        } else {
                            MappingKind::Anonymous
                        };
                        (va, pa, perms, kind)
                    })
                    .collect();
                let code_count = entries
                    .iter()
                    .filter(|(_, _, _, k)| *k == MappingKind::DemandPaged)
                    .count();
                let registered = memory_mut.register_user_pages(&entries);
                crate::println!(
                    "[vm    ] registered {} user pages in software page table ({} code, {} data/stack)",
                    registered,
                    code_count,
                    registered.saturating_sub(code_count),
                );

                // For code pages: extract and store ELF content, then mark
                // NOT PRESENT in hardware and release the backing frame.
                for &(va, _pa, perms) in &user_entries {
                    if perms.contains(PagePermissions::EXECUTE)
                        && !perms.contains(PagePermissions::WRITE)
                    {
                        let content = extract_page_content(va, image_layout, image);
                        memory_mut.store_page_content(va, content);
                        prepared.mark_user_page_not_present(va);
                    }
                }
            }

            return Ok(Some(ProcessUserAddressSpace::from_prepared_process(
                prepared,
            )));
        }

        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
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

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
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
    if let Some(mut memory) = crate::kernel::memory::global_mut() {
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

    Ok(Some(ProcessUserAddressSpace::from_prepared_process(
        prepared,
    )))
}

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
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

#[cfg(all(
    not(target_arch = "x86_64"),
    not(all(target_arch = "aarch64", target_os = "none")),
    not(all(target_arch = "riscv64", target_os = "none"))
))]
pub(crate) fn prepare_arch_user_address_space(
    _image_layout: Option<&UserImageLoadPlan>,
    _image: &[u8],
    _arguments: &[String],
    _environment: &[String],
) -> Result<Option<ProcessUserAddressSpace>> {
    Ok(None)
}

// ── arch-specific thread-start preparation ────────────────────────────

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
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
        build_aarch64_startup_argument_registers(start.stack_pointer, arguments.len())?;
    Ok(Some(
        start.with_aarch64_argument_registers(argument_registers),
    ))
}

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
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
    Ok(Some(
        start.with_riscv64_argument_registers(argument_registers),
    ))
}

#[cfg(not(any(
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
pub(crate) fn prepare_loaded_user_thread_start(
    _prepared_user_address_space: Option<&ProcessUserAddressSpace>,
    image_layout: Option<&UserImageLoadPlan>,
    image: &[u8],
    arguments: &[String],
) -> Result<Option<UserThreadStart>> {
    prepare_arch_user_thread_start(image_layout, image, arguments)
}

#[cfg(not(any(
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
pub(crate) fn prepare_arch_user_thread_start(
    _image_layout: Option<&UserImageLoadPlan>,
    _image: &[u8],
    _arguments: &[String],
) -> Result<Option<UserThreadStart>> {
    Ok(None)
}

// ── initial thread start / stack construction ─────────────────────────

pub(crate) fn build_initial_user_thread_start(
    instruction_pointer: usize,
    image_layout: Option<&UserImageLoadPlan>,
    arguments: &[String],
    environment: &[String],
) -> Result<Option<UserThreadStart>> {
    let Some(image_layout) = image_layout else {
        return Ok(None);
    };

    #[cfg(target_arch = "x86_64")]
    {
        let stack_pointer =
            build_x86_64_initial_user_stack(image_layout, arguments, environment)?.stack_pointer;
        Ok(Some(UserThreadStart::new(
            instruction_pointer,
            stack_pointer,
            Some(image_layout.exception_stack_top),
        )))
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = arguments;
        let _ = environment;
        Ok(Some(UserThreadStart::new(
            instruction_pointer,
            image_layout.stack_top,
            Some(image_layout.exception_stack_top),
        )))
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
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

#[cfg(target_arch = "x86_64")]
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

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
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

// ── RISC-V 64 startup helpers ────────────────────────────────────

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
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

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
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

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) fn riscv64_initial_auxv_entries(entry_point: usize) -> [(u64, u64); 3] {
    [
        (constants::AUXV_AT_PAGESZ, constants::USER_PAGE_SIZE as u64),
        (constants::AUXV_AT_ENTRY, entry_point as u64),
        (constants::AUXV_AT_NULL, 0),
    ]
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn x86_64_initial_auxv_entries(entry_point: usize) -> [(u64, u64); 2] {
    [
        (
            constants::X86_64_AUXV_AT_PAGESZ,
            constants::USER_PAGE_SIZE as u64,
        ),
        (constants::X86_64_AUXV_AT_ENTRY, entry_point as u64),
    ]
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(crate) fn aarch64_initial_auxv_entries(entry_point: usize) -> [(u64, u64); 2] {
    [
        (constants::AUXV_AT_PAGESZ, constants::USER_PAGE_SIZE as u64),
        (constants::AUXV_AT_ENTRY, entry_point as u64),
    ]
}

pub(crate) fn build_initial_user_stack(
    stack_bottom: usize,
    stack_top: usize,
    arguments: &[String],
    environment: &[String],
    auxv_entries: &[(u64, u64)],
) -> Result<PreparedInitialUserStack> {
    let mut stack_pointer = stack_top;
    let mut writes = Vec::new();

    let argument_addresses = push_c_strings(&mut stack_pointer, arguments, &mut writes)?;
    let environment_addresses = push_c_strings(&mut stack_pointer, environment, &mut writes)?;

    // Build a conventional C runtime initial stack:
    // argc, argv[], NULL, envp[], NULL, auxv[], AT_NULL.
    let metadata_slots = 1_usize
        .checked_add(argument_addresses.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(environment_addresses.len()))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(auxv_entries.len().checked_mul(2)?))
        .and_then(|value| value.checked_add(2))
        .ok_or(Error::OutOfMemory)?;
    let metadata_size = metadata_slots
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(Error::OutOfMemory)?;
    // Keep the final SP 16-byte aligned before first user instructions run.
    let final_stack_pointer = constants::align_down(
        stack_pointer
            .checked_sub(metadata_size)
            .ok_or(Error::OutOfMemory)?,
        16,
    );

    if final_stack_pointer < stack_bottom {
        return Err(Error::OutOfMemory);
    }

    let mut cursor = final_stack_pointer;
    write_u64_stack_entry(&mut writes, &mut cursor, arguments.len() as u64)?;
    for address in &argument_addresses {
        write_u64_stack_entry(&mut writes, &mut cursor, *address as u64)?;
    }
    write_u64_stack_entry(&mut writes, &mut cursor, 0)?;
    for address in &environment_addresses {
        write_u64_stack_entry(&mut writes, &mut cursor, *address as u64)?;
    }
    write_u64_stack_entry(&mut writes, &mut cursor, 0)?;
    for (key, value) in auxv_entries {
        write_u64_stack_entry(&mut writes, &mut cursor, *key)?;
        write_u64_stack_entry(&mut writes, &mut cursor, *value)?;
    }
    write_u64_stack_entry(&mut writes, &mut cursor, constants::AUXV_AT_NULL)?;
    write_u64_stack_entry(&mut writes, &mut cursor, 0)?;

    let total_len = stack_top
        .checked_sub(final_stack_pointer)
        .ok_or(Error::OutOfMemory)?;
    let mut bytes = vec![0_u8; total_len];
    for (address, data) in writes {
        let start = address
            .checked_sub(final_stack_pointer)
            .ok_or(Error::OutOfMemory)?;
        let end = start.checked_add(data.len()).ok_or(Error::OutOfMemory)?;
        bytes
            .get_mut(start..end)
            .ok_or(Error::OutOfMemory)?
            .copy_from_slice(&data);
    }

    Ok(PreparedInitialUserStack {
        stack_pointer: final_stack_pointer,
        bytes,
    })
}

pub(crate) fn push_c_strings(
    stack_pointer: &mut usize,
    values: &[String],
    writes: &mut Vec<(usize, Vec<u8>)>,
) -> Result<Vec<usize>> {
    let mut addresses = Vec::with_capacity(values.len());

    // Push from the end downward, then reverse the saved addresses so argv/env
    // pointers preserve the original caller-visible order.
    for value in values.iter().rev() {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        *stack_pointer = stack_pointer
            .checked_sub(bytes.len())
            .ok_or(Error::OutOfMemory)?;
        writes.push((*stack_pointer, bytes));
        addresses.push(*stack_pointer);
    }

    addresses.reverse();
    Ok(addresses)
}

pub(crate) fn write_u64_stack_entry(
    writes: &mut Vec<(usize, Vec<u8>)>,
    cursor: &mut usize,
    value: u64,
) -> Result<()> {
    writes.push((*cursor, value.to_le_bytes().to_vec()));
    *cursor = cursor
        .checked_add(core::mem::size_of::<u64>())
        .ok_or(Error::OutOfMemory)?;
    Ok(())
}

// ── ELF segment planning ──────────────────────────────────────────────

pub(crate) fn plan_user_image_segment(segment: ElfLoadSegment) -> Result<UserImageSegmentPlan> {
    if segment.memory_size == 0 {
        return Err(Error::InvalidArgument);
    }

    // File offset and virtual address must agree modulo alignment so the mapped
    // page image can be reconstructed correctly.
    if segment.alignment != 0
        && (segment.virtual_address & (segment.alignment - 1))
            != (segment.file_offset & (segment.alignment - 1))
    {
        return Err(Error::InvalidArgument);
    }

    let virtual_end = segment
        .virtual_address
        .checked_add(segment.memory_size)
        .ok_or(Error::InvalidArgument)?;
    let zero_start = segment
        .virtual_address
        .checked_add(segment.file_size)
        .ok_or(Error::InvalidArgument)?;
    let page_start = constants::align_down(segment.virtual_address, constants::USER_PAGE_SIZE);
    let page_end = constants::align_up(virtual_end, constants::USER_PAGE_SIZE)
        .ok_or(Error::InvalidArgument)?;

    if page_start < constants::USER_PAGE_SIZE || page_end <= page_start {
        return Err(Error::InvalidArgument);
    }

    Ok(UserImageSegmentPlan {
        virtual_start: segment.virtual_address,
        virtual_end,
        page_start,
        page_end,
        file_offset: segment.file_offset,
        file_size: segment.file_size,
        zero_start,
        zero_end: virtual_end,
        permissions: page_permissions_from_segment_flags(segment.flags)?,
    })
}

pub(crate) fn page_permissions_from_segment_flags(
    flags: ElfSegmentFlags,
) -> Result<PagePermissions> {
    if !flags.readable() && !flags.writable() && !flags.executable() {
        return Err(Error::InvalidArgument);
    }

    Ok(match (flags.writable(), flags.executable()) {
        (false, false) => PagePermissions::READ,
        (true, false) => PagePermissions::READ_WRITE,
        (false, true) => PagePermissions::READ_EXECUTE,
        (true, true) => PagePermissions::READ_WRITE_EXECUTE,
    })
}
