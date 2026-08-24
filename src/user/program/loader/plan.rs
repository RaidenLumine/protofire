//! src/user/program/loader/plan.rs
//!
use super::*;

use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::memory::paging::PagePermissions;
use crate::kernel::process::ProcessUserAddressSpace;
use crate::{Error, Result};

use super::super::constants;
use super::super::metadata::validate_launch_metadata_budget;
use crate::user::elf::{parse_elf64, ElfImage};

// ── ELF → UserImageLoadPlan ──────────────────────────────────────────

pub fn plan_user_image_load(elf: &ElfImage<'_>) -> Result<Option<UserImageLoadPlan>> {
    let load_segments = elf.load_segments()?;
    if load_segments.is_empty() {
        return Ok(None);
    }

    let mut planned_segments = Vec::with_capacity(load_segments.len());
    for segment in load_segments {
        let planned = plan_user_image_segment(segment)?;
        if planned.is_writable_executable() {
            return Err(Error::InvalidArgument);
        }
        planned_segments.push(planned);
    }
    planned_segments.sort_by_key(|segment| segment.page_start);

    for index in 1..planned_segments.len() {
        let previous = &planned_segments[index - 1];
        let current = &planned_segments[index];
        // Only reject segments whose actual virtual-address ranges truly
        // overlap, not merely whose page-aligned bounding boxes touch.
        // Page-aligned adjacency is harmless — the page-table mapper can
        // use the union of permissions for the shared page, which is
        // acceptable within a single ring3 process.
        if constants::ranges_overlap(
            previous.virtual_start,
            previous.virtual_end,
            current.virtual_start,
            current.virtual_end,
        ) && previous.permissions != current.permissions
        {
            return Err(Error::AlreadyExists);
        }
    }

    if !planned_segments.iter().any(|segment| {
        segment.contains(elf.entry_point) && segment.permissions.contains(PagePermissions::EXECUTE)
    }) {
        return Err(Error::InvalidArgument);
    }

    let image_start = planned_segments
        .first()
        .map(|segment| segment.page_start)
        .ok_or(Error::InternalError)?;
    let image_end = planned_segments
        .last()
        .map(|segment| segment.page_end)
        .ok_or(Error::InternalError)?;
    let stack_top = constants::default_user_stack_top();
    let stack_bottom = stack_top
        .checked_sub(constants::USER_STACK_SIZE)
        .ok_or(Error::OutOfMemory)?;
    let stack_guard_start = stack_bottom
        .checked_sub(constants::USER_STACK_GUARD_SIZE)
        .ok_or(Error::OutOfMemory)?;
    let stack_guard_end = stack_bottom;
    let exception_stack_top = stack_guard_start;
    let exception_stack_bottom = exception_stack_top
        .checked_sub(constants::USER_EXCEPTION_STACK_SIZE)
        .ok_or(Error::OutOfMemory)?;
    let exception_stack_guard_start = exception_stack_bottom
        .checked_sub(constants::USER_EXCEPTION_STACK_GUARD_SIZE)
        .ok_or(Error::OutOfMemory)?;
    let exception_stack_guard_end = exception_stack_bottom;
    let required_end = image_end
        .checked_add(constants::USER_IMAGE_STACK_GAP)
        .ok_or(Error::OutOfMemory)?;
    // Leave a fixed gap plus dedicated guard pages between the image, the
    // normal user stack, and the exception stack.
    if required_end > exception_stack_guard_start {
        return Err(Error::OutOfMemory);
    }

    Ok(Some(UserImageLoadPlan {
        entry_point: elf.entry_point,
        image_start,
        image_end,
        stack_guard_start,
        stack_guard_end,
        stack_bottom,
        stack_top,
        exception_stack_guard_start,
        exception_stack_guard_end,
        exception_stack_bottom,
        exception_stack_top,
        segments: planned_segments,
    }))
}

// ── runtime preparation ───────────────────────────────────────────────

pub(crate) fn prepare_loaded_program_runtime(
    image: &[u8],
    arguments: &[String],
    environment: &[String],
    working_dir: &str,
) -> Result<PreparedLoadedProgramRuntime> {
    validate_launch_metadata_budget(arguments, environment, working_dir)?;

    let elf = parse_elf64(image)?;
    let image_layout = plan_user_image_load(&elf)?;
    let mut entry_point = elf.entry_point;
    let mut initial_user_thread_start = build_initial_user_thread_start(
        entry_point,
        image_layout.as_ref(),
        arguments,
        environment,
    )?;
    let prepared_user_address_space =
        prepare_arch_user_address_space(image_layout.as_ref(), image, arguments, environment)?;
    if let Some(start) = prepare_loaded_user_thread_start(
        prepared_user_address_space.as_ref(),
        image_layout.as_ref(),
        image,
        arguments,
    )? {
        entry_point = start.instruction_pointer;
        initial_user_thread_start = Some(start);
    }

    Ok(PreparedLoadedProgramRuntime {
        machine: elf.machine,
        entry_point,
        image_layout,
        image_len: image.len(),
        initial_user_thread_start,
        user_address_space_summary: prepared_user_address_space
            .as_ref()
            .map(ProcessUserAddressSpace::summary),
        process_address_space_summary: prepared_user_address_space
            .as_ref()
            .and_then(ProcessUserAddressSpace::process_summary),
        prepared_user_address_space,
    })
}

// ── page content extraction ────────────────────────────────────────────

/// Extract the ELF-originated content for a single page at `page_start`.
///
/// Returns a zero-filled page if `page_start` does not fall within any
/// image segment, which is the correct behaviour for DemandPaged BSS
/// zero-extensions and guard pages.
#[cfg(target_arch = "x86_64")]
pub(crate) fn extract_page_content(
    page_start: usize,
    load_plan: &UserImageLoadPlan,
    image: &[u8],
) -> Vec<u8> {
    let page_size = constants::USER_PAGE_SIZE;
    let mut content = alloc::vec![0u8; page_size];
    let page_end = page_start + page_size;

    if let Some(segment) = load_plan
        .segments
        .iter()
        .find(|seg| page_start >= seg.page_start && page_start < seg.page_end)
    {
        let copy_start = segment.virtual_start.max(page_start);
        let copy_end = page_end.min(segment.zero_start);

        if copy_start < copy_end {
            let copy_offset = copy_start - segment.virtual_start;
            let src_start = segment.file_offset + copy_offset;
            let copy_len = copy_end - copy_start;
            let dst_start = copy_start - page_start;

            if let Some(source) = image.get(src_start..src_start + copy_len) {
                content[dst_start..dst_start + copy_len].copy_from_slice(source);
            }
        }
    }

    content
}
