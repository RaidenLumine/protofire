//! src/user/program/loader/mod.rs
//!
//! ELF-image planning, user-address-space preparation, initial-user-stack
//! construction, and the [`LoadedProgram`] ↔ [`LaunchedProgram`] pipeline.
//!
//! This module consumes a [`super::catalog::ResolvedCatalogLaunch`] (or a
//! direct filesystem path) and produces a fully-prepared [`LoadedProgram`]
//! that can be spawned into a kernel or user thread.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::FileSystem;
use crate::kernel::memory::paging::PagePermissions;
use crate::kernel::process::LaunchContext;
use crate::kernel::process::Process;
use crate::kernel::process::ProcessAddressSpaceSummary;
use crate::kernel::process::ProcessUserAddressSpace;
use crate::kernel::process::Thread;
use crate::kernel::process::UserAddressSpaceSummary;
use crate::kernel::process::UserThreadStart;
use crate::Error;
use crate::Result;

use super::catalog::read_program_image;
use super::catalog::SpawnProcessOverrides;
use super::catalog::{self};
use super::constants;
#[cfg(any(feature = "demo-disk", test))]
use super::demo_runtime::resolve_program_proxy;

// ── segment / image-plan types ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserImageSegmentPlan {
    pub virtual_start: usize,
    pub virtual_end: usize,
    pub page_start: usize,
    pub page_end: usize,
    pub file_offset: usize,
    pub file_size: usize,
    pub zero_start: usize,
    pub zero_end: usize,
    pub permissions: PagePermissions,
}

impl UserImageSegmentPlan {
    pub fn page_count(&self) -> usize {
        (self.page_end - self.page_start) / constants::USER_PAGE_SIZE
    }

    pub fn contains(&self, address: usize) -> bool {
        (self.virtual_start..self.virtual_end).contains(&address)
    }

    pub fn is_writable_executable(&self) -> bool {
        self.permissions.contains(PagePermissions::WRITE)
            && self.permissions.contains(PagePermissions::EXECUTE)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserImageLoadPlan {
    pub entry_point: usize,
    pub image_start: usize,
    pub image_end: usize,
    pub stack_guard_start: usize,
    pub stack_guard_end: usize,
    pub stack_bottom: usize,
    pub stack_top: usize,
    pub exception_stack_guard_start: usize,
    pub exception_stack_guard_end: usize,
    pub exception_stack_bottom: usize,
    pub exception_stack_top: usize,
    pub segments: Vec<UserImageSegmentPlan>,
}

impl UserImageLoadPlan {
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub fn mapped_page_count(&self) -> usize {
        self.segments
            .iter()
            .map(UserImageSegmentPlan::page_count)
            .sum()
    }

    pub fn contains_instruction_pointer(&self, instruction_pointer: usize) -> bool {
        self.segments
            .iter()
            .any(|segment| segment.contains(instruction_pointer))
    }

    pub fn contains_executable_instruction_pointer(&self, instruction_pointer: usize) -> bool {
        self.segments.iter().any(|segment| {
            segment.contains(instruction_pointer)
                && segment.permissions.contains(PagePermissions::EXECUTE)
        })
    }

    pub fn has_writable_executable_segments(&self) -> bool {
        self.segments
            .iter()
            .any(UserImageSegmentPlan::is_writable_executable)
    }

    pub fn overlaps_runtime_reserved_range(&self, range_start: usize, range_end: usize) -> bool {
        constants::ranges_overlap(
            range_start,
            range_end,
            self.stack_guard_start,
            self.stack_guard_end,
        ) || constants::ranges_overlap(range_start, range_end, self.stack_bottom, self.stack_top)
            || constants::ranges_overlap(
                range_start,
                range_end,
                self.exception_stack_guard_start,
                self.exception_stack_guard_end,
            )
            || constants::ranges_overlap(
                range_start,
                range_end,
                self.exception_stack_bottom,
                self.exception_stack_top,
            )
    }

    pub fn has_consistent_runtime_layout(&self) -> bool {
        if self.image_start >= self.image_end
            || self.image_end > self.exception_stack_guard_start
            || self.exception_stack_guard_start >= self.exception_stack_guard_end
            || self.exception_stack_guard_end != self.exception_stack_bottom
            || self.exception_stack_bottom >= self.exception_stack_top
            || self.exception_stack_top != self.stack_guard_start
            || self.stack_guard_start >= self.stack_guard_end
            || self.stack_guard_end != self.stack_bottom
            || self.stack_bottom >= self.stack_top
            || !constants::is_page_aligned(self.image_start)
            || !constants::is_page_aligned(self.image_end)
            || !constants::is_page_aligned(self.stack_guard_start)
            || !constants::is_page_aligned(self.stack_guard_end)
            || !constants::is_page_aligned(self.stack_bottom)
            || !constants::is_page_aligned(self.stack_top)
            || !constants::is_page_aligned(self.exception_stack_guard_start)
            || !constants::is_page_aligned(self.exception_stack_guard_end)
            || !constants::is_page_aligned(self.exception_stack_bottom)
            || !constants::is_page_aligned(self.exception_stack_top)
        {
            return false;
        }

        let mut previous_segment_end = None;
        for segment in &self.segments {
            if segment.virtual_start >= segment.virtual_end
                || segment.page_start >= segment.page_end
                || segment.zero_start < segment.virtual_start
                || segment.zero_start > segment.zero_end
                || segment.zero_end != segment.virtual_end
                || segment.page_start > segment.virtual_start
                || segment.page_end < segment.virtual_end
                || segment.page_start < self.image_start
                || segment.page_end > self.image_end
                || !constants::is_page_aligned(segment.page_start)
                || !constants::is_page_aligned(segment.page_end)
                || self.overlaps_runtime_reserved_range(segment.page_start, segment.page_end)
                || previous_segment_end.is_some_and(|end| end > segment.page_start)
            {
                return false;
            }
            previous_segment_end = Some(segment.page_end);
        }

        true
    }

    pub fn contains_stack_pointer(&self, stack_pointer: usize) -> bool {
        self.contains_runtime_stack_pointer(self.stack_bottom, self.stack_top, stack_pointer)
    }

    pub fn has_expected_exception_stack_pointer(
        &self,
        exception_stack_pointer: Option<usize>,
    ) -> bool {
        exception_stack_pointer == Some(self.exception_stack_top)
    }

    pub fn validate_thread_start(&self, start: UserThreadStart) -> Result<UserThreadStart> {
        // The top-of-stack value itself is a valid initial SP even though the
        // first writable byte still lies below it, so the range stays inclusive.
        if !self.has_consistent_runtime_layout()
            || self.has_writable_executable_segments()
            || !self.contains_executable_instruction_pointer(start.instruction_pointer)
            || !self.contains_stack_pointer(start.stack_pointer)
            // Loaded programs always reserve a dedicated exception stack, so
            // the starting exception SP must match the planned empty-stack top.
            || !self.has_expected_exception_stack_pointer(start.exception_stack_pointer)
        {
            return Err(Error::InternalError);
        }

        Ok(start)
    }

    fn contains_runtime_stack_pointer(
        &self,
        stack_bottom: usize,
        stack_top: usize,
        stack_pointer: usize,
    ) -> bool {
        (stack_bottom..=stack_top).contains(&stack_pointer)
    }
}

// ── internal runtime-preparation types ────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedInitialUserStack {
    pub(crate) stack_pointer: usize,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) struct PreparedLoadedProgramRuntime {
    machine: u16,
    entry_point: usize,
    image_layout: Option<UserImageLoadPlan>,
    image_len: usize,
    initial_user_thread_start: Option<UserThreadStart>,
    prepared_user_address_space: Option<ProcessUserAddressSpace>,
    user_address_space_summary: Option<UserAddressSpaceSummary>,
    process_address_space_summary: Option<ProcessAddressSpaceSummary>,
}

// ── LoadedProgramDescriptor ───────────────────────────────────────────

pub(crate) struct LoadedProgramDescriptor {
    catalog_path: String,
    catalog_id: String,
    manifest_path: String,
    path: String,
    name: String,
    version: String,
    working_dir: String,
    arguments: Vec<String>,
    environment: Vec<String>,
    host_proxy: Option<String>,
}

impl LoadedProgramDescriptor {
    fn from_direct_filesystem_load(normalized_path: String, normalized_cwd: String) -> Self {
        Self {
            catalog_path: String::new(),
            catalog_id: String::new(),
            manifest_path: String::new(),
            path: normalized_path.clone(),
            name: normalized_path.clone(),
            version: String::new(),
            working_dir: normalized_cwd,
            arguments: vec![normalized_path],
            environment: Vec::new(),
            host_proxy: None,
        }
    }

    fn from_resolved_catalog_launch(
        resolved: super::catalog::ResolvedCatalogLaunch,
    ) -> (Self, Vec<u8>) {
        let super::catalog::ResolvedCatalogLaunch {
            catalog_path,
            catalog_id,
            manifest_path,
            image_path,
            name,
            version,
            working_dir,
            arguments,
            environment,
            host_proxy,
            image,
        } = resolved;

        (
            Self {
                catalog_path,
                catalog_id,
                manifest_path,
                path: image_path,
                name,
                version,
                working_dir,
                arguments,
                environment,
                host_proxy,
            },
            image,
        )
    }

    fn prepare_runtime(&self, image: &[u8]) -> Result<PreparedLoadedProgramRuntime> {
        prepare_loaded_program_runtime(image, &self.arguments, &self.environment, &self.working_dir)
    }

    fn into_loaded_program(self, runtime: PreparedLoadedProgramRuntime) -> LoadedProgram {
        let Self {
            catalog_path,
            catalog_id,
            manifest_path,
            path,
            name,
            version,
            working_dir,
            arguments,
            environment,
            host_proxy,
        } = self;

        LoadedProgram {
            catalog_path,
            catalog_id,
            manifest_path,
            path,
            name,
            version,
            working_dir,
            machine: runtime.machine,
            entry_point: runtime.entry_point,
            image_layout: runtime.image_layout,
            image_len: runtime.image_len,
            arguments,
            environment,
            host_proxy,
            initial_user_thread_start: runtime.initial_user_thread_start,
            prepared_user_address_space: runtime.prepared_user_address_space,
            user_address_space_summary: runtime.user_address_space_summary,
            process_address_space_summary: runtime.process_address_space_summary,
        }
    }
}

// ── LoadedProgram / LoadedProgramInstallState / LaunchedProgram ───────

pub struct LoadedProgram {
    pub catalog_path: String,
    pub catalog_id: String,
    pub manifest_path: String,
    pub path: String,
    pub name: String,
    pub version: String,
    pub working_dir: String,
    pub machine: u16,
    pub entry_point: usize,
    pub image_layout: Option<UserImageLoadPlan>,
    pub image_len: usize,
    pub arguments: Vec<String>,
    pub environment: Vec<String>,
    // Consumed by the demo/test host-proxy dispatch (spawn.rs
    // `resolve_loaded_program_host_proxy_entry`), which is only compiled for
    // the demo disk / tests, so the field stays but is allowed unused.
    #[allow(dead_code)]
    pub(crate) host_proxy: Option<String>,
    pub(crate) initial_user_thread_start: Option<UserThreadStart>,
    pub(crate) prepared_user_address_space: Option<ProcessUserAddressSpace>,
    pub(crate) user_address_space_summary: Option<UserAddressSpaceSummary>,
    pub(crate) process_address_space_summary: Option<ProcessAddressSpaceSummary>,
}

pub(crate) struct LoadedProgramInstallState {
    pub(crate) launch_context: LaunchContext,
    pub(crate) user_thread_start: Option<UserThreadStart>,
    pub(crate) prepared_user_address_space: Option<ProcessUserAddressSpace>,
}

impl LoadedProgramInstallState {
    pub(crate) fn user_thread_start(&self) -> Option<UserThreadStart> {
        self.user_thread_start
    }

    pub(crate) fn into_exec_parts(
        self,
    ) -> (
        LaunchContext,
        Option<ProcessUserAddressSpace>,
        Option<UserThreadStart>,
    ) {
        (
            self.launch_context,
            self.prepared_user_address_space,
            self.user_thread_start,
        )
    }

    pub(crate) fn install_into_process(self, process: &Process) {
        let Self {
            launch_context,
            prepared_user_address_space,
            ..
        } = self;
        process.configure_launch(launch_context);
        if let Some(address_space) = prepared_user_address_space {
            process.install_user_address_space(address_space);
        }
    }
}

impl LoadedProgram {
    pub fn load_segment_count(&self) -> usize {
        self.image_layout
            .as_ref()
            .map(UserImageLoadPlan::segment_count)
            .unwrap_or(0)
    }

    pub fn user_address_space_summary(&self) -> Option<UserAddressSpaceSummary> {
        self.user_address_space_summary
    }

    pub fn process_address_space_summary(&self) -> Option<ProcessAddressSpaceSummary> {
        self.process_address_space_summary
    }

    pub fn user_thread_start(&self) -> Option<UserThreadStart> {
        self.initial_user_thread_start
    }

    fn validate_install_state_shape(&self) -> Result<()> {
        let derived_user_summary = self
            .prepared_user_address_space
            .as_ref()
            .map(ProcessUserAddressSpace::summary);
        let derived_process_summary = self
            .prepared_user_address_space
            .as_ref()
            .and_then(ProcessUserAddressSpace::process_summary);

        if self.initial_user_thread_start.is_some() != self.prepared_user_address_space.is_some() {
            return Err(Error::InternalError);
        }

        if self.user_address_space_summary != derived_user_summary {
            return Err(Error::InternalError);
        }

        if self.process_address_space_summary != derived_process_summary {
            return Err(Error::InternalError);
        }

        if let Some(start) = self.initial_user_thread_start {
            let start = start.validate().map_err(|_| Error::InternalError)?;
            if self.entry_point != start.instruction_pointer {
                return Err(Error::InternalError);
            }
            #[cfg(any(
                all(target_arch = "aarch64", target_os = "none"),
                all(target_arch = "riscv64", target_os = "none")
            ))]
            if let Some(prepared) = self.prepared_user_address_space.as_ref() {
                // The demo-slot loader intentionally rebases the ELF image
                // into a fixed runtime window, so install validation must
                // follow the prepared slot layout rather than the original
                // ELF virtual addresses recorded in `image_layout`.
                if !prepared.matches_prepared_user_thread_start(start) {
                    return Err(Error::InternalError);
                }
            } else if let Some(image_layout) = self.image_layout.as_ref() {
                image_layout.validate_thread_start(start)?;
            }
            #[cfg(not(any(
                all(target_arch = "aarch64", target_os = "none"),
                all(target_arch = "riscv64", target_os = "none")
            )))]
            if let Some(image_layout) = self.image_layout.as_ref() {
                image_layout.validate_thread_start(start)?;
            }
        }

        Ok(())
    }

    pub(crate) fn take_install_state(&mut self) -> Result<LoadedProgramInstallState> {
        self.validate_install_state_shape()?;
        Ok(LoadedProgramInstallState {
            launch_context: self.launch_context(),
            user_thread_start: self.initial_user_thread_start.take(),
            prepared_user_address_space: self.prepared_user_address_space.take(),
        })
    }

    pub(crate) fn launch_context(&self) -> LaunchContext {
        // Copy launch metadata into the process record before the thread starts
        // so user syscalls can query argv/env/cwd immediately.
        LaunchContext {
            catalog_id: self.catalog_id.clone(),
            manifest_path: self.manifest_path.clone(),
            image_path: self.path.clone(),
            version: self.version.clone(),
            working_dir: self.working_dir.clone(),
            arguments: self.arguments.clone(),
            environment: self.environment.clone(),
        }
    }

    #[allow(dead_code)]
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn install_into_current_thread(
        &mut self,
        process: &Process,
        thread: &Thread,
    ) -> Result<()> {
        let install_state = self.take_install_state()?;
        let start = install_state
            .user_thread_start()
            .ok_or(Error::Unsupported)?;
        install_state.install_into_process(process);
        thread.replace_x86_64_user_image(start)?;
        Ok(())
    }

    #[allow(dead_code)]
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub(crate) fn install_into_current_thread(
        &mut self,
        process: &Process,
        thread: &Thread,
    ) -> Result<()> {
        let install_state = self.take_install_state()?;
        let start = install_state
            .user_thread_start()
            .ok_or(Error::Unsupported)?;
        install_state.install_into_process(process);
        thread.replace_aarch64_user_image(start)?;
        Ok(())
    }

    #[allow(dead_code)]
    #[cfg(all(
        not(target_arch = "x86_64"),
        not(all(target_arch = "aarch64", target_os = "none"))
    ))]
    pub(crate) fn install_into_current_thread(
        &mut self,
        _process: &Process,
        _thread: &Thread,
    ) -> Result<()> {
        Err(Error::Unsupported)
    }
}

pub struct LaunchedProgram {
    pub loaded: LoadedProgram,
    pub process: Arc<Process>,
}

// ── public load functions ─────────────────────────────────────────────

pub fn load_from_filesystem(fs: &FileSystem, cwd: &str, path: &str) -> Result<LoadedProgram> {
    let normalized_cwd = crate::kernel::fs::path::normalize_path(cwd, "/")?;
    let normalized_path = crate::kernel::fs::path::normalize_path(path, &normalized_cwd)?;
    let descriptor =
        LoadedProgramDescriptor::from_direct_filesystem_load(normalized_path, normalized_cwd);
    let image = read_program_image(fs, &descriptor.working_dir, &descriptor.path)?;
    let runtime = descriptor.prepare_runtime(&image)?;

    // Direct filesystem loads have no catalog or manifest metadata, so the
    // loaded record carries only the resolved image path and minimal defaults.
    Ok(descriptor.into_loaded_program(runtime))
}

pub fn load_from_catalog(fs: &FileSystem, cwd: &str, catalog_path: &str) -> Result<LoadedProgram> {
    load_from_catalog_with_overrides(fs, cwd, catalog_path, SpawnProcessOverrides::default())
}

pub fn load_from_catalog_with_overrides(
    fs: &FileSystem,
    cwd: &str,
    catalog_path: &str,
    overrides: SpawnProcessOverrides,
) -> Result<LoadedProgram> {
    load_from_catalog_with_appended_arguments(fs, cwd, catalog_path, overrides, &[])
}

pub(crate) fn load_from_catalog_with_appended_arguments(
    fs: &FileSystem,
    cwd: &str,
    catalog_path: &str,
    overrides: SpawnProcessOverrides,
    appended_arguments: &[String],
) -> Result<LoadedProgram> {
    load_from_catalog_with_appended_arguments_at_depth(
        fs,
        cwd,
        catalog_path,
        overrides,
        appended_arguments,
        0,
    )
}

/// Phase 1 of program loading: resolve the catalog entry and read the ELF
/// image from the filesystem.  Must be called with the filesystem lock held.
/// Returns intermediate state that is processed by [`finish_loading_program`].
pub(crate) fn resolve_and_load_catalog_image_at_depth(
    fs: &FileSystem,
    cwd: &str,
    catalog_path: &str,
    overrides: SpawnProcessOverrides,
    appended_arguments: &[String],
    redirect_depth: usize,
) -> Result<(LoadedProgramDescriptor, Vec<u8>)> {
    let resolved = catalog::resolve_catalog_launch_with_appended_arguments_at_depth(
        fs,
        cwd,
        catalog_path,
        overrides,
        appended_arguments,
        redirect_depth,
    )?;
    Ok(LoadedProgramDescriptor::from_resolved_catalog_launch(
        resolved,
    ))
}

/// Phase 2 of program loading: validate, prepare the runtime (ELF → address
/// space), and assemble the final [`LoadedProgram`].  The filesystem lock is
/// NOT held during this phase, so it is safe to call `global_mut()` without
/// risking a deadlock with a cross-CPU TLB shootdown.
pub(crate) fn finish_loading_program(
    descriptor: LoadedProgramDescriptor,
    image: Vec<u8>,
) -> Result<LoadedProgram> {
    let runtime = descriptor.prepare_runtime(&image)?;
    validate_catalog_program(
        descriptor.host_proxy.as_deref(),
        runtime.machine,
        runtime.image_layout.as_ref(),
    )?;
    Ok(descriptor.into_loaded_program(runtime))
}

fn load_from_catalog_with_appended_arguments_at_depth(
    fs: &FileSystem,
    cwd: &str,
    catalog_path: &str,
    overrides: SpawnProcessOverrides,
    appended_arguments: &[String],
    redirect_depth: usize,
) -> Result<LoadedProgram> {
    let (descriptor, image) = resolve_and_load_catalog_image_at_depth(
        fs,
        cwd,
        catalog_path,
        overrides,
        appended_arguments,
        redirect_depth,
    )?;
    finish_loading_program(descriptor, image)
}

// ── submodules ────────────────────────────────────────────────────

pub(crate) mod arch;
pub(crate) mod plan;

// ── re-exports ──────────────────────────────────────────────────────

pub(crate) use arch::*;
pub use plan::plan_user_image_load;
pub(crate) use plan::*;

// ── catalog-program validation (depends on loader types) ──────────────

pub(crate) fn validate_catalog_program(
    host_proxy: Option<&str>,
    machine: u16,
    _image_layout: Option<&UserImageLoadPlan>,
) -> Result<()> {
    if machine != constants::DEMO_PROGRAM_MACHINE {
        return Err(Error::Unsupported);
    }

    #[cfg(target_os = "none")]
    {
        // Bare-metal builds can launch directly when the loader produced a real
        // user image. A host proxy is required only for metadata-only payloads.
        if _image_layout.is_some() {
            return Ok(());
        }
    }

    let host_proxy = host_proxy.ok_or(Error::NotFound)?;
    // Host-proxy resolution is distribution-specific and only available when
    // the demo runtime is compiled; other builds have no proxy programs to
    // resolve, so metadata-only payloads cannot launch.
    #[cfg(any(feature = "demo-disk", test))]
    {
        let _ = resolve_program_proxy(host_proxy, machine)?;
        Ok(())
    }
    #[cfg(not(any(feature = "demo-disk", test)))]
    {
        let _ = host_proxy;
        Err(Error::NotFound)
    }
}
