//! src/user/program/spawn.rs
//!
//! Process-spawn entry points wired to the catalog/manifest loader.
//!
//! This module exposes the public spawn API that external callers
//! ([`super::shell`], kernel syscall pipeline) use to launch user programs
//! from catalog references with optional overrides and security tokens.

use alloc::sync::Arc;

use crate::kernel::fs;
#[cfg(target_os = "none")]
use crate::kernel::process::UserThreadStart;
use crate::kernel::process::{Process, Scheduler, SecurityToken, Thread};
use crate::{Error, Result};

use super::catalog::SpawnProcessOverrides;
#[cfg(any(feature = "demo-disk", test))]
use super::constants::*;
#[cfg(any(feature = "demo-disk", test))]
use super::demo_runtime::resolve_program_proxy;
use super::launch_reference;
#[cfg(not(target_os = "none"))]
use super::loader::LoadedProgramInstallState;
use super::loader::{LaunchedProgram, LoadedProgram};

pub fn spawn_from_global(scheduler: &Scheduler, launch_reference: &str) -> Result<LaunchedProgram> {
    spawn_from_launch_reference(scheduler, "/", launch_reference)
}

pub fn spawn_from_catalog_path(
    scheduler: &Scheduler,
    cwd: &str,
    launch_reference: &str,
) -> Result<LaunchedProgram> {
    spawn_from_catalog_reference(scheduler, cwd, launch_reference)
}

pub fn spawn_from_catalog_reference(
    scheduler: &Scheduler,
    cwd: &str,
    catalog_reference: &str,
) -> Result<LaunchedProgram> {
    spawn_from_launch_reference(scheduler, cwd, catalog_reference)
}

pub fn spawn_from_launch_reference(
    scheduler: &Scheduler,
    cwd: &str,
    launch_reference: &str,
) -> Result<LaunchedProgram> {
    spawn_from_launch_reference_with_overrides(
        scheduler,
        cwd,
        launch_reference,
        SpawnProcessOverrides::default(),
    )
}

pub fn spawn_from_catalog_path_with_overrides(
    scheduler: &Scheduler,
    cwd: &str,
    catalog_path: &str,
    overrides: SpawnProcessOverrides,
) -> Result<LaunchedProgram> {
    spawn_from_launch_reference_with_overrides(scheduler, cwd, catalog_path, overrides)
}

pub fn spawn_from_catalog_reference_with_overrides(
    scheduler: &Scheduler,
    cwd: &str,
    catalog_reference: &str,
    overrides: SpawnProcessOverrides,
) -> Result<LaunchedProgram> {
    spawn_from_launch_reference_with_overrides(scheduler, cwd, catalog_reference, overrides)
}

pub fn spawn_from_launch_reference_with_overrides(
    scheduler: &Scheduler,
    cwd: &str,
    launch_reference: &str,
    overrides: SpawnProcessOverrides,
) -> Result<LaunchedProgram> {
    spawn_from_launch_reference_with_overrides_and_security_token(
        scheduler,
        cwd,
        launch_reference,
        overrides,
        SecurityToken::guest(),
    )
}

pub(crate) fn spawn_from_launch_reference_with_overrides_and_security_token(
    scheduler: &Scheduler,
    cwd: &str,
    launch_reference: &str,
    overrides: SpawnProcessOverrides,
    security_token: SecurityToken,
) -> Result<LaunchedProgram> {
    let loaded =
        load_installed_launch_with_overrides_from_global(cwd, launch_reference, overrides)?;
    launch_loaded_program_with_security_token(scheduler, loaded, security_token, false)
}

pub(crate) fn load_installed_launch_with_overrides_from_global(
    cwd: &str,
    launch_reference: &str,
    overrides: SpawnProcessOverrides,
) -> Result<LoadedProgram> {
    let fs = fs::global().ok_or(Error::InternalError)?;
    // Delegate to the split-phase loader which releases the filesystem lock
    // before calling `prepare_runtime` (which needs `global_mut()`).  This
    // avoids a cross-CPU deadlock: the filesystem SpinLock disables local
    // interrupts, which prevents TLB-shootdown-IPI acknowledgment from
    // another CPU that holds the memory-manager lock.
    launch_reference::load_installed_catalog_split_phase(fs, cwd, launch_reference, overrides)
}

#[cfg(not(target_os = "none"))]
pub(crate) fn launch_loaded_program_with_security_token(
    scheduler: &Scheduler,
    mut loaded: LoadedProgram,
    security_token: SecurityToken,
    _start_suspended: bool,
) -> Result<LaunchedProgram> {
    let host_proxy_entry = resolve_loaded_program_host_proxy_entry(&loaded)?;
    let install_state = loaded.take_install_state()?;

    let thread = launch_host_loaded_program_with_security_token_and_setup(
        scheduler,
        &loaded,
        security_token,
        host_proxy_entry,
        install_state,
    );

    let process = thread.process().clone();

    Ok(LaunchedProgram { loaded, process })
}

#[cfg(target_os = "none")]
pub(crate) fn launch_loaded_program_with_security_token(
    scheduler: &Scheduler,
    mut loaded: LoadedProgram,
    security_token: SecurityToken,
    start_suspended: bool,
) -> Result<LaunchedProgram> {
    let install_state = loaded.take_install_state()?;
    let user_thread_start = install_state.user_thread_start();
    let thread = spawn_bare_metal_loaded_program_thread_with_security_token_and_setup(
        scheduler,
        &loaded,
        security_token,
        user_thread_start,
        |process| install_state.install_into_process(process.as_ref()),
        start_suspended,
    )?;

    let process = thread.process().clone();

    Ok(LaunchedProgram { loaded, process })
}

#[cfg(not(target_os = "none"))]
fn launch_host_loaded_program_with_security_token_and_setup(
    scheduler: &Scheduler,
    loaded: &LoadedProgram,
    security_token: SecurityToken,
    entry: fn(),
    install_state: LoadedProgramInstallState,
) -> Arc<Thread> {
    spawn_host_loaded_program_thread_with_security_token_and_setup(
        scheduler,
        loaded,
        security_token,
        entry,
        move |process| install_state.install_into_process(process.as_ref()),
    )
}

#[cfg(all(not(target_os = "none"), any(feature = "demo-disk", test)))]
fn resolve_loaded_program_host_proxy_entry(loaded: &LoadedProgram) -> Result<fn()> {
    resolve_program_proxy(
        loaded.host_proxy.as_deref().ok_or(Error::NotFound)?,
        loaded.machine,
    )
}

#[cfg(all(not(target_os = "none"), not(any(feature = "demo-disk", test))))]
fn resolve_loaded_program_host_proxy_entry(_loaded: &LoadedProgram) -> Result<fn()> {
    Err(Error::NotFound)
}

#[cfg(not(target_os = "none"))]
fn spawn_host_loaded_program_thread_with_security_token_and_setup<F>(
    scheduler: &Scheduler,
    loaded: &LoadedProgram,
    security_token: SecurityToken,
    entry: fn(),
    setup: F,
) -> Arc<Thread>
where
    F: FnOnce(&Arc<Process>),
{
    scheduler.spawn_kernel_named_with_security_token_and_setup(
        &loaded.name,
        security_token,
        entry,
        setup,
    )
}

#[cfg(target_os = "none")]
fn spawn_bare_metal_loaded_program_thread_with_security_token_and_setup<F>(
    scheduler: &Scheduler,
    loaded: &LoadedProgram,
    security_token: SecurityToken,
    user_thread_start: Option<UserThreadStart>,
    setup: F,
    start_suspended: bool,
) -> Result<Arc<Thread>>
where
    F: FnOnce(&Arc<Process>),
{
    if let Some(start) = user_thread_start
        .map(UserThreadStart::validate)
        .transpose()?
    {
        // Bare metal prefers a real user thread whenever the loader produced a
        // mapped user image and initial register state.
        return scheduler.try_spawn_user_named_with_security_token_and_setup(
            &loaded.name,
            security_token,
            start,
            setup,
            start_suspended,
        );
    }

    // Metadata-only payloads still run through host proxies when the
    // demo-disk feature is enabled or during testing.
    #[cfg(any(feature = "demo-disk", test))]
    {
        let entry = resolve_program_proxy(
            loaded.host_proxy.as_deref().ok_or(Error::NotFound)?,
            loaded.machine,
        )?;
        return Ok(scheduler.spawn_kernel_named_with_security_token_and_setup(
            &loaded.name,
            security_token,
            entry,
            setup,
        ));
    }

    // Without demo-disk, metadata-only payloads cannot be launched —
    // there are no host proxies to resolve.
    #[cfg(not(any(feature = "demo-disk", test)))]
    {
        let _ = (loaded, security_token, setup);
        Err(Error::NotFound)
    }
}

// Demo-specific spawn convenience wrappers.  These are gated behind the
// `demo-disk` feature because they depend on distribution-specific catalog
// paths that only exist on the in-memory demo volumes.
#[cfg(any(feature = "demo-disk", test))]
pub fn spawn_demo_program(scheduler: &Scheduler) -> Result<LaunchedProgram> {
    spawn_from_global(scheduler, DEMO_CURRENT_PATH)
}

#[cfg(any(feature = "demo-disk", test))]
pub fn spawn_demo_rust_program(scheduler: &Scheduler) -> Result<LaunchedProgram> {
    spawn_from_global(scheduler, DEMO_RUST_CURRENT_PATH)
}

#[cfg(any(feature = "demo-disk", test))]
pub fn spawn_demo_rust_io_program(scheduler: &Scheduler) -> Result<LaunchedProgram> {
    spawn_from_global(scheduler, DEMO_RUST_IO_CURRENT_PATH)
}

#[cfg(any(feature = "demo-disk", test))]
pub fn spawn_demo_fault_program(scheduler: &Scheduler) -> Result<LaunchedProgram> {
    spawn_from_global(scheduler, DEMO_FAULT_CURRENT_PATH)
}

#[cfg(any(feature = "demo-disk", test))]
pub fn spawn_demo_invalid_opcode_program(scheduler: &Scheduler) -> Result<LaunchedProgram> {
    spawn_from_global(scheduler, DEMO_INVALID_OPCODE_CURRENT_PATH)
}

#[cfg(any(feature = "demo-disk", test))]
pub fn spawn_demo_general_protection_program(scheduler: &Scheduler) -> Result<LaunchedProgram> {
    spawn_from_global(scheduler, DEMO_GENERAL_PROTECTION_CURRENT_PATH)
}

#[cfg(any(feature = "demo-disk", test))]
pub fn spawn_demo_one_shot_page_fault_program(scheduler: &Scheduler) -> Result<LaunchedProgram> {
    spawn_from_global(scheduler, DEMO_ONE_SHOT_PAGE_FAULT_CURRENT_PATH)
}

#[cfg(any(feature = "demo-disk", test))]
pub fn spawn_demo_nested_page_fault_program(scheduler: &Scheduler) -> Result<LaunchedProgram> {
    spawn_from_global(scheduler, DEMO_NESTED_PAGE_FAULT_CURRENT_PATH)
}
