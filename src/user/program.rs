//! src/user/program.rs
//!
//! Catalog and manifest driven user program loader plus user-program regression
//! tests.
//!
//! This module is the public hub: submodules own the implementation details
//! ([`catalog`], [`constants`], [`loader`], [`metadata`], [`spawn`]) while
//! this file re-exports the public surface.  Regression tests live in
//! [`tests`](tests).

// ── submodules ───────────────────────────────────────────────────────
//
// The user-facing complete-OS surfaces (interactive shell, appctl/app-center
// CLI, install-management recovery) belong out of the kernel per the purity
// directive: they are reachable only from the demo disk or tests, so they are
// gated accordingly.  The catalog/spawn loader core stays always-compiled.

#[cfg(any(feature = "demo-disk", test))]
mod app;
mod catalog;
mod constants;
#[cfg(any(feature = "demo-disk", test))]
pub mod demo_runtime;
#[cfg(any(test, feature = "demo-disk", target_os = "none"))]
mod install;
mod integrity;
mod launch_reference;
mod loader;
mod metadata;
#[cfg(any(feature = "demo-disk", test))]
mod shell;
mod signature;
mod spawn;

// ── re-export public types so external callers and the test suite see
//    them unchanged from the original flat layout ──────────────────────

pub use self::constants::*;

pub use self::catalog::normalize_path_from_root;
pub use self::catalog::normalize_path_pair_from_root;
pub use self::catalog::path_parent_dir;
pub use self::catalog::read_program_image;
pub use self::catalog::read_text_file;
pub use self::catalog::CatalogEntry;
pub use self::catalog::LaunchManifest;
pub use self::catalog::SpawnProcessOverrides;

pub use self::loader::load_from_catalog;
pub use self::loader::load_from_catalog_with_overrides;
pub use self::loader::load_from_filesystem;
pub use self::loader::plan_user_image_load;
pub use self::loader::LaunchedProgram;
pub use self::loader::LoadedProgram;
pub use self::loader::UserImageLoadPlan;
pub use self::loader::UserImageSegmentPlan;

// Install-management recovery (transaction log + download cache) reached at
// boot from kernel/mod.rs under `test`/`target_os = "none"`; the enums are
// surfaced here (kernel/mod.rs reads the report struct's fields through the
// return value without naming the type).  The demo-disk appctl surface calls
// `super::install::` directly, so it does not need this re-export.
#[cfg(any(test, target_os = "none"))]
pub(crate) use self::install::recover_install_management_state;
#[cfg(any(test, target_os = "none"))]
pub(crate) use self::install::DownloadCachePruneOutcome;
#[cfg(any(test, target_os = "none"))]
pub(crate) use self::install::InstallTransactionRecoveryOutcome;
#[cfg(any(test, target_os = "none"))]
pub(crate) use self::install::TransactionLogRepairReason;

// Re-export spawn entry points
pub(crate) use self::spawn::launch_loaded_program_with_security_token;
pub(crate) use self::spawn::load_installed_launch_with_overrides_from_global;
// The shell's `login`/`su` commands are the only callers; gated with the shell
// module (which is only compiled for the demo disk / tests).
#[cfg(any(feature = "demo-disk", test))]
pub(crate) use self::spawn::spawn_from_launch_reference_with_overrides_and_security_token;
// Generic spawn entry points (always available).
pub use self::spawn::spawn_from_catalog_path;
pub use self::spawn::spawn_from_catalog_path_with_overrides;
pub use self::spawn::spawn_from_catalog_reference;
pub use self::spawn::spawn_from_catalog_reference_with_overrides;
pub use self::spawn::spawn_from_global;
pub use self::spawn::spawn_from_launch_reference;
pub use self::spawn::spawn_from_launch_reference_with_overrides;

// Demo-specific spawn wrappers (distribution-specific; gated behind demo-disk).
#[cfg(any(feature = "demo-disk", test))]
pub use self::spawn::spawn_demo_fault_program;
#[cfg(any(feature = "demo-disk", test))]
pub use self::spawn::spawn_demo_general_protection_program;
#[cfg(any(feature = "demo-disk", test))]
pub use self::spawn::spawn_demo_invalid_opcode_program;
#[cfg(any(feature = "demo-disk", test))]
pub use self::spawn::spawn_demo_nested_page_fault_program;
#[cfg(any(feature = "demo-disk", test))]
pub use self::spawn::spawn_demo_one_shot_page_fault_program;
#[cfg(any(feature = "demo-disk", test))]
pub use self::spawn::spawn_demo_program;
#[cfg(any(feature = "demo-disk", test))]
pub use self::spawn::spawn_demo_rust_io_program;
#[cfg(any(feature = "demo-disk", test))]
pub use self::spawn::spawn_demo_rust_program;

// ── host-proxy dispatch helpers ──────────────────────────────────────
// Called by the demo host proxies (and, on bare metal, the ring3 service
// bridge) to execute the lumina package-manager CLI against the global
// filesystem.  The wrapper acquires the global filesystem so the ring3
// payloads don't need to.  The lumina CLI belongs out of the kernel per the
// purity directive, so the whole app surface is gated with the demo runtime.

/// Execute a `lumina` package manager command.
///
/// Returns `(exit_code, output_string)`.
#[cfg(any(feature = "demo-disk", test))]
pub fn dispatch_lumina_command(
    cwd: &str,
    argv: &[alloc::string::String],
) -> (i32, alloc::string::String) {
    use crate::kernel::fs;
    let Some(global_fs) = fs::global() else {
        return (
            -1,
            alloc::string::String::from("lumina: no filesystem available\n"),
        );
    };
    let fs_lock = global_fs.lock();
    app::run_lumina_command(&fs_lock, cwd, argv)
}

#[cfg(test)]
mod tests;
