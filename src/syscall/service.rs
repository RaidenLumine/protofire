//! src/syscall/service.rs
//!
//! The service syscalls: what an init program declares, and what it starts.
//!
//! The kernel owns the mechanism — the registry, the start order, the
//! supervision and `/service` — and a program owns the distribution's
//! declarations: it reads `/system/rc.d`, hands each file's text over, and asks
//! for them to be started.  Both halves matter.  If the kernel read the
//! directory itself, a distribution could not change its own service set
//! without a kernel that knows where to look; if the program started the
//! services itself, the registry would report services it never registered and
//! the supervisor could not restart what it cannot describe.

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
use crate::Result;

/// Register the services one declaration file declares.
///
/// `arg0`/`arg1` are the pointer and length of the file's *path*.  The kernel
/// reads the file itself, out of the read-only system zone: a program chooses
/// which files hold declarations — the directory is the distribution's — but
/// not what they say, so what gets registered is the image's bytes and every
/// service can be attributed to the file that declared it
/// (`/service/<name>/origin`).  Parsing is still the kernel's, with the parser
/// both sides share.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
pub(super) fn declare(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 2)?;

    let path = super::user_memory::user_path_arg(context, 0, 1)?;
    let scheduler = super::runtime::global_scheduler()?;
    let now_tick = scheduler.current_tick();
    let declared = {
        let fs = super::runtime::global_fs()?;
        let fs = fs.lock();
        crate::kernel::service::declare_file(&fs, &path, now_tick)?
    };

    Ok(super::SyscallDispatch::complete(declared))
}

/// Start every declared service that has not started, in declaration order.
///
/// Idempotent, so a program that calls it twice — or a boot path that already
/// started them — starts no second copy.  Returns how many this call started.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
pub(super) fn start_all(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 0)?;

    let scheduler = super::runtime::global_scheduler()?;
    let now_tick = scheduler.current_tick();
    let started = crate::kernel::start_declared_services(now_tick, |path, security_token| {
        crate::kernel::spawn_and_log_user_program(scheduler, path, security_token)
            .map(|launched| launched.process.pid())
    });

    Ok(super::SyscallDispatch::complete(started))
}

// A build with no service launcher has no services to declare or start: the
// numbers stay reserved, and the calls answer that this is not the machine for
// them.
#[cfg(not(all(target_os = "none", any(feature = "demo-disk", test))))]
pub(super) fn declare(
    _context: &mut super::SyscallContext,
) -> super::Result<super::SyscallDispatch> {
    Err(crate::Error::Unsupported)
}

#[cfg(not(all(target_os = "none", any(feature = "demo-disk", test))))]
pub(super) fn start_all(
    _context: &mut super::SyscallContext,
) -> super::Result<super::SyscallDispatch> {
    Err(crate::Error::Unsupported)
}
