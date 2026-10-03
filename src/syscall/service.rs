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
use crate::Error;
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
use crate::Result;

/// Longest rc.d file the kernel accepts.
///
/// A declaration file is a handful of keys per service; this is far above any
/// real one and far below a size that would hold the kernel's lock for long
/// while it parses.  `service_declare` reads at most this much.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
const MAX_DECLARATION_BYTES: usize = 64 * 1024;

/// Register the services one rc.d file declares.
///
/// `arg0`/`arg1` are the pointer and length of the file's text, exactly as it
/// was read.  Parsing is the kernel's — with the parser both sides share — so a
/// file cannot mean one thing to the program that read it and another to the
/// kernel that runs what it declares.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
pub(super) fn declare(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 2)?;

    let pointer = context.arg(0) as *const u8;
    let length = context.arg(1);
    let text = super::user_memory::user_bounded_str(pointer, length, MAX_DECLARATION_BYTES)?;

    let now_tick = super::runtime::global_scheduler()?.current_tick();
    let declared = crate::kernel::service::declare_from_text(&text, now_tick)
        .map_err(|_message| Error::InvalidArgument)?;

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
        crate::user::program::spawn_from_global_with_security_token(scheduler, path, security_token)
            .ok()
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
