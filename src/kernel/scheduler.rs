//! src/kernel/scheduler.rs
//!
//! Thin scheduler-timing facade so modules that only need the current tick
//! count (shm, timed waits, …) do not depend on the full scheduler internals
//! in [`crate::kernel::process::scheduler`].
//!
//! The canonical tick source is the per-arch timer; on platforms without a
//! context-switching timer the scheduler drives a simulated tick counter
//! instead, but no call site here needs that distinction — they all just ask
//! "what time is it now".

use crate::arch;

/// Current scheduler tick count.
///
/// Mirrors `Scheduler::current_tick()` on the bare-metal paths; on host
/// builds the arch timer returns a simulated value so tests still see a
/// monotonic time base.
pub fn current_tick() -> u64 {
    arch::timer::ticks()
}
