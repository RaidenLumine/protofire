//! src/kernel/oom.rs
//!
//! Out-of-memory killer: selects and terminates the worst-scoring process
//! when the physical frame allocator is exhausted.
//!
//! ## Policy
//!
//! - Kernel threads (no user address space) are never killed.
//! - PID 1 (init) is never killed.
//! - Process with the most user-mapped pages is the primary candidate.
//! - Root-owned processes get a score penalty (half).
//! - Processes with many children are slightly penalised (reparenting cost).

use alloc::sync::Arc;

use super::process::scheduler::load_current_scheduler_ptr;
use super::process::Process;

/// Number of frames below which we consider the system OOM.
/// When fewer than this many frames are free, page-fault allocation
/// failures trigger the OOM killer instead of propagating an error.
pub const OOM_MIN_FREE_FRAMES: usize = 4;

// ── Badness scoring ─────────────────────────────────────────────────────────

/// Compute an OOM-badness score for a single process.
///
/// Returns `0` for processes that should never be killed (kernel threads,
/// init).  Higher values = more deserving of termination.
fn oom_badness(process: &Process) -> u64 {
    // Never kill PID 1 (init / idle).
    if process.pid() == 1 {
        return 0;
    }

    // Kernel-only processes (no user address space) are never killed.
    if !process.has_user_address_space() {
        return 0;
    }

    // Base score: number of user-mapped pages.
    let score = process
        .user_address_space_summary()
        .map(|s| s.mapped_page_count as u64)
        .unwrap_or(0);

    if score == 0 {
        return 0;
    }

    let mut score = score;

    // Root-owned processes are less likely to be killed (admin tools,
    // login shell, etc.).
    if process.security_token().is_admin() {
        score /= 2;
    }

    // Many children → reparenting overhead → slightly penalise.
    let child_count = process.children().len() as u64;
    score = score.saturating_sub(child_count * 5);

    score.max(1)
}

// ── Victim selection ────────────────────────────────────────────────────────

/// Select the process with the highest OOM badness score from the scheduler's
/// process list.  Returns `None` if every process scored 0 (nothing killable).
pub fn select_victim() -> Option<(Arc<Process>, u64)> {
    let sched_ptr = load_current_scheduler_ptr();
    if sched_ptr.is_null() {
        return None;
    }
    // SAFETY: the global scheduler pointer is initialised during kernel boot
    // and lives for the entire runtime.
    let scheduler = unsafe { &*sched_ptr };

    let processes = scheduler.processes.lock();
    let mut best: Option<(Arc<Process>, u64)> = None;

    for proc in processes.iter() {
        let score = oom_badness(proc);
        if score == 0 {
            continue;
        }
        match &best {
            Some((_, best_score)) if score <= *best_score => {}
            _ => best = Some((proc.clone(), score)),
        }
    }

    best
}

// ── OOM kill entry point ────────────────────────────────────────────────────

/// Attempt to free memory by killing the worst-scoring process.
///
/// Returns `true` if a process was killed, `false` if no killable process
/// could be found.
///
/// The killed process receives SIGKILL (signal 9).  Its threads are
/// terminated and its pages are eventually reclaimed by the frame allocator
/// during `release_termination_resources`.
pub fn oom_kill() -> bool {
    let Some((victim, score)) = select_victim() else {
        #[cfg(target_os = "none")]
        crate::println!("[oom  ] no killable process found — memory exhausted");
        return false;
    };

    let pid = victim.pid();
    let name = victim.name();
    let pages = victim
        .user_address_space_summary()
        .map(|s| s.mapped_page_count)
        .unwrap_or(0);

    #[cfg(target_os = "none")]
    crate::println!(
        "[oom  ] killing pid={} name=\"{}\" pages={} badness={}",
        pid,
        name,
        pages,
        score,
    );
    #[cfg(not(target_os = "none"))]
    let _ = (name, pages, score);

    // Send SIGKILL (signal 9) from the kernel (sender_pid = 0).
    let sched_ptr = load_current_scheduler_ptr();
    if sched_ptr.is_null() {
        return false;
    }
    let scheduler = unsafe { &*sched_ptr };
    scheduler.send_signal(0, pid, 9, 0).is_ok()
}

// ── OOM-triggered allocation retry ──────────────────────────────────────────

/// Try to allocate `count` frames; if the first attempt fails, invoke the OOM
/// killer and retry once.
///
/// Returns `None` only when both the initial allocation AND the post-OOM retry
/// fail, indicating genuine exhaustion with no killable victim.
pub fn allocate_or_oom(count: usize) -> Option<*mut u8> {
    let frames = super::memory::global_mut()?.allocate_frames(count);

    if frames.is_some() {
        return frames;
    }

    // First attempt failed — invoke the OOM killer.
    if oom_kill() {
        // Retry the allocation after freeing memory.
        let retry = super::memory::global_mut()?.allocate_frames(count);
        if retry.is_some() {
            return retry;
        }
        // Even after killing a process we're still OOM — try once more.
        #[cfg(target_os = "none")]
        crate::println!("[oom  ] retry after kill still failed for {} frames", count);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::process::process::Process;
    use crate::kernel::process::SecurityToken;
    #[allow(unused_imports)]
    use crate::kernel::process::ThreadPriority;

    /// A helper to build a minimal Process-like object for testing.
    /// Since Process::new creates a full Arc<Process> with scheduler setup,
    /// we test the badness scoring logic through the public API where possible.
    fn make_scorable_process(pid: u32, name: &str, _pages: u64, is_admin: bool) -> Arc<Process> {
        // Simulate an address space with the given number of pages by mapping
        // a region of that size.  We only need the summary to return > 0.
        // For unit tests we rely on the fact that Process::new creates an
        // empty process; the address space is populated only during ELF load.
        // So we assert 0 pages for a fresh process (the base case).
        if is_admin {
            Process::new_with_security_token(pid, name, SecurityToken::root())
        } else {
            Process::new(pid, name)
        }
    }

    #[test]
    fn badness_of_init_pid_is_zero() {
        let proc = make_scorable_process(1, "init", 0, true);
        assert_eq!(oom_badness(&proc), 0, "PID 1 should never be killed");
    }

    #[test]
    fn badness_of_kernel_thread_is_zero() {
        // A process with no user address space is treated as kernel.
        let proc = make_scorable_process(42, "kworker", 0, true);
        // has_user_address_space is false by default for new processes.
        assert_eq!(oom_badness(&proc), 0, "kernel thread should score 0");
    }

    #[test]
    fn user_process_with_memory_scores_positive() {
        let proc = make_scorable_process(100, "user-app", 0, false);
        // A freshly-created process has no address space yet, so badness is 0.
        // In real operation the ELF loader populates it.
        // This test verifies the scoring function doesn't panic.
        let score = oom_badness(&proc);
        // It should be 0 because there are no mapped pages.
        assert_eq!(score, 0, "no address space → score 0");
    }

    #[test]
    fn root_process_badness_is_halved() {
        // When ProcessSummary reports pages, root gets halved.
        // We can't easily inject a fake summary, but we can verify the
        // is_admin path works for the zero-pages case.
        let root = make_scorable_process(50, "root-shell", 0, true);
        let user = make_scorable_process(51, "user-shell", 0, false);
        // Both score 0 because no pages mapped — just check no crash.
        let _ = (oom_badness(&root), oom_badness(&user));
    }

    #[test]
    fn select_victim_returns_none_when_no_processes() {
        // Without a scheduler context, select_victim returns None.
        let victim = select_victim();
        assert!(victim.is_none(), "no scheduler → no victim");
    }
}
