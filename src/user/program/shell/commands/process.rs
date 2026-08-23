//! Process and job control commands (jobs, fg, bg) — kernel-only.
//! These stay kernel-side because they access `Scheduler`, `JOBS`, and
//! `FOREGROUND_JOB_ID` globals directly.
//! Pure formatting and parsing logic is shared via `crate::user::shared::jobs`.

use super::super::*;
use crate::kernel::syscall;
use crate::user::shared::jobs;
use crate::user::syscall::UserSyscall;
use alloc::string::String;

/// Parse a job specifier: `%N` or bare `N`.  Delegates to the shared
/// `crate::user::shared::jobs::parse_job_id` implementation.
pub(crate) use crate::user::shared::jobs::parse_job_id;

/// `jobs` — list background and suspended jobs.
pub(crate) fn cmd_jobs() -> CmdResult {
    let mut jobs = JOBS.lock();
    let out = jobs::format_and_sweep_jobs(&mut jobs);
    CmdResult::success(out)
}

/// `fg [%]<job_id>` — bring a job to the foreground.
pub(crate) fn cmd_fg(argv: &[String]) -> CmdResult {
    if argv.len() < 2 {
        return CmdResult::error(2, "fg: usage: fg %<job_id>\n".into());
    }
    let job_id = parse_job_id(&argv[1]);
    let (pid, state) = {
        let jobs = JOBS.lock();
        match jobs.iter().find(|j| j.id == job_id) {
            Some(j) => (j.pid, j.state.clone()),
            None => return CmdResult::error(1, format!("fg: job [{job_id}] not found\n")),
        }
    };

    // If stopped, send SIGCONT to resume.
    if state == JobState::Stopped {
        let mut ctx = UserSyscall::send_signal(pid as usize, jobs::SIGCONT, 0, 0);
        let _ = syscall::dispatch(&mut ctx);
    }

    // Mark as foreground.
    *FOREGROUND_JOB_ID.lock() = Some(job_id);

    // Wait for the process to terminate.
    if let Some(scheduler) = crate::kernel::process::Scheduler::global() {
        if let Some(process) = scheduler.process_by_pid(pid) {
            process.wait_for_termination();
        }
    }

    // Reap and remove.
    {
        let mut jobs = JOBS.lock();
        jobs.retain(|j| j.id != job_id);
    }
    *FOREGROUND_JOB_ID.lock() = None;

    CmdResult::success(format!("[{job_id}] done\n"))
}

/// `bg [%]<job_id>` — resume a stopped job in the background.
pub(crate) fn cmd_bg(argv: &[String]) -> CmdResult {
    if argv.len() < 2 {
        return CmdResult::error(2, "bg: usage: bg %<job_id>\n".into());
    }
    let job_id = parse_job_id(&argv[1]);
    {
        let mut jobs = JOBS.lock();
        match jobs.iter_mut().find(|j| j.id == job_id) {
            Some(job) if job.state == JobState::Stopped => {
                // Send SIGCONT.
                let mut ctx = UserSyscall::send_signal(job.pid as usize, jobs::SIGCONT, 0, 0);
                let _ = syscall::dispatch(&mut ctx);
                job.state = JobState::Running;
                CmdResult::success(format!("[{job_id}] resumed: {}\n", job.command))
            }
            Some(_) => CmdResult::success(format!("[{job_id}] already running\n")),
            None => CmdResult::error(1, format!("bg: job [{job_id}] not found\n")),
        }
    }
}
