//! src/user/shared/jobs.rs
//!
//! Shared job control types and formatting for shell builtins.
//!
//! The `Job` and `JobState` types are defined here so both the kernel shell
//! and any future ring3 job-control tools use the same display format and
//! ID parsing logic.  The actual job table (`JOBS`) lives in the shell's
//! local state; this module provides pure helpers that operate on borrowed
//! job slices.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

// ── Signal constants ──────────────────────────────────────────────────────

/// POSIX SIGCONT — continue a stopped process.
pub const SIGCONT: usize = 18;

// ── Job state ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum JobState {
    Running,
    Stopped,
    Done,
}

impl core::fmt::Display for JobState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JobState::Running => write!(f, "Running"),
            JobState::Stopped => write!(f, "Stopped"),
            JobState::Done => write!(f, "Done"),
        }
    }
}

// ── Job ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Job {
    pub id: u32,
    pub pid: u32,
    pub name: String,
    pub state: JobState,
    pub command: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Parse a job ID from an argument, stripping an optional `%` prefix.
///
/// ```
/// assert_eq!(protofire::user::shared::jobs::parse_job_id("%5"), 5);
/// assert_eq!(protofire::user::shared::jobs::parse_job_id("5"), 5);
/// assert_eq!(protofire::user::shared::jobs::parse_job_id("abc"), 0);
/// ```
pub fn parse_job_id(arg: &str) -> u32 {
    let s = arg.strip_prefix('%').unwrap_or(arg);
    s.parse::<u32>().unwrap_or(0)
}

/// Format a single job line (without trailing newline).
///
/// Format: `[id] pid name state & command`
pub fn format_job_line(job: &Job) -> String {
    format!(
        "[{}] {} {} {} & {}",
        job.id, job.pid, job.name, job.state, job.command
    )
}

/// Format all non-done jobs, removing `Done` entries from the list.
///
/// Returns the formatted output string (one line per job, trailing newline
/// on each).  Also mutates `jobs` in-place to remove entries whose state
/// is `Done`.
///
/// When there are no live jobs, returns `"(no jobs)\n"`.
pub fn format_and_sweep_jobs(jobs: &mut Vec<Job>) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < jobs.len() {
        if jobs[i].state == JobState::Done {
            jobs.remove(i);
        } else {
            out.push_str(&format_job_line(&jobs[i]));
            out.push('\n');
            i += 1;
        }
    }
    if out.is_empty() {
        out.push_str("(no jobs)\n");
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parse_with_percent() {
        assert_eq!(parse_job_id("%1"), 1);
        assert_eq!(parse_job_id("%42"), 42);
    }

    #[test]
    fn parse_without_percent() {
        assert_eq!(parse_job_id("7"), 7);
    }

    #[test]
    fn parse_invalid_returns_zero() {
        assert_eq!(parse_job_id("abc"), 0);
        assert_eq!(parse_job_id("%xyz"), 0);
    }

    #[test]
    fn format_job_line_formatting() {
        let job = Job {
            id: 1,
            pid: 10,
            name: String::from("sleep"),
            state: JobState::Running,
            command: String::from("sleep 10"),
        };
        let line = format_job_line(&job);
        assert!(line.starts_with("[1] 10 sleep Running &"));
    }

    #[test]
    fn sweep_removes_done_jobs() {
        let mut jobs = vec![
            Job {
                id: 1,
                pid: 10,
                name: String::from("a"),
                state: JobState::Running,
                command: String::from("a"),
            },
            Job {
                id: 2,
                pid: 11,
                name: String::from("b"),
                state: JobState::Done,
                command: String::from("b"),
            },
        ];
        let output = format_and_sweep_jobs(&mut jobs);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, 1);
        assert!(!output.contains("(no jobs)"));
    }

    #[test]
    fn sweep_empty_returns_placeholder() {
        let mut jobs: Vec<Job> = vec![];
        let output = format_and_sweep_jobs(&mut jobs);
        assert_eq!(output, "(no jobs)\n");
    }
}
