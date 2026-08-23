//! src/user/shared/commands/process.rs
//! Process and signal commands: ps, kill, true, false.
//!
//! All commands use the syscall bridge (`crate::syscall`) and return
//! `CmdResult` so they work identically in ring0 and ring3.

use alloc::format;
use alloc::string::String;
use alloc::vec;

use crate::user::shared::abi::diagnostic;
use crate::user::shared::syscall;
use crate::user::shared::types::CmdResult;

// ── ABI diagnostic decode helpers ───────────────────────────────────────

fn decode_process_state(state: u64) -> &'static str {
    match state {
        diagnostic::PROCESS_STATE_NEW => "New",
        diagnostic::PROCESS_STATE_READY => "Ready",
        diagnostic::PROCESS_STATE_RUNNING => "Running",
        diagnostic::PROCESS_STATE_WAITING => "Waiting",
        diagnostic::PROCESS_STATE_TERMINATED => "Terminated",
        _ => "?",
    }
}

fn decode_thread_priority(priority: u64) -> &'static str {
    match priority {
        diagnostic::THREAD_PRIORITY_IDLE => "Idle",
        diagnostic::THREAD_PRIORITY_NORMAL => "Norm",
        diagnostic::THREAD_PRIORITY_HIGH => "High",
        diagnostic::THREAD_PRIORITY_REALTIME => "Real",
        _ => "?",
    }
}

fn decode_thread_state(state: u64) -> &'static str {
    match state {
        diagnostic::THREAD_STATE_READY => "Ready",
        diagnostic::THREAD_STATE_RUNNING => "Running",
        diagnostic::THREAD_STATE_WAITING => "Waiting",
        diagnostic::THREAD_STATE_STOPPED => "Stopped",
        diagnostic::THREAD_STATE_TERMINATED => "Term",
        _ => "?",
    }
}

fn process_name_from_record(record: &diagnostic::ProcessInfoRecord) -> &str {
    let nul_pos = record
        .name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(record.name.len());
    core::str::from_utf8(&record.name[..nul_pos]).unwrap_or("?")
}

// ── Signal name table ───────────────────────────────────────────────────

const SIGNAL_NAMES: &[(&str, usize)] = &[
    ("HUP", 1),
    ("INT", 2),
    ("QUIT", 3),
    ("ILL", 4),
    ("TRAP", 5),
    ("ABRT", 6),
    ("BUS", 7),
    ("FPE", 8),
    ("KILL", 9),
    ("USR1", 10),
    ("SEGV", 11),
    ("USR2", 12),
    ("PIPE", 13),
    ("ALRM", 14),
    ("TERM", 15),
    ("STKFLT", 16),
    ("CHLD", 17),
    ("CONT", 18),
    ("STOP", 19),
    ("TSTP", 20),
    ("TTIN", 21),
    ("TTOU", 22),
];

fn signal_name(number: usize) -> Option<&'static str> {
    SIGNAL_NAMES
        .iter()
        .find(|(_, n)| *n == number)
        .map(|(name, _)| *name)
}

fn signal_number(name: &str) -> Option<usize> {
    let name_upper = name.to_uppercase();
    SIGNAL_NAMES
        .iter()
        .find(|(n, _)| n.to_uppercase() == name_upper)
        .map(|(_, num)| *num)
}

// ─── true / false ───────────────────────────────────────────────────────

/// `true` — do nothing, exit 0.
pub fn cmd_true() -> CmdResult {
    CmdResult::empty()
}

/// `false` — do nothing, exit 1.
pub fn cmd_false() -> CmdResult {
    CmdResult::error(1, String::new())
}

// ─── ps ─────────────────────────────────────────────────────────────────

pub fn cmd_ps(argv: &[String]) -> CmdResult {
    // Parse flags.
    let mut long = false;
    let mut thread_pid: Option<u32> = None;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-l" => long = true,
            "-t" => {
                i += 1;
                if i >= argv.len() {
                    return CmdResult::error(1, String::from("ps: -t requires a pid argument\n"));
                }
                thread_pid = match argv[i].parse::<u32>() {
                    Ok(pid) => Some(pid),
                    Err(_) => {
                        return CmdResult::error(1, format!("ps: invalid pid `{}`\n", argv[i]))
                    }
                };
            }
            other if other.starts_with('-') => {
                return CmdResult::error(1, format!("ps: unknown flag `{other}`\n"));
            }
            _ => return CmdResult::error(1, format!("ps: unexpected argument `{}`\n", argv[i])),
        }
        i += 1;
    }

    // Thread mode: list threads of a specific process.
    if let Some(pid) = thread_pid {
        return cmd_ps_threads(pid);
    }

    // Process listing via syscall.
    let record_size = diagnostic::PROCESS_INFO_RECORD_SIZE;
    let max_records = 64;
    let mut buf = vec![0u8; record_size * max_records];
    let count = match syscall::sys_list_processes(&mut buf) {
        Ok(n) => n,
        Err(_) => return CmdResult::error(1, String::from("ps: scheduler not initialised\n")),
    };

    if count == 0 {
        return CmdResult::from_output(String::from("(no processes)\n"));
    }

    let records: &[diagnostic::ProcessInfoRecord] = unsafe {
        core::slice::from_raw_parts(buf.as_ptr() as *const diagnostic::ProcessInfoRecord, count)
    };

    if long {
        let mut out = String::from("PID  PPID PRI    CPU  STATE     NAME\n");
        for r in records {
            let ppid = if r.ppid == 0 {
                String::from("   -")
            } else {
                format!("{:>4}", r.ppid)
            };
            let kind = if r.is_kernel != 0 { "[k]" } else { "[u]" };
            let prio = decode_thread_priority(r.priority);
            out.push_str(&format!(
                "{:>4} {ppid} {:<4} {:>5}  {:<9} {kind} {}\n",
                r.pid,
                prio,
                r.cpu_ticks,
                decode_process_state(r.state),
                process_name_from_record(r),
            ));
        }
        out.push_str(&format!("\n{} processes\n", count));
        CmdResult::from_output(out)
    } else {
        let mut out = String::from("PID  PPID STATE     THR NAME\n");
        for r in records {
            let ppid = if r.ppid == 0 {
                String::from("   -")
            } else {
                format!("{:>4}", r.ppid)
            };
            let kind = if r.is_kernel != 0 { "[k]" } else { "[u]" };
            out.push_str(&format!(
                "{:>4} {ppid} {:<9} {:>3} {kind} {}\n",
                r.pid,
                decode_process_state(r.state),
                r.thread_count,
                process_name_from_record(r),
            ));
        }
        out.push_str(&format!("\n{} processes\n", count));
        CmdResult::from_output(out)
    }
}

fn cmd_ps_threads(pid: u32) -> CmdResult {
    let record_size = diagnostic::THREAD_INFO_RECORD_SIZE;
    let max_records = 64;
    let mut buf = vec![0u8; record_size * max_records];
    let count = match syscall::sys_list_threads(pid as usize, &mut buf) {
        Ok(n) => n,
        Err(_) => {
            return CmdResult::error(1, format!("ps: unable to query threads for pid {pid}\n"))
        }
    };

    if count == 0 {
        // Check if the process exists via process listing.
        let mut probe_buf = vec![0u8; diagnostic::PROCESS_INFO_RECORD_SIZE * 64];
        match syscall::sys_list_processes(&mut probe_buf) {
            Ok(pcount) if pcount > 0 => {
                let precords: &[diagnostic::ProcessInfoRecord] = unsafe {
                    core::slice::from_raw_parts(
                        probe_buf.as_ptr() as *const diagnostic::ProcessInfoRecord,
                        pcount,
                    )
                };
                let found = precords.iter().any(|r| r.pid == pid as u64);
                if !found {
                    return CmdResult::error(1, format!("ps: no process with pid {pid}\n"));
                }
            }
            _ => {}
        }
        return CmdResult::error(1, format!("ps: process {pid} has no live threads\n"));
    }

    let records: &[diagnostic::ThreadInfoRecord] = unsafe {
        core::slice::from_raw_parts(buf.as_ptr() as *const diagnostic::ThreadInfoRecord, count)
    };

    let mut out = format!("Threads of process {pid}:\n");
    out.push_str("TID  PRI    CPU  STATE\n");
    for t in records {
        out.push_str(&format!(
            "{:>4} {:<4} {:>5}  {}\n",
            t.tid,
            decode_thread_priority(t.priority),
            t.cpu_ticks,
            decode_thread_state(t.state),
        ));
    }
    out.push_str(&format!("{} threads\n", count));
    CmdResult::from_output(out)
}

// ─── kill ───────────────────────────────────────────────────────────────

pub fn cmd_kill(argv: &[String]) -> CmdResult {
    if argv.len() < 2 {
        return CmdResult::error(
            1,
            String::from("kill: usage: kill <pid> [signal] | kill -l\n"),
        );
    }

    // kill -l: list signals.
    if argv[1] == "-l" {
        let mut out = String::from("signal names:\n");
        for (i, (name, num)) in SIGNAL_NAMES.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('\n');
            }
            out.push_str(&format!("{:>2} {:<6}", num, name));
        }
        out.push('\n');
        return CmdResult::from_output(out);
    }

    // Parse pid.
    let pid: u32 = match argv[1].parse() {
        Ok(pid) if pid > 0 => pid,
        _ => return CmdResult::error(1, format!("kill: invalid pid `{}`\n", argv[1])),
    };

    // Parse optional signal (name or number).
    let signal: usize = if argv.len() >= 3 {
        // Try as number first, then as name.
        if let Ok(num) = argv[2].parse::<usize>() {
            num
        } else {
            match signal_number(&argv[2]) {
                Some(num) => num,
                None => {
                    return CmdResult::error(1, format!("kill: unknown signal `{}`\n", argv[2]))
                }
            }
        }
    } else {
        15 // TERM is the default
    };

    // Validate signal range.
    if !(1..=31).contains(&signal) {
        return CmdResult::error(1, format!("kill: invalid signal number {signal}\n"));
    }

    // Send signal via syscall.
    match syscall::sys_send_signal(pid as usize, signal, 0) {
        Ok(()) => {
            let name = signal_name(signal).unwrap_or("?");
            CmdResult::from_output(format!("sent signal {signal} ({name}) to process {pid}\n"))
        }
        Err(-2) => CmdResult::error(1, format!("kill: no such process {pid}\n")),
        Err(_) => CmdResult::error(1, format!("kill: failed to send signal to {pid}\n")),
    }
}
