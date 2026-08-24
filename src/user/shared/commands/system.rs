//! src/user/shared/commands/system.rs
//!
//! System information and utility commands (help, echo, clear, sysinfo, top,
//! dmesg, uname, uptime, sleep, test).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::user::shared::abi::diagnostic;
use crate::user::shared::abi::fs::{FileStat, FILE_KIND_DIRECTORY, FILE_KIND_FILE, FILE_STAT_SIZE};
use crate::user::shared::path_util::resolve_path;
use crate::user::shared::syscall;
use crate::user::shared::types::CmdResult;

// ─── help ───────────────────────────────────────────────────────────────

pub fn cmd_help(argv: &[String]) -> CmdResult {
    let output = if argv.len() > 1 {
        let topic = argv[1].as_str();
        match topic {
            "help" => String::from("help [command] — show help for a command or list all\n"),
            "echo" => String::from("echo [...args] — print arguments to the console\n"),
            "clear" => String::from("clear — clear the screen\n"),
            "pwd" => String::from("pwd — print the current working directory\n"),
            "cd" => String::from("cd [path|~] — change working directory (default: home)\n"),
            "ls" => String::from("ls [-a] [path] — list directory contents\n"),
            "cat" => String::from("cat <path> — print file contents\n"),
            "grep" => String::from("grep <pattern> <file> — search for lines matching a pattern\n"),
            "find" => {
                String::from("find <dir> <pattern> — recursively find files matching a pattern\n")
            }
            "head" => {
                String::from("head [-n N] <file> — print first N lines of a file (default 10)\n")
            }
            "tail" => {
                String::from("tail [-n N] <file> — print last N lines of a file (default 10)\n")
            }
            "wc" => String::from("wc <file> — count lines, words, and bytes in a file\n"),
            "cp" => String::from("cp [-r] <source> <dest> — copy a file or directory\n"),
            "mv" => String::from("mv <source> <dest> — move or rename a file\n"),
            "mkdir" => String::from("mkdir [-p] <path> — create a directory\n"),
            "rm" => String::from("rm [-r] <path> — remove a file or directory\n"),
            "touch" => {
                String::from("touch <path> — create an empty file or update its timestamp\n")
            }
            "ps" => String::from(
                "ps [-l] [-t <pid>] — list processes (long format with -l, threads with -t)\n",
            ),
            "kill" => {
                String::from("kill <pid> [signal] | kill -l — send a signal or list signal names\n")
            }
            "sysinfo" => String::from("sysinfo — display system information and statistics\n"),
            "top" => String::from("top [-n N] — show top processes by CPU usage (default 10)\n"),
            "dmesg" => {
                String::from("dmesg [-l trace|info|warn|error|fatal] — print kernel log buffer\n")
            }
            "uname" => String::from("uname [-a] — print system information\n"),
            "uptime" => String::from("uptime — show system uptime\n"),
            "perf" => String::from("perf stat|sched — performance profiling and statistics\n"),
            "sleep" => String::from("sleep <seconds> — pause for the given number of seconds\n"),
            "true" => String::from("true — do nothing, exit 0\n"),
            "false" => String::from("false — do nothing, exit 1\n"),
            "test" => String::from(
                "test [-z|-n|-f|-d|!] [str = str|int -eq int|...] — evaluate expression\n",
            ),
            "[" => String::from("[ expr ] — alias for test\n"),
            "hexdump" => {
                String::from("hexdump [-n <bytes>] <file> — display file as hex + ASCII dump\n")
            }
            "edit" => String::from(
                "edit [-a \"line\" | -d N | -s N \"line\"] <file> — line-oriented file editor\n",
            ),
            "sort" => String::from("sort [-r] [-n] [-u] <file> — sort file lines\n"),
            "uniq" => {
                String::from("uniq [-c] [-d] [-u] <file> — filter adjacent duplicate lines\n")
            }
            "diff" => String::from("diff <file1> <file2> — show differences between two files\n"),
            other => format!("shell: unknown help topic `{other}`\n"),
        }
    } else {
        let mut out = String::from("available commands:\n");
        for cmd in &[
            "help", "echo", "clear", "pwd", "cd", "ls", "cat", "grep", "find", "head", "tail",
            "wc", "cp", "mv", "mkdir", "rm", "touch", "ps", "kill", "sysinfo", "top", "dmesg",
            "uname", "uptime", "sleep", "hexdump", "edit", "sort", "uniq", "diff", "perf", "true",
            "false", "test", "[",
        ] {
            out.push_str(&format!("  {cmd}\n"));
        }
        out.push_str("type 'help <command>' for usage\n");
        out
    };
    CmdResult::from_output(output)
}

// ─── echo, clear ────────────────────────────────────────────────────────

pub fn cmd_echo(argv: &[String]) -> CmdResult {
    let mut out = String::new();
    for (i, arg) in argv.iter().enumerate().skip(1) {
        if i > 1 {
            out.push(' ');
        }
        out.push_str(arg);
    }
    out.push('\n');
    CmdResult::from_output(out)
}

pub fn cmd_clear() -> CmdResult {
    CmdResult::from_output(String::from("\x1b[2J\x1b[H"))
}

// ─── test / [ ───────────────────────────────────────────────────────────

/// `test` / `[` — evaluate an expression and return 0 (true) or 1 (false).
pub fn cmd_test(cwd: &str, argv: &[String]) -> CmdResult {
    // If invoked as `[`, the last argument must be `]`.
    let effective_name = &argv[0];
    let args = if effective_name == "[" {
        if argv.len() < 2 || argv[argv.len() - 1] != "]" {
            return CmdResult::error(2, "[: missing `]'\n".into());
        }
        &argv[1..argv.len() - 1]
    } else {
        &argv[1..]
    };

    let exit_code = test_evaluate(cwd, args);
    CmdResult {
        exit_code,
        output: String::new(),
    }
}

/// Evaluate a `test`-style expression.
/// Returns 0 for true, 1 for false, 2 for syntax/usage errors.
fn test_evaluate(cwd: &str, args: &[String]) -> i32 {
    match args.len() {
        0 => 1,
        1 => {
            if args[0].is_empty() {
                1
            } else {
                0
            }
        }
        2 => match args[0].as_str() {
            "!" => {
                if args[1].is_empty() {
                    0
                } else {
                    1
                }
            }
            "-z" => {
                if args[1].is_empty() {
                    0
                } else {
                    1
                }
            }
            "-n" => {
                if args[1].is_empty() {
                    1
                } else {
                    0
                }
            }
            "-f" => test_file_kind(cwd, &args[1], FILE_KIND_FILE),
            "-d" => test_file_kind(cwd, &args[1], FILE_KIND_DIRECTORY),
            _ => 2,
        },
        3 => match args[1].as_str() {
            "=" => {
                if args[0] == args[2] {
                    0
                } else {
                    1
                }
            }
            "!=" => {
                if args[0] != args[2] {
                    0
                } else {
                    1
                }
            }
            "-eq" => test_int_cmp(&args[0], &args[2], |a, b| a == b),
            "-ne" => test_int_cmp(&args[0], &args[2], |a, b| a != b),
            "-lt" => test_int_cmp(&args[0], &args[2], |a, b| a < b),
            "-le" => test_int_cmp(&args[0], &args[2], |a, b| a <= b),
            "-gt" => test_int_cmp(&args[0], &args[2], |a, b| a > b),
            "-ge" => test_int_cmp(&args[0], &args[2], |a, b| a >= b),
            _ => 2,
        },
        _ => 2,
    }
}

/// Test whether a path exists and has the expected kind.
fn test_file_kind(cwd: &str, path_str: &str, expected: usize) -> i32 {
    let path = resolve_path(cwd, path_str);
    let mut stat_buf = [0u8; FILE_STAT_SIZE];
    match syscall::sys_stat(&path, &mut stat_buf) {
        Ok(()) => {
            let stat: &FileStat = unsafe { &*(stat_buf.as_ptr() as *const FileStat) };
            if stat.kind == expected {
                0
            } else {
                1
            }
        }
        Err(_) => 1,
    }
}

/// Compare two strings as integers using the given comparison.
fn test_int_cmp<F: Fn(i64, i64) -> bool>(a: &str, b: &str, cmp: F) -> i32 {
    match (a.parse::<i64>(), b.parse::<i64>()) {
        (Ok(av), Ok(bv)) => {
            if cmp(av, bv) {
                0
            } else {
                1
            }
        }
        _ => 2,
    }
}

// ─── sysinfo ────────────────────────────────────────────────────────────

pub fn cmd_sysinfo() -> CmdResult {
    let mut out = String::new();

    // ── System section ──
    out.push_str("─── System ───\n");
    out.push_str("OS:      adAstra 2026.6.1\n");
    #[cfg(target_arch = "x86_64")]
    out.push_str("Arch:    x86_64\n");
    #[cfg(target_arch = "aarch64")]
    out.push_str("Arch:    aarch64\n");

    // Query scheduler info via SystemInfo syscall.
    let mut sched_buf = [0u8; diagnostic::SYSTEM_INFO_RECORD_SIZE];
    match syscall::sys_system_info(diagnostic::SYSTEM_INFO_SCHEDULER, &mut sched_buf) {
        Ok(_) => {
            let info: &diagnostic::SystemInfoRecord =
                unsafe { &*(sched_buf.as_ptr() as *const diagnostic::SystemInfoRecord) };
            let ticks = info.uptime_ticks;
            let seconds = ticks / 100;
            let hours = seconds / 3600;
            let minutes = (seconds % 3600) / 60;
            let secs = seconds % 60;
            out.push_str(&format!(
                "Uptime:  {ticks} ticks ({hours}h {minutes}m {secs}s)\n"
            ));
            out.push_str(&format!(
                "Procs:   {} total, {} ready, {} waiting\n",
                info.process_count, info.ready_count, info.waiting_count,
            ));

            // ── Scheduler section ──
            out.push_str("\n─── Scheduler ───\n");
            out.push_str(&format!("dispatch:       {}\n", info.dispatch_count));
            out.push_str(&format!("block:          {}\n", info.block_count));
            out.push_str(&format!(
                "timed_wait:     {}\n",
                info.timed_wait_registration_count
            ));
            out.push_str(&format!("signal_wake:    {}\n", info.signal_wake_count));
            out.push_str(&format!("timeout_wake:   {}\n", info.timeout_wake_count));
            out.push_str(&format!("preempt:        {}\n", info.preempt_count));
        }
        Err(_) => {
            out.push_str("Uptime:  (scheduler not initialised)\n");
        }
    }

    // ── Memory section ──
    out.push_str("\n─── Memory ───\n");
    {
        let mut alloc_buf = [0u8; diagnostic::ALLOC_PROFILER_RECORD_SIZE];
        match syscall::sys_system_info(diagnostic::SYSTEM_INFO_ALLOC_PROFILER, &mut alloc_buf) {
            Ok(_) => {
                let snap: &diagnostic::AllocProfilerRecord =
                    unsafe { &*(alloc_buf.as_ptr() as *const diagnostic::AllocProfilerRecord) };
                out.push_str(&format!("heap_allocs:        {}\n", snap.heap_allocs));
                out.push_str(&format!("heap_frees:         {}\n", snap.heap_frees));
                out.push_str(&format!(
                    "heap_bytes_alloc:   {}\n",
                    snap.heap_bytes_allocated
                ));
                out.push_str(&format!("heap_bytes_freed:   {}\n", snap.heap_bytes_freed));
                out.push_str(&format!("frame_allocs:       {}\n", snap.frame_allocs));
                out.push_str(&format!("frame_frees:        {}\n", snap.frame_frees));
                out.push_str(&format!("frame_recycled:     {}\n", snap.frame_recycled));
                out.push_str(&format!("frame_bump_allocs:  {}\n", snap.frame_bump_allocs));
                out.push_str(&format!("page_table_maps:    {}\n", snap.page_table_maps));
                out.push_str(&format!("page_table_unmaps:  {}\n", snap.page_table_unmaps));
                out.push_str(&format!(
                    "page_table_lookups: {}\n",
                    snap.page_table_lookups
                ));
            }
            Err(_) => {
                out.push_str("(memory manager not initialised)\n");
            }
        }
    }

    // ── Fault section ──
    out.push_str("\n─── Faults ───\n");
    {
        let mut fault_buf = [0u8; diagnostic::FAULT_PROFILER_RECORD_SIZE];
        match syscall::sys_system_info(diagnostic::SYSTEM_INFO_FAULT_PROFILER, &mut fault_buf) {
            Ok(_) => {
                let snap: &diagnostic::FaultProfilerRecord =
                    unsafe { &*(fault_buf.as_ptr() as *const diagnostic::FaultProfilerRecord) };
                out.push_str(&format!("faults_total:          {}\n", snap.faults_total));
                out.push_str(&format!(
                    "page_faults:           {}\n",
                    snap.page_faults_total
                ));
                out.push_str(&format!(
                    "  user:                {}\n",
                    snap.page_faults_user
                ));
                out.push_str(&format!(
                    "  kernel:              {}\n",
                    snap.page_faults_kernel
                ));
                out.push_str(&format!(
                    "  not_present:         {}\n",
                    snap.page_faults_not_present
                ));
                out.push_str(&format!(
                    "  protection_violation:{}\n",
                    snap.page_faults_protection_violation
                ));
                out.push_str(&format!(
                    "double_faults:         {}\n",
                    snap.double_faults_total
                ));
                out.push_str(&format!(
                    "invalid_opcode:        {}\n",
                    snap.invalid_opcode_total
                ));
                out.push_str(&format!(
                    "general_protection:    {}\n",
                    snap.general_protection_total
                ));
                out.push_str(&format!(
                    "other_exceptions:      {}\n",
                    snap.other_exceptions_total
                ));
                out.push_str(&format!(
                    "delivered:             {}\n",
                    snap.faults_delivered_to_handler
                ));
                out.push_str(&format!(
                    "no_handler:            {}\n",
                    snap.faults_no_handler
                ));
                out.push_str(&format!(
                    "terminated:            {}\n",
                    snap.faults_terminated
                ));
                out.push_str(&format!(
                    "kernel_fatal:          {}\n",
                    snap.faults_kernel_fatal
                ));
            }
            Err(_) => {
                out.push_str("(memory manager not initialised)\n");
            }
        }
    }

    CmdResult::from_output(out)
}

// ─── top ────────────────────────────────────────────────────────────────

pub fn cmd_top(argv: &[String]) -> CmdResult {
    let mut count: usize = 10;

    if argv.len() >= 3 && argv[1] == "-n" {
        count = match argv[2].parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => return CmdResult::error(1, format!("top: invalid count `{}`\n", argv[2])),
        };
    } else if argv.len() >= 2 {
        match argv[1].as_str() {
            "-n" => {
                return CmdResult::error(1, String::from("top: -n requires a count argument\n"))
            }
            other if other.starts_with('-') => {
                return CmdResult::error(1, format!("top: unknown flag `{other}`\n"));
            }
            _ => return CmdResult::error(1, format!("top: unexpected argument `{}`\n", argv[1])),
        }
    }

    let record_size = diagnostic::PROCESS_INFO_RECORD_SIZE;
    let max_records = 64;
    let mut buf = vec![0u8; record_size * max_records];
    let total = match syscall::sys_list_processes(&mut buf) {
        Ok(n) => n,
        Err(_) => return CmdResult::error(1, String::from("top: scheduler not initialised\n")),
    };

    if total == 0 {
        return CmdResult::from_output(String::from("top: no processes\n"));
    }

    let records: &[diagnostic::ProcessInfoRecord] = unsafe {
        core::slice::from_raw_parts(buf.as_ptr() as *const diagnostic::ProcessInfoRecord, total)
    };

    // Collect indices and sort by cpu_ticks descending.
    let mut indices: Vec<usize> = (0..total).collect();
    indices.sort_by(|&a, &b| records[b].cpu_ticks.cmp(&records[a].cpu_ticks));

    let shown = count.min(total);
    let mut out = format!("Top {shown} processes by CPU ticks:\n");
    out.push_str("PID  PPID PRI    CPU  NAME\n");
    for &idx in indices.iter().take(shown) {
        let r = &records[idx];
        let ppid = if r.ppid == 0 {
            String::from("   -")
        } else {
            format!("{:>4}", r.ppid)
        };
        let kind = if r.is_kernel != 0 { "[k]" } else { "[u]" };
        let prio = decode_thread_priority(r.priority);
        out.push_str(&format!(
            "{:>4} {ppid} {:<4} {:>5} {kind} {}\n",
            r.pid,
            prio,
            r.cpu_ticks,
            process_name_from_record(r),
        ));
    }
    out.push_str(&format!("\n{} processes total\n", total));
    CmdResult::from_output(out)
}

// ── ABI diagnostic decode helpers ───────────────────────────────────────

fn decode_thread_priority(priority: u64) -> &'static str {
    match priority {
        diagnostic::THREAD_PRIORITY_IDLE => "Idle",
        diagnostic::THREAD_PRIORITY_NORMAL => "Norm",
        diagnostic::THREAD_PRIORITY_HIGH => "High",
        diagnostic::THREAD_PRIORITY_REALTIME => "Real",
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

// ─── dmesg ──────────────────────────────────────────────────────────────

pub fn cmd_dmesg(argv: &[String]) -> CmdResult {
    // Parse optional -l <level> flag.
    let mut level_filter: Option<&str> = None;
    let mut i = 1;
    while i < argv.len() {
        if argv[i] == "-l" {
            if i + 1 < argv.len() {
                level_filter = Some(argv[i + 1].as_str());
                i += 2;
            } else {
                return CmdResult::error(
                    1,
                    String::from("dmesg: -l requires an argument (trace|info|warn|error|fatal)\n"),
                );
            }
        } else {
            return CmdResult::error(1, format!("dmesg: unknown flag '{}'\n", argv[i]));
        }
    }

    // Validate level filter value.
    if let Some(level) = level_filter {
        match level {
            "trace" | "info" | "warn" | "error" | "fatal" => {}
            _ => {
                return CmdResult::error(
                    1,
                    format!(
                        "dmesg: unknown log level '{}' (use trace|info|warn|error|fatal)\n",
                        level
                    ),
                )
            }
        }
    }

    // Probe: get current log length.
    let total = match syscall::sys_kernel_log_probe() {
        Ok(n) => n,
        Err(_) => return CmdResult::error(1, String::from("dmesg: unable to read kernel log\n")),
    };
    if total == 0 {
        return CmdResult::from_output(String::from("(kernel log is empty)\n"));
    }

    let mut raw_buf = vec![0u8; total];
    let n = match syscall::sys_kernel_log(&mut raw_buf) {
        Ok(n) => n,
        Err(_) => return CmdResult::error(1, String::from("dmesg: unable to read kernel log\n")),
    };
    let raw = core::str::from_utf8(&raw_buf[..n]).unwrap_or("<binary>");

    // Apply level filter if requested.
    if let Some(level) = level_filter {
        let prefix = level_to_log_prefix(level);
        let mut out = String::new();
        for line in raw.lines() {
            if line.contains(prefix) {
                out.push_str(line);
                out.push('\n');
            }
        }
        if out.is_empty() {
            return CmdResult::from_output(format!(
                "(no kernel log messages at level '{}')\n",
                level
            ));
        }
        return CmdResult::from_output(out);
    }

    let mut result = raw.to_string();
    if !result.ends_with('\n') {
        result.push('\n');
    }
    CmdResult::from_output(result)
}

/// Map a level name to the log prefix emitted by `util/logger.rs`.
fn level_to_log_prefix(level: &str) -> &str {
    match level {
        "trace" => "[TRACE]",
        "info" => "[INFO]",
        "warn" => "[WARN]",
        "error" => "[ERROR]",
        "fatal" => "[FATAL]",
        _ => "",
    }
}

// ─── uname ──────────────────────────────────────────────────────────────

pub fn cmd_uname(argv: &[String]) -> CmdResult {
    let all = argv.len() > 1 && argv[1] == "-a";

    #[cfg(target_arch = "x86_64")]
    let arch = "x86_64";
    #[cfg(not(target_arch = "x86_64"))]
    #[cfg(target_arch = "aarch64")]
    let arch = "aarch64";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch = "unknown";

    let output = if all {
        format!("adAstra 2026.6.1 {arch} kernel\n")
    } else {
        String::from("adAstra\n")
    };
    CmdResult::from_output(output)
}

// ─── sleep ──────────────────────────────────────────────────────────────

pub fn cmd_sleep(argv: &[String]) -> CmdResult {
    if argv.len() < 2 {
        return CmdResult::error(1, String::from("sleep: usage: sleep <seconds>\n"));
    }
    let Ok(seconds) = argv[1].parse::<u64>() else {
        return CmdResult::error(1, format!("sleep: invalid duration `{}`\n", argv[1]));
    };
    let seconds = seconds.min(3600); // cap at 1 hour
    let _ = syscall::sys_sleep(seconds);
    CmdResult::empty()
}

// ─── uptime ─────────────────────────────────────────────────────────────

pub fn cmd_uptime() -> CmdResult {
    let mut sched_buf = [0u8; diagnostic::SYSTEM_INFO_RECORD_SIZE];
    match syscall::sys_system_info(diagnostic::SYSTEM_INFO_SCHEDULER, &mut sched_buf) {
        Ok(_) => {
            let info: &diagnostic::SystemInfoRecord =
                unsafe { &*(sched_buf.as_ptr() as *const diagnostic::SystemInfoRecord) };
            CmdResult::from_output(format!(
                "uptime: system running — {} processes ({} ready, {} waiting)\n",
                info.process_count, info.ready_count, info.waiting_count,
            ))
        }
        Err(_) => CmdResult::error(1, String::from("uptime: scheduler not available\n")),
    }
}
