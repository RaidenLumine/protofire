//! src/user/shared/commands/perf.rs
//!
//! Performance profiling commands (perf stat, perf sched).

use alloc::format;
use alloc::string::String;

use crate::user::shared::abi::diagnostic;
use crate::user::shared::syscall;
use crate::user::shared::types::CmdResult;

// ─── perf ───────────────────────────────────────────────────────────────

/// Performance profiling command.
///
/// Usage: `perf stat` — show all profiler snapshots (alloc, fault, fs, net)
///        `perf sched` — show scheduler and per-CPU stats
pub fn cmd_perf(argv: &[String]) -> CmdResult {
    let subcmd = argv.get(1).map(|s| s.as_str()).unwrap_or("stat");
    match subcmd {
        "stat" => cmd_perf_stat(),
        "sched" => cmd_perf_sched(),
        _ => CmdResult::error(
            1,
            format!(
                "perf: unknown subcommand '{}' — use 'stat' or 'sched'\n",
                subcmd
            ),
        ),
    }
}

pub fn cmd_perf_stat() -> CmdResult {
    let mut out = String::new();

    // ── Alloc Profiler ──
    out.push_str("─── Alloc Profiler ───\n");
    {
        let mut buf = [0u8; diagnostic::ALLOC_PROFILER_RECORD_SIZE];
        match syscall::sys_system_info(diagnostic::SYSTEM_INFO_ALLOC_PROFILER, &mut buf) {
            Ok(_) => {
                let snap: &diagnostic::AllocProfilerRecord =
                    unsafe { &*(buf.as_ptr() as *const diagnostic::AllocProfilerRecord) };
                out.push_str(&format!("heap_allocs:        {}\n", snap.heap_allocs));
                out.push_str(&format!("heap_frees:         {}\n", snap.heap_frees));
                out.push_str(&format!(
                    "heap_alloc_scan:    {}\n",
                    snap.heap_alloc_scan_steps
                ));
                out.push_str(&format!(
                    "heap_bytes_alloc:   {}\n",
                    snap.heap_bytes_allocated
                ));
                out.push_str(&format!("heap_bytes_freed:   {}\n", snap.heap_bytes_freed));
                out.push_str(&format!("frame_allocs:       {}\n", snap.frame_allocs));
                out.push_str(&format!("frame_frees:        {}\n", snap.frame_frees));
                out.push_str(&format!("frame_recycled:     {}\n", snap.frame_recycled));
                out.push_str(&format!("frame_bump_allocs:  {}\n", snap.frame_bump_allocs));
                out.push_str(&format!("frame_zeroed_bytes: {}\n", snap.frame_zero_bytes));
                out.push_str(&format!("page_table_maps:    {}\n", snap.page_table_maps));
                out.push_str(&format!("page_table_unmaps:  {}\n", snap.page_table_unmaps));
                out.push_str(&format!(
                    "page_table_lookups: {}\n",
                    snap.page_table_lookups
                ));
            }
            Err(_) => out.push_str("(not available)\n"),
        }
    }

    // ── Fault Profiler ──
    out.push_str("\n─── Fault Profiler ───\n");
    {
        let mut buf = [0u8; diagnostic::FAULT_PROFILER_RECORD_SIZE];
        match syscall::sys_system_info(diagnostic::SYSTEM_INFO_FAULT_PROFILER, &mut buf) {
            Ok(_) => {
                let snap: &diagnostic::FaultProfilerRecord =
                    unsafe { &*(buf.as_ptr() as *const diagnostic::FaultProfilerRecord) };
                out.push_str(&format!("faults_total:        {}\n", snap.faults_total));
                out.push_str(&format!(
                    "page_faults:         {}\n",
                    snap.page_faults_total
                ));
                out.push_str(&format!(
                    "  demand_paged:      {}\n",
                    snap.page_faults_demand_paged
                ));
                out.push_str(&format!("  cow:               {}\n", snap.page_faults_cow));
                out.push_str(&format!(
                    "  prot_violation:    {}\n",
                    snap.page_faults_protection_violation
                ));
                out.push_str(&format!(
                    "double_faults:       {}\n",
                    snap.double_faults_total
                ));
                out.push_str(&format!(
                    "general_protection:  {}\n",
                    snap.general_protection_total
                ));
                out.push_str(&format!(
                    "invalid_opcode:      {}\n",
                    snap.invalid_opcode_total
                ));
                out.push_str(&format!(
                    "faults_terminated:   {}\n",
                    snap.faults_terminated
                ));
                out.push_str(&format!(
                    "faults_kernel_fatal: {}\n",
                    snap.faults_kernel_fatal
                ));
            }
            Err(_) => out.push_str("(not available)\n"),
        }
    }

    // ── FS Profiler ──
    out.push_str("\n─── FS Profiler ───\n");
    {
        let mut buf = [0u8; diagnostic::FS_PROFILER_RECORD_SIZE];
        match syscall::sys_system_info(diagnostic::SYSTEM_INFO_FS_PROFILER, &mut buf) {
            Ok(_) => {
                let snap: &diagnostic::FsProfilerRecord =
                    unsafe { &*(buf.as_ptr() as *const diagnostic::FsProfilerRecord) };
                out.push_str(&format!("lookups:            {}\n", snap.lookups));
                out.push_str(&format!("reads:              {}\n", snap.reads));
                out.push_str(&format!("writes:             {}\n", snap.writes));
                out.push_str(&format!("creates:            {}\n", snap.creates));
                out.push_str(&format!("deletes:            {}\n", snap.deletes));
                out.push_str(&format!("renames:            {}\n", snap.renames));
                out.push_str(&format!("transactions:       {}\n", snap.transactions));
                out.push_str(&format!("metadata_flushes:   {}\n", snap.metadata_flushes));
                out.push_str(&format!("elapsed_ticks:      {}\n", snap.elapsed_ticks));
            }
            Err(_) => out.push_str("(not available)\n"),
        }
    }

    // ── Net Profiler ──
    out.push_str("\n─── Net Profiler ───\n");
    {
        let mut buf = [0u8; diagnostic::NET_PROFILER_RECORD_SIZE];
        match syscall::sys_system_info(diagnostic::SYSTEM_INFO_NET_PROFILER, &mut buf) {
            Ok(_) => {
                let snap: &diagnostic::NetProfilerRecord =
                    unsafe { &*(buf.as_ptr() as *const diagnostic::NetProfilerRecord) };
                out.push_str(&format!("arp_lookups:        {}\n", snap.arp_lookups));
                out.push_str(&format!("arp_misses:         {}\n", snap.arp_misses));
                out.push_str(&format!("arp_resolves_sent:  {}\n", snap.arp_resolves_sent));
                out.push_str(&format!("tcp_segments_rx:    {}\n", snap.tcp_segments_rx));
                out.push_str(&format!("tcp_segments_tx:    {}\n", snap.tcp_segments_tx));
                out.push_str(&format!("tcp_bytes_rx:       {}\n", snap.tcp_bytes_rx));
                out.push_str(&format!("tcp_bytes_tx:       {}\n", snap.tcp_bytes_tx));
                out.push_str(&format!("tcp_retransmits:    {}\n", snap.tcp_retransmits));
                out.push_str(&format!("tcp_connects:       {}\n", snap.tcp_connects));
                out.push_str(&format!(
                    "tcp_connects_failed:{}\n",
                    snap.tcp_connects_failed
                ));
                out.push_str(&format!("udp_datagrams_rx:   {}\n", snap.udp_datagrams_rx));
                out.push_str(&format!("udp_datagrams_tx:   {}\n", snap.udp_datagrams_tx));
                out.push_str(&format!("udp_dropped:        {}\n", snap.udp_dropped));
                out.push_str(&format!("icmp_echo_replies:  {}\n", snap.icmp_echo_replies));
                out.push_str(&format!("icmp_unreachable:   {}\n", snap.icmp_unreachable));
                out.push_str(&format!("ipv4_packets_rx:    {}\n", snap.ipv4_packets_rx));
                out.push_str(&format!("ipv4_packets_tx:    {}\n", snap.ipv4_packets_tx));
                out.push_str(&format!(
                    "ipv4_checksum_err:  {}\n",
                    snap.ipv4_checksum_errors
                ));
                out.push_str(&format!("poll_iterations:    {}\n", snap.poll_iterations));
                out.push_str(&format!("poll_rx_empty:      {}\n", snap.poll_rx_empty));
                out.push_str(&format!("poll_errors:        {}\n", snap.poll_errors));
                out.push_str(&format!("elapsed_ticks:      {}\n", snap.elapsed_ticks));
            }
            Err(_) => out.push_str("(not available)\n"),
        }
    }

    CmdResult::from_output(out)
}

pub fn cmd_perf_sched() -> CmdResult {
    let mut out = String::new();

    // ── Scheduler ──
    out.push_str("─── Scheduler ───\n");
    {
        let mut buf = [0u8; diagnostic::SYSTEM_INFO_RECORD_SIZE];
        match syscall::sys_system_info(diagnostic::SYSTEM_INFO_SCHEDULER, &mut buf) {
            Ok(_) => {
                let info: &diagnostic::SystemInfoRecord =
                    unsafe { &*(buf.as_ptr() as *const diagnostic::SystemInfoRecord) };
                let ticks = info.uptime_ticks;
                let seconds = ticks / 100;
                let hours = seconds / 3600;
                let minutes = (seconds % 3600) / 60;
                let secs = seconds % 60;
                out.push_str(&format!(
                    "uptime:           {ticks} ticks ({hours}h {minutes}m {secs}s)\n"
                ));
                out.push_str(&format!("process_count:    {}\n", info.process_count));
                out.push_str(&format!("ready_count:      {}\n", info.ready_count));
                out.push_str(&format!("waiting_count:    {}\n", info.waiting_count));
                out.push_str(&format!("dispatch_count:   {}\n", info.dispatch_count));
                out.push_str(&format!("block_count:      {}\n", info.block_count));
                out.push_str(&format!(
                    "timed_wait:       {}\n",
                    info.timed_wait_registration_count
                ));
                out.push_str(&format!("signal_wake:      {}\n", info.signal_wake_count));
                out.push_str(&format!("timeout_wake:     {}\n", info.timeout_wake_count));
                out.push_str(&format!("preempt_count:    {}\n", info.preempt_count));
            }
            Err(_) => out.push_str("(scheduler not available)\n"),
        }
    }

    // ── Per-CPU ──
    out.push_str("\n─── Per-CPU ───\n");
    {
        let mut buf = [0u8; diagnostic::PER_CPU_RECORD_SIZE];
        match syscall::sys_system_info(diagnostic::SYSTEM_INFO_PER_CPU, &mut buf) {
            Ok(_) => {
                let snap: &diagnostic::PerCpuRecord =
                    unsafe { &*(buf.as_ptr() as *const diagnostic::PerCpuRecord) };
                out.push_str(&format!("cpu_id:           {}\n", snap.cpu_id));
                out.push_str(&format!("context_switches: {}\n", snap.context_switches));
                out.push_str(&format!("kernel_entries:   {}\n", snap.kernel_entries));
            }
            Err(_) => out.push_str("(not available)\n"),
        }
    }

    CmdResult::from_output(out)
}
