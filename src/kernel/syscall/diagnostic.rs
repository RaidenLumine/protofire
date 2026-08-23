//! src/kernel/syscall/diagnostic.rs
//! Diagnostic/management syscall handlers: sleep, process listing, thread
//! listing, kernel log, and system info.

use alloc::vec::Vec;

use crate::abi::diagnostic as diag;
use crate::kernel::memory;
use crate::kernel::process::sleep_current;
use crate::{Error, Result};

// ── Sleep (slot 49) ──────────────────────────────────────────────────────

pub(super) fn sleep(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ticks = context.arg(0) as u64;
    super::validate_zeroed_args(context, 1)?;
    sleep_current(ticks);
    Ok(super::SyscallDispatch::complete(0))
}

// ── ListProcesses (slot 50) ─────────────────────────────────────────────

pub(super) fn list_processes(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let buffer_ptr = context.arg(0) as *mut u8;
    let buffer_len = context.arg(1);
    super::validate_zeroed_args(context, 2)?;

    let scheduler = super::runtime::global_scheduler()?;
    let summaries = scheduler.list_process_summaries();

    let records: Vec<diag::ProcessInfoRecord> = summaries
        .into_iter()
        .map(|s| {
            let mut name = [0u8; diag::PROCESS_INFO_NAME_MAX];
            let name_bytes = s.name.as_bytes();
            let copy_len = name_bytes.len().min(diag::PROCESS_INFO_NAME_MAX);
            name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

            diag::ProcessInfoRecord {
                pid: s.pid as u64,
                ppid: s.ppid.map(|p| p as u64).unwrap_or(0),
                name,
                state: process_state_to_u64(s.state),
                thread_count: s.thread_count as u64,
                priority: thread_priority_to_u64(s.priority),
                cpu_ticks: s.cpu_ticks,
                is_kernel: s.is_kernel as u64,
            }
        })
        .collect();

    write_record_slice_to_user(&records, buffer_ptr, buffer_len)
}

// ── ListThreads (slot 51) ───────────────────────────────────────────────

pub(super) fn list_threads(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let pid = super::user_memory::process_pid_arg(context.arg(0))?;
    let buffer_ptr = context.arg(1) as *mut u8;
    let buffer_len = context.arg(2);
    super::validate_zeroed_args(context, 3)?;

    let scheduler = super::runtime::global_scheduler()?;
    let summaries = scheduler.list_thread_summaries(pid);

    let records: Vec<diag::ThreadInfoRecord> = summaries
        .into_iter()
        .map(|s| diag::ThreadInfoRecord {
            tid: s.tid as u64,
            priority: thread_priority_to_u64(s.priority),
            cpu_ticks: s.cpu_ticks,
            state: thread_state_to_u64(s.state),
        })
        .collect();

    write_record_slice_to_user(&records, buffer_ptr, buffer_len)
}

// ── KernelLog (slot 52) ─────────────────────────────────────────────────

pub(super) fn kernel_log(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let offset = context.arg(0) as u64;
    let buffer_ptr = context.arg(1) as *mut u8;
    let buffer_len = context.arg(2);
    super::validate_zeroed_args(context, 3)?;

    // Probe mode: return current log length.
    if buffer_len == 0 {
        return Ok(super::SyscallDispatch::complete(
            crate::kernel::kernel_log::log_len(),
        ));
    }

    // Read kernel log into a temporary buffer, then copy to user memory.
    let mut temp = alloc::vec![0u8; buffer_len];
    let bytes_read = crate::kernel::kernel_log::read_bytes(offset, &mut temp);
    temp.truncate(bytes_read);

    super::user_memory::copy_user_bytes(&temp, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

// ── SystemInfo (slot 53) ────────────────────────────────────────────────

pub(super) fn system_info(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let info_type = context.arg(0) as u64;
    let buffer_ptr = context.arg(1) as *mut u8;
    let buffer_len = context.arg(2);
    super::validate_zeroed_args(context, 3)?;

    match info_type {
        diag::SYSTEM_INFO_SCHEDULER => system_info_scheduler(buffer_ptr, buffer_len),
        diag::SYSTEM_INFO_ALLOC_PROFILER => system_info_alloc_profiler(buffer_ptr, buffer_len),
        diag::SYSTEM_INFO_FAULT_PROFILER => system_info_fault_profiler(buffer_ptr, buffer_len),
        diag::SYSTEM_INFO_BOOT_REPORT => system_info_boot_report(buffer_ptr, buffer_len),
        diag::SYSTEM_INFO_SYSTEM_HEALTH => system_info_system_health(buffer_ptr, buffer_len),
        diag::SYSTEM_INFO_FS_PROFILER => system_info_fs_profiler(buffer_ptr, buffer_len),
        diag::SYSTEM_INFO_NET_PROFILER => system_info_net_profiler(buffer_ptr, buffer_len),
        diag::SYSTEM_INFO_REAL_TIME => system_info_real_time(buffer_ptr, buffer_len),
        diag::SYSTEM_INFO_PER_CPU => system_info_per_cpu(buffer_ptr, buffer_len),
        diag::SYSTEM_INFO_IRQ_PROFILER => system_info_irq_profiler(buffer_ptr, buffer_len),
        _ => Err(Error::InvalidArgument),
    }
}

fn system_info_scheduler(buffer_ptr: *mut u8, buffer_len: usize) -> Result<super::SyscallDispatch> {
    let scheduler = super::runtime::global_scheduler()?;
    let stats = scheduler.hotspot_stats();

    let record = diag::SystemInfoRecord {
        uptime_ticks: scheduler.current_tick(),
        process_count: scheduler.process_count() as u64,
        ready_count: scheduler.ready_count() as u64,
        waiting_count: scheduler.waiting_count() as u64,
        dispatch_count: stats.dispatch_count,
        block_count: stats.block_count,
        timed_wait_registration_count: stats.timed_wait_registration_count,
        signal_wake_count: stats.signal_wake_count,
        timeout_wake_count: stats.timeout_wake_count,
        preempt_count: stats.preempt_count,
    };

    super::user_memory::copy_user_value(&record, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

fn system_info_alloc_profiler(
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    let snap = memory::global()
        .map(|m| m.alloc_profiler_snapshot())
        .unwrap_or_default();
    let record = diag::AllocProfilerRecord {
        heap_allocs: snap.heap_allocs,
        heap_frees: snap.heap_frees,
        heap_alloc_scan_steps: snap.heap_alloc_scan_steps,
        heap_bytes_allocated: snap.heap_bytes_allocated,
        heap_bytes_freed: snap.heap_bytes_freed,
        frame_allocs: snap.frame_allocs,
        frame_frees: snap.frame_frees,
        frame_recycled: snap.frame_recycled,
        frame_bump_allocs: snap.frame_bump_allocs,
        frame_zero_bytes: snap.frame_zero_bytes,
        page_table_maps: snap.page_table_maps,
        page_table_unmaps: snap.page_table_unmaps,
        page_table_lookups: snap.page_table_lookups,
    };
    super::user_memory::copy_user_value(&record, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

fn system_info_fault_profiler(
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    let snap = memory::global()
        .map(|m| m.fault_profiler_snapshot())
        .unwrap_or_default();
    let record = diag::FaultProfilerRecord {
        faults_total: snap.faults_total,
        page_faults_total: snap.page_faults_total,
        page_faults_user: snap.page_faults_user,
        page_faults_kernel: snap.page_faults_kernel,
        page_faults_not_present: snap.page_faults_not_present,
        page_faults_protection_violation: snap.page_faults_protection_violation,
        page_faults_demand_paged: snap.page_faults_demand_paged,
        page_faults_cow: snap.page_faults_cow,
        double_faults_total: snap.double_faults_total,
        invalid_opcode_total: snap.invalid_opcode_total,
        general_protection_total: snap.general_protection_total,
        device_not_available_total: snap.device_not_available_total,
        other_exceptions_total: snap.other_exceptions_total,
        faults_delivered_to_handler: snap.faults_delivered_to_handler,
        faults_no_handler: snap.faults_no_handler,
        faults_terminated: snap.faults_terminated,
        faults_kernel_fatal: snap.faults_kernel_fatal,
    };
    super::user_memory::copy_user_value(&record, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

// ── SystemInfo: BootReport (type 3) ────────────────────────────────────

fn system_info_boot_report(
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    let record =
        crate::kernel::boot_report::BootReport::with_global(|report| report.to_abi_record())
            .unwrap_or_else(diag::BootReportRecord::zeroed);
    super::user_memory::copy_user_value(&record, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

// ── SystemInfo: SystemHealth (type 4) ───────────────────────────────────

fn system_info_system_health(
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    let scheduler = super::runtime::global_scheduler()?;
    let fault_snap = memory::global()
        .map(|m| m.fault_profiler_snapshot())
        .unwrap_or_default();
    let kernel_log_size = crate::kernel::kernel_log::log_len() as u64;
    let heap_free = memory::global()
        .map(|m| {
            let (start, end) = m.heap_bounds();
            (end - start) as u64
        })
        .unwrap_or(0);

    // Read volume recovery stats from the boot-time summary.
    let vol = crate::kernel::volume_recovery_summary();

    // Read install recovery stats from the boot report.
    let (install_recovered, install_repaired) =
        crate::kernel::boot_report::BootReport::with_global(|boot| {
            (
                boot.recovery_transactions_recovered,
                boot.recovery_transactions_repaired,
            )
        })
        .unwrap_or((0, 0));

    let record = diag::SystemHealthRecord {
        uptime_ticks: scheduler.current_tick(),
        process_count: scheduler.process_count() as u64,
        faults_total: fault_snap.faults_total,
        faults_terminated: fault_snap.faults_terminated,
        faults_kernel_fatal: fault_snap.faults_kernel_fatal,
        volume_issues_detected: vol.issues_detected,
        volume_repairs_applied: vol.repairs_applied,
        volume_orphan_data_blocks: vol.orphan_data_blocks,
        volume_checksum_failures: vol.checksum_failures,
        volume_interrupted_commits: vol.interrupted_commits,
        install_transactions_recovered: install_recovered,
        install_transactions_repaired: install_repaired,
        kernel_log_size,
        heap_free_bytes: heap_free,
    };
    super::user_memory::copy_user_value(&record, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

fn system_info_real_time(buffer_ptr: *mut u8, buffer_len: usize) -> Result<super::SyscallDispatch> {
    let timestamp: u64 = rtc_now_unix();

    super::user_memory::copy_user_value(&timestamp, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

// ── SystemInfo: FsProfiler (type 5) ─────────────────────────────────────

fn system_info_fs_profiler(
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    let snap = crate::kernel::fs::global()
        .map(|fs_guard| fs_guard.lock().fs_profiler_snapshot())
        .unwrap_or_default();
    let record = diag::FsProfilerRecord {
        lookups: snap.lookups,
        reads: snap.reads,
        writes: snap.writes,
        creates: snap.creates,
        deletes: snap.deletes,
        renames: snap.renames,
        transactions: snap.transactions,
        metadata_flushes: snap.metadata_flushes,
        elapsed_ticks: snap.elapsed_ticks,
    };
    super::user_memory::copy_user_value(&record, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

// ── SystemInfo: NetProfiler (type 6) ────────────────────────────────────

fn system_info_net_profiler(
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    let snap = crate::kernel::network::stack::NetworkStack::global()
        .map(|stack| stack.profiler_snapshot())
        .unwrap_or_default();
    let record = diag::NetProfilerRecord {
        arp_lookups: snap.arp_lookups,
        arp_misses: snap.arp_misses,
        arp_resolves_sent: snap.arp_resolves_sent,
        arp_resolves_timeout: snap.arp_resolves_timeout,
        arp_packets_rx: snap.arp_packets_rx,
        tcp_segments_rx: snap.tcp_segments_rx,
        tcp_segments_tx: snap.tcp_segments_tx,
        tcp_bytes_rx: snap.tcp_bytes_rx,
        tcp_bytes_tx: snap.tcp_bytes_tx,
        tcp_retransmits: snap.tcp_retransmits,
        tcp_retransmit_bytes: snap.tcp_retransmit_bytes,
        tcp_connects: snap.tcp_connects,
        tcp_connects_failed: snap.tcp_connects_failed,
        tcp_close_initiated: snap.tcp_close_initiated,
        tcp_duplicate_acks: snap.tcp_duplicate_acks,
        udp_datagrams_rx: snap.udp_datagrams_rx,
        udp_datagrams_tx: snap.udp_datagrams_tx,
        udp_dropped: snap.udp_dropped,
        icmp_echo_replies: snap.icmp_echo_replies,
        icmp_unreachable: snap.icmp_unreachable,
        ipv4_packets_rx: snap.ipv4_packets_rx,
        ipv4_packets_tx: snap.ipv4_packets_tx,
        ipv4_checksum_errors: snap.ipv4_checksum_errors,
        poll_iterations: snap.poll_iterations,
        poll_rx_empty: snap.poll_rx_empty,
        poll_errors: snap.poll_errors,
        elapsed_ticks: snap.elapsed_ticks,
    };
    super::user_memory::copy_user_value(&record, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

// ── SystemInfo: PerCpu (type 8) ─────────────────────────────────────────

fn system_info_per_cpu(buffer_ptr: *mut u8, buffer_len: usize) -> Result<super::SyscallDispatch> {
    let percpu = crate::kernel::percpu::get();
    let record = diag::PerCpuRecord {
        cpu_id: percpu.cpu_id as u64,
        context_switches: percpu.context_switches,
        kernel_entries: percpu.kernel_entries,
    };
    super::user_memory::copy_user_value(&record, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

// ── SystemInfo: IrqProfiler (type 9) ──────────────────────────────────

fn system_info_irq_profiler(
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    let mut record = crate::kernel::irq_stats::snapshot();
    record.irq_balance_enabled = crate::kernel::irq_balance::is_enabled() as u64;
    record.irq_balance_migrations = crate::kernel::irq_balance::migrations();
    record.irq_balance_last_target_cpu = crate::kernel::irq_balance::last_target_cpu() as u64;
    record.online_cpus = crate::arch::cpu_count() as u64;
    super::user_memory::copy_user_value(&record, buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

/// Read the current Unix timestamp from the platform RTC.
/// Returns 0 on platforms without an RTC or when the RTC is not readable.
fn rtc_now_unix() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        crate::arch::x86_64::rtc::rtc_now_unix().unwrap_or(0)
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        crate::arch::aarch64::rtc::rtc_now_unix().unwrap_or(0)
    }
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        crate::arch::riscv64::rtc::rtc_now_unix().unwrap_or(0)
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    )))]
    {
        0
    }
}

// ── ListProcessFaults (slot 61) ───────────────────────────────────────────

pub(super) fn list_process_faults(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let pid = super::user_memory::process_pid_arg(context.arg(0))?;
    let buffer_ptr = context.arg(1) as *mut u8;
    let buffer_len = context.arg(2);
    super::validate_zeroed_args(context, 3)?;

    let scheduler = super::runtime::global_scheduler()?;
    let records: Vec<diag::FaultRecordAbi> = scheduler
        .process_by_pid(pid)
        .map(|process| {
            process
                .fault_records()
                .into_iter()
                .map(|f| diag::FaultRecordAbi {
                    vector: f.vector as u64,
                    error_code: f.error_code,
                    fault_address: f.fault_address.unwrap_or(0) as u64,
                    instruction_pointer: f.instruction_pointer,
                    from_user_mode: f.from_user_mode as u64,
                })
                .collect()
        })
        .unwrap_or_default();

    write_record_slice_to_user(&records, buffer_ptr, buffer_len)
}

// ── ReclaimPages (slot 63) ─────────────────────────────────────────────────

/// Trigger page reclamation: try to reclaim up to `target` anonymous user
/// pages, freeing their physical frames while preserving page content for
/// later backfill on demand.
///
/// This is a diagnostic/management syscall intended for memory pressure
/// testing and system administration.  It is not part of the stable ABI.
///
/// Returns the number of pages actually reclaimed.
pub(super) fn reclaim_pages(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let target = context.arg(0);
    super::validate_zeroed_args(context, 1)?;

    let reclaimed = if let Some(mut memory) = memory::global_mut() {
        memory.reclaim_pages(target)
    } else {
        0
    };

    Ok(super::SyscallDispatch::complete(reclaimed))
}

// ── CompactMemory (slot 150) ─────────────────────────────────────────────

/// Trigger memory defragmentation: relocate movable user frames so the
/// physical frame pool's free ranges coalesce into one contiguous block.
///
/// This is a diagnostic/management syscall for memory-pressure testing and
/// system administration.  It is not part of the stable ABI.
///
/// Returns the number of frames actually moved.
pub(super) fn compact_memory(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 0)?;

    let moved = if let Some(mut memory) = memory::global_mut() {
        memory.compact_memory()
    } else {
        0
    };

    Ok(super::SyscallDispatch::complete(moved))
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn process_state_to_u64(state: crate::kernel::process::ProcessState) -> u64 {
    use crate::kernel::process::ProcessState;
    match state {
        ProcessState::New => diag::PROCESS_STATE_NEW,
        ProcessState::Ready => diag::PROCESS_STATE_READY,
        ProcessState::Running => diag::PROCESS_STATE_RUNNING,
        ProcessState::Waiting => diag::PROCESS_STATE_WAITING,
        ProcessState::Terminated => diag::PROCESS_STATE_TERMINATED,
    }
}

fn thread_priority_to_u64(priority: crate::kernel::process::ThreadPriority) -> u64 {
    use crate::kernel::process::ThreadPriority;
    match priority {
        ThreadPriority::Idle => diag::THREAD_PRIORITY_IDLE,
        ThreadPriority::Normal => diag::THREAD_PRIORITY_NORMAL,
        ThreadPriority::High => diag::THREAD_PRIORITY_HIGH,
        ThreadPriority::Realtime => diag::THREAD_PRIORITY_REALTIME,
    }
}

fn thread_state_to_u64(state: crate::kernel::process::ThreadState) -> u64 {
    use crate::kernel::process::ThreadState;
    match state {
        ThreadState::Ready => diag::THREAD_STATE_READY,
        ThreadState::Running => diag::THREAD_STATE_RUNNING,
        ThreadState::Waiting => diag::THREAD_STATE_WAITING,
        ThreadState::Stopped => diag::THREAD_STATE_STOPPED,
        ThreadState::Terminated => diag::THREAD_STATE_TERMINATED,
    }
}

/// Write a slice of fixed-size records to a user buffer.
///
/// Returns the number of records written.  If `buffer_len == 0` (probe),
/// returns the total byte size needed for all records.  Otherwise writes as
/// many records as fit in the buffer.
fn write_record_slice_to_user<T>(
    records: &[T],
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    let record_size = core::mem::size_of::<T>();

    // Probe mode: return required buffer size.
    if buffer_len == 0 {
        return Ok(super::SyscallDispatch::complete(core::mem::size_of_val(
            records,
        )));
    }

    // Determine how many records fit.
    let count = (buffer_len / record_size).min(records.len());
    let byte_count = count * record_size;

    if count == 0 && !records.is_empty() {
        // Buffer is too small for even one record.
        return Err(Error::InvalidArgument);
    }

    // Build contiguous byte slice from records.
    let bytes: Vec<u8> = records[..count]
        .iter()
        .flat_map(|r| {
            let ptr = (r as *const T).cast::<u8>();
            let slice = unsafe { core::slice::from_raw_parts(ptr, record_size) };
            slice.iter().copied()
        })
        .collect();

    super::user_memory::copy_user_bytes(&bytes, buffer_ptr, byte_count)
        .map(|_| super::SyscallDispatch::complete(count))
}

#[cfg(test)]
mod tests {
    use super::super::test_support;
    use super::*;
    use crate::abi::diagnostic as diag;
    use crate::kernel::syscall::table::SyscallNumber;

    // ── Sleep tests ────────────────────────────────────────────────────

    #[test]
    fn sleep_rejects_non_zero_reserved_args() {
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::Sleep as usize,
            [10, 1, 0, 0, 0, 0],
        );
        assert_eq!(sleep(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn sleep_accepts_zero_ticks() {
        let _guard = test_support::test_lock();
        let (_scheduler, _process) = test_support::scheduled_current_process("sleep-ok");
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::Sleep as usize,
            [0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            sleep(&mut context),
            Ok(crate::kernel::syscall::SyscallDispatch::complete(0))
        );
    }

    // ── ListProcesses tests ────────────────────────────────────────────

    #[test]
    fn list_processes_rejects_non_zero_reserved_args() {
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::ListProcesses as usize,
            [0, 0, 1, 0, 0, 0],
        );
        assert_eq!(list_processes(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn list_processes_probe_returns_byte_size() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("list-probe");
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::ListProcesses as usize,
            [0, 0, 0, 0, 0, 0],
        );
        let result = list_processes(&mut context).expect("probe should succeed");
        // With 1 kernel process + the current process, we expect at least 1 record.
        assert!(result.value > 0);
        assert_eq!(result.value % diag::PROCESS_INFO_RECORD_SIZE, 0);
    }

    #[test]
    fn list_processes_returns_valid_records() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("list-records");
        let buf = [0u8; diag::PROCESS_INFO_RECORD_SIZE * 16];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::ListProcesses as usize,
            [buf.as_ptr() as usize, buf.len(), 0, 0, 0, 0],
        );
        let result = list_processes(&mut context).expect("list should succeed");
        assert!(result.value > 0);
        // The first record should be the idle process or a kernel process.
        let first_pid = u64::from_ne_bytes(buf[..8].try_into().unwrap());
        assert!(first_pid > 0);
    }

    // ── ListThreads tests ──────────────────────────────────────────────

    #[test]
    fn list_threads_rejects_non_zero_reserved_args() {
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::ListThreads as usize,
            [0, 0, 0, 1, 0, 0],
        );
        assert_eq!(list_threads(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn list_threads_for_current_process_returns_threads() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("thread-list");
        let pid = process.pid();
        let buf = [0u8; diag::THREAD_INFO_RECORD_SIZE * 8];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::ListThreads as usize,
            [pid as usize, buf.as_ptr() as usize, buf.len(), 0, 0, 0],
        );
        let result = list_threads(&mut context).expect("list should succeed");
        assert!(result.value >= 1); // at least the current thread
        let first_tid = u64::from_ne_bytes(buf[..8].try_into().unwrap());
        assert!(first_tid > 0);
    }

    #[test]
    fn list_threads_nonexistent_pid_returns_zero() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("thread-none");
        let buf = [0u8; diag::THREAD_INFO_RECORD_SIZE * 8];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::ListThreads as usize,
            [9999, buf.as_ptr() as usize, buf.len(), 0, 0, 0],
        );
        let result = list_threads(&mut context).expect("list should succeed");
        assert_eq!(result.value, 0);
    }

    // ── KernelLog tests ────────────────────────────────────────────────

    #[test]
    fn kernel_log_rejects_non_zero_reserved_args() {
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::KernelLog as usize,
            [0, 0, 0, 1, 0, 0],
        );
        assert_eq!(kernel_log(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn kernel_log_probe_returns_length() {
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::KernelLog as usize,
            [0, 0, 0, 0, 0, 0],
        );
        let result = kernel_log(&mut context).expect("probe should succeed");
        // The log may be empty or have content; either is valid.
        // We just check that the call succeeds.
        let _ = result.value;
    }

    #[test]
    fn kernel_log_read_returns_data() {
        // Write some data to the kernel log first.
        crate::kernel::kernel_log::append_bytes(b"test-log-message");
        let mut buf = [0u8; 256];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::KernelLog as usize,
            [0, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0],
        );
        let result = kernel_log(&mut context).expect("read should succeed");
        // Should have read at least our test message.
        assert!(result.value >= 16);
    }

    // ── SystemInfo tests ───────────────────────────────────────────────

    #[test]
    fn system_info_rejects_non_zero_reserved_args() {
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::SystemInfo as usize,
            [0, 0, 0, 1, 0, 0],
        );
        assert_eq!(system_info(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn system_info_rejects_unknown_info_type() {
        let buf = [0u8; diag::SYSTEM_INFO_RECORD_SIZE];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::SystemInfo as usize,
            [99, buf.as_ptr() as usize, buf.len(), 0, 0, 0],
        );
        assert_eq!(system_info(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn system_info_scheduler_returns_record() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("sysinfo-sched");
        let buf = [0u8; diag::SYSTEM_INFO_RECORD_SIZE];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::SystemInfo as usize,
            [
                diag::SYSTEM_INFO_SCHEDULER as usize,
                buf.as_ptr() as usize,
                buf.len(),
                0,
                0,
                0,
            ],
        );
        let result = system_info(&mut context).expect("scheduler info should succeed");
        assert_eq!(result.value, diag::SYSTEM_INFO_RECORD_SIZE);

        // Validate some fields are non-zero (process_count should be >= 1).
        let process_count = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        assert!(process_count >= 1);
    }

    #[test]
    fn system_info_alloc_profiler_returns_record() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("sysinfo-alloc");
        let buf = [0u8; diag::ALLOC_PROFILER_RECORD_SIZE];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::SystemInfo as usize,
            [
                diag::SYSTEM_INFO_ALLOC_PROFILER as usize,
                buf.as_ptr() as usize,
                buf.len(),
                0,
                0,
                0,
            ],
        );
        let result = system_info(&mut context).expect("alloc profiler info should succeed");
        assert_eq!(result.value, diag::ALLOC_PROFILER_RECORD_SIZE);
    }

    #[test]
    fn system_info_fault_profiler_returns_record() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("sysinfo-fault");
        let buf = [0u8; diag::FAULT_PROFILER_RECORD_SIZE];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::SystemInfo as usize,
            [
                diag::SYSTEM_INFO_FAULT_PROFILER as usize,
                buf.as_ptr() as usize,
                buf.len(),
                0,
                0,
                0,
            ],
        );
        let result = system_info(&mut context).expect("fault profiler info should succeed");
        assert_eq!(result.value, diag::FAULT_PROFILER_RECORD_SIZE);
    }

    #[test]
    fn system_info_fs_profiler_returns_record() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("sysinfo-fs-prof");
        let buf = [0u8; diag::FS_PROFILER_RECORD_SIZE];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::SystemInfo as usize,
            [
                diag::SYSTEM_INFO_FS_PROFILER as usize,
                buf.as_ptr() as usize,
                buf.len(),
                0,
                0,
                0,
            ],
        );
        let result = system_info(&mut context).expect("fs profiler info should succeed");
        assert_eq!(result.value, diag::FS_PROFILER_RECORD_SIZE);
    }

    #[test]
    fn system_info_net_profiler_returns_record() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("sysinfo-net-prof");
        let buf = [0u8; diag::NET_PROFILER_RECORD_SIZE];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::SystemInfo as usize,
            [
                diag::SYSTEM_INFO_NET_PROFILER as usize,
                buf.as_ptr() as usize,
                buf.len(),
                0,
                0,
                0,
            ],
        );
        let result = system_info(&mut context).expect("net profiler info should succeed");
        assert_eq!(result.value, diag::NET_PROFILER_RECORD_SIZE);
    }

    #[test]
    fn system_info_per_cpu_returns_record() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("sysinfo-percpu");
        let buf = [0u8; diag::PER_CPU_RECORD_SIZE];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::SystemInfo as usize,
            [
                diag::SYSTEM_INFO_PER_CPU as usize,
                buf.as_ptr() as usize,
                buf.len(),
                0,
                0,
                0,
            ],
        );
        let result = system_info(&mut context).expect("per-cpu info should succeed");
        assert_eq!(result.value, diag::PER_CPU_RECORD_SIZE);
    }

    #[test]
    fn system_info_irq_profiler_returns_record() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("sysinfo-irq-prof");
        let buf = [0u8; diag::IRQ_PROFILER_RECORD_SIZE];
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::SystemInfo as usize,
            [
                diag::SYSTEM_INFO_IRQ_PROFILER as usize,
                buf.as_ptr() as usize,
                buf.len(),
                0,
                0,
                0,
            ],
        );
        let result = system_info(&mut context).expect("irq profiler info should succeed");
        assert_eq!(result.value, diag::IRQ_PROFILER_RECORD_SIZE);
    }

    // ── write_record_slice_to_user tests ───────────────────────────────

    #[test]
    fn write_record_slice_probe_returns_total_size() {
        let records = [diag::ThreadInfoRecord::zeroed(); 3];
        let result = write_record_slice_to_user(&records, core::ptr::null_mut(), 0)
            .expect("probe should succeed");
        assert_eq!(result.value, 3 * diag::THREAD_INFO_RECORD_SIZE);
    }

    #[test]
    fn write_record_slice_empty_returns_zero() {
        let records: &[diag::ThreadInfoRecord] = &[];
        let buf = [0u8; 64];
        let result = write_record_slice_to_user(records, buf.as_ptr() as *mut u8, buf.len())
            .expect("empty should succeed");
        assert_eq!(result.value, 0);
    }

    #[test]
    fn write_record_slice_buffer_too_small_errors() {
        let records = [diag::ThreadInfoRecord::zeroed(); 2];
        let buf = [0u8; diag::THREAD_INFO_RECORD_SIZE - 1]; // smaller than 1 record
        let result = write_record_slice_to_user(&records, buf.as_ptr() as *mut u8, buf.len());
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    // ── Encoding helpers ───────────────────────────────────────────────

    #[test]
    fn process_state_encoding_are_distinct() {
        use crate::kernel::process::ProcessState;
        let encodings = [
            process_state_to_u64(ProcessState::New),
            process_state_to_u64(ProcessState::Ready),
            process_state_to_u64(ProcessState::Running),
            process_state_to_u64(ProcessState::Waiting),
            process_state_to_u64(ProcessState::Terminated),
        ];
        for i in 0..encodings.len() {
            for j in (i + 1)..encodings.len() {
                assert_ne!(encodings[i], encodings[j], "encodings {i} and {j} collide");
            }
        }
    }

    #[test]
    fn thread_priority_encoding_are_distinct() {
        use crate::kernel::process::ThreadPriority;
        let encodings = [
            thread_priority_to_u64(ThreadPriority::Idle),
            thread_priority_to_u64(ThreadPriority::Normal),
            thread_priority_to_u64(ThreadPriority::High),
            thread_priority_to_u64(ThreadPriority::Realtime),
        ];
        for i in 0..encodings.len() {
            for j in (i + 1)..encodings.len() {
                assert_ne!(encodings[i], encodings[j], "encodings {i} and {j} collide");
            }
        }
    }

    #[test]
    fn thread_state_encoding_are_distinct() {
        use crate::kernel::process::ThreadState;
        let encodings = [
            thread_state_to_u64(ThreadState::Ready),
            thread_state_to_u64(ThreadState::Running),
            thread_state_to_u64(ThreadState::Waiting),
            thread_state_to_u64(ThreadState::Stopped),
            thread_state_to_u64(ThreadState::Terminated),
        ];
        for i in 0..encodings.len() {
            for j in (i + 1)..encodings.len() {
                assert_ne!(encodings[i], encodings[j], "encodings {i} and {j} collide");
            }
        }
    }
}
