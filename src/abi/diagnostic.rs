//! src/abi/diagnostic.rs
//!
//! ABI diagnostic records shared between kernel and user-space.

use core::mem::size_of;

// ── AllocProfilerRecord ──

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocProfilerRecord {
    // Heap counters
    pub heap_allocs: u64,
    pub heap_frees: u64,
    pub heap_alloc_scan_steps: u64,
    pub heap_bytes_allocated: u64,
    pub heap_bytes_freed: u64,
    // Frame counters
    pub frame_allocs: u64,
    pub frame_frees: u64,
    pub frame_recycled: u64,
    pub frame_bump_allocs: u64,
    pub frame_zero_bytes: u64,
    // Page table counters
    pub page_table_maps: u64,
    pub page_table_unmaps: u64,
    pub page_table_lookups: u64,
}

pub const ALLOC_PROFILER_RECORD_SIZE: usize = size_of::<AllocProfilerRecord>();

// ── FaultProfilerRecord ──

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultProfilerRecord {
    pub faults_total: u64,
    pub page_faults_total: u64,
    pub page_faults_user: u64,
    pub page_faults_kernel: u64,
    pub page_faults_not_present: u64,
    pub page_faults_protection_violation: u64,
    pub page_faults_demand_paged: u64,
    pub page_faults_cow: u64,
    pub double_faults_total: u64,
    pub invalid_opcode_total: u64,
    pub general_protection_total: u64,
    pub device_not_available_total: u64,
    pub other_exceptions_total: u64,
    pub faults_delivered_to_handler: u64,
    pub faults_no_handler: u64,
    pub faults_terminated: u64,
    pub faults_kernel_fatal: u64,
}

pub const FAULT_PROFILER_RECORD_SIZE: usize = size_of::<FaultProfilerRecord>();

// ── FsProfilerRecord ──

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsProfilerRecord {
    pub lookups: u64,
    pub reads: u64,
    pub writes: u64,
    pub creates: u64,
    pub deletes: u64,
    pub renames: u64,
    pub transactions: u64,
    pub metadata_flushes: u64,
    pub elapsed_ticks: u64,
}

pub const FS_PROFILER_RECORD_SIZE: usize = size_of::<FsProfilerRecord>();

// ── NetProfilerRecord ──

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetProfilerRecord {
    pub arp_lookups: u64,
    pub arp_misses: u64,
    pub arp_resolves_sent: u64,
    pub arp_resolves_timeout: u64,
    pub arp_packets_rx: u64,
    pub tcp_segments_rx: u64,
    pub tcp_segments_tx: u64,
    pub tcp_bytes_rx: u64,
    pub tcp_bytes_tx: u64,
    pub tcp_retransmits: u64,
    pub tcp_retransmit_bytes: u64,
    pub tcp_connects: u64,
    pub tcp_connects_failed: u64,
    pub tcp_close_initiated: u64,
    pub tcp_duplicate_acks: u64,
    pub udp_datagrams_rx: u64,
    pub udp_datagrams_tx: u64,
    pub udp_dropped: u64,
    pub icmp_echo_replies: u64,
    pub icmp_unreachable: u64,
    pub ipv4_packets_rx: u64,
    pub ipv4_packets_tx: u64,
    pub ipv4_checksum_errors: u64,
    pub poll_iterations: u64,
    pub poll_rx_empty: u64,
    pub poll_errors: u64,
    pub elapsed_ticks: u64,
}

pub const NET_PROFILER_RECORD_SIZE: usize = size_of::<NetProfilerRecord>();

// ── PerCpuRecord ──

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PerCpuRecord {
    pub cpu_id: u64,
    pub context_switches: u64,
    pub kernel_entries: u64,
}

pub const PER_CPU_RECORD_SIZE: usize = size_of::<PerCpuRecord>();

// ── IrqProfilerRecord ──

/// Snapshot of the interrupt profiler: per-vector and per-CPU interrupt
/// counts, plus the load-balancer state.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqProfilerRecord {
    /// Total interrupt deliveries (all CPUs, all vectors).
    pub total_irqs: u64,
    /// Total IPI deliveries.
    pub total_ipis: u64,
    /// Total NMI-class entries (NMI / SError / FIQ).
    pub total_nmis: u64,
    /// Total spurious (unmatched) interrupts.
    pub spurious_interrupts: u64,
    /// 1 when IRQ load balancing is enabled.
    pub irq_balance_enabled: u64,
    /// Number of IRQ migrations performed by the load balancer.
    pub irq_balance_migrations: u64,
    /// CPU id of the most recent migration target.
    pub irq_balance_last_target_cpu: u64,
    /// Number of online CPUs.
    pub online_cpus: u64,
    /// Per-vector delivery counts (indexed by interrupt vector / controller
    /// id).
    pub irq_counts: [u64; 256],
    /// Per-CPU IRQ delivery counts.
    pub per_cpu_irqs: [u64; 16],
    /// Per-CPU IPI delivery counts.
    pub per_cpu_ipis: [u64; 16],
    /// Per-CPU NMI delivery counts.
    pub per_cpu_nmis: [u64; 16],
}

pub const IRQ_PROFILER_RECORD_SIZE: usize = size_of::<IrqProfilerRecord>();

// `[u64; 256]` does not implement `Default` (array `Default` only covers
// lengths <= 32), so a manual default is required.
impl Default for IrqProfilerRecord {
    fn default() -> Self {
        Self {
            total_irqs: 0,
            total_ipis: 0,
            total_nmis: 0,
            spurious_interrupts: 0,
            irq_balance_enabled: 0,
            irq_balance_migrations: 0,
            irq_balance_last_target_cpu: 0,
            online_cpus: 0,
            irq_counts: [0; 256],
            per_cpu_irqs: [0; 16],
            per_cpu_ipis: [0; 16],
            per_cpu_nmis: [0; 16],
        }
    }
}

// ── BootReportRecord ──

/// Subsystem init outcome.
pub const SUBSYSTEM_STATUS_NOT_STARTED: u64 = 0;
pub const SUBSYSTEM_STATUS_OK: u64 = 1;
pub const SUBSYSTEM_STATUS_FAILED: u64 = 2;
pub const SUBSYSTEM_STATUS_SKIPPED: u64 = 3;

pub const BOOT_REPORT_SUBSYSTEM_NAME_MAX: usize = 32;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubsystemInitRecord {
    pub name: [u8; BOOT_REPORT_SUBSYSTEM_NAME_MAX],
    pub status: u64,
    pub duration_ticks: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootReportRecord {
    /// Total boot duration in scheduler ticks from bootloader to main loop.
    pub total_boot_ticks: u64,
    /// Duration per boot stage (loader→console, console→kernel, kernel→init,
    /// init→scheduler).
    pub stage_ticks: [u64; 4],
    /// Physical memory total in bytes.
    pub physical_memory_total: u64,
    /// Heap free bytes at the end of boot.
    pub heap_free_bytes: u64,
    /// Kernel page table root address.
    pub kernel_page_table_root: u64,
    /// Kernel page count in page tables.
    pub kernel_page_count: u64,
    /// User page count in page tables.
    pub user_page_count: u64,
    /// Number of recorded subsystem init records.
    pub subsystem_count: u64,
    /// Install-management recovery counters (retained for ABI compat).
    pub recovery_transactions_recovered: u64,
    pub recovery_transactions_repaired: u64,
    pub recovery_volumes_checked: u64,
    pub recovery_volume_repairs: u64,
    /// Total boot-time faults observed.
    pub boot_faults: u64,
}

impl BootReportRecord {
    /// All-zero boot report (used when no boot report was captured).
    pub const fn zeroed() -> Self {
        Self {
            total_boot_ticks: 0,
            stage_ticks: [0; 4],
            physical_memory_total: 0,
            heap_free_bytes: 0,
            kernel_page_table_root: 0,
            kernel_page_count: 0,
            user_page_count: 0,
            subsystem_count: 0,
            recovery_transactions_recovered: 0,
            recovery_transactions_repaired: 0,
            recovery_volumes_checked: 0,
            recovery_volume_repairs: 0,
            boot_faults: 0,
        }
    }
}

// ── ProcessInfoRecord ──

/// Maximum length of a process name in [`ProcessInfoRecord`].
pub const PROCESS_INFO_NAME_MAX: usize = 32;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessInfoRecord {
    pub pid: u64,
    pub ppid: u64,
    pub name: [u8; PROCESS_INFO_NAME_MAX],
    pub state: u64,
    pub thread_count: u64,
    pub priority: u64,
    pub cpu_ticks: u64,
    pub is_kernel: u64,
}

pub const PROCESS_INFO_RECORD_SIZE: usize = size_of::<ProcessInfoRecord>();

// ── ThreadInfoRecord ──

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadInfoRecord {
    pub tid: u64,
    pub priority: u64,
    pub cpu_ticks: u64,
    pub state: u64,
}

impl ThreadInfoRecord {
    /// All-zero thread record (used by tests / as a placeholder).
    pub const fn zeroed() -> Self {
        Self {
            tid: 0,
            priority: 0,
            cpu_ticks: 0,
            state: 0,
        }
    }
}

pub const THREAD_INFO_RECORD_SIZE: usize = size_of::<ThreadInfoRecord>();

// ── SystemInfoRecord (SystemInfo selector 0) ──

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemInfoRecord {
    pub uptime_ticks: u64,
    pub process_count: u64,
    pub ready_count: u64,
    pub waiting_count: u64,
    pub dispatch_count: u64,
    pub block_count: u64,
    pub timed_wait_registration_count: u64,
    pub signal_wake_count: u64,
    pub timeout_wake_count: u64,
    pub preempt_count: u64,
}

pub const SYSTEM_INFO_RECORD_SIZE: usize = size_of::<SystemInfoRecord>();

// ── SystemHealthRecord (SystemInfo selector 4) ──

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemHealthRecord {
    pub uptime_ticks: u64,
    pub process_count: u64,
    pub faults_total: u64,
    pub faults_terminated: u64,
    pub faults_kernel_fatal: u64,
    pub volume_issues_detected: u64,
    pub volume_repairs_applied: u64,
    pub volume_orphan_data_blocks: u64,
    pub volume_checksum_failures: u64,
    pub volume_interrupted_commits: u64,
    pub install_transactions_recovered: u64,
    pub install_transactions_repaired: u64,
    pub kernel_log_size: u64,
    pub heap_free_bytes: u64,
}

pub const SYSTEM_HEALTH_RECORD_SIZE: usize = size_of::<SystemHealthRecord>();

// ── FaultRecordAbi (ListProcessFaults) ──

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultRecordAbi {
    pub vector: u64,
    pub error_code: u64,
    pub fault_address: u64,
    pub instruction_pointer: u64,
    pub from_user_mode: u64,
}

pub const FAULT_RECORD_ABI_SIZE: usize = size_of::<FaultRecordAbi>();

// ── SystemInfo selectors ──

pub const SYSTEM_INFO_SCHEDULER: u64 = 0;
pub const SYSTEM_INFO_ALLOC_PROFILER: u64 = 1;
pub const SYSTEM_INFO_FAULT_PROFILER: u64 = 2;
pub const SYSTEM_INFO_BOOT_REPORT: u64 = 3;
pub const SYSTEM_INFO_SYSTEM_HEALTH: u64 = 4;
pub const SYSTEM_INFO_FS_PROFILER: u64 = 5;
pub const SYSTEM_INFO_NET_PROFILER: u64 = 6;
pub const SYSTEM_INFO_REAL_TIME: u64 = 7;
pub const SYSTEM_INFO_PER_CPU: u64 = 8;
pub const SYSTEM_INFO_IRQ_PROFILER: u64 = 9;

// ── Process state encodings ──

pub const PROCESS_STATE_NEW: u64 = 0;
pub const PROCESS_STATE_READY: u64 = 1;
pub const PROCESS_STATE_RUNNING: u64 = 2;
pub const PROCESS_STATE_WAITING: u64 = 3;
pub const PROCESS_STATE_TERMINATED: u64 = 4;

// ── Thread priority encodings ──

pub const THREAD_PRIORITY_IDLE: u64 = 0;
pub const THREAD_PRIORITY_NORMAL: u64 = 1;
pub const THREAD_PRIORITY_HIGH: u64 = 2;
pub const THREAD_PRIORITY_REALTIME: u64 = 3;

// ── Thread state encodings ──

pub const THREAD_STATE_READY: u64 = 0;
pub const THREAD_STATE_RUNNING: u64 = 1;
pub const THREAD_STATE_WAITING: u64 = 2;
pub const THREAD_STATE_STOPPED: u64 = 3;
pub const THREAD_STATE_TERMINATED: u64 = 4;
