//! src/kernel/boot_report.rs
//!
//! Structured boot-phase diagnostics: timing, subsystem status, memory layout,
//! and recovery summary captured during `Kernel::init()` and queryable via the
//! `SystemInfo` syscall after boot completes.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::abi::diagnostic::BootReportRecord;
use crate::abi::diagnostic::SubsystemInitRecord;
use crate::abi::diagnostic::BOOT_REPORT_SUBSYSTEM_NAME_MAX;
use crate::kernel::sync::Mutex;

/// Boot-phase stage indices (matching `BootStage` in main.rs).
pub const STAGE_BOOTLOADER: usize = 0;
pub const STAGE_CONSOLE: usize = 1;
pub const STAGE_KERNEL: usize = 2;
pub const STAGE_INIT: usize = 3;

/// Store the boot report once initialisation completes.
static BOOT_REPORT: Mutex<Option<BootReport>> = Mutex::new(None);
static BOOT_REPORT_READY: AtomicBool = AtomicBool::new(false);

/// Track the current tick at each boot-stage transition so we can compute
/// stage durations.  Written by `boot_kernel` in main.rs.
static STAGE_TICK: [AtomicU64; 5] = [
    AtomicU64::new(0), // STAGE_BOOTLOADER
    AtomicU64::new(0), // STAGE_CONSOLE
    AtomicU64::new(0), // STAGE_KERNEL
    AtomicU64::new(0), // STAGE_INIT
    AtomicU64::new(0), // STAGE_MAIN_LOOP (scheduler handoff)
];

/// Record the current uptime tick for a boot stage transition.
///
/// Called from `boot_kernel` in main.rs at each stage boundary.
pub fn record_stage_tick(stage_index: usize, tick: u64) {
    if stage_index < STAGE_TICK.len() {
        STAGE_TICK[stage_index].store(tick, Ordering::Relaxed);
    }
}

/// Boot report, gradually populated during kernel initialisation.
#[derive(Debug, Clone)]
pub struct BootReport {
    pub stage_ticks: [u64; 4],
    pub physical_memory_total: u64,
    pub heap_free_bytes: u64,
    pub kernel_page_table_root: u64,
    pub kernel_page_count: u64,
    pub user_page_count: u64,
    pub subsystem_names: Vec<[u8; BOOT_REPORT_SUBSYSTEM_NAME_MAX]>,
    pub subsystem_statuses: Vec<u64>,
    pub subsystem_durations: Vec<u64>,
    pub recovery_transactions_recovered: u64,
    pub recovery_transactions_repaired: u64,
    pub recovery_volumes_checked: u64,
    pub recovery_volume_repairs: u64,
    pub boot_faults: u64,
}

use alloc::vec::Vec;

impl Default for BootReport {
    fn default() -> Self {
        Self::new()
    }
}

impl BootReport {
    pub const fn new() -> Self {
        Self {
            stage_ticks: [0; 4],
            physical_memory_total: 0,
            heap_free_bytes: 0,
            kernel_page_table_root: 0,
            kernel_page_count: 0,
            user_page_count: 0,
            subsystem_names: Vec::new(),
            subsystem_statuses: Vec::new(),
            subsystem_durations: Vec::new(),
            recovery_transactions_recovered: 0,
            recovery_transactions_repaired: 0,
            recovery_volumes_checked: 0,
            recovery_volume_repairs: 0,
            boot_faults: 0,
        }
    }

    pub fn record_subsystem(&mut self, name: &str, status: u64, start_tick: u64, end_tick: u64) {
        let mut buf = [0u8; BOOT_REPORT_SUBSYSTEM_NAME_MAX];
        let bytes = name.as_bytes();
        let copy = bytes.len().min(BOOT_REPORT_SUBSYSTEM_NAME_MAX);
        buf[..copy].copy_from_slice(&bytes[..copy]);
        self.subsystem_names.push(buf);
        self.subsystem_statuses.push(status);
        self.subsystem_durations
            .push(end_tick.saturating_sub(start_tick));
    }

    pub fn set_memory_layout(
        &mut self,
        physical_total: u64,
        heap_free: u64,
        page_table_root: u64,
        kernel_pages: u64,
        user_pages: u64,
    ) {
        self.physical_memory_total = physical_total;
        self.heap_free_bytes = heap_free;
        self.kernel_page_table_root = page_table_root;
        self.kernel_page_count = kernel_pages;
        self.user_page_count = user_pages;
    }

    pub fn set_recovery_summary(
        &mut self,
        transactions_recovered: u64,
        transactions_repaired: u64,
        volumes_checked: u64,
        volume_repairs: u64,
    ) {
        self.recovery_transactions_recovered = transactions_recovered;
        self.recovery_transactions_repaired = transactions_repaired;
        self.recovery_volumes_checked = volumes_checked;
        self.recovery_volume_repairs = volume_repairs;
    }

    pub fn add_boot_faults(&mut self, count: u64) {
        self.boot_faults += count;
    }

    /// Compute boot-stage durations from the tick records captured in
    /// `STAGE_TICK`.
    pub fn finalise(&mut self, current_tick: u64) {
        let ticks: [u64; 5] = [
            STAGE_TICK[0].load(Ordering::Relaxed),
            STAGE_TICK[1].load(Ordering::Relaxed),
            STAGE_TICK[2].load(Ordering::Relaxed),
            STAGE_TICK[3].load(Ordering::Relaxed),
            current_tick,
        ];

        for i in 0..4 {
            let prev = ticks[i];
            let next = ticks[i + 1];
            if next >= prev && prev != 0 {
                self.stage_ticks[i] = next - prev;
            }
        }
    }

    pub fn to_abi_record(&self) -> BootReportRecord {
        let total = self.stage_ticks.iter().sum();
        BootReportRecord {
            total_boot_ticks: total,
            stage_ticks: self.stage_ticks,
            physical_memory_total: self.physical_memory_total,
            heap_free_bytes: self.heap_free_bytes,
            kernel_page_table_root: self.kernel_page_table_root,
            kernel_page_count: self.kernel_page_count,
            user_page_count: self.user_page_count,
            subsystem_count: self.subsystem_names.len() as u64,
            recovery_transactions_recovered: self.recovery_transactions_recovered,
            recovery_transactions_repaired: self.recovery_transactions_repaired,
            recovery_volumes_checked: self.recovery_volumes_checked,
            recovery_volume_repairs: self.recovery_volume_repairs,
            boot_faults: self.boot_faults,
        }
    }

    pub fn subsystem_records(&self) -> Vec<SubsystemInitRecord> {
        let count = self
            .subsystem_names
            .len()
            .min(self.subsystem_statuses.len())
            .min(self.subsystem_durations.len());
        (0..count)
            .map(|i| SubsystemInitRecord {
                name: self.subsystem_names[i],
                status: self.subsystem_statuses[i],
                duration_ticks: self.subsystem_durations[i],
            })
            .collect()
    }

    // ── Global access ──

    pub fn install_global(report: BootReport) {
        let mut slot = BOOT_REPORT.lock();
        *slot = Some(report);
        BOOT_REPORT_READY.store(true, Ordering::Release);
    }

    pub fn with_global<F, T>(f: F) -> Option<T>
    where
        F: FnOnce(&BootReport) -> T,
    {
        if !BOOT_REPORT_READY.load(Ordering::Acquire) {
            return None;
        }
        let guard = BOOT_REPORT.lock();
        guard.as_ref().map(f)
    }
}
