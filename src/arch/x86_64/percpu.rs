//! src/arch/x86_64/percpu.rs
//!
//! Where this CPU's `PerCpuData` lives: the `IA32_GS_BASE` MSR.
//!
//! The base is mirrored in `IA32_KERNEL_GS_BASE`, because user mode is free to
//! set `gs` to its own value and the interrupt entry path uses `swapgs` to get
//! the kernel's view back.
//!
//! This module is the only place in the tree that names those MSRs or the
//! `gs:`-relative addressing that makes the scheduler lookup one instruction.

use crate::kernel::percpu::PerCpuData;
use crate::kernel::percpu::PERCPU_OFFSET_SCHEDULER;
use crate::kernel::process::Scheduler;
use crate::util::sync_unsafe_cell::SyncUnsafeCell;

/// `IA32_GS_BASE`: the base the CPU uses to resolve `gs:` addresses.
const IA32_GS_BASE: u32 = 0xC000_0101;

/// `IA32_KERNEL_GS_BASE`: what `swapgs` exchanges `IA32_GS_BASE` with.
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// The BSP's per-CPU block, which exists before the heap does.
static BSP_PERCPU: SyncUnsafeCell<PerCpuData> = SyncUnsafeCell::new(PerCpuData::zeroed());

/// Whether a zero base means "too early" rather than "a bug".
///
/// x86_64 installs the base during GDT load, before anything in the kernel can
/// ask for per-CPU data, so a zero base later is a defect worth stopping on.
pub fn expects_base_installed() -> bool {
    true
}

/// The current CPU's `PerCpuData` base, or 0 before it is installed.
pub fn base() -> u64 {
    read_msr(IA32_GS_BASE)
}

/// Point this CPU at its `PerCpuData`.
///
/// # Safety
///
/// `base` must be the address of a live, 64-byte-aligned [`PerCpuData`] that
/// outlives this CPU's use of it, and `IA32_KERNEL_GS_BASE` must be set with
/// [`set_kernel_base`] or [`init_ap_gs_bases`] so `swapgs` stays consistent.
pub unsafe fn set_base(base: u64) {
    // SAFETY: the caller guarantees `base` is this CPU's live PerCpuData.
    unsafe {
        write_msr(IA32_GS_BASE, base);
    }
}

/// The scheduler pointer, one `gs:`-relative load away.
#[inline]
pub fn scheduler_ptr() -> *mut Scheduler {
    let ptr: *mut Scheduler;
    // SAFETY: the GS base points at this CPU's PerCpuData, whose `scheduler`
    // field is at `PERCPU_OFFSET_SCHEDULER` (checked at compile time).  Before
    // the base is installed the load reads address 8, which is why callers
    // that may run that early use `base()` first.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[{}]",
            out(reg) ptr,
            const PERCPU_OFFSET_SCHEDULER,
            options(nostack, readonly),
        );
    }
    ptr
}

/// Install the BSP's per-CPU base in both MSRs.
///
/// Called once during early boot, after the GDT is loaded and before any
/// per-CPU accessor runs.
///
/// # Safety
///
/// Must run exactly once, on the BSP.
pub unsafe fn init_bsp_gs_bases() {
    let base = BSP_PERCPU.get() as u64;
    // SAFETY: the caller guarantees this runs once, on the BSP, and `base` is
    // that CPU's own static block.
    unsafe {
        write_msr(IA32_GS_BASE, base);
        write_msr(IA32_KERNEL_GS_BASE, base);
    }
}

/// Install an AP's per-CPU base in both MSRs.
///
/// # Safety
///
/// `percpu` must be this AP's live [`PerCpuData`]; call once per AP, on that
/// AP, after its GDT is loaded.
pub unsafe fn init_ap_gs_bases(percpu: *const PerCpuData) {
    let base = percpu as u64;
    // SAFETY: the caller guarantees `percpu` is this AP's live block, and that
    // this runs on that AP.
    unsafe {
        write_msr(IA32_GS_BASE, base);
        write_msr(IA32_KERNEL_GS_BASE, base);
    }
}

/// Fill in the BSP's per-CPU fields once the scheduler and LAPIC exist.
///
/// # Safety
///
/// Called once, on the BSP, after [`init_bsp_gs_bases`].
pub unsafe fn init_bsp_data(scheduler: *mut Scheduler, lapic_id: u8, tss: *mut u8) {
    let percpu = unsafe { &mut *BSP_PERCPU.get() };
    percpu.cpu_id = 0;
    percpu.lapic_id = lapic_id;
    percpu.scheduler = scheduler;
    percpu.tss = tss;
}

fn read_msr(msr: u32) -> u64 {
    let value: u64;
    // SAFETY: `rdmsr` reads the named MSR into edx:eax and has no other effect.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            "shl rdx, 32",
            "or rax, rdx",
            in("ecx") msr,
            out("rax") value,
            out("rdx") _,
        );
    }
    value
}

unsafe fn write_msr(msr: u32, value: u64) {
    // SAFETY: `wrmsr` writes edx:eax into the named MSR; the caller has
    // established that the value is the right one for this CPU.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
        );
    }
}
