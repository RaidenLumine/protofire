//! src/arch/x86_64/control_regs.rs
//! CR0 / CR4 read/write helpers and control-register bit definitions.
//!
//! Used during early boot to set up the FPU/SSE environment (CR0) and to
//! enable SMEP / SMAP (CR4) once CPUID confirms the CPU supports them.
//! Writing reserved CR4 bits raises #GP, so callers must gate every write
//! on a feature check first.

use core::arch::asm;

// ── CR0 bits ────────────────────────────────────────────────────────────────

/// CR0 bit 1: Monitor co-processor.  Controls the WAIT/FWAIT behaviour
/// relative to CR0.TS.
pub const CR0_MP: u64 = 1 << 1;

/// CR0 bit 2: Emulation.  When set, all x87 FPU / SSE instructions trap
/// with #UD and must be emulated in software.  Cleared once the FPU has
/// been initialised.
pub const CR0_EM: u64 = 1 << 2;

/// CR0 bit 3: Task Switched.  When set, x87 FPU / SSE instructions raise
/// #NM so the kernel can lazy-switch the FPU state between threads.
pub const CR0_TS: u64 = 1 << 3;

/// Read the current value of CR0.
#[inline]
pub fn read_cr0() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Write CR0.
///
/// # Safety
///
/// Unconditionally reloads CR0.  Clearing CR0.PE or otherwise mis-setting
/// protected-mode bits while the MMU is active is catastrophic.
#[inline]
pub unsafe fn write_cr0(value: u64) {
    asm!("mov cr0, {}", in(reg) value, options(nomem, nostack));
}

/// Read the current value of CR2 (the last page-fault linear address).
#[inline]
pub fn read_cr2() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Read the current value of CR3 (the active page-table root).
#[inline]
pub fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Write CR3 (switch the active page table).
///
/// # Safety
///
/// The referenced page-table root must be valid and identity-mapped at the
/// point of the switch, or the next instruction fetch faults.
#[inline]
pub unsafe fn write_cr3(value: u64) {
    asm!("mov cr3, {}", in(reg) value, options(nomem, nostack));
}

/// Read the current value of CR4.
///
/// # Safety
///
/// Reading CR4 is safe at CPL 0 and cannot fault; the `unsafe` marker is
/// retained for symmetry with the write helpers.
#[inline]
pub unsafe fn read_cr4() -> u64 {
    let value: u64;
    asm!("mov {}, cr4", out(reg) value, options(nomem, nostack));
    value
}

/// Write CR4.
///
/// # Safety
///
/// Writing reserved bits (e.g. SMEP/SMAP on CPUs that do not support them)
/// raises a #GP fault, so callers must gate writes on CPUID checks.
#[inline]
pub unsafe fn write_cr4(value: u64) {
    asm!("mov cr4, {}", in(reg) value, options(nomem, nostack));
}

// ── CR4 bits ────────────────────────────────────────────────────────────────

/// CR4 bit 9: OS FXSAVE/FXRSTOR support.  **Required** for SSE
/// instructions (`movdqu`, etc.) – without this bit they raise #UD.
const CR4_OSFXSR: u64 = 1 << 9;

/// CR4 bit 10: OS support for unmasked SSE exceptions (#XM).
const CR4_OSXMMEXCPT: u64 = 1 << 10;

/// CR4 bit 20: Supervisor Mode Execution Prevention.
pub const CR4_SMEP: u64 = 1 << 20;

/// CR4 bit 21: Supervisor Mode Access Prevention.
pub const CR4_SMAP: u64 = 1 << 21;

/// Initialise the FPU/SSE execution environment.
///
/// Clears CR0.EM and CR0.TS so that x87 / SSE instructions execute natively
/// rather than trapping.  Sets CR0.MP so that WAIT/FWAIT still honour
/// CR0.TS for lazy state switching.
pub fn enable_fpu() {
    let cr0 = read_cr0();
    unsafe {
        write_cr0((cr0 | CR0_MP) & !(CR0_EM | CR0_TS));
    }
}

/// Enable SSE by advertising FXSAVE/FXRSTOR and unmasked-exception support
/// in CR4.  Must run after `enable_fpu`, which clears CR0.EM.
pub fn enable_sse() {
    let new_cr4 = unsafe { read_cr4() } | CR4_OSFXSR | CR4_OSXMMEXCPT;
    unsafe { write_cr4(new_cr4) };
}

/// Enable SMEP (Supervisor Mode Execution Prevention).
///
/// No-op on CPUs that do not advertise SMEP (CPUID leaf 7, EBX bit 7) —
/// writing the reserved CR4.SMEP bit would raise #GP.  Also a no-op on
/// non-bare-metal targets, where the host CR4 must never be touched.
pub fn enable_smep() {
    if !super::cpuid::has_smep() {
        return;
    }
    let cr4 = unsafe { read_cr4() };
    unsafe { write_cr4(cr4 | CR4_SMEP) };
}

/// Enable SMAP (Supervisor Mode Access Prevention).
///
/// No-op on CPUs that do not advertise SMAP (CPUID leaf 7, EBX bit 20) and on
/// non-bare-metal targets.  After CR4.SMAP is written, the user-access
/// helpers are told SMAP is live so `stac`/`clac` are actually emitted — with
/// SMAP_ACTIVE left false, every `UserAccessGuard` silently becomes a no-op
/// and the SMAP protection the kernel advertises is not enforced.
pub fn enable_smap() {
    if !super::cpuid::has_smap() {
        return;
    }
    let cr4 = unsafe { read_cr4() };
    unsafe { write_cr4(cr4 | CR4_SMAP) };
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    unsafe {
        super::user_access::set_smap_active();
    }
}
