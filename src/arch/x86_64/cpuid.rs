//! src/arch/x86_64/cpuid.rs
//! CPUID instruction wrapper and feature-detection helpers.
//!
//! Used by early-boot code to check whether the CPU supports SMEP, SMAP, and
//! other features before attempting to set the corresponding CR4 bits.
//! On CPUs that do not advertise a feature the associated control-register
//! bits are reserved — writing them causes a #GP fault.

/// CPUID leaf 7 (Structured Extended Features), sub-leaf 0, EBX bit 7.
pub const CPUID_LEAF_7_EBX_SMEP: u32 = 1 << 7;

/// CPUID leaf 7 (Structured Extended Features), sub-leaf 0, EBX bit 20.
pub const CPUID_LEAF_7_EBX_SMAP: u32 = 1 << 20;

/// CPUID leaf 1, ECX bit 30 — RDRAND instruction available.
pub const CPUID_LEAF_1_ECX_RDRAND: u32 = 1 << 30;

/// CPUID leaf 7 (Structured Extended Features), sub-leaf 0, EBX bit 18 — RDSEED instruction available.
pub const CPUID_LEAF_7_EBX_RDSEED: u32 = 1 << 18;

/// Result of a CPUID invocation: EAX, EBX, ECX, EDX.
#[derive(Debug, Clone, Copy)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Execute the CPUID instruction for the given leaf and sub-leaf.
///
/// # Safety
///
/// This is a bare-metal instruction; calling it under a host kernel is UB.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn cpuid(leaf: u32, sub_leaf: u32) -> CpuidResult {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;

    // LLVM reserves rbx as the frame pointer / base register, so we cannot
    // bind it directly with `out("ebx")`.  Save it on the stack around the
    // CPUID instruction and capture the result in a scratch register.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            inout("ecx") sub_leaf => ecx,
            out("edx") edx,
            ebx_out = out(reg) ebx,
        );
    }

    CpuidResult { eax, ebx, ecx, edx }
}

/// Check whether the CPU advertises SMEP support (CPUID leaf 7, EBX bit 7).
///
/// Returns `true` if SMEP is available and it is safe to set CR4.SMEP.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn has_smep() -> bool {
    // CPUID leaf 7 requires that the CPU supports leaf 7 at all.
    // Check the maximum supported leaf first.
    let max_leaf = unsafe { cpuid(0, 0) }.eax;
    if max_leaf < 7 {
        return false;
    }

    let result = unsafe { cpuid(7, 0) };
    result.ebx & CPUID_LEAF_7_EBX_SMEP != 0
}

/// Check whether the CPU advertises SMAP support (CPUID leaf 7, EBX bit 20).
///
/// Returns `true` if SMAP is available and it is safe to set CR4.SMAP.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn has_smap() -> bool {
    let max_leaf = unsafe { cpuid(0, 0) }.eax;
    if max_leaf < 7 {
        return false;
    }

    let result = unsafe { cpuid(7, 0) };
    result.ebx & CPUID_LEAF_7_EBX_SMAP != 0
}

/// Check whether the CPU advertises RDRAND support (CPUID leaf 1, ECX bit 30).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn has_rdrand() -> bool {
    let result = unsafe { cpuid(1, 0) };
    result.ecx & CPUID_LEAF_1_ECX_RDRAND != 0
}

/// Check whether the CPU advertises RDSEED support (CPUID leaf 7, EBX bit 18).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn has_rdseed() -> bool {
    let max_leaf = unsafe { cpuid(0, 0) }.eax;
    if max_leaf < 7 {
        return false;
    }

    let result = unsafe { cpuid(7, 0) };
    result.ebx & CPUID_LEAF_7_EBX_RDSEED != 0
}

// On non-bare-metal targets, provide stubs so callers don't need their own cfg
// gates.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn has_smep() -> bool {
    false
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn has_smap() -> bool {
    false
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn has_rdrand() -> bool {
    false
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn has_rdseed() -> bool {
    false
}
