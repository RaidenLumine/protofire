//! src/arch/percpu.rs
//!
//! Where this CPU's `PerCpuData` pointer lives, per architecture.
//!
//! Every architecture keeps that pointer somewhere the CPU can reach without
//! loading a global: `gs` on x86_64, `TPIDR_EL1` on aarch64, `tp` on riscv64.
//! The kernel names none of those registers.  It asks this module for the base
//! and for the scheduler fast path, and the architecture answers — a new
//! architecture adds a module beside the others and one line here, rather than
//! another `#[cfg(target_arch = ...)]` in the middle of the kernel.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::percpu::base;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::percpu::base;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::percpu::base;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::percpu::set_base;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::percpu::set_base;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::percpu::set_base;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::percpu::scheduler_ptr;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::percpu::scheduler_ptr;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::percpu::scheduler_ptr;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::percpu::expects_base_installed;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::percpu::expects_base_installed;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use super::x86_64::percpu::expects_base_installed;

/// Host and other targets have no per-CPU register, so there is no per-CPU
/// base to find: `base()` answers 0 and the kernel falls back to its single
/// static block.
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
mod absent {
    use crate::kernel::process::Scheduler;

    pub fn base() -> u64 {
        0
    }

    /// # Safety
    ///
    /// Nothing to install on a target without per-CPU registers; the call is
    /// accepted and ignored so that kernel code needs no `cfg` of its own.
    pub unsafe fn set_base(_base: u64) {}

    pub fn scheduler_ptr() -> *mut Scheduler {
        core::ptr::null_mut()
    }

    pub fn expects_base_installed() -> bool {
        false
    }
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::base;
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::expects_base_installed;
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::scheduler_ptr;
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub use absent::set_base;

/// Install the bootstrap processor's per-CPU block and register its scheduler,
/// returning the logical CPU id this machine calls it.
///
/// The machine decides which CPU that is — 0 where the reset lands on CPU 0,
/// and the hart the boot protocol named on riscv64, which is not always hart
/// 0: calling it 0 on a machine that booted on hart 2 would have it claim and
/// complete interrupts in hart 0's PLIC context.  The machines also differ in
/// how the block is reachable: x86_64 fills a static that `gs` already points
/// at and records its LAPIC id, while aarch64 and riscv64 allocate one and
/// point `TPIDR_EL1` / `tp` at it.
///
/// The scheduler pointer is the kernel's long-lived one, passed raw because
/// it is stored *in* the per-CPU block that the CPU reaches without going
/// through this function.
pub(crate) fn install_bsp(scheduler: *mut crate::kernel::process::Scheduler) -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        // LAPIC IDs fit in a byte on current hardware, and the SMP layer and
        // per-CPU tables store them as u8.
        let lapic_id = crate::arch::x86_64::apic::lapic_id() as u8;
        crate::arch::x86_64::smp::save_bsp_lapic_id(lapic_id);
        // SAFETY: the BSP's per-CPU block is a static, `gs` already points at
        // it, and this runs once during boot.
        unsafe {
            crate::arch::x86_64::percpu::init_bsp_data(
                scheduler,
                lapic_id,
                crate::arch::x86_64::gdt::bsp_tss_ptr() as *mut u8,
            );
        }
        // SAFETY: the scheduler lives as long as the kernel does.
        unsafe {
            crate::kernel::process::scheduler::registry::register(0, scheduler);
        }
        crate::println!("[init  ] percpu BSP cpu_id=0 lapic_id={}", lapic_id);
        0
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        use alloc::boxed::Box;
        let percpu = Box::new(crate::kernel::percpu::PerCpuData::zeroed());
        let percpu_ptr = Box::into_raw(percpu);
        // SAFETY: `percpu_ptr` is the BSP's freshly allocated block, which
        // outlives every access (it is never freed).
        unsafe {
            (*percpu_ptr).cpu_id = 0; // BSP
            (*percpu_ptr).scheduler = scheduler;
        }
        // SAFETY: `percpu_ptr` outlives every access, and `set_base` points
        // this CPU's register at it.
        unsafe {
            crate::arch::percpu::set_base(percpu_ptr as u64);
        }
        // SAFETY: the scheduler lives as long as the kernel does.
        unsafe {
            crate::kernel::process::scheduler::registry::register(0, scheduler);
        }
        crate::println!("[init  ] aarch64: BSP percpu cpu_id=0 TPIDR_EL1 set");
        0
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        use alloc::boxed::Box;
        let cpu_id = crate::arch::riscv64::smp::boot_hart_id().unwrap_or(0) as u32;
        let percpu = Box::new(crate::kernel::percpu::PerCpuData::zeroed());
        let percpu_ptr = Box::into_raw(percpu);
        // SAFETY: `percpu_ptr` is the BSP's freshly allocated block, which
        // outlives every access (it is never freed).
        unsafe {
            (*percpu_ptr).cpu_id = cpu_id;
            (*percpu_ptr).scheduler = scheduler;
        }
        // SAFETY: `percpu_ptr` outlives every access.  `set_base` writes both
        // `tp` and this hart's per-CPU slot, which is what the trap entry
        // reloads `tp` from.
        unsafe {
            crate::arch::percpu::set_base(percpu_ptr as u64);
        }
        // SAFETY: the scheduler lives as long as the kernel does.
        unsafe {
            crate::kernel::process::scheduler::registry::register(cpu_id, scheduler);
        }
        crate::println!("[init  ] riscv64: BSP percpu cpu_id={} tp set", cpu_id);
        cpu_id
    }

    // A host has no per-CPU register to point anywhere: the kernel's single
    // static block serves every "CPU" there is, and it is already registered
    // as CPU 0.
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none"),
    )))]
    {
        let _ = scheduler;
        0
    }
}
