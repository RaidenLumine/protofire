//! src/arch/mod.rs
//!
//! Architecture entry point that selects per-target code and exposes shared
//! shims for boot, traps, interrupts, serial output, and context switching.

use core::fmt;

use crate::kernel::process::Context;

pub mod boot;
pub mod exception_recoverability;
pub mod interrupt_controller;
pub mod mmu;
pub mod syscall_trap;
pub mod timer;
pub mod trap;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

// Re-export the per-architecture interrupt load-balancing dispatcher at the
// top level so `kernel::irq_balance` can call `crate::arch::irq_balance::*`
// uniformly across targets (each arch module is host-safe).
#[cfg(target_arch = "aarch64")]
pub use aarch64::irq_balance;
#[cfg(target_arch = "riscv64")]
pub use riscv64::irq_balance;
#[cfg(target_arch = "x86_64")]
pub use x86_64::irq_balance;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
#[path = "aarch64/fdt.rs"]
pub mod fdt;

/// Architecture abstraction trait.
///
/// Every bare-metal target provides an implementation of this trait to
/// expose the fundamental operations that the kernel's platform-independent
/// layer needs during early boot and runtime.
pub trait Arch {
    /// Perform very-early hardware initialisation.
    ///
    /// Called once on the bootstrap CPU before any kernel data structures
    /// are set up.  Typical duties include:
    /// - disabling interrupts
    /// - configuring the MMU (identity-map the kernel)
    /// - initialising the console/serial port for early panic output
    /// - setting up the exception vector table
    fn init_early();

    /// Halt the current CPU indefinitely.
    ///
    /// On real hardware this executes a platform-specific wait-for-interrupt
    /// or halt instruction.  No guarantee is made about wake-up; the CPU
    /// may stay halted until a reset or interrupt.
    fn halt();

    /// Reboot the entire system.
    ///
    /// This function never returns.  On real hardware it triggers a reset
    /// via the platform's watchdog or reset controller.
    fn reboot() -> !;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchitectureCapabilityInventory {
    pub architecture: &'static str,
    pub bare_metal: bool,
    pub supports_context_switch: bool,
    pub supports_user_mode_runtime: bool,
    pub supports_user_exception_delivery: bool,
    pub supports_lower_el_user_exception_delivery: bool,
    pub supports_kernel_page_table_activation: bool,
    pub supports_kernel_page_fault_recovery_hook: bool,
    pub supports_pan: bool,
    pub supports_pci_config_access: bool,
    pub supports_smp_bootstrap: bool,
}

impl ArchitectureCapabilityInventory {
    /// Return a capability inventory describing the target architecture.
    ///
    /// The returned struct has all fields statically determined at compile
    /// time via `cfg!()` — no runtime probe is performed.
    pub const fn current() -> Self {
        Self {
            architecture: crate::arch::boot::current_architecture(),
            bare_metal: cfg!(target_os = "none"),
            supports_context_switch: cfg!(any(
                all(target_arch = "x86_64", target_os = "none"),
                all(target_arch = "aarch64", target_os = "none"),
                all(target_arch = "riscv64", target_os = "none")
            )),
            supports_user_mode_runtime: cfg!(any(
                all(target_arch = "x86_64", target_os = "none"),
                all(target_arch = "aarch64", target_os = "none"),
                all(target_arch = "riscv64", target_os = "none")
            )),
            supports_user_exception_delivery: cfg!(any(
                all(target_arch = "x86_64", target_os = "none"),
                all(target_arch = "aarch64", target_os = "none"),
                all(target_arch = "riscv64", target_os = "none")
            )),
            supports_lower_el_user_exception_delivery: cfg!(any(
                all(target_arch = "aarch64", target_os = "none"),
                all(target_arch = "riscv64", target_os = "none")
            )),
            supports_kernel_page_table_activation: cfg!(any(
                all(target_arch = "x86_64", target_os = "none"),
                all(target_arch = "aarch64", target_os = "none"),
                all(target_arch = "riscv64", target_os = "none")
            )),
            supports_kernel_page_fault_recovery_hook: cfg!(any(
                all(target_arch = "x86_64", target_os = "none"),
                all(target_arch = "aarch64", target_os = "none"),
                all(target_arch = "riscv64", target_os = "none")
            )),
            supports_smp_bootstrap: cfg!(any(
                all(target_arch = "x86_64", target_os = "none"),
                all(target_arch = "aarch64", target_os = "none"),
                all(target_arch = "riscv64", target_os = "none"),
            )),
            supports_pan: cfg!(any(
                all(target_arch = "aarch64", target_os = "none"),
                all(target_arch = "riscv64", target_os = "none")
            )),
            supports_pci_config_access: cfg!(any(
                all(target_arch = "x86_64", target_os = "none"),
                all(target_arch = "aarch64", target_os = "none")
            )),
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub type CurrentArch = aarch64::AArch64;

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub type CurrentArch = riscv64::RiscV64;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub type CurrentArch = x86_64::X86_64;

#[cfg(all(
    target_os = "none",
    any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "riscv64"
    )
))]
pub fn init_early() {
    CurrentArch::init_early();
}

#[cfg(not(all(
    target_os = "none",
    any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "riscv64"
    )
)))]
pub fn init_early() {}

#[cfg(all(
    target_os = "none",
    any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "riscv64"
    )
))]
pub fn halt() {
    CurrentArch::halt();
}

#[cfg(not(all(
    target_os = "none",
    any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "riscv64"
    )
)))]
pub fn halt() {
    core::hint::spin_loop();
}

#[cfg(all(
    target_os = "none",
    any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "riscv64"
    )
))]
pub fn reboot() -> ! {
    CurrentArch::reboot();
}

#[cfg(not(all(
    target_os = "none",
    any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "riscv64"
    )
)))]
pub fn reboot() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Write formatted output to the serial port.
///
/// Delegates to the per-architecture serial implementation.  Returns
/// [`Ok(())`] on the host side even when no serial hardware is present.
pub fn write_fmt(args: fmt::Arguments<'_>) -> fmt::Result {
    serial::write_fmt(args)
}

// ── CPU frequency / power management ──────────────────────────────────────
//
// The power subsystem (`kernel::power`) talks to the platform exclusively
// through these four dispatchers.  x86_64 uses the MSR P-state driver; the
// ARM/RISC-V drivers discover the frequency range from device-tree OPP
// tables and track the requested target in software.  Targets without a
// driver report 0 / `Unsupported` / `None` so the subsystem stays inert.
// Host builds are safe: the x86_64 driver never probes MSRs outside bare
// metal.

/// Current core frequency in KHz (0 when no driver is present).
pub fn arch_get_freq() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::cpufreq::arch_get_freq()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::cpufreq::arch_get_freq()
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::cpufreq::arch_get_freq()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        0
    }
}

/// Request a core frequency in KHz.
pub fn arch_set_freq(freq_khz: u32) -> crate::Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::cpufreq::arch_set_freq(freq_khz)
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::cpufreq::arch_set_freq(freq_khz)
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::cpufreq::arch_set_freq(freq_khz)
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        let _ = freq_khz;
        Err(crate::Error::Unsupported)
    }
}

/// (min, max) achievable frequency in KHz, if the platform can scale.
pub fn arch_get_freq_range() -> Option<(u32, u32)> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::cpufreq::arch_get_freq_range()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::cpufreq::arch_get_freq_range()
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::cpufreq::arch_get_freq_range()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        None
    }
}

/// Package temperature in millidegrees Celsius, if readable.
pub fn arch_get_temperature_mc() -> Option<u32> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::cpufreq::arch_get_temperature_mc()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::cpufreq::arch_get_temperature_mc()
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::cpufreq::arch_get_temperature_mc()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        None
    }
}

/// Returns `true` when the current target can perform a hardware context
/// switch (saving and restoring CPU registers).
///
/// On bare-metal x86_64, AArch64, and RISC-V this returns `true`; on
/// host-side builds it returns `false` and scheduling is simulated.
pub fn supports_context_switch() -> bool {
    ArchitectureCapabilityInventory::current().supports_context_switch
}

/// Number of online CPUs.
///
/// AArch64 and RISC-V derive the count from the FDT CPU nodes; x86_64
/// consults the SMP bookkeeping after AP bring-up (returning 1 on the
/// bootstrap CPU or in host builds).
pub fn cpu_count() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        crate::kernel::smp::online_cpu_count()
    }
    #[cfg(any(
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    ))]
    {
        crate::arch::fdt::cpu_count()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    )))]
    {
        1
    }
}

/// # Safety
///
/// The caller must provide valid pointers to the current and next saved
/// contexts. On bare-metal x86_64 this will swap register state and transfer
/// execution to `next`.
pub unsafe fn switch_context(current: *mut Context, next: *const Context) {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        unsafe {
            aarch64::context::switch(current, next);
        }
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        unsafe {
            riscv64::context::switch(current, next);
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        unsafe {
            x86_64::context::switch(current, next);
        }
    }

    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    )))]
    {
        let _ = current;
        let _ = next;
    }
}

pub mod instructions {
    /// Halt the CPU until the next interrupt.
    ///
    /// A convenience wrapper around [`super::halt()`].
    pub fn hlt() {
        super::halt();
    }

    /// Halt the CPU with interrupts enabled (idle loop).
    ///
    /// On x86_64 this executes `sti; hlt` so that a pending interrupt
    /// fires before the halt takes effect.  On AArch64 it masks
    /// DAIF exceptions around a `wfi` instruction.  On RISC-V it
    /// issues a plain `wfi`.
    pub fn idle() {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        unsafe {
            core::arch::asm!(
                "msr DAIFClr, #0xf",
                "wfi",
                "msr DAIFSet, #0xf",
                options(nomem, nostack)
            );
        }

        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        unsafe {
            // Enable supervisor interrupts around `wfi` (mirroring x86_64's
            // `sti; hlt; cli`) so a pending timer IRQ is actually taken while
            // the idle loop sleeps.  With SIE clear, `wfi` wakes on the pending
            // timer but never services it, leaving the CPU spinning forever
            // with the tick timer stalled.
            //
            // SIE is bit 1 of sstatus on QEMU (raw alias of mstatus), so a
            // `csrs sstatus, 1` here would be a silent no-op and the idle
            // loop would never take the timer interrupt.
            core::arch::asm!(
                "csrs sstatus, {sie}",
                "wfi",
                "csrc sstatus, {sie}",
                sie = in(reg) 1u64 << 1,
                options(nomem, nostack)
            );
        }

        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        unsafe {
            core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack));
        }

        #[cfg(not(any(
            all(target_arch = "aarch64", target_os = "none"),
            all(target_arch = "x86_64", target_os = "none"),
            all(target_arch = "riscv64", target_os = "none")
        )))]
        super::halt();
    }
}

pub mod interrupts {
    /// Returns `true` if local CPU interrupts are currently enabled.
    pub fn are_enabled() -> bool {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            super::aarch64::interrupts::are_enabled()
        }

        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        {
            super::riscv64::interrupts::are_enabled()
        }

        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            super::x86_64::interrupts::are_enabled()
        }

        #[cfg(not(any(
            all(target_arch = "aarch64", target_os = "none"),
            all(target_arch = "x86_64", target_os = "none"),
            all(target_arch = "riscv64", target_os = "none")
        )))]
        {
            false
        }
    }

    /// Save the interrupt enable state and disable local interrupts.
    ///
    /// Returns `true` if interrupts were enabled before the call, `false`
    /// if they were already disabled.  The returned value should be passed
    /// to [`restore()`] to undo this operation.
    pub fn save_and_disable() -> bool {
        let enabled = are_enabled();
        if enabled {
            disable();
        }
        enabled
    }

    /// Restore the interrupt enable state to the given value.
    ///
    /// # Parameters
    ///
    /// * `enabled` — if `true`, re-enables interrupts; otherwise leaves them
    ///   disabled.  Typically the value returned by a prior call to
    ///   [`save_and_disable()`].
    pub fn restore(enabled: bool) {
        if enabled {
            enable();
        }
    }

    /// Enable local interrupts.
    pub fn enable() {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        super::aarch64::interrupts::enable();

        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        super::riscv64::interrupts::enable();

        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        super::x86_64::interrupts::enable();
    }

    /// Disable local interrupts.
    pub fn disable() {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        super::aarch64::interrupts::disable();

        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        super::riscv64::interrupts::disable();

        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        super::x86_64::interrupts::disable();
    }

    /// Enable interrupts and halt the CPU.  On x86_64 this uses the
    /// `sti; hlt` instruction pair so a pending interrupt fires before
    /// the halt takes effect.
    pub fn enable_and_halt() {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        super::x86_64::interrupts::enable_and_halt();

        #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
        crate::arch::instructions::idle();
    }
}

pub mod serial {
    use core::fmt;

    /// Initialise the platform serial port.
    ///
    /// Must be called once after the MMU and page tables are live.  On
    /// real hardware this configures baud rate, line parameters, and
    /// pin muxing for the UART.
    pub fn init() {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        super::aarch64::serial::init();

        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        super::riscv64::serial::init();

        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        super::x86_64::serial::init();
    }

    /// Write a string to the serial port.
    ///
    /// # Parameters
    ///
    /// * `message` — the string to transmit.  No trailing newline is added.
    pub fn write_str(message: &str) {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        super::aarch64::serial::write_str(message);

        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        super::riscv64::serial::write_str(message);

        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        super::x86_64::serial::write_str(message);

        #[cfg(not(any(
            all(target_arch = "aarch64", target_os = "none"),
            all(target_arch = "x86_64", target_os = "none"),
            all(target_arch = "riscv64", target_os = "none")
        )))]
        let _ = message;
    }

    /// Write a single byte to the serial port.
    ///
    /// # Parameters
    ///
    /// * `byte` — the byte to transmit.
    pub fn write_byte(byte: u8) {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        super::aarch64::serial::write_byte(byte);

        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        super::riscv64::serial::write_byte(byte);

        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        super::x86_64::serial::write_byte(byte);

        #[cfg(not(any(
            all(target_arch = "aarch64", target_os = "none"),
            all(target_arch = "x86_64", target_os = "none"),
            all(target_arch = "riscv64", target_os = "none")
        )))]
        let _ = byte;
    }

    /// Try to read a single byte from the serial port, if one is available.
    ///
    /// Returns `Some(byte)` if a byte was received, or `None` if the
    /// receive buffer is empty.  Never blocks.
    pub fn try_read_byte() -> Option<u8> {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            super::aarch64::serial::try_read_byte()
        }

        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        {
            super::riscv64::serial::try_read_byte()
        }

        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            super::x86_64::serial::try_read_byte()
        }

        #[cfg(not(any(
            all(target_arch = "aarch64", target_os = "none"),
            all(target_arch = "x86_64", target_os = "none"),
            all(target_arch = "riscv64", target_os = "none")
        )))]
        {
            None
        }
    }

    /// Write a formatted argument structure to the serial port.
    ///
    /// Used by the `print!` / `println!` macros to delegate formatted
    /// output to the serial backend.
    pub fn write_fmt(args: fmt::Arguments<'_>) -> fmt::Result {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            super::aarch64::serial::write_fmt(args)
        }

        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        {
            super::riscv64::serial::write_fmt(args)
        }

        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            super::x86_64::serial::write_fmt(args)
        }

        #[cfg(not(any(
            all(target_arch = "aarch64", target_os = "none"),
            all(target_arch = "x86_64", target_os = "none"),
            all(target_arch = "riscv64", target_os = "none")
        )))]
        {
            let _ = args;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ArchitectureCapabilityInventory;

    #[test]
    fn architecture_capability_inventory_matches_host_runtime_expectations() {
        let inventory = ArchitectureCapabilityInventory::current();

        #[cfg(not(target_os = "none"))]
        {
            assert_eq!(inventory.architecture, "host");
            assert!(!inventory.bare_metal);
            assert!(!inventory.supports_context_switch);
            assert!(!inventory.supports_user_mode_runtime);
            assert!(!inventory.supports_user_exception_delivery);
            assert!(!inventory.supports_lower_el_user_exception_delivery);
            assert!(!inventory.supports_kernel_page_table_activation);
            assert!(!inventory.supports_kernel_page_fault_recovery_hook);
            assert!(!inventory.supports_smp_bootstrap);
        }
    }

    #[test]
    fn architecture_capability_inventory_reports_smp_bootstrap_availability() {
        let inventory = ArchitectureCapabilityInventory::current();
        // SMP bootstrap is enabled on bare-metal x86_64, AArch64, and RISC-V.
        if cfg!(any(
            all(target_arch = "x86_64", target_os = "none"),
            all(target_arch = "aarch64", target_os = "none"),
            all(target_arch = "riscv64", target_os = "none"),
        )) {
            assert!(inventory.supports_smp_bootstrap);
        } else {
            assert!(!inventory.supports_smp_bootstrap);
        }
    }
}
