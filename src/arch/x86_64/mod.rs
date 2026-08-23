//! src/arch/x86_64/mod.rs
//! x86_64 architecture bring-up glue and backend exports.

#[cfg(target_os = "none")]
pub mod context;
pub mod control_regs;
pub mod cpuid;
pub mod gdt;
pub mod idt;
pub mod interrupt_controller;
pub mod interrupts;
pub mod paging;
pub mod pci;
pub mod port;
pub mod serial;
pub mod timer;
pub mod user_access;

// Priority 3: new driver modules.
pub mod apic;
pub mod cpufreq;
pub mod ioapic;
pub mod irq_balance;
pub mod msi;
pub mod rand;
pub mod rtc;

// KASLR boot-time self-relocation.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod kaslr;

use core::arch::asm;

use crate::arch::Arch;

/// Write a byte to the Bochs/QEMU debug console (port 0xe9).
/// No locking — safe to use from any CPU at any time for diagnostics.
/// Requires QEMU's `-debugcon` flag to capture output.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn debugcon_write(byte: u8) {
    unsafe {
        asm!("out dx, al", in("dx") 0xe9u16, in("al") byte, options(nomem, nostack));
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn debugcon_write(_byte: u8) {}

pub struct X86_64;

impl Arch for X86_64 {
    fn init_early() {
        gdt::init();
        // Set up the IDT before anything that may fault (e.g. SMEP/SMAP
        // enable on CPUs that don't support those features, or early
        // page-table writes).  A triple-fault here is a silent reset;
        // with the IDT loaded we at least get a legible panic.
        interrupts::disable();
        idt::init();
        paging::init();
        serial::init();
    }

    fn halt() {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }

    fn reboot() -> ! {
        let mut command = port::Port::<u8>::new(0x64);

        unsafe {
            command.write(0xFE);
        }

        loop {
            Self::halt();
        }
    }
}
