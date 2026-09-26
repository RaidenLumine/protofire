//! src/arch/entry.rs
//!
//! What the bootloader calls, and the boot sequence that follows it.
//!
//! Each machine's firmware arrives with its own handshake: x86_64 is handed
//! multiboot2 values in registers, aarch64 and riscv64 a device-tree blob in a
//! register named by their own boot protocol.  The *entry symbol* is the
//! machine's — its name and its arguments come from the assembly beside it —
//! and so is the name it reports.
//!
//! Everything after the handshake is the same on all three: announce the
//! stages, construct the kernel, initialize it, and hand it the CPU.  That
//! sequence lives here, in one place, because the order is what makes it
//! correct.

use core::panic::PanicInfo;

use crate::arch;
use crate::kernel::Kernel;
use crate::println;
use crate::util;

/// x86_64 boots from the multiboot2 handshake `boot.asm` establishes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn kernel_entry(multiboot_magic: u32, multiboot_info: u32) -> ! {
    let boot_info = arch::boot::from_x86_64_multiboot2(multiboot_magic, multiboot_info);
    boot_kernel(boot_info)
}

/// aarch64 boots from the device-tree blob its boot protocol passes in `x0`.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn kernel_entry_aarch64(device_tree_blob: usize) -> ! {
    let boot_info = arch::boot::from_aarch64_qemu_direct(device_tree_blob);
    boot_kernel(boot_info)
}

/// RISC-V boots from the device-tree blob QEMU `-machine virt` passes in `a0`;
/// `boot.S`'s `_start` calls this with it.
#[cfg(target_arch = "riscv64")]
#[no_mangle]
pub extern "C" fn kernel_entry_riscv64(device_tree_blob: usize) -> ! {
    let boot_info = arch::boot::from_riscv64_qemu_direct(device_tree_blob);
    boot_kernel(boot_info)
}

/// The stages the kernel announces as it comes up.
///
/// They are reported rather than inferred from timing: when a boot stops, the
/// last stage that spoke says where it stopped.
#[derive(Clone, Copy)]
enum BootStage {
    Bootloader,
    Console,
    KernelObject,
    KernelInit,
    Scheduler,
}

impl BootStage {
    const fn label(self) -> &'static str {
        match self {
            Self::Bootloader => "loader",
            Self::Console => "console",
            Self::KernelObject => "kernel",
            Self::KernelInit => "init",
            Self::Scheduler => "scheduler",
        }
    }
}

/// Come up: console first, then the kernel object, then its subsystems, then
/// hand the CPU over.
fn boot_kernel(boot_info: arch::boot::BootInfo) -> ! {
    util::debug::init();
    print_banner();
    announce(BootStage::Bootloader, boot_info.protocol().as_str());
    println!(
        "[boot:loader] arch={} protocol={} magic={:#010x}, info={:#010x}",
        boot_info.architecture(),
        boot_info.protocol().as_str(),
        boot_info.loader_magic(),
        boot_info.handoff_address()
    );
    announce(BootStage::Console, "early serial console is ready");

    announce(BootStage::KernelObject, "constructing kernel state");
    let mut kernel = Kernel::new();

    announce(BootStage::KernelInit, "initializing subsystems");
    kernel.init();

    announce(BootStage::Scheduler, "handing control to the main loop");
    kernel.run();
}

fn print_banner() {
    println!(
        "{} v{} [{} | {}]",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        arch::boot::current_architecture(),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!("Protofire kernel prototype starting");
}

fn announce(stage: BootStage, message: &str) {
    println!("[boot:{}] {}", stage.label(), message);
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    util::logger::panic(info)
}
