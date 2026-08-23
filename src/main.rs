//! src/main.rs
//! Bare-metal kernel entrypoint plus the host-side `mkimage` utility command.

//! Xiucoatl Kernel Main Entry Point
//!
//! This file contains the main entry points for both bare-metal kernel operation
//! and host-side utility commands. For bare-metal targets, it provides the kernel
//! initialization and boot sequence. For host targets, it provides the `mkimage`
//! command for creating demo disk images.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

extern crate alloc;
extern crate protofire;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
core::arch::global_asm!(include_str!("arch/x86_64/boot.asm"));
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
core::arch::global_asm!(include_str!("arch/x86_64/ap_trampoline.asm"));
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
core::arch::global_asm!(include_str!("arch/aarch64/boot.S"));

#[cfg(target_os = "none")]
use core::panic::PanicInfo;
#[cfg(target_os = "none")]
use protofire::kernel::Kernel;
#[cfg(target_os = "none")]
use protofire::println;
#[cfg(target_os = "none")]
use protofire::{arch, util};
#[cfg(not(target_os = "none"))]
use std::{env, fs, path::Path, process};

const KERNEL_NAME: &str = env!("CARGO_PKG_NAME");
const KERNEL_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

#[cfg(target_os = "none")]
#[cfg(target_arch = "aarch64")]
const TARGET_ARCH: &str = "aarch64";

#[cfg(target_os = "none")]
#[cfg(target_arch = "x86_64")]
const TARGET_ARCH: &str = "x86_64";

#[cfg(target_os = "none")]
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const TARGET_ARCH: &str = "unknown";

#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
enum BootStage {
    Bootloader,
    Console,
    KernelObject,
    KernelInit,
    Scheduler,
}

#[cfg(target_os = "none")]
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

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[no_mangle]
pub extern "C" fn kernel_entry(multiboot_magic: u32, multiboot_info: u32) -> ! {
    let boot_info = arch::boot::from_x86_64_multiboot2(multiboot_magic, multiboot_info);
    boot_kernel(boot_info)
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[no_mangle]
pub extern "C" fn kernel_entry_aarch64(device_tree_blob: usize) -> ! {
    let boot_info = arch::boot::from_aarch64_qemu_direct(device_tree_blob);
    boot_kernel(boot_info)
}

#[cfg(target_os = "none")]
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

#[cfg(target_os = "none")]
fn print_banner() {
    println!(
        "{} v{} [{} | {}]",
        KERNEL_NAME, KERNEL_VERSION, TARGET_ARCH, BUILD_PROFILE
    );
    println!("Xiucoatl kernel prototype starting");
}

#[cfg(target_os = "none")]
fn announce(stage: BootStage, message: &str) {
    println!("[boot:{}] {}", stage.label(), message);
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    util::logger::panic(info)
}

#[cfg(not(target_os = "none"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("mkimage") => {
            let output = args
                .next()
                .unwrap_or_else(|| "target/xiucoatl-demo-disk.img".to_string());
            if args.next().is_some() {
                print_host_usage_and_exit(2);
            }

            write_demo_disk_image(Path::new(&output))?;
        }
        Some(_) => {
            print_host_usage_and_exit(2);
        }
        None => {
            println!(
                "{} v{} host stub [{}]",
                KERNEL_NAME, KERNEL_VERSION, BUILD_PROFILE
            );
            println!("Build the bare-metal kernel with `make build`.");
            println!("Host commands:");
            println!("  mkimage [path]  Build the MBR-partitioned ATA demo disk image.");
        }
    }

    Ok(())
}

#[cfg(not(target_os = "none"))]
fn write_demo_disk_image(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let image = protofire::kernel::fs::build_demo_disk_image();
    fs::write(path, &image)?;
    println!("wrote {} bytes to {}", image.len(), path.display());
    Ok(())
}

#[cfg(not(target_os = "none"))]
fn print_host_usage_and_exit(code: i32) -> ! {
    eprintln!("usage: cargo run -- mkimage [output]");
    process::exit(code);
}
