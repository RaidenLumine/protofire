//! src/main.rs
//!
//! The host-side `mkimage` utility, and the crate that links the kernel.
//!
//! The bare-metal side of this binary is the library's: `arch::entry` holds
//! the entry symbols the boot assembly calls, and everything after them.  What
//! is left here is the host half — the `mkimage` command that writes a demo
//! disk image — and the two `extern crate` lines that make a bare-metal build
//! link the kernel's objects in.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

extern crate alloc;
extern crate protofire;

#[cfg(not(target_os = "none"))]
use std::env;
#[cfg(not(target_os = "none"))]
use std::fs;
#[cfg(not(target_os = "none"))]
use std::path::Path;
#[cfg(not(target_os = "none"))]
use std::process;

#[cfg(not(target_os = "none"))]
const KERNEL_NAME: &str = env!("CARGO_PKG_NAME");
#[cfg(not(target_os = "none"))]
const KERNEL_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(not(target_os = "none"))]
const BUILD_PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

#[cfg(not(target_os = "none"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("mkimage") => {
            let output = args
                .next()
                .unwrap_or_else(|| "target/protofire-demo-disk.img".to_string());
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

    let image = protofire::fs::build_demo_disk_image();
    fs::write(path, &image)?;
    println!("wrote {} bytes to {}", image.len(), path.display());
    Ok(())
}

#[cfg(not(target_os = "none"))]
fn print_host_usage_and_exit(code: i32) -> ! {
    eprintln!("usage: cargo run -- mkimage [output]");
    process::exit(code);
}
