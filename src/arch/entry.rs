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
///
/// With the `kaslr` feature on, the first thing this does is hand the boot to
/// the relocator, which copies the image and either jumps into the copy (and
/// never returns here) or returns because the machine's memory left no room —
/// in which case the boot continues at the link address exactly as it does
/// without the feature.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn kernel_entry(multiboot_magic: u32, multiboot_info: u32) -> ! {
    #[cfg(feature = "kaslr")]
    crate::arch::x86_64::kaslr::relocate_or_continue(multiboot_magic, multiboot_info);
    x86_64_boot(multiboot_magic, multiboot_info)
}

#[cfg(target_arch = "x86_64")]
fn x86_64_boot(multiboot_magic: u32, multiboot_info: u32) -> ! {
    let boot_info = arch::boot::from_x86_64_multiboot2(multiboot_magic, multiboot_info);
    boot_kernel(boot_info)
}

/// Where a relocated boot continues: the copy's own entry.
///
/// The relocator jumps here **in the copy**, with the copy's base and the
/// delta it patched sites by in the first two registers.  Everything below
/// this point runs from the copy, so symbol reads are the copy's own.  Nothing
/// of the loader's state has to be re-pointed: the boot stub's GDT descriptor
/// is only ever read in 32-bit mode (before long mode), and the first thing
/// the copy's own `init_early` does is load the kernel's GDT
/// (`gdt::init`), so a GDTR still naming the abandoned image is never used —
/// measured, by a relocated boot that reached its shell with this call absent.
#[cfg(all(target_arch = "x86_64", feature = "kaslr"))]
#[no_mangle]
pub extern "C" fn kernel_entry_relocated(
    base: usize,
    delta: usize,
    multiboot_magic: u32,
    multiboot_info: u32,
) -> ! {
    crate::arch::x86_64::kaslr::record_relocation(base, delta);
    x86_64_boot(multiboot_magic, multiboot_info)
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
    // Where this boot put the kernel, on a machine that relocates: the
    // decision is made before the console exists, so this is where it is
    // said.  The line reports the delta as well, which is what lets the
    // gate check that the ranges below really moved (see
    // `make check-x8664-kaslr-runtime`).
    #[cfg(all(target_arch = "x86_64", feature = "kaslr"))]
    crate::arch::x86_64::kaslr::announce();
    // The machine's memory is asked before the kernel is built, so the memory
    // manager sizes its pool from the answer: x86_64's map is a pointer walk
    // over the loader's block and a device tree's `/memory` window is a pointer
    // walk over the blob, and neither walk allocates ([RFC
    // 0019](../../docs/rfcs/0019-what-a-frame-is.md)).
    crate::memory::report_machine_memory();
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

/// How many bytes the banner's identity field occupies, always.
///
/// This is a layout fact rather than a formatting preference: the identity is
/// embedded in the image, and the KASLR relocation table describes exactly
/// one layout.  A value whose *length* moved with build state — `git describe
/// --dirty` adds six bytes whenever the tree has uncommitted changes, which
/// is the state a table is generated in — made a clean checkout of the same
/// sources build a different layout than the table described; measured,
/// `make check-x8664-kaslr-runtime` reported `the relocation table is stale`
/// on a clean tree for that reason.  Fixing the width here, in the source,
/// is what makes the value's content free (a hash, `-dirty`, a tag) and the
/// layout fixed.  The padding cannot come from `build.rs`: Cargo trims
/// trailing spaces from a build script's `rustc-env` value (also measured,
/// when the padding was done there).
const BUILD_ID_WIDTH: usize = 16;

/// The build identity, truncated or space-padded to [`BUILD_ID_WIDTH`].
///
/// A `const fn` rather than a literal so the width is applied in one place:
/// `build.rs` emits printable ASCII of any length, and this is what turns it
/// into bytes of exactly one length.  The array type is the guarantee — a
/// width that stopped being 16 would fail to compile at the assignment below.
const fn fixed_width_id(raw: &str) -> [u8; BUILD_ID_WIDTH] {
    let mut id = [b' '; BUILD_ID_WIDTH];
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() && index < BUILD_ID_WIDTH {
        id[index] = bytes[index];
        index += 1;
    }
    id
}

const BUILD_ID: [u8; BUILD_ID_WIDTH] = fixed_width_id(env!("PROTOFIRE_BUILD_ID"));

fn print_banner() {
    // The field is ASCII by `build.rs`'s construction; the fallback exists
    // because `from_utf8` is the checked conversion and a panic is not worth
    // it for a banner.
    let build_id = core::str::from_utf8(&BUILD_ID).unwrap_or("unknown");
    println!(
        "{} v{} [{} | {}] {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        arch::boot::current_architecture(),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        // The padding is layout, not text: trimming it here keeps a log line
        // from ending in spaces a reader cannot see.
        build_id.trim_end(),
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
