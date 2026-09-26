//! src/arch/virtio_mmio.rs
//!
//! Where this machine's VirtIO MMIO transports are.
//!
//! A machine either describes them — the `virtio,mmio` nodes in its device
//! tree, which is how the aarch64 and riscv64 QEMU `virt` machines do it — or
//! it wires up a fixed window with a stride and a slot count of its own.  The
//! drivers ask for the addresses and get a list; which of the two answered is
//! not their business, and the numbers live here so that a driver which forgot
//! to ask cannot carry a second copy of them.
//!
//! The windows are the machines' own numbers.  QEMU `virt` creates every
//! transport up front and binds each `-device virtio-*-device` from the top of
//! the window down, so a window that covers only the first few slots cannot
//! see a device bound near the end — the aarch64 window is therefore the whole
//! 32-transport window.  On riscv64 the transports are packed one page apart
//! from 0x1000_1000, and a scan past the eighth reads unmapped MMIO, so its
//! window is exactly eight.

use alloc::vec::Vec;

/// The addresses to scan for a VirtIO device, in the order to try them.
///
/// The device tree's own list when it described one, and the fixed window
/// otherwise.
pub(crate) fn slot_addresses() -> Vec<usize> {
    fdt_slots().unwrap_or_else(window_slots)
}

/// The slots the device tree described, when it described any.
///
/// `None` when there is no device tree, or it has no `virtio,mmio` node — the
/// caller falls back to [`window_slots`].
pub(crate) fn fdt_slots() -> Option<Vec<usize>> {
    let info = crate::arch::fdt::platform_info();
    let base = info.virtio_mmio_base?;
    let count = info.virtio_mmio_count?;
    let stride = info.virtio_mmio_stride?;
    Some((0..count).map(|slot| base + slot * stride).collect())
}

/// The fixed window this machine wires up, in the order to try its slots.
pub(crate) fn window_slots() -> Vec<usize> {
    (0..MAX_SLOTS)
        .map(|slot| WINDOW_BASE + slot * WINDOW_STRIDE)
        .collect()
}

/// How many slots a scan of the fixed window covers.
pub(crate) const MAX_SLOTS: usize = MAX_SLOTS_PER_MACHINE;

#[cfg(target_arch = "aarch64")]
const WINDOW_BASE: usize = 0x0A00_0000;
#[cfg(target_arch = "aarch64")]
const WINDOW_STRIDE: usize = 0x200;
#[cfg(target_arch = "aarch64")]
const MAX_SLOTS_PER_MACHINE: usize = 32; // QEMU aarch64 virt: NUM_VIRTIO_TRANSPORTS

#[cfg(target_arch = "riscv64")]
const WINDOW_BASE: usize = 0x1000_1000;
#[cfg(target_arch = "riscv64")]
const WINDOW_STRIDE: usize = 0x1000;
#[cfg(target_arch = "riscv64")]
const MAX_SLOTS_PER_MACHINE: usize = 8; // QEMU riscv64 virt: NUM_VIRTIO_TRANSPORTS

#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
const WINDOW_BASE: usize = 0x0A00_0000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
const WINDOW_STRIDE: usize = 0x200;
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
const MAX_SLOTS_PER_MACHINE: usize = 8;
