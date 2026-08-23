//! src/arch/x86_64/gdt.rs
//! x86_64 GDT descriptors, selectors, and install helpers.

use crate::util::sync_unsafe_cell::SyncUnsafeCell;
use core::arch::asm;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

const KERNEL_CODE_SELECTOR: u16 = 0x08;
const KERNEL_DATA_SELECTOR: u16 = 0x10;
const USER_DATA_SELECTOR: u16 = 0x18;
const USER_CODE_SELECTOR: u16 = 0x20;
const TSS_SELECTOR: u16 = 0x28;

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

#[repr(C, packed)]
pub struct TaskStateSegment {
    reserved0: u32,
    privilege_stack_table: [u64; 3],
    reserved1: u64,
    interrupt_stack_table: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_map_base: u16,
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            privilege_stack_table: [0; 3],
            reserved1: 0,
            interrupt_stack_table: [0; 7],
            reserved2: 0,
            reserved3: 0,
            io_map_base: size_of::<TaskStateSegment>() as u16,
        }
    }
}

impl Default for TaskStateSegment {
    fn default() -> Self {
        Self::new()
    }
}

static GDT: SyncUnsafeCell<[u64; 7]> = SyncUnsafeCell::new([
    0x0000_0000_0000_0000,
    0x00AF_9A00_0000_FFFF,
    0x00AF_9200_0000_FFFF,
    0x00AF_F200_0000_FFFF,
    0x00AF_FA00_0000_FFFF,
    0,
    0,
]);
static TSS: SyncUnsafeCell<TaskStateSegment> = SyncUnsafeCell::new(TaskStateSegment::new());

pub fn init() {
    if INITIALIZED.swap(true, Ordering::Acquire) {
        return;
    }

    let tss_base = TSS.get() as u64;
    let tss_limit = (size_of::<TaskStateSegment>() - 1) as u64;
    let tss_low = (tss_limit & 0xFFFF)
        | ((tss_base & 0x00FF_FFFF) << 16)
        | ((0x89_u64) << 40)
        | (((tss_limit >> 16) & 0xF) << 48)
        | (((tss_base >> 24) & 0xFF) << 56);
    let tss_high = tss_base >> 32;

    unsafe {
        (*GDT.get())[5] = tss_low;
        (*GDT.get())[6] = tss_high;
    }

    let gdtr = DescriptorTablePointer {
        limit: (size_of::<[u64; 7]>() - 1) as u16,
        base: GDT.get() as u64,
    };

    unsafe {
        asm!("lgdt [{}]", in(reg) &gdtr, options(readonly, nostack, preserves_flags));
        asm!(
            "mov ax, {selector}",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            selector = const KERNEL_DATA_SELECTOR,
            options(nostack, preserves_flags)
        );
        asm!(
            "ltr ax",
            in("ax") TSS_SELECTOR,
            options(nostack, preserves_flags)
        );
    }

    // Wire up the GS segment base to the BSP's PerCpuData so that
    // per-CPU accessors work from this point onward.
    // SAFETY: called once during early boot, before any other CPU exists.
    #[cfg(target_os = "none")]
    unsafe {
        crate::kernel::percpu::early_init_gs_base();
        // Also set IA32_KERNEL_GS_BASE so that swapgs works correctly
        // when entering/exiting user mode via interrupts.
        crate::kernel::percpu::early_init_kernel_gs_base();
    }
}

pub const fn kernel_code_selector() -> u16 {
    KERNEL_CODE_SELECTOR
}

pub const fn kernel_data_selector() -> u16 {
    KERNEL_DATA_SELECTOR
}

pub const fn user_code_selector() -> u16 {
    USER_CODE_SELECTOR | 0x3
}

pub const fn user_data_selector() -> u16 {
    USER_DATA_SELECTOR | 0x3
}

/// Initialise the GDT on an AP (already in 64-bit long mode).
///
/// `tss` must point to a [`TaskStateSegment`] that is private to this CPU.
/// The BSP must have called [`init`] first so that the static GDT page is
/// mapped writable.
///
/// The TSS descriptor is re-written before `lgdt` to ensure the GDT page
/// has a fresh writable TLB entry.  Without this explicit write the
/// subsequent `ltr` instruction — which sets the busy bit in the TSS
/// descriptor — may fault on the AP because the runtime page tables map
/// BSS pages with the NX bit set, and on some microarchitectures / QEMU
/// the first write to a page that was only read via segment-descriptor
/// loads trips a spurious TLB miss that escalates to #GP.
pub fn init_ap(tss: *mut TaskStateSegment) {
    let tss_base = tss as u64;
    let tss_limit = (size_of::<TaskStateSegment>() - 1) as u64;
    let tss_low = (tss_limit & 0xFFFF)
        | ((tss_base & 0x00FF_FFFF) << 16)
        | ((0x89_u64) << 40)
        | (((tss_limit >> 16) & 0xF) << 48)
        | (((tss_base >> 24) & 0xFF) << 56);
    let tss_high = tss_base >> 32;

    unsafe {
        (*GDT.get())[5] = tss_low;
        (*GDT.get())[6] = tss_high;
    }

    let gdtr = DescriptorTablePointer {
        limit: (size_of::<[u64; 7]>() - 1) as u16,
        base: GDT.get() as u64,
    };

    unsafe {
        asm!("lgdt [{}]", in(reg) &gdtr, options(readonly, nostack, preserves_flags));
        asm!(
            "mov ax, {selector}",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            selector = const KERNEL_DATA_SELECTOR,
            options(nostack, preserves_flags)
        );
        asm!(
            "ltr ax",
            in("ax") TSS_SELECTOR,
            options(nostack, preserves_flags)
        );
    }
}

/// Return a raw pointer to the BSP's TSS (used during early boot before
/// per-CPU data is available, and as the default for single-CPU operation).
pub fn bsp_tss_ptr() -> *mut TaskStateSegment {
    TSS.get()
}

pub fn set_kernel_stack_top(stack_top: usize) {
    // Use the current CPU's per-CPU TSS when available, falling back to the
    // global BSP TSS for early boot or single-CPU operation.
    let tss_ptr = {
        let percpu_tss = crate::kernel::percpu::get().tss as *mut TaskStateSegment;
        if !percpu_tss.is_null() {
            percpu_tss
        } else {
            TSS.get()
        }
    };
    unsafe {
        (*tss_ptr).privilege_stack_table[0] = stack_top as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        kernel_code_selector, kernel_data_selector, user_code_selector, user_data_selector,
    };

    #[test]
    fn selectors_encode_expected_privilege_levels() {
        assert_eq!(kernel_code_selector() & 0x3, 0);
        assert_eq!(kernel_data_selector() & 0x3, 0);
        assert_eq!(user_code_selector() & 0x3, 0x3);
        assert_eq!(user_data_selector() & 0x3, 0x3);
    }
}
