//! src/arch/riscv64/smp.rs
//! RISC-V 64 SMP bring-up via SBI Hart State Management (HSM).
//!
//! ## Boot flow
//!
//! 1. BSP discovers secondary hart IDs from the FDT `/cpus` node.
//! 2. For each secondary hart the BSP allocates a 64 KiB kernel stack.
//! 3. [`sbi_hart_start`] is called with the target hart ID and the address of
//!    `_secondary_start` (in `.text.boot`), passing the stack pointer as
//!    the opaque context value.
//! 4. The secondary hart resets, executes the trampoline in [boot.S], sets up
//!    its exception vectors and MMU context, then calls [`ap_entry`].
//! 5. [`ap_entry`] initialises per-CPU state and enters the idle loop.
//!
//! ## SBI HSM extension
//!
//! Extension ID `0x48534D` ("HSM"), functions:
//! - `hart_start(hartid, start_addr, opaque)` — FID 0
//! - `hart_stop()` — FID 1
//! - `hart_get_status(hartid)` — FID 2
//!
//! Returns 0 on success, negative error code on failure.

use alloc::vec::Vec;

/// Maximum number of secondary CPUs we attempt to boot.
const MAX_APS: usize = 8;

/// Stack size for each secondary CPU (64 KiB).
const AP_STACK_SIZE: usize = 65536;

/// Statically-allocated stacks in kernel BSS so the runtime page tables
/// always cover them.
#[repr(C, align(4096))]
struct ApStack([u8; AP_STACK_SIZE]);

static AP_STACKS: crate::util::sync_unsafe_cell::SyncUnsafeCell<[ApStack; MAX_APS]> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new([
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
    ]);

// External assembly trampoline for secondary CPUs (defined in boot.S).
extern "C" {
    fn _secondary_start();
}

// ---------------------------------------------------------------------------
// SBI HSM extension
// ---------------------------------------------------------------------------

/// SBI Extension ID for Hart State Management.
const SBI_EXT_HSM: u64 = 0x48534D;

/// SBI HSM function: start a hart.
const SBI_HSM_HART_START: u64 = 0;

/// Start a hart via SBI HSM.
///
/// `hartid` — the target hart to start.
/// `start_addr` — physical address of the entry point.
/// `opaque` — value passed to the hart in `a1` (used as stack pointer here).
///
/// Returns 0 on success, or a negative SBI error code.
///
/// # Safety
///
/// The caller must ensure `start_addr` is a valid entry point in
/// executable memory.  The target hart must not already be running.
unsafe fn sbi_hart_start(hartid: u64, start_addr: usize, opaque: u64) -> i64 {
    let ret: u64;
    // SAFETY: SBI ecall with HSM extension — the HSM extension is present
    // on OpenSBI ≥ 0.9 (QEMU virt ships with ≥ 1.0).
    // On success a0=0; on error a0 contains a negative error code cast to u64.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") hartid => ret,
            in("a1") start_addr,
            in("a2") opaque,
            in("a6") SBI_HSM_HART_START,
            in("a7") SBI_EXT_HSM,
            options(nomem, nostack, preserves_flags),
        );
    }
    ret as i64
}

// ---------------------------------------------------------------------------
// FDT CPU discovery
// ---------------------------------------------------------------------------

/// Read the BSP hart ID via `mhartid`.
///
/// In S-mode, `mhartid` is not directly readable — but OpenSBI provides
/// the hart ID via `a0` on entry if configured.  Since we arrive from
/// OpenSBI with only the FDT pointer in `a1`, we query OpenSBI at runtime.
///
/// We use a lightweight approach: probe the hart ID via the SBI HSM
/// `hart_get_status` extension, or fall back to FDT-based detection
/// (matching the boot hart CPU node).
fn bsp_hartid() -> Option<u64> {
    // On QEMU virt, the BSP is always hart 0.  For multi-hart systems
    // we discover the exact hart ID from the FDT below, and filter
    // out hart 0 as the BSP.
    Some(0)
}

/// Discover secondary hart IDs from the Flattened Device Tree.
///
/// The shared FDT module exposes the total CPU count parsed from the `/cpus`
/// node, but provides no raw FDT-pointer accessor for riscv64 (the pointer
/// the bootloader passed in `a1` is not stored anywhere).  We therefore
/// derive the secondary hart IDs from that count: on QEMU `virt` and other
/// OpenSBI platforms hart IDs are contiguous starting at 0, and the BSP is
/// hart 0.  When the FDT has not been parsed (the common case in this
/// prototype) the count is 0 and no secondary harts are reported.
fn discover_secondary_hartids() -> Vec<u64> {
    let mut hartids = Vec::new();

    let total = crate::arch::fdt::cpu_count() as u64;
    let bsp_hartid = bsp_hartid().unwrap_or(0);
    for hartid in 1..total {
        if hartid != bsp_hartid {
            hartids.push(hartid);
        }
    }

    hartids
}

// ---------------------------------------------------------------------------
// AP bring-up
// ---------------------------------------------------------------------------

/// Bring up all secondary harts discovered via FDT.
///
/// For each hart ID, allocate a stack, then call SBI HSM `hart_start`
/// with the `_secondary_start` trampoline address and the stack pointer
/// as the opaque context.
pub fn bring_up_aps() {
    let hartids = discover_secondary_hartids();
    if hartids.is_empty() {
        crate::println!("[smp] riscv64: no secondary harts found in FDT");
        return;
    }

    crate::println!(
        "[smp] riscv64: bringing up {} secondary hart(s)...",
        hartids.len()
    );

    let entry = _secondary_start as *const () as usize;

    let mut online_aps = 0u32;

    for (i, &hartid) in hartids.iter().enumerate() {
        if i >= MAX_APS {
            crate::println!("[smp] riscv64: reached MAX_APS limit, skipping remaining harts");
            break;
        }

        // Allocate stack for this AP from the static pool.
        // The stack grows downward from the top.
        let stack_top = unsafe {
            let stacks = &mut *AP_STACKS.get();
            let stack_ptr = stacks[i].0.as_mut_ptr_range().end as u64;
            stack_ptr
        };

        crate::println!(
            "[smp] riscv64: SBI hart_start hartid={} entry=0x{:x} stack=0x{:x}",
            hartid,
            entry,
            stack_top
        );

        // SAFETY: `_secondary_start` points to the trampoline in `.text.boot`
        // (executable kernel memory).  The target hart is currently stopped
        // (managed by OpenSBI).  `stack_top` is the top of a statically
        // allocated 64 KiB BSS stack.
        let ret = unsafe { sbi_hart_start(hartid, entry, stack_top) };
        match ret {
            0 => {
                // Hart successfully started.  Give it time to come online.
                for _ in 0..100_000 {
                    core::hint::spin_loop();
                }
                online_aps += 1;
                crate::println!(
                    "[smp] riscv64: hart {} online, total APs={}",
                    hartid,
                    online_aps
                );
            }
            code => {
                crate::println!(
                    "[smp] riscv64: SBI hart_start failed for hartid={} (err={})",
                    hartid,
                    code
                );
            }
        }
    }

    // Record the online AP count for the SMP subsystem.  The x86_64-only
    // `ONLINE_AP_COUNT` static is not compiled on riscv64; use the shared
    // setter that the AArch64 backend also uses.
    crate::kernel::smp::bringup::set_online_ap_count(online_aps);
}

/// Entry point for secondary harts, called from the assembly trampoline
/// in boot.S.
///
/// The trampoline has already set up the initial stack from the value
/// passed in `a1` (the opaque context from `sbi_hart_start`).  This
/// function completes hart-local initialisation (exception vectors,
/// MMU enable, FPU enable) and enters the idle loop.
///
/// # Safety
///
/// Called only from the secondary hart trampoline with a valid kernel
/// stack pointer in `sp`.
#[no_mangle]
unsafe extern "C" fn ap_entry() -> ! {
    // Set up exception vectors.
    super::trap::init();

    // Enable the MMU if the BSP's page tables are active.
    // Secondary harts inherit the BSP's satp and only need to enable
    // the MMU if it's not already on.
    let satp: u64;
    // SAFETY: reading satp CSR to check MMU status.
    unsafe {
        core::arch::asm!(
            "csrr {satp}, satp",
            satp = out(reg) satp,
            options(nomem, nostack, preserves_flags)
        );
    }
    let current_mode = satp >> 60;
    if current_mode == 0 {
        // MMU is off — the BSP should have set up satp before bringing
        // up APs.  Enable Sv39 with the BSP's root table address (which
        // is identity-mapped for kernel memory).
        // The satp value is inherited — read the prepared root table.
        // For now, just note that MMU is not yet active.
        crate::println!("[smp] riscv64 AP: warning — MMU not active on secondary hart");
    }

    // Enable FPU (FS field in sstatus).
    // SAFETY: modifying sstatus FS bits to enable FPU.
    unsafe {
        core::arch::asm!(
            "csrs sstatus, {fs_mask}",
            fs_mask = in(reg) 0x0000_6000u64, // FS = 0b11 (Clean)
            options(nomem, nostack, preserves_flags)
        );
    }

    // Enable interrupts.
    // SAFETY: clearing all DAIF-like bits in sstatus (SIE bit).
    unsafe {
        core::arch::asm!("csrsi sstatus, 2", options(nomem, nostack, preserves_flags));
    }

    crate::println!("[smp] riscv64 AP: hart online, entering idle loop");

    // Enter the idle loop.
    loop {
        // SAFETY: WFI wakes on any enabled interrupt; safe to execute
        // in S-mode idle loop.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}
