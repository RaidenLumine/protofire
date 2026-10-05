//! src/arch/riscv64/trap.rs
//!
//! RISC-V 64 trap decoding, IRQ routing, syscall dispatch, and exception
//! logging.

use core::arch::asm;
use core::mem::size_of;
use core::ptr::read_volatile;

use crate::abi::syscall as syscall_abi;
use crate::arch::interrupt_controller::InterruptController;
use crate::arch::syscall_trap;
use crate::kernel::process::thread::RiscV64UserThreadContext;
use crate::kernel::process::TerminationReason;
use crate::println;
use crate::syscall::table::user_memory;
use crate::syscall::SyscallAction;
use crate::syscall::SyscallContext;
use crate::syscall::{self};

/// Harts the trap-stub table in `trap.S` can name.
///
/// The entry stubs are addressed as a table with a four-byte stride, and the
/// handler picks its hart's per-CPU slot out of that stride — so a CPU count
/// the table cannot name is a hart whose traps would run against another
/// hart's state.  The two numbers are one number, and this is where they are
/// held together: the table's own size is checked in `trap.S`, and this build
/// fails here if the kernel starts tracking more CPUs than the table has
/// stubs.
const RISCV64_TRAP_STUBS: usize = 17;
const _: () = assert!(crate::kernel::smp::MAX_CPUS == RISCV64_TRAP_STUBS);

// ── RISC-V exception / interrupt constants ──

// scause exception codes (top bit = 0)
const EXCEPTION_INSTRUCTION_ADDRESS_MISALIGNED: u64 = 0;
const EXCEPTION_INSTRUCTION_ACCESS_FAULT: u64 = 1;
const EXCEPTION_ILLEGAL_INSTRUCTION: u64 = 2;
const EXCEPTION_BREAKPOINT: u64 = 3;
const EXCEPTION_LOAD_ADDRESS_MISALIGNED: u64 = 4;
const EXCEPTION_LOAD_ACCESS_FAULT: u64 = 5;
const EXCEPTION_STORE_ADDRESS_MISALIGNED: u64 = 6;
const EXCEPTION_STORE_ACCESS_FAULT: u64 = 7;
const EXCEPTION_USER_ECALL: u64 = 8;
const EXCEPTION_SUPERVISOR_ECALL: u64 = 9;
const EXCEPTION_INSTRUCTION_PAGE_FAULT: u64 = 12;
const EXCEPTION_LOAD_PAGE_FAULT: u64 = 13;
const EXCEPTION_STORE_PAGE_FAULT: u64 = 15;

// scause interrupt codes (top bit = 1)
const INTERRUPT_SUPERVISOR_SOFTWARE: u64 = 1;
const INTERRUPT_SUPERVISOR_TIMER: u64 = 5;
const INTERRUPT_SUPERVISOR_EXTERNAL: u64 = 9;

// Vector encoding: bit 6 = interrupt flag (1 = interrupt, 0 = exception)
// bits 5..0 = scause code
#[allow(dead_code)]
const VECTOR_USER_ECALL: u8 = EXCEPTION_USER_ECALL as u8;
#[allow(dead_code)]
const VECTOR_SUPERVISOR_ECALL: u8 = EXCEPTION_SUPERVISOR_ECALL as u8;

// SSTATUS fields
const SSTATUS_SPP_MASK: u64 = 1 << 8;
const SSTATUS_SPP_USER: u64 = 0; // SPP = 0 means came from U-mode

// ── Trap frame ──

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapFrame {
    pub ra: u64,
    pub gp: u64,
    pub tp: u64,
    pub t0: u64,
    pub t1: u64,
    pub t2: u64,
    pub s0: u64,
    pub s1: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
    pub a6: u64,
    pub a7: u64,
    pub s2: u64,
    pub s3: u64,
    pub s4: u64,
    pub s5: u64,
    pub s6: u64,
    pub s7: u64,
    pub s8: u64,
    pub s9: u64,
    pub s10: u64,
    pub s11: u64,
    pub t3: u64,
    pub t4: u64,
    pub t5: u64,
    pub t6: u64,
    pub stack_pointer: u64,
    pub sepc: u64,
    pub scause: u64,
    pub stval: u64,
    pub sstatus: u64,
    pub kernel_sp: u64,
    pub vector: u64,
    _reserved: u64,
}

const _: [(); 304] = [(); size_of::<TrapFrame>()];

/// Bytes between one hart's entry stub and the next, as `trap.S` lays them out.
const TRAP_STUB_STRIDE: usize = 4;

extern "C" {
    /// The `stvec` value for a hart: its stub in `trap.S`.
    fn riscv64_trap_stub_for_hart(hart_id: usize) -> usize;
}

/// Install `hart_id`'s exception vector.
///
/// `stvec` is per-hart, so this is a per-hart call: the BSP makes it from
/// `init_early`, an application hart from its own entry point.  It used to be
/// guarded by a "first call wins" flag, which meant the second hart to call it
/// returned without installing anything and ran on whatever `stvec` firmware
/// left behind — a hart that takes a timer interrupt with no vector does not
/// degrade, it jumps to address zero.
///
/// # Safety
///
/// `hart_id` must be the hart this runs on, and must be within the stub
/// table — a hart the kernel tracks has one by construction.
pub unsafe fn install_for_hart(hart_id: usize) {
    // A hart ID past the stub table would index a stub that is not one.  The
    // table is sized to the CPU count the kernel tracks and the BSP declines to
    // start a hart it cannot keep state for, so this cannot happen; stub 0
    // keeps a failure inside the vector table rather than inside whatever
    // followed it.
    let indexed = if hart_id < RISCV64_TRAP_STUBS {
        hart_id
    } else {
        0
    };
    // SAFETY: `indexed` is inside the stub table (`trap.S` lays out exactly
    // `RISCV64_TRAP_STUBS`, checked against the CPU count above), so the stub
    // this asks for exists.
    let stub = unsafe { riscv64_trap_stub_for_hart(indexed) };
    // The entry reads its hart out of the offset between the `stvec` it arrived
    // through and the table base, so consecutive stubs have to be one stride
    // apart.  `trap.S` asks for the encoding that makes that so; this is the
    // check that it did, and it costs one compare per hart at boot.
    // SAFETY: as above — both indices are inside the table.
    let stride = unsafe { riscv64_trap_stub_for_hart(1) - riscv64_trap_stub_for_hart(0) };
    assert!(
        stride == TRAP_STUB_STRIDE,
        "riscv64: entry stubs are {} bytes apart, not {}; the trap entry reads \
         its hart out of that offset",
        stride,
        TRAP_STUB_STRIDE
    );
    // SAFETY: writing `stvec` and `sscratch` affects only this hart, and
    // `stub` is this hart's own entry point in the kernel's text.
    unsafe {
        // stvec mode 0: all traps go to BASE (direct mode).
        asm!("csrw stvec, {stub}", stub = in(reg) stub, options(nostack, preserves_flags));

        // sscratch holds 0 in kernel mode: the entry sequence reads it as
        // "this trap came from a kernel stack, not a user one".
        asm!("csrw sscratch, zero", options(nostack, preserves_flags));
    }
}

/// Install the boot hart's exception vector.
pub fn init() {
    // The boot protocol named this hart in `a0` before the Rust entry; a
    // missing hand-off means the same boot that cannot name its hart also
    // finds no harts in the device tree, and 0 is what such a boot is on.
    let hart_id = crate::arch::riscv64::smp::boot_hart_id().unwrap_or(0) as usize;
    // SAFETY: the hart ID is this hart's own, straight from the hand-off, and
    // is inside the table (the table is sized to the CPU count the kernel
    // tracks, and this is one of those CPUs).
    unsafe { install_for_hart(hart_id) };
}

pub fn entered_from_user_mode(frame: &TrapFrame) -> bool {
    // SPP bit (sstatus[8]) = 0 means trap came from user mode.
    frame.sstatus & SSTATUS_SPP_MASK == SSTATUS_SPP_USER
}

pub fn instruction_pointer(frame: &TrapFrame) -> usize {
    frame.sepc as usize
}

pub fn vector(frame: &TrapFrame) -> u8 {
    frame.vector as u8
}

pub fn exception_code(frame: &TrapFrame) -> u64 {
    frame.scause & 0x7f
}

pub fn is_interrupt(frame: &TrapFrame) -> bool {
    frame.scause >> 63 != 0
}

pub fn interrupt_code(frame: &TrapFrame) -> u64 {
    frame.scause & 0x7f
}

// ── Main trap dispatch ──

#[no_mangle]
extern "C" fn riscv64_trap_dispatch(frame: &mut TrapFrame) {
    // Look at what the other harts have asked this one to drop, before any of
    // this entry's code reads memory through a translation somebody else may
    // have changed.  `sfence.vma` is hart-local, so an edit made elsewhere
    // reaches this hart only through the log — and this is the only place
    // every entry passes through.
    crate::kernel::smp::apply_remote_tlb_invalidations();

    let entered_from_user = entered_from_user_mode(frame);
    validate_user_entry_frame_or_terminate(frame, entered_from_user);
    capture_current_user_context(frame);

    if is_interrupt(frame) {
        handle_interrupt(frame);
        // Process softirqs and deliver pending async signals before returning
        // to user mode, matching the x86_64 and AArch64 ordering.
        crate::kernel::softirq::process_softirqs();
        if entered_from_user {
            try_async_signal_delivery_riscv64(frame);
        }
        validate_user_return_frame_or_terminate(frame, entered_from_user);
        return;
    }

    // Synchronous exception
    let code = exception_code(frame);

    if code == EXCEPTION_USER_ECALL && handle_supervisor_ecall(frame) {
        validate_user_return_frame_or_terminate(frame, entered_from_user);
        return;
    }

    // ── Page fault recovery (demand-paging / CoW) ──
    if let Some(mut memory) = crate::memory::global_mut() {
        match code {
            EXCEPTION_INSTRUCTION_PAGE_FAULT
            | EXCEPTION_LOAD_PAGE_FAULT
            | EXCEPTION_STORE_PAGE_FAULT => {
                let fault_address = frame.stval as usize;
                let is_write = code == EXCEPTION_STORE_PAGE_FAULT;

                // ── fault profiler: page fault type counters ──
                memory.fault_profiler.inc_faults_total();
                memory.fault_profiler.inc_page_faults_total();
                if entered_from_user {
                    memory.fault_profiler.inc_page_faults_user();
                } else {
                    memory.fault_profiler.inc_page_faults_kernel();
                }
                if memory.resolve_page_fault(fault_address, is_write) {
                    validate_user_return_frame_or_terminate(frame, entered_from_user);
                    return;
                }
                // Resolution failed — fall through to fatal handler below.
            }
            _ => {}
        }
    }

    // ── fault profiler: unhandled trap fatal ──
    if let Some(memory) = crate::memory::global_mut() {
        memory.fault_profiler.inc_faults_kernel_fatal();
    }

    super::interrupts::disable();

    println!(
        "[FATAL] riscv64 trap scause={:#018x} sepc={:#018x} stval={:#018x} sstatus={:#018x} sp={:#018x}",
        frame.scause,
        frame.sepc,
        frame.stval,
        frame.sstatus,
        frame.stack_pointer
    );

    loop {
        crate::arch::instructions::hlt();
    }
}

// ── User frame validation ──

fn validate_user_entry_frame_or_terminate(frame: &TrapFrame, entered_from_user: bool) {
    validate_user_frame_or_terminate(frame, entered_from_user, "entry");
}

fn validate_user_return_frame_or_terminate(frame: &TrapFrame, entered_from_user: bool) {
    validate_user_frame_or_terminate(frame, entered_from_user, "return");
}

fn validate_user_frame_or_terminate(frame: &TrapFrame, entered_from_user: bool, phase: &str) {
    let frame_valid =
        !entered_from_user || RiscV64UserThreadContext::validated_from_trap(frame).is_ok();
    let current_thread = if entered_from_user && !frame_valid {
        crate::kernel::process::Scheduler::global().and_then(|scheduler| scheduler.current_thread())
    } else {
        None
    };

    if frame_valid {
        return;
    }

    if let Some(thread) = current_thread {
        if let Some(memory) = crate::memory::global_mut() {
            memory.fault_profiler.inc_faults_terminated();
        }
        push_fault_record_from_trap(frame);
        println!(
            "[user  ] refusing invalid riscv64 {} frame pid={} tid={} sepc={:#018x} sstatus={:#018x} sp={:#018x}",
            phase,
            thread.pid(),
            thread.tid(),
            frame.sepc,
            frame.sstatus,
            frame.stack_pointer
        );
        crate::kernel::process::terminate_current_with_reason(TerminationReason::exception(
            EXCEPTION_ILLEGAL_INSTRUCTION as u8,
            0,
            None,
        ));
    }

    if let Some(memory) = crate::memory::global_mut() {
        memory.fault_profiler.inc_faults_kernel_fatal();
    }

    println!(
        "[FATAL] invalid riscv64 {} frame without current thread sepc={:#018x} sstatus={:#018x} sp={:#018x}",
        phase,
        frame.sepc,
        frame.sstatus,
        frame.stack_pointer
    );
    super::interrupts::disable();
    loop {
        crate::arch::instructions::hlt();
    }
}

fn capture_current_user_context(frame: &TrapFrame) {
    if !entered_from_user_mode(frame) {
        return;
    }

    if let Some(thread) =
        crate::kernel::process::Scheduler::global().and_then(|scheduler| scheduler.current_thread())
    {
        thread.capture_riscv64_user_context_from_trap(frame);
    }
}

// ── Interrupt handling ──

fn handle_interrupt(frame: &mut TrapFrame) {
    let code = interrupt_code(frame);

    match code {
        INTERRUPT_SUPERVISOR_TIMER => {
            crate::kernel::irq_stats::record_irq(INTERRUPT_SUPERVISOR_TIMER as u32);
            let pending_tick = super::timer::prepare_pending_interrupt();
            if let Some(ticks) = pending_tick {
                let _ = crate::kernel::process::on_timer_tick(ticks);
                advance_past_idle_wfi(frame);
            }
        }
        INTERRUPT_SUPERVISOR_EXTERNAL => {
            if super::aia_imsic::has_aia_imsic() {
                // AIA IMSIC is the external-interrupt source: claim, dispatch
                // through the per-IRQ handler table, and complete the claim.
                let claimed = super::aia_imsic::handle_pending_external();
                if claimed != 0 {
                    // A timer wired through an MSI still drives the tick.
                    let tick = super::timer::prepare_interrupt(claimed);
                    if let Some(ticks) = tick {
                        let preempted = crate::kernel::process::on_timer_tick(ticks);
                        let _ = preempted;
                    }
                    advance_past_idle_wfi(frame);
                }
            } else {
                // PLIC external interrupt.
                let claim = super::interrupt_controller::claim_interrupt();
                if claim != 0 {
                    crate::kernel::irq_stats::record_irq(claim);
                    let tick = super::timer::prepare_interrupt(claim);
                    if let Some(ticks) = tick {
                        let preempted = crate::kernel::process::on_timer_tick(ticks);
                        let _ = preempted;
                    }

                    // End of interrupt.
                    super::interrupt_controller::PLIC_CONTROLLER.end_of_interrupt(claim);

                    advance_past_idle_wfi(frame);
                }
            }
        }
        INTERRUPT_SUPERVISOR_SOFTWARE => {
            // Software interrupt (IPI): a hart asking this one to look at its
            // run queue.  What the request is and how it is answered belong to
            // the hart that receives it — see `smp::handle_reschedule_ipi`,
            // which also lowers the request.  Any invalidation that came with
            // it was already walked at this entry's top, where every entry
            // passes.
            crate::kernel::irq_stats::record_ipi();
            super::smp::handle_reschedule_ipi();
        }
        _ => {
            crate::kernel::irq_stats::record_spurious();
            println!(
                "[WARN] riscv64 unknown interrupt code={} sepc={:#018x}",
                code, frame.sepc
            );
        }
    }
}

// ── Syscall handling ──

/// Handle a non-maskable interrupt (machine-level trap).
///
/// RISC-V NMIs are machine-mode events: standard S-mode has no
/// architectural NMI source, so this entry is dormant on QEMU.  It keeps the
/// NMI framework complete and testable on this architecture and would be
/// invoked if the kernel is extended to run at M-mode or gains `smnmi`
/// (supervisor-NMI) support.
///
/// Runs the arch-neutral NMI handler registry; when no handler claims the
/// NMI, the condition is logged with the interrupted context.
pub fn handle_nmi(frame: &mut TrapFrame) {
    let handled = crate::kernel::nmi::dispatch();
    if !handled {
        crate::println!(
            "[NMI   ] unhandled riscv64 NMI sepc={:#018x} scause={:#018x} stval={:#018x}",
            frame.sepc,
            frame.scause,
            frame.stval
        );
    }
}

fn handle_supervisor_ecall(frame: &mut TrapFrame) -> bool {
    let code = exception_code(frame);

    match code {
        EXCEPTION_USER_ECALL => {
            if !entered_from_user_mode(frame) {
                println!(
                    "[WARN] kernel-mode ecall sepc={:#018x} scause={:#018x}",
                    frame.sepc, frame.scause
                );
                return false;
            }
            // RISC-V `ecall` does NOT advance `sepc`: on trap it points at the
            // ecall instruction itself, and `sret` would otherwise re-execute
            // it forever.  Advance past it now, before any handler that might
            // snapshot or context-switch the frame, so the recorded resume
            // point is the instruction after the syscall.  (`ecall` is always
            // a 4-byte non-compressed instruction.)
            frame.sepc += 4;
            handle_syscall(frame);
            true
        }
        _ => false,
    }
}

fn handle_syscall(frame: &mut TrapFrame) {
    let current_thread = crate::kernel::process::Scheduler::global()
        .and_then(|scheduler| scheduler.current_thread());
    let mut syscall_context = SyscallContext::new(
        frame.a7 as usize, // syscall number in a7
        [
            frame.a0 as usize,
            frame.a1 as usize,
            frame.a2 as usize,
            frame.a3 as usize,
            frame.a4 as usize,
            frame.a5 as usize,
        ],
    );
    syscall_context.caller_pid = current_thread.as_ref().map(|thread| thread.pid());

    if let Err(error) =
        user_memory::validate_syscall_pointers(syscall_context.number, &syscall_context.args)
    {
        frame.a0 = syscall_abi::encode_error(error) as u64;
        return;
    }

    let mut post_action = SyscallAction::None;

    match syscall::dispatch_with_action(&mut syscall_context) {
        Ok(dispatch) => match dispatch.action {
            SyscallAction::ReturnFromException { frame_pointer: _ } => {
                // RISC-V doesn't yet support user exception delivery;
                // fall through to set the result.
                frame.a0 = syscall_abi::encode_result(Ok(dispatch.value)) as u64;
            }
            action => {
                frame.a0 = syscall_abi::encode_result(Ok(dispatch.value)) as u64;
                post_action = action;
            }
        },
        Err(error) => {
            frame.a0 = syscall_abi::encode_error(error) as u64;
        }
    }

    // Capture the live frame back into the thread only where the action says
    // it still describes the interrupted code.  `SIGRETURN` restores a
    // context the handler already installed, and the frame here is the
    // trampoline's `ecall`; capturing it would undo the restore.
    match syscall_trap::user_context_capture_point(post_action) {
        syscall_trap::UserContextCapturePoint::BeforePostAction => {
            capture_current_user_context(frame);
        }
        syscall_trap::UserContextCapturePoint::AfterExecProcessApply
        | syscall_trap::UserContextCapturePoint::RestoredByHandler => {}
    }

    match post_action {
        SyscallAction::Yield => {
            crate::kernel::process::yield_current();
        }
        SyscallAction::Exit { status } => {
            crate::kernel::process::terminate_current_with_reason(TerminationReason::Exit {
                status,
            });
        }
        SyscallAction::ExecProcess => {
            let apply_result = current_thread
                .as_ref()
                .ok_or(crate::Error::InternalError)
                .and_then(|thread| thread.write_riscv64_user_context_to_trap(frame));

            match syscall_trap::resolve_exec_process_apply_result(apply_result) {
                syscall_trap::ExecProcessApplyResolution::CaptureUserContext => {
                    capture_current_user_context(frame);
                }
                syscall_trap::ExecProcessApplyResolution::SetErrorAndCaptureUserContext(error) => {
                    frame.a0 = syscall_abi::encode_error(error) as u64;
                    capture_current_user_context(frame);
                }
            }
        }
        SyscallAction::None | SyscallAction::ReturnFromException { .. } => {}
        SyscallAction::SigReturn => {
            // Restore the RISC-V user context from the signal frame that
            // was injected by try_async_signal_delivery_riscv64.
            if let Some(thread) = current_thread.as_ref() {
                let _ = thread.write_riscv64_user_context_to_trap(frame);
            }
        }
    }
}

fn advance_past_idle_wfi(frame: &mut TrapFrame) {
    if entered_from_user_mode(frame) {
        return;
    }

    // WFI instruction is 0x10500073 (4 bytes).  `sepc` may point at a
    // 2-byte compressed instruction, which can never be a WFI and would
    // make the aligned u32 read below fault -- bail out in that case.
    if frame.sepc & 0x3 != 0 {
        return;
    }
    // SAFETY: `frame.sepc` is the faulting instruction's address, checked for
    // alignment above, in an image the kernel is running.
    let instruction = unsafe { read_volatile(frame.sepc as *const u32) };
    if instruction == 0x10500073 {
        // Advance past the WFI.
        frame.sepc += 4;
    }
}

// ── Async signal delivery (preemptive) ──

/// Attempt to deliver a pending async signal by injecting a signal frame
/// onto the user stack and rewriting the [`TrapFrame`].
///
/// Semantics match `try_async_signal_delivery` on x86_64 and
/// `try_async_signal_delivery_aarch64` on AArch64 -- called from the
/// trap dispatch path before returning to user mode after an IRQ.
fn try_async_signal_delivery_riscv64(frame: &mut TrapFrame) {
    use crate::abi::process::RiscV64SignalFrame;
    use crate::abi::process::RISCV64_SIGNAL_FRAME_SIZE;
    use crate::kernel::process::Process;
    use crate::kernel::process::Scheduler;

    let scheduler = match Scheduler::global() {
        Some(s) => s,
        None => return,
    };
    let thread = match scheduler.current_thread() {
        Some(t) => t,
        None => return,
    };
    let process: &Process = thread.process();

    let record = match process.peek_pending_signal() {
        Some(r) => r,
        None => return,
    };
    let signal_num = record.signal;

    if process.is_signal_blocked(signal_num) {
        return;
    }

    let handler_addr = match process.user_signal_handler(signal_num) {
        Some(addr) if addr != 0 => addr,
        _ => return,
    };

    let trampoline_addr = process.signal_trampoline_addr();
    if trampoline_addr == 0 {
        return;
    }

    // Consume the signal.
    let _ = process.take_pending_signal();

    // ── Build the signal frame on the user stack ────────────────────
    //
    // Stack layout (addresses descending, RISC-V stack grows down):
    //
    //   [original stack]                    ← user_sp (original)
    //   [signal frame: 32 bytes]            ← user_sp - 40 (signal_frame_base)
    //   [trampoline return addr (8 bytes)]  ← user_sp - 8  (handler SP)
    //
    // After handler `ret`:
    //   - pops trampoline address, SP = user_sp - 32
    //   - trampoline runs, eventually calls SYS_SIGRETURN
    let user_sp = frame.stack_pointer;
    let trampoline_ret_addr = user_sp.wrapping_sub(8);
    let signal_frame_base = trampoline_ret_addr.wrapping_sub(RISCV64_SIGNAL_FRAME_SIZE as u64);

    let total_len = user_sp.wrapping_sub(signal_frame_base) as usize;
    if total_len == 0 || total_len > 128 {
        return;
    }

    let validation_ok = crate::arch::user_access::validate_user_mapping(
        process,
        signal_frame_base as usize,
        total_len,
        crate::memory::paging::PagePermissions::WRITE,
    )
    .is_ok();

    if !validation_ok {
        return;
    }

    // ── SA_RESTART ─────────────────────────────────────────────────
    // On RISC-V an async signal is only ever delivered on an interrupt
    // frame returning to user mode, and the interrupted SEPC there is
    // never an *executed* ecall: the ecall traps synchronously, so the
    // interrupt frame either points at an ordinary user instruction or at
    // an ecall that has not yet executed (in which case the handler
    // returns and the ecall runs fresh).  Rewinding SEPC in either case
    // would corrupt the user PC.  The x86_64 rewind works because
    // delivery there happens on the syscall interrupt frame itself
    // (`vector == SYSCALL_VECTOR`), i.e. after `int 0x80` was actually
    // taken.  Restarting an interrupted syscall on RISC-V therefore has
    // to be driven from the synchronous syscall path, not here.
    //
    // The frame is the ABI record `SYS_SIGRETURN` reads back, so the shape has
    // one definition rather than one per side of the syscall.
    let sig_frame = RiscV64SignalFrame {
        orig_sepc: frame.sepc,
        orig_sp: user_sp,
        orig_sstatus: frame.sstatus,
        signal: signal_num as u64,
    };

    // SAFETY: both addresses validated as writable user pages above.
    unsafe {
        core::ptr::write(signal_frame_base as *mut RiscV64SignalFrame, sig_frame);
        core::ptr::write(trampoline_ret_addr as *mut u64, trampoline_addr);
    }

    // ── Rewrite TrapFrame for handler entry ────────────────────────
    frame.sepc = handler_addr;
    frame.stack_pointer = trampoline_ret_addr;
    frame.a0 = signal_num as u64; // a0 = first argument (signal number)

    // Zero volatile caller-saved registers (a1-a7, t0-t6).
    frame.a1 = 0;
    frame.a2 = 0;
    frame.a3 = 0;
    frame.a4 = 0;
    frame.a5 = 0;
    frame.a6 = 0;
    frame.a7 = 0;
    frame.t0 = 0;
    frame.t1 = 0;
    frame.t2 = 0;
    frame.t3 = 0;
    frame.t4 = 0;
    frame.t5 = 0;
    frame.t6 = 0;
}

// ── Fault records ──

fn push_fault_record_from_trap(frame: &TrapFrame) {
    if let Some(scheduler) = crate::kernel::process::Scheduler::global() {
        if let Some(thread) = scheduler.current_thread() {
            thread.push_fault_record(
                exception_code(frame) as u8,
                frame.stval,
                Some(frame.stval as usize),
                frame.sepc,
                entered_from_user_mode(frame),
            );
        }
    }

    // Process pending softirqs before returning from the trap handler.
    if entered_from_user_mode(frame) {
        crate::kernel::softirq::process_softirqs();
    }
}

#[allow(dead_code)]
fn log_user_exception_termination(frame: &TrapFrame, exception_name: &str) {
    let Some(thread) = crate::kernel::process::Scheduler::global()
        .and_then(|scheduler| scheduler.current_thread())
    else {
        return;
    };

    push_fault_record_from_trap(frame);

    println!(
        "[user] terminating pid={} tid={} after {} ec={} stval={:#018x} sepc={:#018x}",
        thread.pid(),
        thread.tid(),
        exception_name,
        exception_code(frame),
        frame.stval,
        frame.sepc
    );
}

// ── Exception classification helpers (shared with thread.rs) ──

/// Map an scause exception code to a human-readable name.
pub fn exception_name(code: u64) -> &'static str {
    match code {
        EXCEPTION_INSTRUCTION_ADDRESS_MISALIGNED => "instruction-address-misaligned",
        EXCEPTION_INSTRUCTION_ACCESS_FAULT => "instruction-access-fault",
        EXCEPTION_ILLEGAL_INSTRUCTION => "illegal-instruction",
        EXCEPTION_BREAKPOINT => "breakpoint",
        EXCEPTION_LOAD_ADDRESS_MISALIGNED => "load-address-misaligned",
        EXCEPTION_LOAD_ACCESS_FAULT => "load-access-fault",
        EXCEPTION_STORE_ADDRESS_MISALIGNED => "store-address-misaligned",
        EXCEPTION_STORE_ACCESS_FAULT => "store-access-fault",
        EXCEPTION_USER_ECALL => "user-ecall",
        EXCEPTION_SUPERVISOR_ECALL => "supervisor-ecall",
        EXCEPTION_INSTRUCTION_PAGE_FAULT => "instruction-page-fault",
        EXCEPTION_LOAD_PAGE_FAULT => "load-page-fault",
        EXCEPTION_STORE_PAGE_FAULT => "store-page-fault",
        _ => "unknown",
    }
}

/// Determine whether the lower-privilege synchronous exception should
/// result in thread termination.
pub fn lower_el_sync_termination_reason(code: u64, stval: u64) -> Option<TerminationReason> {
    match code {
        EXCEPTION_INSTRUCTION_PAGE_FAULT
        | EXCEPTION_LOAD_PAGE_FAULT
        | EXCEPTION_STORE_PAGE_FAULT
        | EXCEPTION_ILLEGAL_INSTRUCTION
        | EXCEPTION_LOAD_ACCESS_FAULT
        | EXCEPTION_STORE_ACCESS_FAULT
        | EXCEPTION_INSTRUCTION_ACCESS_FAULT => Some(TerminationReason::exception(
            code as u8,
            stval,
            Some(stval as usize),
        )),
        _ => None,
    }
}

/// RISC-V exception vectors for compatibility with aarch64_exception dispatch.
pub const VECTOR_SUPERVISOR_ECALL_CONST: u8 = EXCEPTION_SUPERVISOR_ECALL as u8;
pub const VECTOR_TIMER_INTERRUPT: u8 = (INTERRUPT_SUPERVISOR_TIMER | (1 << 6)) as u8;
pub const VECTOR_EXTERNAL_INTERRUPT: u8 = (INTERRUPT_SUPERVISOR_EXTERNAL | (1 << 6)) as u8;

/// Map a RISC-V vector to its human-readable name.
pub fn vector_name(vec: u8) -> &'static str {
    if vec & (1 << 6) != 0 {
        match vec & 0x3f {
            1 => "supervisor-software-interrupt",
            5 => "supervisor-timer-interrupt",
            9 => "supervisor-external-interrupt",
            _ => "unknown-interrupt",
        }
    } else {
        match vec & 0x3f {
            0 => "instruction-address-misaligned",
            1 => "instruction-access-fault",
            2 => "illegal-instruction",
            3 => "breakpoint",
            4 => "load-address-misaligned",
            5 => "load-access-fault",
            6 => "store-address-misaligned",
            7 => "store-access-fault",
            8 => "user-ecall",
            9 => "supervisor-ecall",
            12 => "instruction-page-fault",
            13 => "load-page-fault",
            15 => "store-page-fault",
            _ => "unknown-exception",
        }
    }
}

/// Check whether a vector corresponds to an IRQ (interrupt).
pub fn is_irq_vector(vec: u8) -> bool {
    vec & (1 << 6) != 0
}
