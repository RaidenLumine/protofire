//! src/arch/x86_64/idt/dispatch.rs
//!
//! Interrupt dispatch and syscall handling.

use core::arch::asm;
use core::mem::size_of;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use crate::abi::syscall as syscall_abi;
use crate::arch::syscall_trap;
use crate::kernel::process::TerminationReason;
use crate::kernel::syscall::table::user_memory;
use crate::kernel::syscall::SyscallAction;
use crate::kernel::syscall::SyscallContext;
use crate::kernel::syscall::{self};
use crate::println;

use super::exception::handle_exception;
use super::exception::page_fault_address;
use super::exception::sync_user_iret_stack;
use super::types::interrupt_stub_128;
use super::types::interrupt_stub_default;
use super::types::DescriptorTablePointer;
use super::types::InterruptContext;
use super::types::InterruptDescriptorTable;
use super::types::InterruptGate;
use super::types::EARLY_HANDLERS;
use super::types::IDT;
use super::types::IPI_RESCHEDULE_VECTOR;
use super::types::IPI_SHOOTDOWN_VECTOR;
use super::types::SYSCALL_VECTOR;
use super::types::USER_INTERRUPT_GATE;

#[cfg(target_os = "none")]
use crate::abi::process::SignalFrame;
#[cfg(target_os = "none")]
use crate::abi::process::SA_RESTART;
#[cfg(target_os = "none")]
use crate::abi::process::SIGNAL_FRAME_SIZE;
#[cfg(target_os = "none")]
use crate::kernel::process::Process;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Load the kernel IDT on the BSP.
///
/// This function is idempotent: subsequent calls after the first are no-ops.
pub fn init() {
    if INITIALIZED.swap(true, Ordering::Acquire) {
        return;
    }

    unsafe {
        let idt = IDT.get();
        let gates = &mut (*idt).gates;

        for (index, gate) in gates.iter_mut().enumerate() {
            let handler = EARLY_HANDLERS
                .get(index)
                .copied()
                .unwrap_or(interrupt_stub_default);
            *gate = InterruptGate::new(handler);
        }

        // Keep normal interrupts/exceptions ring-0 only, but expose the
        // syscall vector as a DPL3 gate so user mode can enter the kernel.
        gates[SYSCALL_VECTOR as usize] =
            InterruptGate::new_with_attributes(interrupt_stub_128, USER_INTERRUPT_GATE);

        let idtr = DescriptorTablePointer {
            limit: (size_of::<InterruptDescriptorTable>() - 1) as u16,
            base: idt as *const _ as u64,
        };

        asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

/// Load the shared kernel IDT on an AP.
///
/// The BSP must have called [`init`] first to populate the static IDT.
/// Each AP must call this function (or otherwise execute `lidt`) so that
/// interrupts — including IPIs — are delivered correctly.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn init_ap() {
    let idt = unsafe { &*IDT.get() };
    let idtr = DescriptorTablePointer {
        limit: (core::mem::size_of::<InterruptDescriptorTable>() - 1) as u16,
        base: idt as *const InterruptDescriptorTable as u64,
    };
    unsafe {
        asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

#[no_mangle]
extern "C" fn interrupt_dispatch(context: &mut InterruptContext) {
    // Capture CR2 immediately before any handler code could trigger a secondary
    // page fault and clobber it. This must be the very first thing we do after
    // the assembly stub saves registers.
    let cr2 = page_fault_address();
    // Capture the current user register view before dispatch mutates it, then
    // patch the hardware iret frame back up before returning to ring 3.
    capture_current_user_context(context);
    let vector = context.vector as u8;

    // NMI (vector 2) — not maskable and can interrupt code holding locks, so
    // it is handled on a dedicated minimal path before normal dispatch: count
    // it, run any registered NMI handlers, and return.  We deliberately skip
    // user-context capture, softirqs, and async signal delivery here.
    if vector == 2 {
        handle_x86_64_nmi(context);
        return;
    }

    match vector {
        0..=31 => handle_exception(context, cr2),
        vector if is_irq_vector(vector) => {
            crate::kernel::irq_stats::record_irq(vector as u32);
            crate::arch::x86_64::interrupts::handle_irq(vector, context.entered_from_user_mode());
        }
        SYSCALL_VECTOR => handle_syscall(context),
        IPI_RESCHEDULE_VECTOR => {
            crate::kernel::irq_stats::record_ipi();
            // Acknowledge LAPIC EOI and request a scheduler pass.
            #[cfg(all(target_arch = "x86_64", target_os = "none"))]
            crate::arch::x86_64::apic::lapic_eoi();
            // Set need_resched so the scheduler preempts the current thread
            // at the next safe point (timer tick or kernel exit).
            if let Some(scheduler) = crate::kernel::process::Scheduler::global() {
                scheduler.set_need_resched();
            }
        }
        IPI_SHOOTDOWN_VECTOR => {
            crate::kernel::irq_stats::record_ipi();
            // Acknowledge LAPIC EOI.
            #[cfg(all(target_arch = "x86_64", target_os = "none"))]
            {
                crate::arch::x86_64::apic::lapic_eoi();
            }
            // Execute the pending TLB invalidation.
            #[cfg(all(target_arch = "x86_64", target_os = "none"))]
            crate::kernel::smp::handle_tlb_shootdown();
        }
        _ => {
            crate::kernel::irq_stats::record_spurious();
            println!(
                "[WARN ] unhandled interrupt vector={} rip={:#018x}",
                vector, context.rip
            );
        }
    }

    // Apply any remote TLB invalidations that were requested by another
    // CPU since the last time this CPU checked.  Must happen after the
    // interrupt is fully processed and before we return to the interrupted
    // context so that the now-running code sees the latest page-table state.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    crate::kernel::smp::apply_remote_tlb_invalidations();

    // ── Softirq processing ───────────────────────────────────────────
    // Process any pending softirqs (deferred interrupt work) before
    // checking for signal delivery or returning to user mode.
    crate::kernel::softirq::process_softirqs();

    // ── Async signal delivery check ──────────────────────────────────
    // If the current process has pending signals with async handlers and
    // we are returning to user mode, inject a signal frame on the user
    // stack and redirect execution to the handler.
    if context.entered_from_user_mode() {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        try_async_signal_delivery(context);
    }

    sync_user_iret_stack(context);
}

/// Handle an x86_64 NMI (vector 2).
///
/// Runs the arch-neutral NMI handler registry; when no handler claims the
/// NMI, the condition is logged with the interrupted context so it is not
/// silently lost.  The handler never touches the interrupted context, so the
/// return via `iretq` is safe even when the NMI arrived inside another
/// interrupt or a syscall.
fn handle_x86_64_nmi(context: &InterruptContext) {
    let handled = crate::kernel::nmi::dispatch();
    if !handled {
        println!(
            "[NMI   ] unhandled x86_64 NMI rip={:#018x} cs={:#018x} rflags={:#018x}",
            context.rip, context.cs, context.rflags
        );
    }
}

pub(crate) fn is_irq_vector(vector: u8) -> bool {
    // With APIC/IOAPIC, interrupt vectors can range from 32 (first
    // non-exception vector) up to 254.  The syscall vector (128) is
    // excluded because it is handled separately.  We also exclude
    // IPI vectors (reschedule, shootdown) and the LAPIC spurious
    // vector (0xFF).
    //
    // The legacy PIC range (32..=47) is a subset of this range and
    // will still match.
    vector >= 32
        && vector != SYSCALL_VECTOR
        && vector != IPI_RESCHEDULE_VECTOR
        && vector != IPI_SHOOTDOWN_VECTOR
        && vector < 255
}

pub(crate) fn capture_current_user_context(context: &InterruptContext) {
    if !context.entered_from_user_mode() {
        return;
    }

    if let Some(thread) =
        crate::kernel::process::Scheduler::global().and_then(|scheduler| scheduler.current_thread())
    {
        thread.capture_x86_64_user_context_from_interrupt(context);
    }
}

fn handle_syscall(context: &mut InterruptContext) {
    if !context.entered_from_user_mode() {
        println!(
            "[WARN] kernel-mode int {:#x} rip={:#018x}",
            SYSCALL_VECTOR, context.rip
        );
        return;
    }

    let current_thread = crate::kernel::process::Scheduler::global()
        .and_then(|scheduler| scheduler.current_thread());
    let mut syscall_context = SyscallContext::new(
        context.rax as usize,
        [
            context.rdi as usize,
            context.rsi as usize,
            context.rdx as usize,
            context.rcx as usize,
            context.r8 as usize,
            context.r9 as usize,
        ],
    );
    syscall_context.caller_pid = current_thread.as_ref().map(|thread| thread.pid());

    // Pre-validate user-memory pointers declared in the static syscall
    // pointer-spec table.  Return early with a clear error if any pointer
    // is out of bounds or unmapped — the individual handler never runs.
    if let Err(error) =
        user_memory::validate_syscall_pointers(syscall_context.number, &syscall_context.args)
    {
        context.rax = syscall_abi::encode_error(error) as u64;
        return;
    }

    let mut post_action = SyscallAction::None;

    match syscall::dispatch_with_action(&mut syscall_context) {
        Ok(dispatch) => match dispatch.action {
            SyscallAction::SigReturn => {
                // The sigreturn handler (#134) already restored the thread's
                // saved user context from the SignalFrame.  Apply it to the
                // InterruptContext before returning to user mode via iretq.
                if let Some(thread) = current_thread.as_ref() {
                    let _ = thread.write_x86_64_user_context_to_interrupt(context);
                }
                return;
            }
            SyscallAction::ReturnFromException { frame_pointer } => {
                let resume_result = current_thread
                    .as_ref()
                    .ok_or(crate::Error::InternalError)
                    .and_then(|thread| thread.resume_x86_64_user_exception(context, frame_pointer));

                match syscall_trap::resolve_return_from_exception_resume(resume_result) {
                    syscall_trap::ReturnFromExceptionResolution::ReturnToUser => {
                        if let Some(thread) = current_thread.as_ref() {
                            thread.capture_x86_64_user_context_from_interrupt(context);
                        }
                        return;
                    }
                    syscall_trap::ReturnFromExceptionResolution::SetError(error) => {
                        context.rax = syscall_abi::encode_error(error) as u64;
                    }
                }
            }
            action => {
                context.rax = syscall_abi::encode_result(Ok(dispatch.value)) as u64;
                post_action = action;
            }
        },
        Err(error) => {
            context.rax = syscall_abi::encode_error(error) as u64;
        }
    }

    match syscall_trap::user_context_capture_point(post_action) {
        syscall_trap::UserContextCapturePoint::BeforePostAction => {
            capture_current_user_context(context);
        }
        syscall_trap::UserContextCapturePoint::AfterExecProcessApply => {}
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
                .and_then(|thread| thread.write_x86_64_user_context_to_interrupt(context));

            match syscall_trap::resolve_exec_process_apply_result(apply_result) {
                syscall_trap::ExecProcessApplyResolution::CaptureUserContext => {
                    if let Some(thread) = current_thread.as_ref() {
                        thread.capture_x86_64_user_context_from_interrupt(context);
                    }
                }
                syscall_trap::ExecProcessApplyResolution::SetErrorAndCaptureUserContext(error) => {
                    context.rax = syscall_abi::encode_error(error) as u64;
                    capture_current_user_context(context);
                }
            }
        }
        SyscallAction::None | SyscallAction::ReturnFromException { .. } => {}
        // Unreachable — SigReturn is handled by early return in the dispatch
        // action match above, before post_action is set.
        SyscallAction::SigReturn => unreachable!(),
    }
}

/// Attempt to deliver a pending async signal by injecting a [`SignalFrame`]
/// onto the user stack and rewriting the [`InterruptContext`].
///
/// This function is a no-op when:
/// - No pending signals with async capability exist.
/// - The front signal is blocked by the signal mask.
/// - No trampoline address has been registered.
///
/// Called from [`interrupt_dispatch`] before returning to user mode.
#[cfg(target_os = "none")]
fn try_async_signal_delivery(context: &mut InterruptContext) {
    // Resolve current process.
    let scheduler = match crate::kernel::process::Scheduler::global() {
        Some(s) => s,
        None => return,
    };
    let thread = match scheduler.current_thread() {
        Some(t) => t,
        None => return,
    };
    let process: &Process = thread.process();

    // Peek at the front of the signal queue (non-destructive).
    let record = match process.peek_pending_signal() {
        Some(r) => r,
        None => return,
    };

    let signal_num = record.signal;

    // If the signal is blocked by the mask, leave it in the queue
    // for cooperative delivery when unblocked.
    if process.is_signal_blocked(signal_num) {
        return;
    }

    // Does this signal have an async handler registered?
    let handler_addr = match process.user_signal_handler(signal_num) {
        Some(addr) if addr != 0 => addr,
        _ => return, // cooperative-only — leave in queue for wait_signal
    };

    // Do we have a trampoline address?
    let trampoline_addr = process.signal_trampoline_addr();
    if trampoline_addr == 0 {
        return; // no trampoline — cannot deliver async
    }

    // Consume the signal from the queue.
    let _ = process.take_pending_signal();

    // ── SA_RESTART logic ───────────────────────────────────────────
    // If the signal handler was installed with SA_RESTART and the
    // signal interrupted a syscall (int 0x80), arrange for the syscall
    // to be re-issued after the handler returns by rewinding the saved
    // RIP by 2 bytes (the length of `int 0x80`).
    let restart_pending = (process.signal_sa_flags(signal_num) & SA_RESTART) != 0
        && context.vector == SYSCALL_VECTOR as u64;

    // ── Build the SignalFrame on the user stack ────────────────────
    //
    // Stack layout (addresses descending):
    //
    //   [original stack]           ← user_rsp (original)
    //   [SignalFrame: 32 bytes]    ← user_rsp - 40 (signal_frame_base)
    //   [trampoline return addr]   ← user_rsp - 8  (handler RSP)
    //
    // After handler `ret`:
    //   - pops trampoline address, RSP = user_rsp - 32
    //   - trampoline sees RSP pointing at SignalFrame.orig_rip

    let user_rsp = context.saved_stack_pointer;
    let trampoline_ret_addr = user_rsp.wrapping_sub(8);
    let signal_frame_base = trampoline_ret_addr.wrapping_sub(SIGNAL_FRAME_SIZE as u64);

    // Validate the whole region [signal_frame_base .. user_rsp).
    let total_len = user_rsp.wrapping_sub(signal_frame_base) as usize;
    if total_len == 0 || total_len > 128 {
        // Sanity check — should never happen with valid RSP.
        return;
    }

    let validation_ok = user_memory::validate_user_mapping(
        process,
        signal_frame_base as usize,
        total_len,
        crate::kernel::memory::paging::PagePermissions::WRITE,
    )
    .is_ok();

    if !validation_ok {
        // Can't write to user stack — signal was consumed but can't deliver.
        return;
    }

    // Write the SignalFrame and trampoline address.
    let frame = SignalFrame {
        orig_rip: if restart_pending {
            context.rip.wrapping_sub(2)
        } else {
            context.rip
        },
        orig_rsp: user_rsp,
        orig_rflags: context.rflags,
        signal: signal_num as u64,
    };

    // SAFETY: both addresses have been validated as writable user pages above.
    unsafe {
        user_memory::write_user_value_untracked(signal_frame_base, &frame);
        user_memory::write_user_value_untracked(trampoline_ret_addr, &trampoline_addr);
    }

    // ── Rewrite InterruptContext for handler entry ──────────────────
    context.rip = handler_addr;
    context.saved_stack_pointer = trampoline_ret_addr;
    context.rdi = signal_num as u64;

    // Zero volatile registers for cleanliness.
    context.rax = 0;
    context.rcx = 0;
    context.r11 = 0;
}
