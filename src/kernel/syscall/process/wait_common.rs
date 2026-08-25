//! src/kernel/syscall/process/wait_common.rs
//!
//! Shared syscall-side wait-loop helpers for timeout, deadline, and
//! wake-outcome handling.

use crate::arch;
use crate::kernel::process::ThreadWaitOutcome;
use crate::{Error, Result};

pub(super) struct TimedOutputRequest<T: super::user_memory::PaddingFree> {
    pub(super) timeout_ticks: u64,
    pub(super) record_buffer: super::user_memory::FixedOutputBuffer<T>,
}

impl<T: super::user_memory::PaddingFree> TimedOutputRequest<T> {
    pub(super) fn finish_with(
        self,
        wait: impl FnOnce(u64) -> Result<T>,
    ) -> Result<super::SyscallDispatch> {
        let Self {
            timeout_ticks,
            record_buffer,
        } = self;
        record_buffer.finish_with(|| wait(timeout_ticks))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitStrategy {
    BlockIndefinitely,
    Timed,
}

enum TimedWaitProgress<T> {
    Ready(T),
    Retry,
    TimedOut,
}

fn finish_timed_wait_progress<T>(
    probe: &mut impl FnMut() -> Option<T>,
    did_last_wait_time_out: &mut impl FnMut() -> Result<bool>,
) -> Result<TimedWaitProgress<T>> {
    if let Some(value) = probe() {
        return Ok(TimedWaitProgress::Ready(value));
    }

    if did_last_wait_time_out()? {
        return Ok(TimedWaitProgress::TimedOut);
    }

    Ok(TimedWaitProgress::Retry)
}

fn wait_indefinitely_until_ready<T>(
    probe: &mut impl FnMut() -> Option<T>,
    wait_once: &mut impl FnMut() -> bool,
) -> Result<T> {
    loop {
        let _ = wait_once();
        if let Some(value) = probe() {
            return Ok(value);
        }
    }
}

fn wait_timed_until_ready<T>(
    timeout_ticks: u64,
    probe: &mut impl FnMut() -> Option<T>,
    wait_once_timeout: &mut impl FnMut(u64) -> bool,
    did_last_wait_time_out: &mut impl FnMut() -> Result<bool>,
) -> Result<T> {
    let scheduler = super::runtime::global_scheduler()?;
    let deadline = wait_deadline(scheduler.current_tick(), timeout_ticks);
    loop {
        let remaining = remaining_wait_ticks(deadline, scheduler.current_tick())?;
        let _ = wait_once_timeout(remaining);
        match finish_timed_wait_progress(probe, did_last_wait_time_out)? {
            TimedWaitProgress::Ready(value) => return Ok(value),
            TimedWaitProgress::Retry => {}
            TimedWaitProgress::TimedOut => return Err(Error::TimedOut),
        }
    }
}

pub(super) fn wait_until_ready<T>(
    timeout_ticks: u64,
    block_indefinitely_ticks: u64,
    mut probe: impl FnMut() -> Option<T>,
    mut wait_once: impl FnMut() -> bool,
    mut wait_once_timeout: impl FnMut(u64) -> bool,
    mut did_last_wait_time_out: impl FnMut() -> Result<bool>,
) -> Result<T> {
    if let Some(value) = probe() {
        return Ok(value);
    }

    match classify_wait_strategy(
        timeout_ticks,
        block_indefinitely_ticks,
        arch::supports_context_switch(),
    )? {
        WaitStrategy::BlockIndefinitely => {
            wait_indefinitely_until_ready(&mut probe, &mut wait_once)
        }
        WaitStrategy::Timed => wait_timed_until_ready(
            timeout_ticks,
            &mut probe,
            &mut wait_once_timeout,
            &mut did_last_wait_time_out,
        ),
    }
}

pub(super) fn timed_output_request<T: super::user_memory::PaddingFree>(
    context: &super::SyscallContext,
    timeout_arg: usize,
    ptr_arg: usize,
    len_arg: usize,
) -> Result<TimedOutputRequest<T>> {
    Ok(TimedOutputRequest {
        timeout_ticks: context.arg(timeout_arg) as u64,
        record_buffer: super::user_memory::fixed_output_buffer_arg(context, ptr_arg, len_arg)?,
    })
}

pub(super) fn current_wait_timed_out() -> Result<bool> {
    super::runtime::with_current_thread(|thread| {
        Ok(thread.wait_outcome() == ThreadWaitOutcome::TimedOut)
    })
}

fn classify_wait_strategy(
    timeout_ticks: u64,
    block_indefinitely_ticks: u64,
    supports_context_switch: bool,
) -> Result<WaitStrategy> {
    if timeout_ticks == 0 {
        return Err(Error::TimedOut);
    }

    if !supports_context_switch {
        return Err(Error::TimedOut);
    }

    if timeout_ticks == block_indefinitely_ticks {
        return Ok(WaitStrategy::BlockIndefinitely);
    }

    Ok(WaitStrategy::Timed)
}

fn wait_deadline(current_tick: u64, timeout_ticks: u64) -> u64 {
    current_tick.saturating_add(timeout_ticks)
}

fn remaining_wait_ticks(deadline: u64, current_tick: u64) -> Result<u64> {
    match deadline.checked_sub(current_tick) {
        Some(remaining) if remaining != 0 => Ok(remaining),
        _ => Err(Error::TimedOut),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn wait_until_ready_returns_immediately_when_probe_already_succeeds() {
        let waited = Cell::new(false);
        let result = wait_until_ready(
            0,
            u64::MAX,
            || Some(7_u32),
            || {
                waited.set(true);
                false
            },
            |_| {
                waited.set(true);
                false
            },
            || Ok(false),
        );

        assert_eq!(result, Ok(7));
        assert!(!waited.get());
    }

    #[test]
    fn classify_wait_strategy_rejects_zero_timeout_before_any_blocking() {
        assert_eq!(
            classify_wait_strategy(0, u64::MAX, false),
            Err(Error::TimedOut)
        );
        assert_eq!(
            classify_wait_strategy(0, u64::MAX, true),
            Err(Error::TimedOut)
        );
    }

    #[test]
    fn classify_wait_strategy_rejects_blocking_without_context_switch_support() {
        assert_eq!(
            classify_wait_strategy(1, u64::MAX, false),
            Err(Error::TimedOut)
        );
        assert_eq!(
            classify_wait_strategy(u64::MAX, u64::MAX, false),
            Err(Error::TimedOut)
        );
    }

    #[test]
    fn classify_wait_strategy_accepts_infinite_and_finite_wait_modes_with_context_switch() {
        assert_eq!(
            classify_wait_strategy(u64::MAX, u64::MAX, true),
            Ok(WaitStrategy::BlockIndefinitely)
        );
        assert_eq!(
            classify_wait_strategy(5, u64::MAX, true),
            Ok(WaitStrategy::Timed)
        );
    }

    #[test]
    fn wait_deadline_saturates_when_timeout_overflows_tick_counter() {
        assert_eq!(wait_deadline(u64::MAX - 2, 5), u64::MAX);
    }

    #[test]
    fn remaining_wait_ticks_reports_timeout_once_deadline_is_reached() {
        assert_eq!(remaining_wait_ticks(10, 7), Ok(3));
        assert_eq!(remaining_wait_ticks(10, 10), Err(Error::TimedOut));
        assert_eq!(remaining_wait_ticks(10, 11), Err(Error::TimedOut));
    }

    #[test]
    fn wait_indefinitely_until_ready_reprobes_after_each_wait() {
        let waits = Cell::new(0);
        let probes = Cell::new(0);

        let result = wait_indefinitely_until_ready(
            &mut || {
                probes.set(probes.get() + 1);
                (probes.get() == 2).then_some(9_u32)
            },
            &mut || {
                waits.set(waits.get() + 1);
                false
            },
        );

        assert_eq!(result, Ok(9));
        assert_eq!(waits.get(), 2);
        assert_eq!(probes.get(), 2);
    }

    #[test]
    fn timed_output_request_finish_with_passes_timeout_and_copies_record() {
        #[repr(C)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct TestRecord {
            value: u32,
            extra: u32,
        }

        // SAFETY: homogeneous u32 `#[repr(C)]` struct — no padding.
        unsafe impl super::super::user_memory::PaddingFree for TestRecord {}

        let mut buffer = [0_u8; core::mem::size_of::<TestRecord>()];
        let result = TimedOutputRequest {
            timeout_ticks: 9,
            record_buffer: super::super::user_memory::FixedOutputBuffer::new(
                buffer.as_mut_ptr(),
                buffer.len(),
            )
            .expect("build output buffer"),
        }
        .finish_with(|timeout_ticks| {
            assert_eq!(timeout_ticks, 9);
            Ok(TestRecord {
                value: 0x1234_5678,
                extra: 0x9abc_def0,
            })
        });

        assert_eq!(
            result,
            Ok(super::super::SyscallDispatch::complete(buffer.len()))
        );
        let copied = unsafe { core::ptr::read_unaligned(buffer.as_ptr().cast::<TestRecord>()) };
        assert_eq!(
            copied,
            TestRecord {
                value: 0x1234_5678,
                extra: 0x9abc_def0,
            }
        );
    }

    #[test]
    fn timed_output_request_decodes_timeout_and_output_buffer() {
        let mut buffer = [0_u8; core::mem::size_of::<u32>()];
        let context = super::super::SyscallContext::new(
            0,
            [11, buffer.as_mut_ptr() as usize, buffer.len(), 0, 0, 0],
        );

        let result = timed_output_request::<u32>(&context, 0, 1, 2)
            .expect("decode timed output request")
            .finish_with(|timeout_ticks| {
                assert_eq!(timeout_ticks, 11);
                Ok(0x1234_5678)
            });

        assert_eq!(
            result,
            Ok(super::super::SyscallDispatch::complete(buffer.len()))
        );
        assert_eq!(
            unsafe { core::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) },
            0x1234_5678
        );
    }

    #[test]
    fn wait_timed_until_ready_returns_timeout_after_wait_outcome_reports_timeout() {
        let scheduler = crate::kernel::process::Scheduler::new();
        let waits = Cell::new(0);

        unsafe {
            scheduler.install_global_unchecked();
        }

        let result = wait_timed_until_ready(
            3,
            &mut || None::<u32>,
            &mut |_| {
                waits.set(waits.get() + 1);
                false
            },
            &mut || Ok(true),
        );

        assert_eq!(result, Err(Error::TimedOut));
        assert_eq!(waits.get(), 1);
    }

    #[test]
    fn wait_timed_until_ready_retries_after_spurious_wake_without_timeout() {
        let scheduler = crate::kernel::process::Scheduler::new();
        let waits = Cell::new(0);
        let probes = Cell::new(0);

        unsafe {
            scheduler.install_global_unchecked();
        }

        let result = wait_timed_until_ready(
            3,
            &mut || {
                probes.set(probes.get() + 1);
                (probes.get() == 2).then_some(11_u32)
            },
            &mut |_| {
                waits.set(waits.get() + 1);
                false
            },
            &mut || Ok(false),
        );

        assert_eq!(result, Ok(11));
        assert_eq!(waits.get(), 2);
        assert_eq!(probes.get(), 2);
    }

    #[test]
    fn wait_timed_until_ready_prefers_ready_probe_over_timeout_outcome() {
        let scheduler = crate::kernel::process::Scheduler::new();
        let waits = Cell::new(0);

        unsafe {
            scheduler.install_global_unchecked();
        }

        let result = wait_timed_until_ready(
            3,
            &mut || Some(17_u32),
            &mut |_| {
                waits.set(waits.get() + 1);
                false
            },
            &mut || Ok(true),
        );

        assert_eq!(result, Ok(17));
        assert_eq!(waits.get(), 1);
    }
}
