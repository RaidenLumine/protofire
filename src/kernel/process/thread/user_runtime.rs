//! src/kernel/process/thread/user_runtime.rs
//!
//! User-runtime state management: snapshot, validate, restore, replace, and
//! clear user-mode execution context.

#[cfg(any(target_arch = "aarch64", test))]
use ::core::sync::atomic::Ordering;

#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    test
))]
use crate::{Error, Result};

use super::super::ProcessState;
use super::types::{ThreadExecutionState, ThreadState, ThreadUserRuntimeState, UserThreadStart};
use super::Thread;

impl Thread {
    pub(crate) fn ensure_runtime_mutable(&self) -> Result<()> {
        // Do not mutate user runtime state once thread/process is terminated.
        if self.state() == ThreadState::Terminated
            || self.process.state() == ProcessState::Terminated
        {
            return Err(Error::Busy);
        }

        Ok(())
    }

    pub(crate) fn ensure_user_runtime_mutable(&self) -> Result<()> {
        self.ensure_runtime_mutable()?;

        // User-runtime operations only apply to user threads.
        if self.user_start().is_none() {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }

    pub(crate) fn clear_user_runtime_state(&self) {
        let mut execution_state = self.execution_state.lock();
        execution_state.kernel_entry = None;
        execution_state.user_start = None;
        #[cfg(target_arch = "x86_64")]
        {
            execution_state.x86_64_exception_stack_pointer = None;
        }
        drop(execution_state);

        #[cfg(any(target_arch = "aarch64", test))]
        self.clear_aarch64_user_runtime_state();
        #[cfg(target_arch = "x86_64")]
        self.clear_x86_64_user_runtime_state();
    }

    pub(crate) fn snapshot_user_runtime_state(&self) -> Result<ThreadUserRuntimeState> {
        self.ensure_user_runtime_mutable()?;
        let state = ThreadUserRuntimeState {
            execution_state: *self.execution_state.lock(),
            #[cfg(any(target_arch = "aarch64", test))]
            aarch64_user_context: *self.aarch64_user_context.lock(),
            #[cfg(any(target_arch = "aarch64", test))]
            aarch64_exception_handlers: *self.aarch64_exception_handlers.lock(),
            #[cfg(any(target_arch = "aarch64", test))]
            aarch64_pending_exception_frames: *self.aarch64_pending_exception_frames.lock(),
            #[cfg(any(target_arch = "aarch64", test))]
            aarch64_exception_preempt_resume_logged: self
                .aarch64_exception_preempt_resume_logged
                .load(Ordering::SeqCst),
            #[cfg(target_arch = "x86_64")]
            x86_64_user_context: *self.x86_64_user_context.lock(),
            #[cfg(target_arch = "x86_64")]
            x86_64_exception_handlers: *self.x86_64_exception_handlers.lock(),
            #[cfg(target_arch = "x86_64")]
            x86_64_pending_exception_frames: *self.x86_64_pending_exception_frames.lock(),
            #[cfg(any(target_arch = "riscv64", test))]
            riscv64_user_context: *self.riscv64_user_context.lock(),
        };
        Self::validate_restored_user_runtime_state(&state)?;
        Ok(state)
    }

    fn validate_restored_user_runtime_state(state: &ThreadUserRuntimeState) -> Result<()> {
        let user_start = state
            .execution_state
            .user_start
            .ok_or(Error::InvalidArgument)?;
        user_start.validate()?;

        #[cfg(any(target_arch = "aarch64", test))]
        {
            let user_context = state.aarch64_user_context.ok_or(Error::InvalidArgument)?;
            user_context.validate_runtime_state()?;
        }
        #[cfg(target_arch = "x86_64")]
        {
            let user_context = state.x86_64_user_context.ok_or(Error::InvalidArgument)?;
            user_context.validate_runtime_state()?;
        }

        Ok(())
    }

    pub(crate) fn restore_user_runtime_state(&self, state: ThreadUserRuntimeState) -> Result<()> {
        self.ensure_runtime_mutable()?;
        Self::validate_restored_user_runtime_state(&state)?;
        *self.execution_state.lock() = state.execution_state;
        #[cfg(any(target_arch = "aarch64", test))]
        {
            *self.aarch64_user_context.lock() = state.aarch64_user_context;
            *self.aarch64_exception_handlers.lock() = state.aarch64_exception_handlers;
            *self.aarch64_pending_exception_frames.lock() = state.aarch64_pending_exception_frames;
            self.aarch64_exception_preempt_resume_logged.store(
                state.aarch64_exception_preempt_resume_logged,
                Ordering::SeqCst,
            );
        }
        #[cfg(target_arch = "x86_64")]
        {
            *self.x86_64_user_context.lock() = state.x86_64_user_context;
            *self.x86_64_exception_handlers.lock() = state.x86_64_exception_handlers;
            *self.x86_64_pending_exception_frames.lock() = state.x86_64_pending_exception_frames;
        }
        Ok(())
    }

    #[cfg_attr(all(target_arch = "riscv64", target_os = "none"), allow(dead_code))]
    pub(crate) fn replace_user_execution_state(
        &self,
        start: UserThreadStart,
        update_arch_state: impl FnOnce(&mut ThreadExecutionState),
    ) -> Result<()> {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
        let start = start.validate()?;
        self.ensure_user_runtime_mutable()?;
        let mut execution_state = self.execution_state.lock();
        execution_state.entry_point = start.instruction_pointer;
        execution_state.kernel_entry = None;
        execution_state.user_start = Some(start);
        update_arch_state(&mut execution_state);
        Ok(())
    }
}
