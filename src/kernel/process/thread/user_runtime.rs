//! src/kernel/process/thread/user_runtime.rs
//!
//! User-runtime state management: snapshot, validate, restore, replace, and
//! clear user-mode execution context.

use crate::Error;
use crate::Result;

use super::super::ProcessState;
use super::types::ThreadExecutionState;
use super::types::ThreadState;
use super::types::ThreadUserRuntimeState;
use super::types::UserThreadStart;
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
        drop(execution_state);

        // The per-architecture half is the architecture's to clear; see
        // `crate::arch::thread`.
        crate::arch::thread::clear_user_runtime_state(self);
    }

    pub(crate) fn snapshot_user_runtime_state(&self) -> Result<ThreadUserRuntimeState> {
        self.ensure_user_runtime_mutable()?;
        let state = crate::arch::thread::new_user_runtime_state(self, *self.execution_state.lock());
        Self::validate_restored_user_runtime_state(&state)?;
        Ok(state)
    }

    fn validate_restored_user_runtime_state(state: &ThreadUserRuntimeState) -> Result<()> {
        let user_start = state
            .execution_state
            .user_start
            .ok_or(Error::InvalidArgument)?;
        user_start.validate()?;

        crate::arch::thread::validate_user_runtime_state(state)
    }

    pub(crate) fn restore_user_runtime_state(&self, state: ThreadUserRuntimeState) -> Result<()> {
        self.ensure_runtime_mutable()?;
        Self::validate_restored_user_runtime_state(&state)?;
        *self.execution_state.lock() = state.execution_state;
        crate::arch::thread::restore_user_runtime_state(self, state);
        Ok(())
    }

    #[cfg_attr(
        any(
            all(target_arch = "riscv64", target_os = "none"),
            all(target_arch = "aarch64", not(target_os = "none"))
        ),
        allow(dead_code)
    )]
    pub(crate) fn replace_user_execution_state(
        &self,
        start: UserThreadStart,
        update_arch_state: impl FnOnce(&mut ThreadExecutionState),
    ) -> Result<()> {
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
