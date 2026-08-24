//! src/kernel/syscall/process/launch/decode.rs
//!
//! Launch-option decoding: limits, profiles, string-list reading, and override specs.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::abi::process::{self as process_abi, ProcessSpawnStringRef};
use crate::user::program::SpawnProcessOverrides;
use crate::{Error, Result};

use super::{
    MAX_ARGUMENT_OVERRIDE_ENTRIES, MAX_ARGUMENT_OVERRIDE_TOTAL_BYTES,
    MAX_ENVIRONMENT_OVERRIDE_ENTRIES, MAX_ENVIRONMENT_OVERRIDE_TOTAL_BYTES,
    MAX_EXEC_ARGUMENT_OVERRIDE_ENTRIES, MAX_EXEC_ARGUMENT_OVERRIDE_TOTAL_BYTES,
    MAX_EXEC_ENVIRONMENT_OVERRIDE_ENTRIES, MAX_EXEC_ENVIRONMENT_OVERRIDE_TOTAL_BYTES,
    MAX_EXEC_OVERRIDE_BUDGET_BYTES, MAX_EXEC_WORKING_DIR_BYTES, MAX_OVERRIDE_BUDGET_BYTES,
    MAX_OVERRIDE_STRING_BYTES, MAX_WORKING_DIR_BYTES,
};

// ── Limits & profile types ────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub(super) struct StringListLimits {
    pub(super) max_entries: usize,
    pub(super) max_total_payload_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct LaunchDecodeLimits {
    pub(super) argument: StringListLimits,
    pub(super) environment: StringListLimits,
    pub(super) max_working_dir_bytes: usize,
    pub(super) max_override_budget_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct LaunchDecodeProfile {
    pub(super) known_flags: usize,
    pub(super) limits: LaunchDecodeLimits,
}

impl LaunchDecodeProfile {
    pub(super) fn decode(
        self,
        current_working_dir: &str,
        options_ptr: *const u8,
        options_len: usize,
    ) -> Result<DecodedLaunchOptions> {
        let (option_flags, override_specs) =
            self.read_option_flags_and_override_specs(options_ptr, options_len)?;
        let overrides = override_specs
            .decode_with_budget(current_working_dir, self.limits.max_override_budget_bytes)?;

        Ok(DecodedLaunchOptions {
            option_flags,
            overrides,
        })
    }

    fn read_option_flags_and_override_specs(
        self,
        options_ptr: *const u8,
        options_len: usize,
    ) -> Result<(usize, LaunchOverrideSpecs)> {
        let options = self.read_options(options_ptr, options_len)?;
        let option_flags = options.flags;
        let override_specs = LaunchOverrideSpecs::from_options(&options, self.limits);
        override_specs.validate()?;
        Ok((option_flags, override_specs))
    }

    fn read_options(
        self,
        options_ptr: *const u8,
        options_len: usize,
    ) -> Result<process_abi::ProcessSpawnOptions> {
        if options_len == 0 {
            if !options_ptr.is_null() {
                return Err(Error::InvalidArgument);
            }
            return Ok(process_abi::ProcessSpawnOptions::defaults());
        }

        if options_len != process_abi::PROCESS_SPAWN_OPTIONS_SIZE {
            return Err(Error::InvalidArgument);
        }

        let options = super::super::user_memory::read_user_value::<process_abi::ProcessSpawnOptions>(
            options_ptr,
            options_len,
            process_abi::PROCESS_SPAWN_OPTIONS_SIZE,
        )?;

        super::super::validate_known_flags(options.flags, self.known_flags)?;
        Ok(options)
    }
}

// ── Constant limit/profile instances ──────────────────────────────────

const ARGUMENT_STRING_LIST_LIMITS: StringListLimits = StringListLimits {
    max_entries: MAX_ARGUMENT_OVERRIDE_ENTRIES,
    max_total_payload_bytes: MAX_ARGUMENT_OVERRIDE_TOTAL_BYTES,
};

const ENVIRONMENT_STRING_LIST_LIMITS: StringListLimits = StringListLimits {
    max_entries: MAX_ENVIRONMENT_OVERRIDE_ENTRIES,
    max_total_payload_bytes: MAX_ENVIRONMENT_OVERRIDE_TOTAL_BYTES,
};

const EXEC_ARGUMENT_STRING_LIST_LIMITS: StringListLimits = StringListLimits {
    max_entries: MAX_EXEC_ARGUMENT_OVERRIDE_ENTRIES,
    max_total_payload_bytes: MAX_EXEC_ARGUMENT_OVERRIDE_TOTAL_BYTES,
};

const EXEC_ENVIRONMENT_STRING_LIST_LIMITS: StringListLimits = StringListLimits {
    max_entries: MAX_EXEC_ENVIRONMENT_OVERRIDE_ENTRIES,
    max_total_payload_bytes: MAX_EXEC_ENVIRONMENT_OVERRIDE_TOTAL_BYTES,
};

pub(super) const SPAWN_LAUNCH_DECODE_LIMITS: LaunchDecodeLimits = LaunchDecodeLimits {
    argument: ARGUMENT_STRING_LIST_LIMITS,
    environment: ENVIRONMENT_STRING_LIST_LIMITS,
    max_working_dir_bytes: MAX_WORKING_DIR_BYTES,
    max_override_budget_bytes: MAX_OVERRIDE_BUDGET_BYTES,
};

pub(super) const EXEC_LAUNCH_DECODE_LIMITS: LaunchDecodeLimits = LaunchDecodeLimits {
    argument: EXEC_ARGUMENT_STRING_LIST_LIMITS,
    environment: EXEC_ENVIRONMENT_STRING_LIST_LIMITS,
    max_working_dir_bytes: MAX_EXEC_WORKING_DIR_BYTES,
    max_override_budget_bytes: MAX_EXEC_OVERRIDE_BUDGET_BYTES,
};

pub(super) const SPAWN_LAUNCH_DECODE_PROFILE: LaunchDecodeProfile = LaunchDecodeProfile {
    known_flags: super::super::PROCESS_SPAWN_KNOWN_FLAGS,
    limits: SPAWN_LAUNCH_DECODE_LIMITS,
};

pub(super) const EXEC_LAUNCH_DECODE_PROFILE: LaunchDecodeProfile = LaunchDecodeProfile {
    known_flags: super::super::PROCESS_EXEC_KNOWN_FLAGS,
    limits: EXEC_LAUNCH_DECODE_LIMITS,
};

// ── Decoded launch options ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(super) struct DecodedLaunchOptions {
    pub(super) option_flags: usize,
    pub(super) overrides: SpawnProcessOverrides,
}

// ── Override specs ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(super) struct LaunchOverrideSpecs {
    arguments: StringListOverrideSpec,
    environment: StringListOverrideSpec,
    working_dir: WorkingDirOverrideSpec,
}

impl LaunchOverrideSpecs {
    pub(super) fn from_options(
        options: &process_abi::ProcessSpawnOptions,
        limits: LaunchDecodeLimits,
    ) -> Self {
        Self {
            arguments: StringListOverrideSpec::new(
                options.overrides_arguments(),
                options.argv,
                options.argc,
                limits.argument,
            ),
            environment: StringListOverrideSpec::new(
                options.overrides_environment(),
                options.env,
                options.envc,
                limits.environment,
            ),
            working_dir: WorkingDirOverrideSpec::new(
                options.overrides_working_dir(),
                options.inherits_working_dir(),
                options.working_dir,
                options.working_dir_len,
                limits.max_working_dir_bytes,
            ),
        }
    }

    fn validate(&self) -> Result<()> {
        self.arguments.validate()?;
        self.environment.validate()?;
        self.working_dir.validate()
    }

    fn decode_with_budget(
        self,
        current_working_dir: &str,
        max_override_budget_bytes: usize,
    ) -> Result<SpawnProcessOverrides> {
        let overrides = self.decode(current_working_dir)?;
        if decoded_override_budget_bytes(&overrides)? > max_override_budget_bytes {
            return Err(Error::InvalidArgument);
        }
        Ok(overrides)
    }

    fn decode(self, current_working_dir: &str) -> Result<SpawnProcessOverrides> {
        Ok(SpawnProcessOverrides {
            arguments: self.arguments.decode()?,
            environment: self.environment.decode()?,
            working_dir: self.working_dir.decode(current_working_dir)?,
        })
    }
}

#[derive(Debug, Clone)]
struct StringListOverrideSpec {
    enabled: bool,
    entries_ptr: usize,
    count: usize,
    limits: StringListLimits,
}

impl StringListOverrideSpec {
    const fn new(
        enabled: bool,
        entries_ptr: usize,
        count: usize,
        limits: StringListLimits,
    ) -> Self {
        Self {
            enabled,
            entries_ptr,
            count,
            limits,
        }
    }

    fn validate(&self) -> Result<()> {
        if !self.enabled && (self.entries_ptr != 0 || self.count != 0) {
            return Err(Error::InvalidArgument);
        }

        if !self.enabled {
            return Ok(());
        }

        if self.count > self.limits.max_entries {
            return Err(Error::InvalidArgument);
        }

        // Keep pointer/count pairing strict to reject malformed ABI payloads early.
        if (self.count == 0) != (self.entries_ptr == 0) {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }

    fn decode(self) -> Result<Option<Vec<String>>> {
        if !self.enabled {
            return Ok(None);
        }

        read_string_list_with_limits(self.entries_ptr as *const u8, self.count, self.limits)
            .map(Some)
    }
}

#[derive(Debug, Clone, Copy)]
enum WorkingDirOverrideMode {
    Default,
    Inherit,
    Override { path_ptr: usize, path_len: usize },
}

#[derive(Debug, Clone, Copy)]
struct WorkingDirOverrideSpec {
    overrides: bool,
    inherits: bool,
    path_ptr: usize,
    path_len: usize,
    max_bytes: usize,
}

impl WorkingDirOverrideSpec {
    const fn new(
        overrides: bool,
        inherits: bool,
        path_ptr: usize,
        path_len: usize,
        max_bytes: usize,
    ) -> Self {
        Self {
            overrides,
            inherits,
            path_ptr,
            path_len,
            max_bytes,
        }
    }

    fn validate(self) -> Result<()> {
        self.mode().map(|_| ())
    }

    fn decode(self, current_working_dir: &str) -> Result<Option<String>> {
        match self.mode()? {
            WorkingDirOverrideMode::Default => Ok(None),
            WorkingDirOverrideMode::Inherit => Ok(Some(current_working_dir.to_string())),
            WorkingDirOverrideMode::Override { path_ptr, path_len } => {
                super::super::user_memory::user_string(path_ptr as *const u8, path_len).map(Some)
            }
        }
    }

    fn mode(self) -> Result<WorkingDirOverrideMode> {
        // Working directory is either inherited, explicitly overridden, or
        // left to the loader defaults, but never a mixture of those modes.
        if self.overrides && self.inherits {
            return Err(Error::InvalidArgument);
        }

        if self.overrides {
            if self.path_len > self.max_bytes {
                return Err(Error::InvalidArgument);
            }

            if self.path_ptr == 0 || self.path_len == 0 {
                return Err(Error::InvalidArgument);
            }

            return Ok(WorkingDirOverrideMode::Override {
                path_ptr: self.path_ptr,
                path_len: self.path_len,
            });
        }

        if self.path_ptr != 0 || self.path_len != 0 {
            return Err(Error::InvalidArgument);
        }

        if self.inherits {
            return Ok(WorkingDirOverrideMode::Inherit);
        }

        Ok(WorkingDirOverrideMode::Default)
    }
}

// ── Decode helpers ────────────────────────────────────────────────────

fn decoded_override_budget_bytes(overrides: &SpawnProcessOverrides) -> Result<usize> {
    let mut used_budget = 0usize;
    // Count decoded bytes, not declared counts, to enforce real payload cost.
    for values in [
        overrides.arguments.as_deref(),
        overrides.environment.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        for value in values {
            used_budget = used_budget
                .checked_add(value.len())
                .ok_or(Error::InvalidArgument)?;
        }
    }
    if let Some(working_dir) = overrides.working_dir.as_deref() {
        used_budget = used_budget
            .checked_add(working_dir.len())
            .ok_or(Error::InvalidArgument)?;
    }
    Ok(used_budget)
}

fn read_string_list_with_limits(
    entries_ptr: *const u8,
    count: usize,
    limits: StringListLimits,
) -> Result<Vec<String>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    if count > limits.max_entries {
        return Err(Error::InvalidArgument);
    }

    if entries_ptr.is_null() {
        return Err(Error::InvalidArgument);
    }

    let entries_len = count
        .checked_mul(process_abi::PROCESS_SPAWN_STRING_REF_SIZE)
        .ok_or(Error::InvalidArgument)?;
    // Validate the descriptor array first, then validate each pointed-to string
    // as it is decoded so malformed user buffers fail before partial launch.
    super::super::user_memory::validate_current_process_user_input_buffer(
        entries_ptr,
        entries_len,
        entries_len,
    )?;

    let mut values = Vec::new();
    values.try_reserve(count).map_err(|_| Error::OutOfMemory)?;
    let mut total_payload_bytes = 0usize;
    for index in 0..count {
        let byte_offset = index
            .checked_mul(process_abi::PROCESS_SPAWN_STRING_REF_SIZE)
            .ok_or(Error::InvalidArgument)?;
        let entry_ptr = unsafe { entries_ptr.add(byte_offset).cast::<ProcessSpawnStringRef>() };
        // Read the spawn-string descriptor from user memory inside a SMAP
        // guard so the hardware allows supervisor access to user pages.
        let entry = super::super::user_memory::with_user_access_guard(|| unsafe {
            core::ptr::read_unaligned(entry_ptr)
        });

        if entry.len > MAX_OVERRIDE_STRING_BYTES {
            return Err(Error::InvalidArgument);
        }

        total_payload_bytes = total_payload_bytes
            .checked_add(entry.len)
            .ok_or(Error::InvalidArgument)?;
        if total_payload_bytes > limits.max_total_payload_bytes {
            return Err(Error::InvalidArgument);
        }

        values.push(super::super::user_memory::user_string(
            entry.ptr as *const u8,
            entry.len,
        )?);
    }

    Ok(values)
}
