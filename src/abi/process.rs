//! src/abi/process.rs
//!
//! Shared process ABI constants and records for spawn, wait, and termination
//! flows.

use core::mem::{offset_of, size_of};

use super::exception::AArch64AbortSyndrome;

pub const PROCESS_TERMINATION_KIND_NONE: usize = 0;
pub const PROCESS_TERMINATION_KIND_EXIT: usize = 1;
pub const PROCESS_TERMINATION_KIND_EXCEPTION: usize = 2;
/// Reserved non-zero timeout sentinel for `wait_process`.
///
/// Callers pass this value in `timeout_ticks` to request a blocking wait on
/// bare-metal targets that support scheduler context switching.
pub const WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS: usize = usize::MAX;
pub const PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS: usize = 1 << 0;
pub const PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT: usize = 1 << 1;
pub const PROCESS_SPAWN_FLAG_OVERRIDE_WORKING_DIR: usize = 1 << 2;
pub const PROCESS_SPAWN_FLAG_INHERIT_WORKING_DIR: usize = 1 << 3;
pub const PROCESS_SPAWN_FLAG_INHERIT_STDIN: usize = 1 << 4;
pub const PROCESS_SPAWN_FLAG_INHERIT_STDOUT: usize = 1 << 5;
pub const PROCESS_SPAWN_FLAG_INHERIT_STDERR: usize = 1 << 6;
pub const PROCESS_SPAWN_FLAG_INHERIT_STDIO: usize = PROCESS_SPAWN_FLAG_INHERIT_STDIN
    | PROCESS_SPAWN_FLAG_INHERIT_STDOUT
    | PROCESS_SPAWN_FLAG_INHERIT_STDERR;
/// When set, the child inherits every open file descriptor that does not have
/// `FD_CLOEXEC` set, in addition to any stdio handles requested via the
/// individual `INHERIT_STD{IN,OUT,ERR}` flags.
pub const PROCESS_SPAWN_FLAG_INHERIT_FDS: usize = 1 << 7;
/// When set, the child process is created but not placed in the ready queue.
/// It stays suspended until the parent calls `wait_process`, which resumes
/// the child before blocking.  This eliminates the race where a child faults
/// (with no exception handler) before the parent can register a wait.
pub const PROCESS_SPAWN_FLAG_START_SUSPENDED: usize = 1 << 8;
pub const PROCESS_SIGNAL_MIN: usize = 1;
pub const PROCESS_SIGNAL_MAX: usize = 31;
pub const PROCESS_SIGNAL_FLAG_NONE: usize = 0;
pub const PROCESS_SIGNAL_KNOWN_FLAGS: usize = PROCESS_SIGNAL_FLAG_NONE;
pub const WAIT_SIGNAL_BLOCK_INDEFINITELY_TICKS: usize = WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS;

// ── POSIX well-known signal numbers ──────────────────────────────────────

pub const SIGHUP: usize = 1;
pub const SIGINT: usize = 2;
pub const SIGQUIT: usize = 3;
pub const SIGKILL: usize = 9;
pub const SIGUSR1: usize = 10;
pub const SIGUSR2: usize = 12;
pub const SIGPIPE: usize = 13;
pub const SIGALRM: usize = 14;
pub const SIGTERM: usize = 15;
pub const SIGCHLD: usize = 17;
pub const SIGCONT: usize = 18;
pub const SIGSTOP: usize = 19;
pub const SIGTSTP: usize = 20;
pub const SIGSYS: usize = 31;

pub const fn is_valid_process_signal(signal: usize) -> bool {
    signal >= PROCESS_SIGNAL_MIN && signal <= PROCESS_SIGNAL_MAX
}

/// `sa_flags` bit: restart interrupted syscalls after the handler returns.
/// Matches the Linux value (bit 28 of `sa_flags`).
pub const SA_RESTART: u64 = 0x1000_0000;

/// Mask of `SA_*` flags the kernel understands and will act on.  Only
/// `SA_RESTART` is currently supported; `SetSignalHandler` rejects any other
/// bit rather than silently ignoring it.
pub const SIGNAL_SA_FLAGS_KNOWN: u64 = SA_RESTART;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size termination record written by `wait_process`.
///
/// User space must provide an output buffer whose byte length is exactly
/// `PROCESS_TERMINATION_RECORD_SIZE`.
pub struct ProcessTerminationRecord {
    pub kind: usize,
    pub status: usize,
    pub vector: u64,
    pub error_code: u64,
    pub fault_address_present: usize,
    pub fault_address: usize,
}

impl ProcessTerminationRecord {
    pub const fn none() -> Self {
        Self {
            kind: PROCESS_TERMINATION_KIND_NONE,
            status: 0,
            vector: 0,
            error_code: 0,
            fault_address_present: 0,
            fault_address: 0,
        }
    }

    pub const fn exited(status: usize) -> Self {
        Self {
            kind: PROCESS_TERMINATION_KIND_EXIT,
            status,
            vector: 0,
            error_code: 0,
            fault_address_present: 0,
            fault_address: 0,
        }
    }

    pub const fn exception(vector: u8, error_code: u64, fault_address: Option<usize>) -> Self {
        Self {
            kind: PROCESS_TERMINATION_KIND_EXCEPTION,
            status: 0,
            vector: vector as u64,
            error_code,
            fault_address_present: fault_address.is_some() as usize,
            fault_address: match fault_address {
                Some(address) => address,
                None => 0,
            },
        }
    }

    #[inline(always)]
    pub const fn aarch64_abort_syndrome(&self) -> Option<AArch64AbortSyndrome> {
        if self.kind != PROCESS_TERMINATION_KIND_EXCEPTION {
            return None;
        }

        AArch64AbortSyndrome::from_exception(self.vector as u8, self.error_code)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size process signal record delivered by `wait_signal`.
///
/// `signal` and `payload` are user-defined values. `sender_pid` identifies the
/// sending process so receivers can attribute cooperative notifications.
pub struct ProcessSignalRecord {
    pub signal: usize,
    pub sender_pid: usize,
    pub payload: usize,
}

impl ProcessSignalRecord {
    pub const fn new(signal: usize, sender_pid: usize, payload: usize) -> Self {
        Self {
            signal,
            sender_pid,
            payload,
        }
    }
}

/// Required byte size for `ProcessTerminationRecord`.
pub const PROCESS_TERMINATION_RECORD_SIZE: usize = size_of::<ProcessTerminationRecord>();
pub const PROCESS_TERMINATION_RECORD_KIND_OFFSET: usize =
    offset_of!(ProcessTerminationRecord, kind);
pub const PROCESS_TERMINATION_RECORD_STATUS_OFFSET: usize =
    offset_of!(ProcessTerminationRecord, status);
pub const PROCESS_TERMINATION_RECORD_VECTOR_OFFSET: usize =
    offset_of!(ProcessTerminationRecord, vector);
pub const PROCESS_TERMINATION_RECORD_ERROR_CODE_OFFSET: usize =
    offset_of!(ProcessTerminationRecord, error_code);
pub const PROCESS_TERMINATION_RECORD_FAULT_ADDRESS_PRESENT_OFFSET: usize =
    offset_of!(ProcessTerminationRecord, fault_address_present);
pub const PROCESS_TERMINATION_RECORD_FAULT_ADDRESS_OFFSET: usize =
    offset_of!(ProcessTerminationRecord, fault_address);
pub const PROCESS_SIGNAL_RECORD_SIZE: usize = size_of::<ProcessSignalRecord>();
pub const PROCESS_SIGNAL_RECORD_SIGNAL_OFFSET: usize = offset_of!(ProcessSignalRecord, signal);
pub const PROCESS_SIGNAL_RECORD_SENDER_PID_OFFSET: usize =
    offset_of!(ProcessSignalRecord, sender_pid);
pub const PROCESS_SIGNAL_RECORD_PAYLOAD_OFFSET: usize = offset_of!(ProcessSignalRecord, payload);

/// Frame pushed onto the user stack for async (preemptive) signal delivery.
///
/// The kernel writes this below the user's current RSP before rewriting the
/// InterruptContext to jump to the user handler.  When the handler returns,
/// the ring3 trampoline passes a pointer to this frame to `SYS_SIGRETURN`,
/// which restores the original RIP / RSP / RFLAGS.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalFrame {
    /// Original RIP of the interrupted user code.
    pub orig_rip: u64,
    /// Original RSP of the interrupted user code.
    pub orig_rsp: u64,
    /// Original RFLAGS of the interrupted user code.
    pub orig_rflags: u64,
    /// Signal number being delivered.
    pub signal: u64,
}

/// Wire size of [`SignalFrame`].
pub const SIGNAL_FRAME_SIZE: usize = size_of::<SignalFrame>();

/// AArch64-specific signal frame, pushed on the user stack by
/// [`try_async_signal_delivery_aarch64`].
///
/// Layout-compatible with [`SignalFrame`] (4 × u64 = 32 bytes) but stores
/// AArch64 exception-return state (ELR, SP, SPSR) rather than x86_64
/// (RIP, RSP, RFLAGS).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AArch64SignalFrame {
    /// Original ELR_EL1 of the interrupted user code.
    pub orig_elr: u64,
    /// Original SP_EL0 of the interrupted user code.
    pub orig_sp: u64,
    /// Original SPSR_EL1 of the interrupted user code.
    pub orig_spsr: u64,
    /// Signal number being delivered.
    pub signal: u64,
}

/// Wire size of [`AArch64SignalFrame`].
pub const AARCH64_SIGNAL_FRAME_SIZE: usize = size_of::<AArch64SignalFrame>();

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size string descriptor used by `ProcessSpawnOptions`.
///
/// Strings are passed as UTF-8 byte slices without a trailing NUL. When
/// `len == 0`, the entry represents an explicit empty string and `ptr` is
/// ignored.
pub struct ProcessSpawnStringRef {
    pub ptr: usize,
    pub len: usize,
}

impl ProcessSpawnStringRef {
    pub const fn new(ptr: usize, len: usize) -> Self {
        Self { ptr, len }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size launch-options block shared by `spawn_process` and
/// `exec_process`.
///
/// User space must either pass exactly `PROCESS_SPAWN_OPTIONS_SIZE` bytes, or
/// pass `options_len == 0` with `options_ptr == 0` to select
/// manifest/default launch metadata.
pub struct ProcessSpawnOptions {
    pub flags: usize,
    pub argv: usize,
    pub argc: usize,
    pub env: usize,
    pub envc: usize,
    pub working_dir: usize,
    pub working_dir_len: usize,
}

impl ProcessSpawnOptions {
    pub const fn defaults() -> Self {
        Self {
            flags: 0,
            argv: 0,
            argc: 0,
            env: 0,
            envc: 0,
            working_dir: 0,
            working_dir_len: 0,
        }
    }

    pub const fn new(flags: usize, argv: usize, argc: usize, env: usize, envc: usize) -> Self {
        Self {
            flags,
            argv,
            argc,
            env,
            envc,
            working_dir: 0,
            working_dir_len: 0,
        }
    }

    pub const fn with_flags(mut self, flags: usize) -> Self {
        self.flags |= flags;
        self
    }

    pub const fn with_working_dir(mut self, working_dir: usize, working_dir_len: usize) -> Self {
        self.working_dir = working_dir;
        self.working_dir_len = working_dir_len;
        self
    }

    pub const fn override_argv(argv: usize, argc: usize) -> Self {
        Self::new(PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS, argv, argc, 0, 0)
    }

    pub const fn override_env(env: usize, envc: usize) -> Self {
        Self::new(PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT, 0, 0, env, envc)
    }

    pub const fn override_argv_env(argv: usize, argc: usize, env: usize, envc: usize) -> Self {
        Self::new(
            PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS | PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT,
            argv,
            argc,
            env,
            envc,
        )
    }

    pub const fn override_working_dir(working_dir: usize, working_dir_len: usize) -> Self {
        Self::defaults()
            .with_flags(PROCESS_SPAWN_FLAG_OVERRIDE_WORKING_DIR)
            .with_working_dir(working_dir, working_dir_len)
    }

    pub const fn inherit_working_dir() -> Self {
        Self::defaults().with_flags(PROCESS_SPAWN_FLAG_INHERIT_WORKING_DIR)
    }

    pub const fn inherit_stdio() -> Self {
        Self::defaults().with_flags(PROCESS_SPAWN_FLAG_INHERIT_STDIO)
    }

    const fn has_flags(self, flags: usize) -> bool {
        self.flags & flags == flags
    }

    pub const fn overrides_arguments(self) -> bool {
        self.has_flags(PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS)
    }

    pub const fn overrides_environment(self) -> bool {
        self.has_flags(PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT)
    }

    pub const fn overrides_working_dir(self) -> bool {
        self.has_flags(PROCESS_SPAWN_FLAG_OVERRIDE_WORKING_DIR)
    }

    pub const fn inherits_working_dir(self) -> bool {
        self.has_flags(PROCESS_SPAWN_FLAG_INHERIT_WORKING_DIR)
    }

    pub const fn inherits_stdin(self) -> bool {
        self.has_flags(PROCESS_SPAWN_FLAG_INHERIT_STDIN)
    }

    pub const fn inherits_stdout(self) -> bool {
        self.has_flags(PROCESS_SPAWN_FLAG_INHERIT_STDOUT)
    }

    pub const fn inherits_stderr(self) -> bool {
        self.has_flags(PROCESS_SPAWN_FLAG_INHERIT_STDERR)
    }
}

/// Required byte size for `ProcessSpawnStringRef`.
pub const PROCESS_SPAWN_STRING_REF_SIZE: usize = size_of::<ProcessSpawnStringRef>();
pub const PROCESS_SPAWN_STRING_REF_PTR_OFFSET: usize = offset_of!(ProcessSpawnStringRef, ptr);
pub const PROCESS_SPAWN_STRING_REF_LEN_OFFSET: usize = offset_of!(ProcessSpawnStringRef, len);
/// Required byte size for `ProcessSpawnOptions`.
pub const PROCESS_SPAWN_OPTIONS_SIZE: usize = size_of::<ProcessSpawnOptions>();
pub const PROCESS_SPAWN_OPTIONS_FLAGS_OFFSET: usize = offset_of!(ProcessSpawnOptions, flags);
pub const PROCESS_SPAWN_OPTIONS_ARGV_OFFSET: usize = offset_of!(ProcessSpawnOptions, argv);
pub const PROCESS_SPAWN_OPTIONS_ARGC_OFFSET: usize = offset_of!(ProcessSpawnOptions, argc);
pub const PROCESS_SPAWN_OPTIONS_ENV_OFFSET: usize = offset_of!(ProcessSpawnOptions, env);
pub const PROCESS_SPAWN_OPTIONS_ENVC_OFFSET: usize = offset_of!(ProcessSpawnOptions, envc);
pub const PROCESS_SPAWN_OPTIONS_WORKING_DIR_OFFSET: usize =
    offset_of!(ProcessSpawnOptions, working_dir);
pub const PROCESS_SPAWN_OPTIONS_WORKING_DIR_LEN_OFFSET: usize =
    offset_of!(ProcessSpawnOptions, working_dir_len);

#[cfg(test)]
mod tests {
    use super::{
        is_valid_process_signal, ProcessSignalRecord, ProcessSpawnOptions, ProcessSpawnStringRef,
        ProcessTerminationRecord, PROCESS_SIGNAL_FLAG_NONE, PROCESS_SIGNAL_KNOWN_FLAGS,
        PROCESS_SIGNAL_MAX, PROCESS_SIGNAL_MIN, PROCESS_SIGNAL_RECORD_PAYLOAD_OFFSET,
        PROCESS_SIGNAL_RECORD_SENDER_PID_OFFSET, PROCESS_SIGNAL_RECORD_SIGNAL_OFFSET,
        PROCESS_SIGNAL_RECORD_SIZE, PROCESS_SPAWN_FLAG_INHERIT_STDERR,
        PROCESS_SPAWN_FLAG_INHERIT_STDIN, PROCESS_SPAWN_FLAG_INHERIT_STDIO,
        PROCESS_SPAWN_FLAG_INHERIT_STDOUT, PROCESS_SPAWN_FLAG_INHERIT_WORKING_DIR,
        PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS, PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT,
        PROCESS_SPAWN_FLAG_OVERRIDE_WORKING_DIR, PROCESS_SPAWN_OPTIONS_ARGC_OFFSET,
        PROCESS_SPAWN_OPTIONS_ARGV_OFFSET, PROCESS_SPAWN_OPTIONS_ENVC_OFFSET,
        PROCESS_SPAWN_OPTIONS_ENV_OFFSET, PROCESS_SPAWN_OPTIONS_FLAGS_OFFSET,
        PROCESS_SPAWN_OPTIONS_SIZE, PROCESS_SPAWN_OPTIONS_WORKING_DIR_LEN_OFFSET,
        PROCESS_SPAWN_OPTIONS_WORKING_DIR_OFFSET, PROCESS_SPAWN_STRING_REF_LEN_OFFSET,
        PROCESS_SPAWN_STRING_REF_PTR_OFFSET, PROCESS_SPAWN_STRING_REF_SIZE,
        PROCESS_TERMINATION_KIND_EXCEPTION, PROCESS_TERMINATION_KIND_EXIT,
        PROCESS_TERMINATION_KIND_NONE, PROCESS_TERMINATION_RECORD_ERROR_CODE_OFFSET,
        PROCESS_TERMINATION_RECORD_FAULT_ADDRESS_OFFSET,
        PROCESS_TERMINATION_RECORD_FAULT_ADDRESS_PRESENT_OFFSET,
        PROCESS_TERMINATION_RECORD_KIND_OFFSET, PROCESS_TERMINATION_RECORD_SIZE,
        PROCESS_TERMINATION_RECORD_STATUS_OFFSET, PROCESS_TERMINATION_RECORD_VECTOR_OFFSET,
        WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS, WAIT_SIGNAL_BLOCK_INDEFINITELY_TICKS,
    };
    use core::mem::offset_of;

    #[test]
    fn process_termination_record_constructors_encode_expected_fields() {
        assert_eq!(
            ProcessTerminationRecord::none(),
            ProcessTerminationRecord {
                kind: PROCESS_TERMINATION_KIND_NONE,
                status: 0,
                vector: 0,
                error_code: 0,
                fault_address_present: 0,
                fault_address: 0,
            }
        );

        assert_eq!(
            ProcessTerminationRecord::exited(23),
            ProcessTerminationRecord {
                kind: PROCESS_TERMINATION_KIND_EXIT,
                status: 23,
                vector: 0,
                error_code: 0,
                fault_address_present: 0,
                fault_address: 0,
            }
        );

        assert_eq!(
            ProcessTerminationRecord::exception(14, 0x4, Some(0x7fff_ffff_d000)),
            ProcessTerminationRecord {
                kind: PROCESS_TERMINATION_KIND_EXCEPTION,
                status: 0,
                vector: 14,
                error_code: 0x4,
                fault_address_present: 1,
                fault_address: 0x7fff_ffff_d000,
            }
        );
    }

    #[test]
    fn process_termination_record_exposes_aarch64_abort_decoder() {
        let record = ProcessTerminationRecord::exception(0x24, 0x4f, Some(0x4040_2000));
        let syndrome = record
            .aarch64_abort_syndrome()
            .expect("aarch64 abort syndrome");

        assert_eq!(syndrome.fault_status_code(), 0x0f);
        assert_eq!(syndrome.fault_status_name(), "permission fault level 3");
        assert_eq!(syndrome.access_kind(), "write");
    }

    #[test]
    fn process_termination_record_size_matches_layout() {
        assert_eq!(
            PROCESS_TERMINATION_RECORD_SIZE,
            size_of::<ProcessTerminationRecord>()
        );
        assert_eq!(
            PROCESS_TERMINATION_RECORD_KIND_OFFSET,
            offset_of!(ProcessTerminationRecord, kind)
        );
        assert_eq!(
            PROCESS_TERMINATION_RECORD_STATUS_OFFSET,
            offset_of!(ProcessTerminationRecord, status)
        );
        assert_eq!(
            PROCESS_TERMINATION_RECORD_VECTOR_OFFSET,
            offset_of!(ProcessTerminationRecord, vector)
        );
        assert_eq!(
            PROCESS_TERMINATION_RECORD_ERROR_CODE_OFFSET,
            offset_of!(ProcessTerminationRecord, error_code)
        );
        assert_eq!(
            PROCESS_TERMINATION_RECORD_FAULT_ADDRESS_PRESENT_OFFSET,
            offset_of!(ProcessTerminationRecord, fault_address_present)
        );
        assert_eq!(
            PROCESS_TERMINATION_RECORD_FAULT_ADDRESS_OFFSET,
            offset_of!(ProcessTerminationRecord, fault_address)
        );
    }

    #[test]
    fn blocking_wait_timeout_uses_reserved_non_zero_sentinel() {
        assert_ne!(WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS, 0);
        assert_eq!(WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS, usize::MAX);
        assert_eq!(
            WAIT_SIGNAL_BLOCK_INDEFINITELY_TICKS,
            WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS
        );
    }

    #[test]
    fn process_signal_range_and_flags_are_stable() {
        assert_eq!(PROCESS_SIGNAL_MIN, 1);
        assert_eq!(PROCESS_SIGNAL_MAX, 31);
        assert_eq!(PROCESS_SIGNAL_FLAG_NONE, 0);
        assert_eq!(PROCESS_SIGNAL_KNOWN_FLAGS, 0);
        assert!(!is_valid_process_signal(0));
        assert!(is_valid_process_signal(PROCESS_SIGNAL_MIN));
        assert!(is_valid_process_signal(PROCESS_SIGNAL_MAX));
        assert!(!is_valid_process_signal(PROCESS_SIGNAL_MAX + 1));
    }

    #[test]
    fn process_signal_record_layout_matches_public_offsets() {
        let record = ProcessSignalRecord::new(3, 17, 0xfeed);
        assert_eq!(
            PROCESS_SIGNAL_RECORD_SIZE,
            core::mem::size_of::<ProcessSignalRecord>()
        );
        assert_eq!(PROCESS_SIGNAL_RECORD_SIGNAL_OFFSET, 0);
        assert_eq!(
            PROCESS_SIGNAL_RECORD_SENDER_PID_OFFSET,
            core::mem::size_of::<usize>()
        );
        assert_eq!(
            PROCESS_SIGNAL_RECORD_PAYLOAD_OFFSET,
            core::mem::size_of::<usize>() * 2
        );
        assert_eq!(record.signal, 3);
        assert_eq!(record.sender_pid, 17);
        assert_eq!(record.payload, 0xfeed);
    }

    #[test]
    fn signal_frame_size_and_layout() {
        use super::{SignalFrame, SIGNAL_FRAME_SIZE};
        assert_eq!(SIGNAL_FRAME_SIZE, 32);
        assert_eq!(SIGNAL_FRAME_SIZE, core::mem::size_of::<SignalFrame>());
        // Offset 0 = orig_rip
        // Offset 8 = orig_rsp
        // Offset 16 = orig_rflags
        // Offset 24 = signal
        assert_eq!(core::mem::offset_of!(SignalFrame, orig_rip), 0);
        assert_eq!(core::mem::offset_of!(SignalFrame, orig_rsp), 8);
        assert_eq!(core::mem::offset_of!(SignalFrame, orig_rflags), 16);
        assert_eq!(core::mem::offset_of!(SignalFrame, signal), 24);
    }

    #[test]
    fn process_spawn_options_constructors_encode_expected_fields() {
        assert_eq!(
            ProcessSpawnStringRef::new(0x4000, 24),
            ProcessSpawnStringRef {
                ptr: 0x4000,
                len: 24,
            }
        );

        assert_eq!(
            ProcessSpawnOptions::defaults(),
            ProcessSpawnOptions {
                flags: 0,
                argv: 0,
                argc: 0,
                env: 0,
                envc: 0,
                working_dir: 0,
                working_dir_len: 0,
            }
        );

        assert_eq!(
            ProcessSpawnOptions::override_argv(0x4100, 3),
            ProcessSpawnOptions {
                flags: PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS,
                argv: 0x4100,
                argc: 3,
                env: 0,
                envc: 0,
                working_dir: 0,
                working_dir_len: 0,
            }
        );

        assert_eq!(
            ProcessSpawnOptions::override_env(0x4200, 2),
            ProcessSpawnOptions {
                flags: PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT,
                argv: 0,
                argc: 0,
                env: 0x4200,
                envc: 2,
                working_dir: 0,
                working_dir_len: 0,
            }
        );

        let combined = ProcessSpawnOptions::override_argv_env(0x4300, 4, 0x4400, 5);
        assert_eq!(
            combined,
            ProcessSpawnOptions {
                flags: PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS
                    | PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT,
                argv: 0x4300,
                argc: 4,
                env: 0x4400,
                envc: 5,
                working_dir: 0,
                working_dir_len: 0,
            }
        );
        assert!(combined.overrides_arguments());
        assert!(combined.overrides_environment());

        let override_working_dir = ProcessSpawnOptions::override_working_dir(0x4500, 12);
        assert_eq!(
            override_working_dir,
            ProcessSpawnOptions {
                flags: PROCESS_SPAWN_FLAG_OVERRIDE_WORKING_DIR,
                argv: 0,
                argc: 0,
                env: 0,
                envc: 0,
                working_dir: 0x4500,
                working_dir_len: 12,
            }
        );
        assert!(override_working_dir.overrides_working_dir());

        let inherited =
            ProcessSpawnOptions::inherit_working_dir().with_flags(PROCESS_SPAWN_FLAG_INHERIT_STDIO);
        assert_eq!(
            inherited.flags,
            PROCESS_SPAWN_FLAG_INHERIT_WORKING_DIR | PROCESS_SPAWN_FLAG_INHERIT_STDIO
        );
        assert!(inherited.inherits_working_dir());
        assert!(inherited.inherits_stdin());
        assert!(inherited.inherits_stdout());
        assert!(inherited.inherits_stderr());
        assert_eq!(
            ProcessSpawnOptions::inherit_stdio().flags,
            PROCESS_SPAWN_FLAG_INHERIT_STDIN
                | PROCESS_SPAWN_FLAG_INHERIT_STDOUT
                | PROCESS_SPAWN_FLAG_INHERIT_STDERR
        );
    }

    #[test]
    fn process_spawn_abi_sizes_match_layout() {
        assert_eq!(
            PROCESS_SPAWN_STRING_REF_SIZE,
            size_of::<ProcessSpawnStringRef>()
        );
        assert_eq!(PROCESS_SPAWN_OPTIONS_SIZE, size_of::<ProcessSpawnOptions>());
        assert_eq!(
            PROCESS_SPAWN_STRING_REF_PTR_OFFSET,
            offset_of!(ProcessSpawnStringRef, ptr)
        );
        assert_eq!(
            PROCESS_SPAWN_STRING_REF_LEN_OFFSET,
            offset_of!(ProcessSpawnStringRef, len)
        );
        assert_eq!(
            PROCESS_SPAWN_OPTIONS_FLAGS_OFFSET,
            offset_of!(ProcessSpawnOptions, flags)
        );
        assert_eq!(
            PROCESS_SPAWN_OPTIONS_ARGV_OFFSET,
            offset_of!(ProcessSpawnOptions, argv)
        );
        assert_eq!(
            PROCESS_SPAWN_OPTIONS_ARGC_OFFSET,
            offset_of!(ProcessSpawnOptions, argc)
        );
        assert_eq!(
            PROCESS_SPAWN_OPTIONS_ENV_OFFSET,
            offset_of!(ProcessSpawnOptions, env)
        );
        assert_eq!(
            PROCESS_SPAWN_OPTIONS_ENVC_OFFSET,
            offset_of!(ProcessSpawnOptions, envc)
        );
        assert_eq!(
            PROCESS_SPAWN_OPTIONS_WORKING_DIR_OFFSET,
            offset_of!(ProcessSpawnOptions, working_dir)
        );
        assert_eq!(
            PROCESS_SPAWN_OPTIONS_WORKING_DIR_LEN_OFFSET,
            offset_of!(ProcessSpawnOptions, working_dir_len)
        );
    }
}
