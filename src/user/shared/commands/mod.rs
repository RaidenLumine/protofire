//! src/user/shared/commands/mod.rs
//!
//! ring3-common/src/commands/mod.rs
//! Shell builtin command implementations shared between kernel and ring3.
//!
//! Commands that require kernel-specific APIs (network stack, user database,
//! Scheduler) remain in the kernel crate.  All other commands live here and
//! use the syscall bridge (`crate::syscall`) for I/O.

pub(crate) mod fs;
mod fuse;
mod perf;
mod process;
mod state;
mod system;
pub(crate) mod text;

pub use fs::{
    cmd_cat, cmd_cd, cmd_chmod, cmd_cp, cmd_df, cmd_du, cmd_ls, cmd_mkdir, cmd_mv, cmd_pwd, cmd_rm,
    cmd_touch, human_size,
};
pub use fuse::cmd_fuse;
pub use perf::cmd_perf;
pub use process::{cmd_false, cmd_kill, cmd_ps, cmd_true};
pub use state::{cmd_alias, cmd_export, cmd_history, cmd_read, cmd_shift, cmd_source};
pub use system::{
    cmd_clear, cmd_dmesg, cmd_echo, cmd_help, cmd_sleep, cmd_sysinfo, cmd_test, cmd_top, cmd_uname,
    cmd_uptime,
};
pub use text::{
    cmd_diff, cmd_edit, cmd_find, cmd_grep, cmd_head, cmd_hexdump, cmd_sort, cmd_tail, cmd_uniq,
    cmd_wc, parse_head_tail_args,
};
