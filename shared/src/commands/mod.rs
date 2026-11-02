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

pub use fs::cmd_cat;
pub use fs::cmd_cd;
pub use fs::cmd_chmod;
pub use fs::cmd_cp;
pub use fs::cmd_df;
pub use fs::cmd_du;
pub use fs::cmd_ls;
pub use fs::cmd_mkdir;
pub use fs::cmd_mv;
pub use fs::cmd_pwd;
pub use fs::cmd_rm;
pub use fs::cmd_touch;
pub use fs::human_size;
pub use fuse::cmd_fuse;
pub use perf::cmd_perf;
pub use process::cmd_false;
pub use process::cmd_kill;
pub use process::cmd_ps;
pub use process::cmd_true;
pub use state::cmd_alias;
pub use state::cmd_export;
pub use state::cmd_history;
pub use state::cmd_read;
pub use state::cmd_shift;
pub use state::cmd_source;
pub use system::cmd_clear;
pub use system::cmd_dmesg;
pub use system::cmd_echo;
pub use system::cmd_help;
pub use system::cmd_sleep;
pub use system::cmd_sysinfo;
pub use system::cmd_test;
pub use system::cmd_top;
pub use system::cmd_uname;
pub use system::cmd_uptime;
pub use text::cmd_diff;
pub use text::cmd_edit;
pub use text::cmd_find;
pub use text::cmd_grep;
pub use text::cmd_head;
pub use text::cmd_hexdump;
pub use text::cmd_sort;
pub use text::cmd_tail;
pub use text::cmd_uniq;
pub use text::cmd_wc;
pub use text::parse_head_tail_args;
