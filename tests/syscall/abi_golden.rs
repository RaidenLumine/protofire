//! tests/syscall/abi_golden.rs
//!
//! The syscall number table, frozen.
//!
//! `docs/fmts/syscall-abi.md` states the rule this file enforces: numbers are
//! assigned once and never change meaning.  Until this snapshot existed the
//! rule had no teeth — the tests next to the manifest checked that every number
//! has *a* name and that the stability boundary is where the policy says, so
//! swapping two stable syscalls left all of them green while every program
//! calling the old number would have silently reached the other handler.
//!
//! Two rules are enforced here:
//!
//! - A row's name may not change.  If the number is in the frozen range
//!   (`0..=GOLDEN_LAST_STABLE`) that is the whole rule — the mapping is part of
//!   the ABI and a program built against it keeps working.
//! - If the number is experimental, the mapping may be changed on a minor
//!   version, and the way to do that is to bump `SYSCALL_ABI_VERSION_MINOR`,
//!   change the row here, and change `GOLDEN_ABI_VERSION` — all in one change.
//!   Anything less leaves this file failing, and the failure message says which
//!   rule applies.
//!
//! Regenerating the table (only ever as part of such a change):
//!
//! ```text
//! rg -o '([0-9]+) => Some\("([^"]+)"\)' src/user/shared/abi/syscall.rs
//! ```

use protofire::user::shared::abi::syscall::syscall_name;
use protofire::user::shared::abi::syscall::syscall_stability;
use protofire::user::shared::abi::syscall::SyscallStability;
use protofire::user::shared::abi::syscall::SYSCALL_ABI_VERSION_MAJOR;
use protofire::user::shared::abi::syscall::SYSCALL_ABI_VERSION_MINOR;
use protofire::user::shared::abi::syscall::SYSCALL_COUNT;

/// The ABI version this table was recorded against.
const GOLDEN_ABI_VERSION: (u32, u32) = (1, 2);

/// The last number in the frozen range: `syscall_stability` calls everything
/// up to and including this one `Stable`, and everything above it
/// `Experimental`.
const GOLDEN_LAST_STABLE: usize = 120;

/// `<number, name>` for every public syscall, in number order.
const GOLDEN: &[(usize, &str)] = &[
    (0, "yield"),
    (1, "write_debug"),
    (2, "open"),
    (3, "exit"),
    (4, "read_console"),
    (5, "read"),
    (6, "write"),
    (7, "close"),
    (8, "dup"),
    (9, "seek"),
    (10, "arg_count"),
    (11, "arg_value"),
    (12, "env_count"),
    (13, "env_value"),
    (14, "current_dir"),
    (15, "app_id"),
    (16, "app_version"),
    (17, "image_path"),
    (18, "manifest_path"),
    (19, "create_dir"),
    (20, "set_length"),
    (21, "remove_path"),
    (22, "install_exception_handler"),
    (23, "return_from_exception"),
    (24, "wait_process"),
    (25, "spawn_process"),
    (26, "exec_process"),
    (27, "stat"),
    (28, "read_dir"),
    (29, "rename"),
    (30, "stat_fd"),
    (31, "read_dir_fd"),
    (32, "open_at"),
    (33, "stat_at"),
    (34, "rename_at"),
    (35, "create_dir_at"),
    (36, "remove_path_at"),
    (37, "network_status"),
    (38, "connect_tcp"),
    (39, "abi_info"),
    (40, "send_signal"),
    (41, "wait_signal"),
    (42, "access_query"),
    (43, "access_query_at"),
    (44, "access_query_fd"),
    (45, "permission_metadata"),
    (46, "permission_metadata_at"),
    (47, "permission_metadata_fd"),
    (48, "set_fd_flags"),
    (49, "sleep"),
    (50, "list_processes"),
    (51, "list_threads"),
    (52, "kernel_log"),
    (53, "system_info"),
    (54, "fsync"),
    (55, "fdatasync"),
    (56, "listen_tcp"),
    (57, "accept_tcp"),
    (58, "bind_udp"),
    (59, "sendto_udp"),
    (60, "recvfrom_udp"),
    (61, "list_process_faults"),
    (62, "fork"),
    (63, "reclaim_pages"),
    (64, "pipe"),
    (65, "mount"),
    (66, "umount"),
    (67, "mmap"),
    (68, "munmap"),
    (69, "dup2"),
    (70, "get_time_of_day"),
    (71, "gethostname"),
    (72, "sethostname"),
    (73, "getsockname"),
    (74, "getpeername"),
    (75, "get_random"),
    (76, "create_raw_socket"),
    (77, "send_raw_packet"),
    (78, "recv_raw_packet"),
    (79, "setsockopt"),
    (80, "getsockopt"),
    (81, "getpid"),
    (82, "getppid"),
    (83, "getuid"),
    (84, "getgid"),
    (85, "set_current_dir"),
    (86, "list_mounts"),
    (87, "list_block_devices"),
    (88, "set_security_descriptor"),
    (89, "add_user"),
    (90, "remove_user"),
    (91, "set_user_password"),
    (92, "brk"),
    (93, "resolve_hostname"),
    (94, "set_signal_mask"),
    (95, "repair_volume"),
    (96, "poll"),
    (97, "bind_local"),
    (98, "connect_local"),
    (99, "accept_local"),
    (100, "shmget"),
    (101, "shmat"),
    (102, "shmdt"),
    (103, "shmctl"),
    (104, "set_signal_handler"),
    (105, "fuse_mount"),
    (106, "futex"),
    (107, "eventfd"),
    (108, "signalfd"),
    (109, "timerfd"),
    (110, "sched_setaffinity"),
    (111, "sched_getaffinity"),
    (112, "mqopen"),
    (113, "mqclose"),
    (114, "mqsend"),
    (115, "mqreceive"),
    (116, "mqnotify"),
    (117, "mqunlink"),
    (118, "epoll_create"),
    (119, "epoll_ctl"),
    (120, "epoll_wait"),
    (121, "tls_connect"),
    (122, "filter_add_rule"),
    (123, "filter_remove_rule"),
    (124, "filter_set_default_action"),
    (125, "filter_get_stats"),
    (126, "io_uring_setup"),
    (127, "io_uring_enter"),
    (128, "ptrace"),
    (129, "seccomp"),
    (130, "prctl"),
    (131, "mlock"),
    (132, "munlock"),
    (133, "madvise"),
    (134, "sigreturn"),
    (135, "sigsuspend"),
    (136, "restart_syscall"),
    (137, "timer_create"),
    (138, "timer_settime"),
    (139, "timer_gettime"),
    (140, "timer_delete"),
    (141, "reserved_141"),
    (142, "reserved_142"),
    (143, "audit_set_enable"),
    (144, "audit_read_log"),
    (145, "cpufreq_get"),
    (146, "cpufreq_set"),
    (147, "cpufreq_get_range"),
    (148, "cpufreq_set_governor"),
    (149, "cpufreq_get_temp"),
    (150, "compact_memory"),
    (151, "set_xattr"),
    (152, "get_xattr"),
    (153, "list_xattr"),
    (154, "remove_xattr"),
    (155, "set_file_flags"),
    (156, "get_file_flags"),
    (157, "dccp_bind"),
    (158, "dccp_listen"),
    (159, "dccp_connect"),
    (160, "dccp_accept"),
    (161, "dccp_send"),
    (162, "dccp_recv"),
    (163, "dccp_close"),
    (164, "ipsec_add_sp"),
    (165, "ipsec_del_sp"),
    (166, "ipsec_add_sa"),
    (167, "ipsec_del_sa"),
    (168, "ipsec_get_stats"),
    (169, "mrt_init"),
    (170, "mrt_done"),
    (171, "mrt_add_vif"),
    (172, "mrt_del_vif"),
    (173, "mrt_add_mfc"),
    (174, "mrt_del_mfc"),
    (175, "mac_set_mode"),
    (176, "mac_add_rule"),
    (177, "mac_set_path_type"),
    (178, "mac_get_status"),
    (179, "fcntl"),
    (180, "sync"),
    (181, "gpu_ctx_create"),
    (182, "gpu_ctx_destroy"),
    (183, "gpu_res_create_3d"),
    (184, "gpu_res_unref"),
    (185, "gpu_transfer_to_host_3d"),
    (186, "gpu_transfer_from_host_3d"),
    (187, "gpu_submit_3d"),
    (188, "gpu_set_scanout"),
    (189, "gpu_device_info"),
    (190, "service_declare"),
    (191, "service_start_all"),
];

#[test]
fn every_number_still_names_the_same_syscall() {
    let mut stable_moves = Vec::new();
    let mut experimental_moves = Vec::new();

    for &(number, expected) in GOLDEN {
        let actual = syscall_name(number);
        if actual == Some(expected) {
            continue;
        }
        let row = format!(
            "  #{number}: was `{expected}`, now `{}`",
            actual.unwrap_or("<no name>")
        );
        match syscall_stability(number) {
            SyscallStability::Stable => stable_moves.push(row),
            SyscallStability::Experimental => experimental_moves.push(row),
        }
    }

    assert!(
        stable_moves.is_empty(),
        "a syscall in the frozen range (0..={GOLDEN_LAST_STABLE}) changed name:\n{}\n\
         Numbers are assigned once and never change meaning: a program built \
         against the old number would silently reach another handler.  Add a new \
         syscall at the end of the range instead (docs/fmts/syscall-abi.md §3.1).",
        stable_moves.join("\n")
    );

    assert!(
        experimental_moves.is_empty(),
        "an experimental syscall changed name:\n{}\n\
         Renumbering an experimental slot is allowed on a minor version, but the \
         change has to be recorded: bump SYSCALL_ABI_VERSION_MINOR in \
         src/user/shared/abi/syscall.rs, update GOLDEN_ABI_VERSION and the rows \
         here, and say so in the release notes (docs/fmts/syscall-abi.md §3).",
        experimental_moves.join("\n")
    );
}

#[test]
fn the_table_covers_the_whole_public_range() {
    assert_eq!(
        GOLDEN.len(),
        SYSCALL_COUNT,
        "the snapshot has {} rows for {SYSCALL_COUNT} syscalls",
        GOLDEN.len()
    );
    for (position, &(number, _)) in GOLDEN.iter().enumerate() {
        assert_eq!(
            number, position,
            "the snapshot skips or repeats #{position}"
        );
    }
    let (last_number, last_name) = *GOLDEN.last().expect("the table is not empty");
    assert_eq!(last_number + 1, SYSCALL_COUNT);
    assert_eq!(syscall_name(last_number), Some(last_name));
    assert!(syscall_name(SYSCALL_COUNT).is_none());
}

#[test]
fn the_stability_boundary_has_not_moved() {
    assert_eq!(
        syscall_stability(GOLDEN_LAST_STABLE),
        SyscallStability::Stable
    );
    assert_eq!(
        syscall_stability(GOLDEN_LAST_STABLE + 1),
        SyscallStability::Experimental,
        "the frozen range ends at {GOLDEN_LAST_STABLE}; moving the boundary \
         changes the promise the ABI makes, so it belongs in a version change"
    );
}

#[test]
fn the_recorded_abi_version_is_the_manifest_s_one() {
    assert_eq!(
        (SYSCALL_ABI_VERSION_MAJOR, SYSCALL_ABI_VERSION_MINOR),
        GOLDEN_ABI_VERSION,
        "the manifest's ABI version and the version this snapshot was recorded \
         against disagree: bump both together, or neither"
    );
}

#[test]
fn retired_numbers_are_still_retired() {
    // A number whose syscall was removed keeps its `reserved_<n>` name: the
    // slot is never reused, and assigning it to something else is a change in
    // the experimental range that needs the minor bump above.
    let retired: Vec<usize> = GOLDEN
        .iter()
        .filter(|(_, name)| name.starts_with("reserved_"))
        .map(|(number, _)| *number)
        .collect();
    assert_eq!(
        retired,
        vec![141, 142],
        "the set of retired numbers changed; see docs/fmts/syscall-abi.md §3.1"
    );
    for number in retired {
        // The exact names are checked by the snapshot above; what this adds is
        // that each one still reads as a reservation rather than as a syscall
        // somebody quietly took over.
        let name = syscall_name(number).unwrap_or("<no name>");
        assert!(
            name.starts_with("reserved_"),
            "#{number} is a retired slot but reads as `{name}`"
        );
    }
}
