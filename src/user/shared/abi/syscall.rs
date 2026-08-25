//! src/user/shared/abi/syscall.rs
//!
//! Canonical syscall-number definitions and ABI metadata (single source of
//! truth).
//!
//! Both the kernel's `SyscallNumber` enum and ring3 syscall wrappers resolve
//! their numbers through this module (`crate::user::shared::abi::syscall`), so
//! the kernel and user space can never drift.  The table is frozen in [0,
//! SYSCALL_COUNT).

pub const SYSCALL_ABI_VERSION_MAJOR: u32 = 1;
pub const SYSCALL_ABI_VERSION_MINOR: u32 = 0;

pub const SYSCALL_COUNT: usize = 190;
pub const MAX_SYSCALLS: usize = 256;

// ── Syscall numbers (0-189) ──────────────────────────────────────────

pub const SYS_YIELD: usize = 0;
pub const SYS_WRITE_DEBUG: usize = 1;
pub const SYS_OPEN: usize = 2;
pub const SYS_EXIT: usize = 3;
pub const SYS_READ_CONSOLE: usize = 4;
pub const SYS_READ: usize = 5;
pub const SYS_WRITE: usize = 6;
pub const SYS_CLOSE: usize = 7;
pub const SYS_DUP: usize = 8;
pub const SYS_SEEK: usize = 9;
pub const SYS_ARG_COUNT: usize = 10;
pub const SYS_ARG_VALUE: usize = 11;
pub const SYS_ENV_COUNT: usize = 12;
pub const SYS_ENV_VALUE: usize = 13;
pub const SYS_CURRENT_DIR: usize = 14;
pub const SYS_APP_ID: usize = 15;
pub const SYS_APP_VERSION: usize = 16;
pub const SYS_IMAGE_PATH: usize = 17;
pub const SYS_MANIFEST_PATH: usize = 18;
pub const SYS_CREATE_DIR: usize = 19;
pub const SYS_SET_LENGTH: usize = 20;
pub const SYS_REMOVE_PATH: usize = 21;
pub const SYS_INSTALL_EXCEPTION_HANDLER: usize = 22;
pub const SYS_RETURN_FROM_EXCEPTION: usize = 23;
pub const SYS_WAIT_PROCESS: usize = 24;
pub const SYS_SPAWN_PROCESS: usize = 25;
pub const SYS_EXEC_PROCESS: usize = 26;
pub const SYS_STAT: usize = 27;
pub const SYS_READ_DIR: usize = 28;
pub const SYS_RENAME: usize = 29;
pub const SYS_STAT_FD: usize = 30;
pub const SYS_READ_DIR_FD: usize = 31;
pub const SYS_OPEN_AT: usize = 32;
pub const SYS_STAT_AT: usize = 33;
pub const SYS_RENAME_AT: usize = 34;
pub const SYS_CREATE_DIR_AT: usize = 35;
pub const SYS_REMOVE_PATH_AT: usize = 36;
pub const SYS_NETWORK_STATUS: usize = 37;
pub const SYS_CONNECT_TCP: usize = 38;
pub const SYS_ABI_INFO: usize = 39;
pub const SYS_SEND_SIGNAL: usize = 40;
pub const SYS_WAIT_SIGNAL: usize = 41;
pub const SYS_ACCESS_QUERY: usize = 42;
pub const SYS_ACCESS_QUERY_AT: usize = 43;
pub const SYS_ACCESS_QUERY_FD: usize = 44;
pub const SYS_PERMISSION_METADATA: usize = 45;
pub const SYS_PERMISSION_METADATA_AT: usize = 46;
pub const SYS_PERMISSION_METADATA_FD: usize = 47;
pub const SYS_SET_FD_FLAGS: usize = 48;
pub const SYS_SLEEP: usize = 49;
pub const SYS_LIST_PROCESSES: usize = 50;
pub const SYS_LIST_THREADS: usize = 51;
pub const SYS_KERNEL_LOG: usize = 52;
pub const SYS_SYSTEM_INFO: usize = 53;
pub const SYS_FSYNC: usize = 54;
pub const SYS_FDATASYNC: usize = 55;
pub const SYS_LISTEN_TCP: usize = 56;
pub const SYS_ACCEPT_TCP: usize = 57;
pub const SYS_BIND_UDP: usize = 58;
pub const SYS_SENDTO_UDP: usize = 59;
pub const SYS_RECVFROM_UDP: usize = 60;
pub const SYS_LIST_PROCESS_FAULTS: usize = 61;
pub const SYS_FORK: usize = 62;
pub const SYS_RECLAIM_PAGES: usize = 63;
pub const SYS_PIPE: usize = 64;
pub const SYS_MOUNT: usize = 65;
pub const SYS_UMOUNT: usize = 66;
pub const SYS_MMAP: usize = 67;
pub const SYS_MUNMAP: usize = 68;
pub const SYS_DUP2: usize = 69;
pub const SYS_GET_TIME_OF_DAY: usize = 70;
pub const SYS_GETHOSTNAME: usize = 71;
pub const SYS_SETHOSTNAME: usize = 72;
pub const SYS_GETSOCKNAME: usize = 73;
pub const SYS_GETPEERNAME: usize = 74;
pub const SYS_GET_RANDOM: usize = 75;
pub const SYS_CREATE_RAW_SOCKET: usize = 76;
pub const SYS_SEND_RAW_PACKET: usize = 77;
pub const SYS_RECV_RAW_PACKET: usize = 78;
pub const SYS_SETSOCKOPT: usize = 79;
pub const SYS_GETSOCKOPT: usize = 80;
pub const SYS_GETPID: usize = 81;
pub const SYS_GETPPID: usize = 82;
pub const SYS_GETUID: usize = 83;
pub const SYS_GETGID: usize = 84;
pub const SYS_SET_CURRENT_DIR: usize = 85;
pub const SYS_LIST_MOUNTS: usize = 86;
pub const SYS_LIST_BLOCK_DEVICES: usize = 87;
pub const SYS_SET_SECURITY_DESCRIPTOR: usize = 88;
pub const SYS_ADD_USER: usize = 89;
pub const SYS_REMOVE_USER: usize = 90;
pub const SYS_SET_USER_PASSWORD: usize = 91;
pub const SYS_BRK: usize = 92;
pub const SYS_RESOLVE_HOSTNAME: usize = 93;
pub const SYS_SET_SIGNAL_MASK: usize = 94;
pub const SYS_REPAIR_VOLUME: usize = 95;
pub const SYS_POLL: usize = 96;
pub const SYS_BIND_LOCAL: usize = 97;
pub const SYS_CONNECT_LOCAL: usize = 98;
pub const SYS_ACCEPT_LOCAL: usize = 99;
pub const SYS_SHMGET: usize = 100;
pub const SYS_SHMAT: usize = 101;
pub const SYS_SHMDT: usize = 102;
pub const SYS_SHMCTL: usize = 103;
pub const SYS_SET_SIGNAL_HANDLER: usize = 104;
pub const SYS_FUSE_MOUNT: usize = 105;
pub const SYS_FUTEX: usize = 106;
pub const SYS_EVENTFD: usize = 107;
pub const SYS_SIGNALFD: usize = 108;
pub const SYS_TIMERFD: usize = 109;
pub const SYS_SCHED_SETAFFINITY: usize = 110;
pub const SYS_SCHED_GETAFFINITY: usize = 111;
pub const SYS_MQOPEN: usize = 112;
pub const SYS_MQCLOSE: usize = 113;
pub const SYS_MQSEND: usize = 114;
pub const SYS_MQRECEIVE: usize = 115;
pub const SYS_MQNOTIFY: usize = 116;
pub const SYS_MQUNLINK: usize = 117;
pub const SYS_EPOLL_CREATE: usize = 118;
pub const SYS_EPOLL_CTL: usize = 119;
pub const SYS_EPOLL_WAIT: usize = 120;
pub const SYS_TLS_CONNECT: usize = 121;
pub const SYS_FILTER_ADD_RULE: usize = 122;
pub const SYS_FILTER_REMOVE_RULE: usize = 123;
pub const SYS_FILTER_SET_DEFAULT_ACTION: usize = 124;
pub const SYS_FILTER_GET_STATS: usize = 125;
pub const SYS_IO_URING_SETUP: usize = 126;
pub const SYS_IO_URING_ENTER: usize = 127;
pub const SYS_PTRACE: usize = 128;
pub const SYS_SECCOMP: usize = 129;
pub const SYS_PRCTL: usize = 130;
pub const SYS_MLOCK: usize = 131;
pub const SYS_MUNLOCK: usize = 132;
pub const SYS_MADVISE: usize = 133;
pub const SYS_SIGRETURN: usize = 134;
pub const SYS_SIGSUSPEND: usize = 135;
pub const SYS_RESTART_SYSCALL: usize = 136;
pub const SYS_TIMER_CREATE: usize = 137;
pub const SYS_TIMER_SETTIME: usize = 138;
pub const SYS_TIMER_GETTIME: usize = 139;
pub const SYS_TIMER_DELETE: usize = 140;
pub const SYS_RESERVED_141: usize = 141;
pub const SYS_RESERVED_142: usize = 142;
pub const SYS_AUDIT_SET_ENABLE: usize = 143;
pub const SYS_AUDIT_READ_LOG: usize = 144;
pub const SYS_CPUFREQ_GET: usize = 145;
pub const SYS_CPUFREQ_SET: usize = 146;
pub const SYS_CPUFREQ_GET_RANGE: usize = 147;
pub const SYS_CPUFREQ_SET_GOVERNOR: usize = 148;
pub const SYS_CPUFREQ_GET_TEMP: usize = 149;
pub const SYS_COMPACT_MEMORY: usize = 150;
pub const SYS_SET_XATTR: usize = 151;
pub const SYS_GET_XATTR: usize = 152;
pub const SYS_LIST_XATTR: usize = 153;
pub const SYS_REMOVE_XATTR: usize = 154;
pub const SYS_SET_FILE_FLAGS: usize = 155;
pub const SYS_GET_FILE_FLAGS: usize = 156;
pub const SYS_DCCP_BIND: usize = 157;
pub const SYS_DCCP_LISTEN: usize = 158;
pub const SYS_DCCP_CONNECT: usize = 159;
pub const SYS_DCCP_ACCEPT: usize = 160;
pub const SYS_DCCP_SEND: usize = 161;
pub const SYS_DCCP_RECV: usize = 162;
pub const SYS_DCCP_CLOSE: usize = 163;
pub const SYS_IPSEC_ADD_SP: usize = 164;
pub const SYS_IPSEC_DEL_SP: usize = 165;
pub const SYS_IPSEC_ADD_SA: usize = 166;
pub const SYS_IPSEC_DEL_SA: usize = 167;
pub const SYS_IPSEC_GET_STATS: usize = 168;
pub const SYS_MRT_INIT: usize = 169;
pub const SYS_MRT_DONE: usize = 170;
pub const SYS_MRT_ADD_VIF: usize = 171;
pub const SYS_MRT_DEL_VIF: usize = 172;
pub const SYS_MRT_ADD_MFC: usize = 173;
pub const SYS_MRT_DEL_MFC: usize = 174;
pub const SYS_MAC_SET_MODE: usize = 175;
pub const SYS_MAC_ADD_RULE: usize = 176;
pub const SYS_MAC_SET_PATH_TYPE: usize = 177;
pub const SYS_MAC_GET_STATUS: usize = 178;
pub const SYS_FCNTL: usize = 179;
pub const SYS_SYNC: usize = 180;
pub const SYS_GPU_CTX_CREATE: usize = 181;
pub const SYS_GPU_CTX_DESTROY: usize = 182;
pub const SYS_GPU_RES_CREATE_3D: usize = 183;
pub const SYS_GPU_RES_UNREF: usize = 184;
pub const SYS_GPU_TRANSFER_TO_HOST_3D: usize = 185;
pub const SYS_GPU_TRANSFER_FROM_HOST_3D: usize = 186;
pub const SYS_GPU_SUBMIT_3D: usize = 187;
pub const SYS_GPU_SET_SCANOUT: usize = 188;
pub const SYS_GPU_DEVICE_INFO: usize = 189;

// ── Stability classification ────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallStability {
    Stable,
    Experimental,
}

/// Syscalls 0..=120 are stable ABI; 121..=189 are experimental and may
/// still be adjusted on a minor bump.  Reserved slots (141/142) are treated
/// as experimental until assigned.
pub const fn syscall_stability(number: usize) -> SyscallStability {
    if number <= 120 {
        SyscallStability::Stable
    } else {
        SyscallStability::Experimental
    }
}

// ── Name lookup (audit trails + tests) ───────────────────────────────

/// Human-readable name for a syscall number, or `None` outside [0,
/// SYSCALL_COUNT).
pub const fn syscall_name(number: usize) -> Option<&'static str> {
    match number {
        0 => Some("yield"),
        1 => Some("write_debug"),
        2 => Some("open"),
        3 => Some("exit"),
        4 => Some("read_console"),
        5 => Some("read"),
        6 => Some("write"),
        7 => Some("close"),
        8 => Some("dup"),
        9 => Some("seek"),
        10 => Some("arg_count"),
        11 => Some("arg_value"),
        12 => Some("env_count"),
        13 => Some("env_value"),
        14 => Some("current_dir"),
        15 => Some("app_id"),
        16 => Some("app_version"),
        17 => Some("image_path"),
        18 => Some("manifest_path"),
        19 => Some("create_dir"),
        20 => Some("set_length"),
        21 => Some("remove_path"),
        22 => Some("install_exception_handler"),
        23 => Some("return_from_exception"),
        24 => Some("wait_process"),
        25 => Some("spawn_process"),
        26 => Some("exec_process"),
        27 => Some("stat"),
        28 => Some("read_dir"),
        29 => Some("rename"),
        30 => Some("stat_fd"),
        31 => Some("read_dir_fd"),
        32 => Some("open_at"),
        33 => Some("stat_at"),
        34 => Some("rename_at"),
        35 => Some("create_dir_at"),
        36 => Some("remove_path_at"),
        37 => Some("network_status"),
        38 => Some("connect_tcp"),
        39 => Some("abi_info"),
        40 => Some("send_signal"),
        41 => Some("wait_signal"),
        42 => Some("access_query"),
        43 => Some("access_query_at"),
        44 => Some("access_query_fd"),
        45 => Some("permission_metadata"),
        46 => Some("permission_metadata_at"),
        47 => Some("permission_metadata_fd"),
        48 => Some("set_fd_flags"),
        49 => Some("sleep"),
        50 => Some("list_processes"),
        51 => Some("list_threads"),
        52 => Some("kernel_log"),
        53 => Some("system_info"),
        54 => Some("fsync"),
        55 => Some("fdatasync"),
        56 => Some("listen_tcp"),
        57 => Some("accept_tcp"),
        58 => Some("bind_udp"),
        59 => Some("sendto_udp"),
        60 => Some("recvfrom_udp"),
        61 => Some("list_process_faults"),
        62 => Some("fork"),
        63 => Some("reclaim_pages"),
        64 => Some("pipe"),
        65 => Some("mount"),
        66 => Some("umount"),
        67 => Some("mmap"),
        68 => Some("munmap"),
        69 => Some("dup2"),
        70 => Some("get_time_of_day"),
        71 => Some("gethostname"),
        72 => Some("sethostname"),
        73 => Some("getsockname"),
        74 => Some("getpeername"),
        75 => Some("get_random"),
        76 => Some("create_raw_socket"),
        77 => Some("send_raw_packet"),
        78 => Some("recv_raw_packet"),
        79 => Some("setsockopt"),
        80 => Some("getsockopt"),
        81 => Some("getpid"),
        82 => Some("getppid"),
        83 => Some("getuid"),
        84 => Some("getgid"),
        85 => Some("set_current_dir"),
        86 => Some("list_mounts"),
        87 => Some("list_block_devices"),
        88 => Some("set_security_descriptor"),
        89 => Some("add_user"),
        90 => Some("remove_user"),
        91 => Some("set_user_password"),
        92 => Some("brk"),
        93 => Some("resolve_hostname"),
        94 => Some("set_signal_mask"),
        95 => Some("repair_volume"),
        96 => Some("poll"),
        97 => Some("bind_local"),
        98 => Some("connect_local"),
        99 => Some("accept_local"),
        100 => Some("shmget"),
        101 => Some("shmat"),
        102 => Some("shmdt"),
        103 => Some("shmctl"),
        104 => Some("set_signal_handler"),
        105 => Some("fuse_mount"),
        106 => Some("futex"),
        107 => Some("eventfd"),
        108 => Some("signalfd"),
        109 => Some("timerfd"),
        110 => Some("sched_setaffinity"),
        111 => Some("sched_getaffinity"),
        112 => Some("mqopen"),
        113 => Some("mqclose"),
        114 => Some("mqsend"),
        115 => Some("mqreceive"),
        116 => Some("mqnotify"),
        117 => Some("mqunlink"),
        118 => Some("epoll_create"),
        119 => Some("epoll_ctl"),
        120 => Some("epoll_wait"),
        121 => Some("tls_connect"),
        122 => Some("filter_add_rule"),
        123 => Some("filter_remove_rule"),
        124 => Some("filter_set_default_action"),
        125 => Some("filter_get_stats"),
        126 => Some("io_uring_setup"),
        127 => Some("io_uring_enter"),
        128 => Some("ptrace"),
        129 => Some("seccomp"),
        130 => Some("prctl"),
        131 => Some("mlock"),
        132 => Some("munlock"),
        133 => Some("madvise"),
        134 => Some("sigreturn"),
        135 => Some("sigsuspend"),
        136 => Some("restart_syscall"),
        137 => Some("timer_create"),
        138 => Some("timer_settime"),
        139 => Some("timer_gettime"),
        140 => Some("timer_delete"),
        141 => Some("reserved_141"),
        142 => Some("reserved_142"),
        143 => Some("audit_set_enable"),
        144 => Some("audit_read_log"),
        145 => Some("cpufreq_get"),
        146 => Some("cpufreq_set"),
        147 => Some("cpufreq_get_range"),
        148 => Some("cpufreq_set_governor"),
        149 => Some("cpufreq_get_temp"),
        150 => Some("compact_memory"),
        151 => Some("set_xattr"),
        152 => Some("get_xattr"),
        153 => Some("list_xattr"),
        154 => Some("remove_xattr"),
        155 => Some("set_file_flags"),
        156 => Some("get_file_flags"),
        157 => Some("dccp_bind"),
        158 => Some("dccp_listen"),
        159 => Some("dccp_connect"),
        160 => Some("dccp_accept"),
        161 => Some("dccp_send"),
        162 => Some("dccp_recv"),
        163 => Some("dccp_close"),
        164 => Some("ipsec_add_sp"),
        165 => Some("ipsec_del_sp"),
        166 => Some("ipsec_add_sa"),
        167 => Some("ipsec_del_sa"),
        168 => Some("ipsec_get_stats"),
        169 => Some("mrt_init"),
        170 => Some("mrt_done"),
        171 => Some("mrt_add_vif"),
        172 => Some("mrt_del_vif"),
        173 => Some("mrt_add_mfc"),
        174 => Some("mrt_del_mfc"),
        175 => Some("mac_set_mode"),
        176 => Some("mac_add_rule"),
        177 => Some("mac_set_path_type"),
        178 => Some("mac_get_status"),
        179 => Some("fcntl"),
        180 => Some("sync"),
        181 => Some("gpu_ctx_create"),
        182 => Some("gpu_ctx_destroy"),
        183 => Some("gpu_res_create_3d"),
        184 => Some("gpu_res_unref"),
        185 => Some("gpu_transfer_to_host_3d"),
        186 => Some("gpu_transfer_from_host_3d"),
        187 => Some("gpu_submit_3d"),
        188 => Some("gpu_set_scanout"),
        189 => Some("gpu_device_info"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        syscall_name, syscall_stability, SyscallStability, MAX_SYSCALLS, SYSCALL_ABI_VERSION_MAJOR,
        SYSCALL_ABI_VERSION_MINOR, SYSCALL_COUNT, SYS_ABI_INFO, SYS_DUP2, SYS_GPU_DEVICE_INFO,
        SYS_OPEN, SYS_WRITE,
    };

    #[test]
    fn syscall_numbers_are_dense_in_0_190() {
        // Every number in [0, SYSCALL_COUNT) must have a name; SYSCALL_COUNT must not.
        for i in 0..SYSCALL_COUNT {
            assert!(syscall_name(i).is_some(), "syscall {i} missing name");
        }
        assert!(syscall_name(SYSCALL_COUNT).is_none());
        assert!(syscall_name(usize::MAX).is_none());
    }

    #[test]
    fn syscall_name_round_trips_key_constants() {
        assert_eq!(syscall_name(SYS_OPEN), Some("open"));
        assert_eq!(syscall_name(SYS_WRITE), Some("write"));
        assert_eq!(syscall_name(SYS_DUP2), Some("dup2"));
        assert_eq!(syscall_name(SYS_ABI_INFO), Some("abi_info"));
        assert_eq!(syscall_name(SYS_GPU_DEVICE_INFO), Some("gpu_device_info"));
    }

    #[test]
    fn stability_boundary_matches_policy() {
        assert_eq!(syscall_stability(0), SyscallStability::Stable);
        assert_eq!(syscall_stability(120), SyscallStability::Stable);
        assert_eq!(syscall_stability(121), SyscallStability::Experimental);
        assert_eq!(syscall_stability(189), SyscallStability::Experimental);
    }

    #[test]
    fn abi_version_is_v1_initial() {
        assert_eq!(SYSCALL_ABI_VERSION_MAJOR, 1);
        assert_eq!(SYSCALL_ABI_VERSION_MINOR, 0);
    }

    #[test]
    fn count_checks() {
        assert_eq!(SYSCALL_COUNT, 190);
        assert_eq!(MAX_SYSCALLS, 256);
    }
}
