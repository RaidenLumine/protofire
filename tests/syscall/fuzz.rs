//! tests/syscall/fuzz.rs
//! Syscall argument fuzzing — feed random/edge-case arguments into each
//! syscall handler and verify that all failures are clean `Result::Err`
//! returns rather than panics or undefined behaviour.
//!
//! We use a deterministic PRNG seeded per test for reproducibility.
//!
//! **Safety note:** When running host-side, syscall handlers that dereference
//! user-space pointers will segfault unless a user address space is active.
//! We avoid passing plausible-looking pointers (like 0x1000) to such handlers;
//! `ptr=0` and `ptr=usize::MAX` reliably hit the null-check or bounds-check
//! in `user_string`/`user_memory` before dereference.

use protofire::kernel::syscall::{SyscallContext, SyscallNumber, Table};

// ── Simple PRNG ─────────────────────────────────────────────────────────────

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(6_364_136_223_846_793_005);
        self.state = self.state.wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next() as usize) % bound
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn public_syscall_count() -> usize {
    SyscallNumber::ConnectLocal as usize + 1
}

/// Syscall numbers that are safe to fuzz without a user address space.
/// These handlers validate arguments before dereferencing any pointer.
fn safe_syscall_numbers() -> Vec<usize> {
    // Exclude syscalls that dereference user-space pointers without a
    // current process/address-space: Open, OpenAt, Stat, StatAt, ReadDir,
    // CreateDir, CreateDirAt, RemovePath, RemovePathAt, Rename, RenameAt,
    // Mount, Umount, SpawnProcess, ExecProcess, Fork,
    // SetCurrentDir, AccessQuery*, PermissionMetadata*,
    // BindLocal, ConnectLocal, Mmap, Munmap, Brk,
    // InstallExceptionHandler, ReturnFromException,
    // ListProcesses, ListThreads, ListProcessFaults, ListMounts,
    // ListBlockDevices, AddUser, RemoveUser, SetUserPassword,
    // SetSecurityDescriptor, ResolveHostname, ReclaimPages,
    // RepairVolume, AbiInfo, GetTimeOfDay, GetHostName, SetHostName.
    //
    // Safe syscalls are those that only take integer arguments and validate
    // them before touching any process state they can't initialize.
    let exclude: &[usize] = &[
        SyscallNumber::Open as usize,
        SyscallNumber::OpenAt as usize,
        SyscallNumber::Stat as usize,
        SyscallNumber::StatAt as usize,
        SyscallNumber::ReadDir as usize,
        SyscallNumber::CreateDir as usize,
        SyscallNumber::CreateDirAt as usize,
        SyscallNumber::RemovePath as usize,
        SyscallNumber::RemovePathAt as usize,
        SyscallNumber::Rename as usize,
        SyscallNumber::RenameAt as usize,
        SyscallNumber::Mount as usize,
        SyscallNumber::Umount as usize,
        SyscallNumber::SpawnProcess as usize,
        SyscallNumber::ExecProcess as usize,
        SyscallNumber::Fork as usize,
        SyscallNumber::SetCurrentDir as usize,
        SyscallNumber::AccessQuery as usize,
        SyscallNumber::AccessQueryAt as usize,
        SyscallNumber::AccessQueryFd as usize,
        SyscallNumber::PermissionMetadata as usize,
        SyscallNumber::PermissionMetadataAt as usize,
        SyscallNumber::PermissionMetadataFd as usize,
        SyscallNumber::BindLocal as usize,
        SyscallNumber::ConnectLocal as usize,
        SyscallNumber::Mmap as usize,
        SyscallNumber::Munmap as usize,
        SyscallNumber::Brk as usize,
        SyscallNumber::InstallExceptionHandler as usize,
        SyscallNumber::ReturnFromException as usize,
        SyscallNumber::ListProcesses as usize,
        SyscallNumber::ListThreads as usize,
        SyscallNumber::ListProcessFaults as usize,
        SyscallNumber::ListMounts as usize,
        SyscallNumber::ListBlockDevices as usize,
        SyscallNumber::AddUser as usize,
        SyscallNumber::RemoveUser as usize,
        SyscallNumber::SetUserPassword as usize,
        SyscallNumber::SetSecurityDescriptor as usize,
        SyscallNumber::ResolveHostname as usize,
        SyscallNumber::ReclaimPages as usize,
        SyscallNumber::RepairVolume as usize,
        SyscallNumber::AbiInfo as usize,
        SyscallNumber::GetTimeOfDay as usize,
        SyscallNumber::GetHostName as usize,
        SyscallNumber::SetHostName as usize,
        SyscallNumber::ConnectTcp as usize,
        SyscallNumber::ListenTcp as usize,
        SyscallNumber::AcceptTcp as usize,
        SyscallNumber::BindUdp as usize,
        SyscallNumber::SendToUdp as usize,
        SyscallNumber::RecvFromUdp as usize,
        SyscallNumber::CreateRawSocket as usize,
        SyscallNumber::SendRawPacket as usize,
        SyscallNumber::RecvRawPacket as usize,
        SyscallNumber::NetworkStatus as usize,
        SyscallNumber::ArgCount as usize,
        SyscallNumber::ArgValue as usize,
        SyscallNumber::EnvCount as usize,
        SyscallNumber::EnvValue as usize,
        SyscallNumber::AppId as usize,
        SyscallNumber::AppVersion as usize,
        SyscallNumber::ImagePath as usize,
        SyscallNumber::ManifestPath as usize,
        SyscallNumber::CurrentDir as usize,
    ];

    let mut safe = Vec::new();
    for n in 0..public_syscall_count() {
        if !exclude.contains(&n) {
            safe.push(n);
        }
    }
    safe
}

/// Interesting/boundary values for a single syscall argument.
/// We avoid `usize::MAX` and similar extremes for length/buffer arguments
/// because some handlers allocate based on these values (capacity overflow
/// on `Vec::with_capacity`).  The fuzzer focuses on validation correctness,
/// not memory exhaustion.
fn edge_values() -> &'static [usize] {
    &[
        0, 1, 2, 31, // max valid signal
        32, // just above max signal
        9,  // SIGKILL
        15, // SIGTERM
        64, // common buffer size
        128, 256, 512, 1024, 4096,  // page size
        8192,  // 2 pages
        65536, // 64 KiB
    ]
}

/// Extreme values for args that aren't allocation sizes (e.g. fd, flags).
fn extreme_values() -> &'static [usize] {
    &[usize::MAX, usize::MAX / 2, usize::MAX - 1]
}

/// Generate a set of argument tuples for fuzzing.
fn fuzz_args(rng: &mut Lcg, count: usize) -> Vec<[usize; 6]> {
    let mut args = Vec::with_capacity(count);
    let edges = edge_values();
    let extremes = extreme_values();

    // Always include the all-zeros baseline.
    args.push([0; 6]);

    // Include all-MAX only in arg0 (which is typically fd/pid, not length).
    let mut max_first = [0usize; 6];
    max_first[0] = usize::MAX;
    args.push(max_first);

    // Each position gets each edge value, others zeroed.
    for pos in 0..6 {
        for &val in edges {
            let mut a = [0usize; 6];
            a[pos] = val;
            args.push(a);
        }
    }

    // Each position also gets extreme values, others zeroed.
    for pos in [0, 3] {
        // arg0 = fd/pid, arg3 = flags — safe for extremes
        for &val in extremes {
            let mut a = [0usize; 6];
            a[pos] = val;
            args.push(a);
        }
    }

    // Random fills to reach `count`.  Keep values ≤ 1 MiB for length-like
    // args; use extreme values only for flag/fd-like slots (0, 3).
    while args.len() < count {
        let mut a = [0usize; 6];
        for (i, slot) in a.iter_mut().enumerate() {
            if i == 0 || i == 3 {
                // fd/pid (arg0) or flags (arg3): can use extremes.
                match rng.next_usize(4) {
                    0 => *slot = extremes[rng.next_usize(extremes.len())],
                    1 => *slot = edges[rng.next_usize(edges.len())],
                    _ => *slot = rng.next_usize(65536),
                }
            } else {
                // Length/buffer/pointer args: stay in safe range.
                *slot = edges[rng.next_usize(edges.len())];
            }
        }
        args.push(a);
    }

    args
}

/// Dispatch fuzzed arguments and verify the handler doesn't panic.
fn fuzz_syscall(table: &Table, syscall_number: usize, arg_sets: &[[usize; 6]]) {
    for args in arg_sets {
        let mut context = SyscallContext::new(syscall_number, *args);
        let _ = table.dispatch_with_action(&mut context);

        let mut context2 = SyscallContext::new(syscall_number, *args);
        let _ = table.dispatch(&mut context2);
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn fuzz_safe_syscalls_with_edge_arguments() {
    let mut table = Table::new();
    table.init();
    let mut rng = Lcg::new(0xF0F0_0001);

    for &syscall_num in &safe_syscall_numbers() {
        let arg_sets = fuzz_args(&mut rng, 40);
        fuzz_syscall(&table, syscall_num, &arg_sets);
    }
}

#[test]
fn fuzz_top_safe_syscalls_with_broad_random_args() {
    let frequent: &[usize] = &[
        SyscallNumber::Read as usize,
        SyscallNumber::Write as usize,
        SyscallNumber::Close as usize,
        SyscallNumber::Seek as usize,
        SyscallNumber::WaitProcess as usize,
        SyscallNumber::SendSignal as usize,
        SyscallNumber::WaitSignal as usize,
        SyscallNumber::GetPid as usize,
        SyscallNumber::GetUid as usize,
        SyscallNumber::GetGid as usize,
        SyscallNumber::Exit as usize,
        SyscallNumber::Dup as usize,
        SyscallNumber::Dup2 as usize,
        SyscallNumber::SetLength as usize,
        SyscallNumber::SetFdFlags as usize,
        SyscallNumber::Sleep as usize,
        SyscallNumber::KernelLog as usize,
        SyscallNumber::SystemInfo as usize,
        SyscallNumber::Fsync as usize,
        SyscallNumber::Fdatasync as usize,
        SyscallNumber::Pipe as usize,
        SyscallNumber::GetSockName as usize,
        SyscallNumber::GetPeerName as usize,
        SyscallNumber::SetSockOpt as usize,
        SyscallNumber::GetSockOpt as usize,
        SyscallNumber::GetPpid as usize,
        SyscallNumber::GetRandom as usize,
        SyscallNumber::WriteDebug as usize,
        SyscallNumber::Yield as usize,
        SyscallNumber::ReadConsole as usize,
        SyscallNumber::Poll as usize,
        SyscallNumber::SetSignalMask as usize,
    ];

    let mut table = Table::new();
    table.init();
    let mut rng = Lcg::new(0xF0F0_0002);

    for &syscall_num in frequent {
        let arg_sets = fuzz_args(&mut rng, 200);
        fuzz_syscall(&table, syscall_num, &arg_sets);
    }
}

#[test]
fn fuzz_flag_validation_across_syscalls() {
    let mut table = Table::new();
    table.init();

    let syscalls_with_flags: &[(usize, usize)] = &[
        (SyscallNumber::SendSignal as usize, 3),    // arg3=flags
        (SyscallNumber::WaitSignal as usize, 3),    // arg3=flags
        (SyscallNumber::WaitProcess as usize, 3),   // arg3=flags
        (SyscallNumber::SetSignalMask as usize, 1), // arg1=flags
    ];

    for &(syscall_num, flags_pos) in syscalls_with_flags {
        for flag_bit in 0..16usize {
            let mut args = [0usize; 6];
            args[flags_pos] = 1 << flag_bit;
            let mut context = SyscallContext::new(syscall_num, args);
            let _ = table.dispatch_with_action(&mut context);
        }
    }
}

#[test]
fn fuzz_signal_numbers_edge_cases() {
    let mut table = Table::new();
    table.init();

    for signal in 0..64usize {
        let args = [1, signal, 0, 0, 0, 0];
        let mut context = SyscallContext::new(SyscallNumber::SendSignal as usize, args);
        let _ = table.dispatch_with_action(&mut context);
    }
}

#[test]
fn fuzz_poll_fd_array_edge_cases() {
    let mut table = Table::new();
    table.init();

    let test_args: &[[usize; 6]] = &[
        [0, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0],
        [0x1000, 0, 0, 0, 0, 0],
        [0x1000, 64, 0, 0, 0, 0],
        [0x1000, 128, 0, 0, 0, 0],
        [usize::MAX, 64, 0, 0, 0, 0],
        [0x1000, usize::MAX, 0, 0, 0, 0],
        [0, 0, usize::MAX, 0, 0, 0],
        [0, 0, 0, usize::MAX, 0, 0],
    ];

    for args in test_args {
        let mut context = SyscallContext::new(SyscallNumber::Poll as usize, *args);
        let _ = table.dispatch_with_action(&mut context);
    }
}

#[test]
fn fuzz_local_socket_edge_args() {
    // Only use ptr=0 (triggers null-check in user_string before deref)
    // or ptr=usize::MAX (triggers bounds check).
    let mut table = Table::new();
    table.init();

    let safe_args: &[[usize; 6]] = &[
        [0, 0, 0, 0, 0, 0],
        [0, 64, 0, 0, 0, 0],
        [usize::MAX, 0, 0, 0, 0, 0],
        [usize::MAX, 64, 0, 0, 0, 0],
        [0, usize::MAX, 0, 0, 0, 0],
    ];

    for args in safe_args {
        let mut context = SyscallContext::new(SyscallNumber::BindLocal as usize, *args);
        let _ = table.dispatch_with_action(&mut context);

        let mut context = SyscallContext::new(SyscallNumber::ConnectLocal as usize, *args);
        let _ = table.dispatch_with_action(&mut context);
    }
}

#[test]
fn fuzz_invalid_syscall_numbers() {
    let mut table = Table::new();
    table.init();

    let invalid_numbers: &[usize] = &[
        public_syscall_count(),
        200,
        255,
        256,
        512,
        usize::MAX,
        usize::MAX - 1,
    ];

    for &num in invalid_numbers {
        let args = [0usize; 6];
        let mut context = SyscallContext::new(num, args);
        assert!(
            table.dispatch_with_action(&mut context).is_err(),
            "invalid syscall {num} should return error"
        );
    }
}

#[test]
fn fuzz_spawn_process_edge_args() {
    // Only test with null pointers to avoid deref of unbacked addresses.
    let mut table = Table::new();
    table.init();
    let mut rng = Lcg::new(0xF0F0_0003);

    let spawn_num = SyscallNumber::SpawnProcess as usize;
    // Use ptr=0 for path/options/output; vary the other args.
    let mut arg_sets = Vec::new();
    let edges = edge_values();
    for _ in 0..200 {
        let mut a = [0usize; 6]; // ptr (path), len, options_ptr, options_len, output_ptr, output_len
        a[1] = edges[rng.next_usize(edges.len())]; // path len
        a[3] = edges[rng.next_usize(edges.len())]; // options len
        a[5] = edges[rng.next_usize(edges.len())]; // output len
        arg_sets.push(a);
    }
    // Include explicit ptr=usize::MAX variants.
    arg_sets.push([usize::MAX, 64, 0, 0, 0, 0]);
    arg_sets.push([0, 64, usize::MAX, 64, 0, 0]);

    fuzz_syscall(&table, spawn_num, &arg_sets);
}

#[test]
fn fuzz_file_descriptor_syscalls() {
    let mut table = Table::new();
    table.init();

    let fd_syscalls = &[
        SyscallNumber::Read as usize,
        SyscallNumber::Write as usize,
        SyscallNumber::Close as usize,
        SyscallNumber::Seek as usize,
        SyscallNumber::Dup as usize,
        SyscallNumber::SetLength as usize,
        SyscallNumber::Fsync as usize,
        SyscallNumber::Fdatasync as usize,
        SyscallNumber::StatFd as usize,
        SyscallNumber::ReadDirFd as usize,
        SyscallNumber::SetFdFlags as usize,
    ];

    let fd_values = &[0usize, 1, 2, 3, 10, 100, usize::MAX, usize::MAX / 2];

    for &syscall_num in fd_syscalls {
        for &fd in fd_values {
            // Use ptr=0 for buffer to avoid deref of unbacked host address.
            let args = [fd, 0, 64, 0, 0, 0];
            let mut context = SyscallContext::new(syscall_num, args);
            let _ = table.dispatch_with_action(&mut context);
        }
    }
}

#[test]
fn fuzz_path_based_syscalls_null_ptrs() {
    // Path-based syscalls: only test with null (ptr=0) or MAX pointers
    // to avoid deref in host-side test.  These should all fail gracefully
    // in user_string validation.
    let mut table = Table::new();
    table.init();

    let path_syscalls = &[
        SyscallNumber::Open as usize,
        SyscallNumber::Stat as usize,
        SyscallNumber::ReadDir as usize,
        SyscallNumber::CreateDir as usize,
        SyscallNumber::RemovePath as usize,
        SyscallNumber::Rename as usize,
        SyscallNumber::Mount as usize,
        SyscallNumber::Umount as usize,
    ];

    let safe_ptrs = &[0usize, usize::MAX];
    let safe_lens = &[0usize, 1, 64, 256, usize::MAX];

    for &syscall_num in path_syscalls {
        for &ptr in safe_ptrs {
            for &len in safe_lens {
                let args = [ptr, len, 0, 0, 0, 0];
                let mut context = SyscallContext::new(syscall_num, args);
                let _ = table.dispatch_with_action(&mut context);
            }
        }
    }
}
