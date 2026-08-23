//! src/user/syscall/payload.rs
//! Architecture-specific payload-runtime macros that emit compact syscall
//! stubs into extracted section blobs for user-program payloads.

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
// Payload runtimes live in extracted section blobs, so these helpers must stay
// self-contained, allocation-free, and easy for the linker to keep together.
// Only invoked by the demo payload programs (feature-gated), so allow the
// macro to be unused on plain builds.
#[allow(unused_macros)]
macro_rules! define_aarch64_payload_runtime {
    ($section:literal) => {
        #[allow(dead_code)]
        const PAYLOAD_RUNTIME_HEX_CAPACITY: usize = 2 + core::mem::size_of::<usize>() * 2;

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        unsafe fn payload_runtime_invoke_raw_status(
            number: usize,
            arg0: usize,
            arg1: usize,
            arg2: usize,
            arg3: usize,
            arg4: usize,
            arg5: usize,
        ) -> usize {
            let status: usize;
            core::arch::asm!(
                "svc #0",
                in("x8") number,
                inlateout("x0") arg0 => status,
                in("x1") arg1,
                in("x2") arg2,
                in("x3") arg3,
                in("x4") arg4,
                in("x5") arg5,
                options(nostack),
            );
            status
        }

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_status_is_error(status: usize) -> bool {
            // The stripped payload only needs the numeric floor check, not the
            // full host-side `Result` decoder.
            status >= $crate::abi::syscall::ERROR_STATUS_FLOOR
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn install_exception_handler(
            vector: u8,
            handler: usize,
            stack_pointer: usize,
            flags: usize,
        ) -> usize {
            unsafe {
                $crate::user::exception::AArch64UserException::install_handler_from_user_mode_with(
                    vector,
                    handler,
                    stack_pointer,
                    flags,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn spawn_process_with(
            path: usize,
            length: usize,
            options: usize,
            options_length: usize,
        ) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::SpawnProcess as usize,
                    path,
                    length,
                    options,
                    options_length,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn wait_process_blocking(pid: usize, record: usize, record_length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::WaitProcess as usize,
                    pid,
                    $crate::abi::process::WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS,
                    record,
                    record_length,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn write_section_message(buffer: usize, length: usize) {
            let _ = write_section_message_status(buffer, length);
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn write_section_message_status(buffer: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::Write as usize,
                    $crate::kernel::process::STDOUT_FD,
                    buffer,
                    length,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_write_hex(value: usize) {
            let mut hex_buffer =
                core::mem::MaybeUninit::<[u8; PAYLOAD_RUNTIME_HEX_CAPACITY]>::uninit();
            let hex_buffer = unsafe { &mut *hex_buffer.as_mut_ptr() };
            hex_buffer[0] = b'0';
            hex_buffer[1] = b'x';

            let digit_count = core::mem::size_of::<usize>() * 2;
            let mut index = 0;
            while index < digit_count {
                let shift = (digit_count - 1 - index) * 4;
                let nibble = ((value >> shift) & 0x0f) as u8;
                hex_buffer[index + 2] = payload_runtime_encode_hex_nibble(nibble);
                index += 1;
            }

            write_section_message(hex_buffer.as_ptr() as usize, hex_buffer.len());
        }

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_encode_hex_nibble(nibble: u8) -> u8 {
            match nibble {
                0..=9 => b'0' + nibble,
                10..=15 => b'a' + (nibble - 10),
                _ => b'0',
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        unsafe fn return_from_exception(
            frame: *const $crate::user::exception::AArch64UserExceptionFrame,
        ) -> ! {
            let _ = $crate::user::exception::AArch64UserException::return_from_frame_from_user_mode(
                frame,
            );
            // Returning here would mean the kernel rejected the resume request.
            core::arch::asm!("brk #0", options(noreturn));
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn exit_with_code(code: usize) -> ! {
            unsafe {
                let _ = payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::Exit as usize,
                    code,
                    0,
                    0,
                    0,
                    0,
                    0,
                );
                core::arch::asm!("brk #0", options(noreturn));
            }
        }

        // ── ring3 identity / chdir / console line stubs (AArch64) ─────

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn chdir(path: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::SetCurrentDir as usize,
                    path,
                    length,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn getpid() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::GetPid as usize,
                    0, 0, 0, 0, 0, 0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn getppid() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::GetPpid as usize,
                    0, 0, 0, 0, 0, 0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn getuid() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::GetUid as usize,
                    0, 0, 0, 0, 0, 0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn getgid() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::GetGid as usize,
                    0, 0, 0, 0, 0, 0,
                )
            }
        }

    };
}

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
pub(crate) use define_aarch64_payload_runtime;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
// Payload runtimes live in extracted section blobs, so these helpers must stay
// self-contained, allocation-free, and easy for the linker to keep together.
// Only invoked by the demo payload programs (feature-gated), so allow the
// macro to be unused on plain builds.
#[allow(unused_macros)]
macro_rules! define_x86_64_payload_runtime {
    ($section:literal) => {
        #[allow(dead_code)]
        const PAYLOAD_RUNTIME_HEX_CAPACITY: usize = 2 + core::mem::size_of::<usize>() * 2;
        #[allow(dead_code)]
        const PAYLOAD_RUNTIME_MAX_C_STRING_BYTES: usize = 4096;
        #[allow(dead_code)]
        // Mirror the auxv keys emitted by `build_initial_user_stack` so stripped
        // payloads can recover page size and entry point without the full ABI
        // crate.
        const PAYLOAD_RUNTIME_X86_64_AUXV_AT_NULL: usize = 0;
        #[allow(dead_code)]
        const PAYLOAD_RUNTIME_X86_64_AUXV_AT_PAGESZ: usize = 6;
        #[allow(dead_code)]
        const PAYLOAD_RUNTIME_X86_64_AUXV_AT_ENTRY: usize = 9;

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        unsafe fn payload_runtime_invoke_raw_status(
            number: usize,
            arg0: usize,
            arg1: usize,
            arg2: usize,
            arg3: usize,
            arg4: usize,
            arg5: usize,
        ) -> usize {
            let status: usize;
            core::arch::asm!(
                "int {vector}",
                vector = const $crate::abi::syscall::X86_64_INTERRUPT_VECTOR,
                inlateout("rax") number => status,
                in("rdi") arg0,
                in("rsi") arg1,
                in("rdx") arg2,
                in("rcx") arg3,
                in("r8") arg4,
                in("r9") arg5,
            );
            status
        }

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_status_is_error(status: usize) -> bool {
            // The stripped payload only needs the numeric floor check, not the
            // full host-side `Result` decoder.
            status >= $crate::abi::syscall::ERROR_STATUS_FLOOR
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn yield_now() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::Yield as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn install_exception_handler(vector: u8, handler: usize, stack_pointer: usize, flags: usize) {
            unsafe {
                let _ = payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::InstallExceptionHandler as usize,
                    vector as usize,
                    handler,
                    stack_pointer,
                    flags,
                    0,
                    0,
                );
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn app_id(buffer: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::AppId as usize,
                    buffer,
                    length,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn app_version(buffer: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::AppVersion as usize,
                    buffer,
                    length,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn arg_count() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::ArgCount as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn arg_value(index: usize, buffer: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::ArgValue as usize,
                    index,
                    buffer,
                    length,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn env_count() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::EnvCount as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn env_value(index: usize, buffer: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::EnvValue as usize,
                    index,
                    buffer,
                    length,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn current_dir(buffer: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::CurrentDir as usize,
                    buffer,
                    length,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn image_path(buffer: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::ImagePath as usize,
                    buffer,
                    length,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn manifest_path(buffer: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::ManifestPath as usize,
                    buffer,
                    length,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn open_path(path: usize, length: usize, flags: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::Open as usize,
                    path,
                    length,
                    flags,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn make_dir(path: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::CreateDir as usize,
                    path,
                    length,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn set_len(fd: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::SetLength as usize,
                    fd,
                    length,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn remove_path(path: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::RemovePath as usize,
                    path,
                    length,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn read_fd(
            fd: usize,
            buffer: usize,
            length: usize,
            timeout_ticks: usize,
        ) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::Read as usize,
                    fd,
                    buffer,
                    length,
                    timeout_ticks,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn write_fd(fd: usize, buffer: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::Write as usize,
                    fd,
                    buffer,
                    length,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn seek_fd(fd: usize, offset: isize, whence: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::Seek as usize,
                    fd,
                    offset as usize,
                    whence,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn close_fd(fd: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::Close as usize,
                    fd,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn wait_process(
            pid: usize,
            timeout_ticks: usize,
            record: usize,
            record_length: usize,
        ) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::WaitProcess as usize,
                    pid,
                    timeout_ticks,
                    record,
                    record_length,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn wait_process_blocking(pid: usize, record: usize, record_length: usize) -> usize {
            // Match the main user helper by using the ABI's blocking-timeout
            // sentinel directly.
            wait_process(
                pid,
                $crate::abi::process::WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS,
                record,
                record_length,
            )
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn spawn_process(path: usize, length: usize) -> usize {
            spawn_process_with(path, length, 0, 0)
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn spawn_process_with(
            path: usize,
            length: usize,
            options: usize,
            options_length: usize,
        ) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::SpawnProcess as usize,
                    path,
                    length,
                    options,
                    options_length,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn exec_process(path: usize, length: usize) -> usize {
            exec_process_with(path, length, 0, 0)
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn exec_process_with(
            path: usize,
            length: usize,
            options: usize,
            options_length: usize,
        ) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::ExecProcess as usize,
                    path,
                    length,
                    options,
                    options_length,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn write_section_message(buffer: usize, length: usize) {
            // Route payload logging through the normal stdout fd so host and
            // kernel execution see the same output path.
            let _ = write_fd($crate::kernel::process::STDOUT_FD, buffer, length);
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_write_c_string(c_string: usize) {
            write_section_message(c_string, payload_runtime_c_string_len(c_string));
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_c_string_len(c_string: usize) -> usize {
            if c_string == 0 {
                return 0;
            }

            let start = c_string as *const u8;
            let mut cursor = start;
            let mut scanned = 0usize;
            unsafe {
                // Use volatile reads so the linker-extracted payload keeps a
                // straightforward byte scan with no libc dependency.
                while scanned < PAYLOAD_RUNTIME_MAX_C_STRING_BYTES
                    && core::ptr::read_volatile(cursor) != 0
                {
                    cursor = cursor.add(1);
                    scanned += 1;
                }
                scanned
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_write_hex(value: usize) {
            let mut hex_buffer =
                core::mem::MaybeUninit::<[u8; PAYLOAD_RUNTIME_HEX_CAPACITY]>::uninit();
            let buffer = hex_buffer.as_mut_ptr() as *mut u8;
            unsafe {
                core::ptr::write(buffer, b'0');
                core::ptr::write(buffer.add(1), b'x');
                let digit_count = core::mem::size_of::<usize>() * 2;
                let mut index = 0;
                while index < digit_count {
                    let shift = (digit_count - 1 - index) * 4;
                    let nibble = ((value >> shift) & 0xF) as u8;
                    core::ptr::write(
                        buffer.add(index + 2),
                        payload_runtime_encode_hex_nibble(nibble),
                    );
                    index += 1;
                }
            }

            write_section_message(
                hex_buffer.as_ptr() as *const u8 as usize,
                PAYLOAD_RUNTIME_HEX_CAPACITY,
            );
        }

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_encode_hex_nibble(nibble: u8) -> u8 {
            match nibble {
                0..=9 => b'0' + nibble,
                10..=15 => b'a' + (nibble - 10),
                _ => b'0',
            }
        }

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_read_word(address: usize) -> usize {
            unsafe { core::ptr::read(address as *const usize) }
        }

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_stack_argc(initial_stack: usize) -> usize {
            // The loader writes argc into the first machine word of the initial
            // x86_64 user stack.
            payload_runtime_read_word(initial_stack)
        }

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_stack_argv_value(initial_stack: usize, index: usize) -> usize {
            // argv pointers start immediately after argc on the initial stack.
            unsafe { core::ptr::read((initial_stack as *const usize).add(index.wrapping_add(1))) }
        }

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_stack_envp_start(initial_stack: usize) -> usize {
            let argc = payload_runtime_stack_argc(initial_stack);
            // envp starts after `argc`, `argv[argc]`, and the trailing NULL.
            unsafe { (initial_stack as *const usize).add(argc.wrapping_add(2)) as usize }
        }

        #[inline(always)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_stack_env_value(initial_stack: usize, index: usize) -> usize {
            // envp is another NULL-terminated pointer table that begins after
            // argv and its terminator.
            unsafe {
                core::ptr::read((payload_runtime_stack_envp_start(initial_stack) as *const usize).add(index))
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_stack_auxv_start(initial_stack: usize) -> usize {
            let mut cursor = payload_runtime_stack_envp_start(initial_stack) as *const usize;
            unsafe {
                // Walk envp until its terminating NULL, then the auxv pairs begin
                // immediately afterwards.
                while core::ptr::read(cursor) != 0 {
                    cursor = cursor.add(1);
                }
                cursor.add(1) as usize
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn payload_runtime_stack_find_auxv_value(initial_stack: usize, key: usize) -> usize {
            let mut cursor = payload_runtime_stack_auxv_start(initial_stack) as *const usize;
            // The auxv list is tiny, so a linear scan keeps the payload runtime
            // small and self-contained.
            loop {
                let entry_key = unsafe { core::ptr::read(cursor) };
                if entry_key == PAYLOAD_RUNTIME_X86_64_AUXV_AT_NULL {
                    return 0;
                }
                if entry_key == key {
                    return unsafe { core::ptr::read(cursor.add(1)) };
                }
                cursor = unsafe { cursor.add(2) };
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        unsafe fn return_from_exception(
            frame: *const $crate::user::exception::X86_64UserExceptionFrame,
        ) -> ! {
            let _ = payload_runtime_invoke_raw_status(
                $crate::kernel::syscall::SyscallNumber::ReturnFromException as usize,
                frame as usize,
                0,
                0,
                0,
                0,
                0,
            );
            // Reaching this point means the kernel rejected the resume request.
            core::arch::asm!("ud2", options(noreturn));
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn exit_with_code(code: usize) -> ! {
            unsafe {
                let _ = payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::Exit as usize,
                    code,
                    0,
                    0,
                    0,
                    0,
                    0,
                );
                // Falling through would mean the kernel unexpectedly returned
                // from an exit request.
                core::arch::asm!("ud2", options(noreturn));
            }
        }

        // ── ring3 identity / chdir / console line stubs ────────────────

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn chdir(path: usize, length: usize) -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::SetCurrentDir as usize,
                    path,
                    length,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn getpid() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::GetPid as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn getppid() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::GetPpid as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn getuid() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::GetUid as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

        #[inline(never)]
        #[allow(dead_code)]
        #[link_section = $section]
        fn getgid() -> usize {
            unsafe {
                payload_runtime_invoke_raw_status(
                    $crate::kernel::syscall::SyscallNumber::GetGid as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }

    };
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
pub(crate) use define_x86_64_payload_runtime;
