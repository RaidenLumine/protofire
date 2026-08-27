//! src/user/program/demo_runtime.rs
//!
//! Host-side demo runtime proxy resolution used when bare-metal payloads are
//! not executed directly.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::abi::process::ProcessSpawnOptions;
use crate::abi::process::ProcessSpawnStringRef;
use crate::abi::process::ProcessTerminationRecord;
use crate::abi::process::PROCESS_SPAWN_OPTIONS_SIZE;
use crate::abi::process::PROCESS_TERMINATION_KIND_EXCEPTION;
use crate::abi::process::PROCESS_TERMINATION_KIND_EXIT;
use crate::abi::process::PROCESS_TERMINATION_RECORD_SIZE;
use crate::kernel::fs;
use crate::kernel::process::STDOUT_FD;
use crate::kernel::syscall;
use crate::println;
use crate::Error;
use crate::Result;

use super::super::syscall::UserSyscall;
use super::app::run_app_center_command;
use super::app::run_appctl_command;
use super::dispatch_lumina_command;
use super::DEMO_DATA_PATH;
use super::DEMO_PROGRAM_MACHINE;
use super::DEMO_RUST_CATALOG_PATH;
use super::DEMO_RUST_IO_CHILD_ARGV0;
use super::DEMO_RUST_IO_CHILD_ARGV1;
use super::DEMO_RUST_IO_CHILD_ENV0;
use super::DEMO_RUST_IO_CHILD_ENV1;
use super::DEMO_RUST_IO_DATA_PATH;
use super::DEMO_RUST_IO_DATA_PAYLOAD;
use super::DEMO_RUST_IO_SESSION_PATH;
use super::DEMO_RUST_IO_SESSION_PAYLOAD;
use super::DEMO_RUST_IO_SESSION_TRUNCATED;
use super::DEMO_RUST_IO_STATE_DIR;
use super::DEMO_RUST_IO_TEMP_PATH;
use super::DEMO_RUST_IO_TEMP_PAYLOAD;
use super::DEMO_SESSION_DIR;
use super::DEMO_SESSION_LOG_PATH;
use super::DEMO_TEMP_PATH;

pub(super) fn resolve_program_proxy(host_proxy: &str, machine: u16) -> Result<fn()> {
    if machine != DEMO_PROGRAM_MACHINE {
        return Err(Error::Unsupported);
    }

    // Host proxies mirror the catalog-declared payload identity so host tests
    // can exercise the same launch metadata and syscall flows without running
    // the extracted bare-metal text blobs directly.
    if host_proxy == "demo-launcher" {
        Ok(demo_launcher_entry as fn())
    } else if host_proxy == "appctl" {
        Ok(appctl_entry as fn())
    } else if host_proxy == "app-center" {
        Ok(app_center_entry as fn())
    } else if host_proxy == "lumina" {
        Ok(lumina_entry as fn())
    } else if host_proxy == "demo-launcher-rust" {
        Ok(demo_rust_launcher_entry as fn())
    } else if host_proxy == "demo-launcher-rust-io" {
        Ok(demo_rust_io_launcher_entry as fn())
    } else if host_proxy == "demo-launcher-virgl" {
        Ok(demo_virgl_launcher_entry as fn())
    } else if host_proxy == "shell" {
        Ok(super::shell::shell_user_main as fn())
    } else {
        Err(Error::NotFound)
    }
}

fn demo_launcher_entry() {
    let _ = write_stdout(b"[user  ] demo-launcher started\n");
    log_launch_context();

    let path = b"/system/runtime/README.txt";
    let mut open_ctx = UserSyscall::open(
        path.as_ptr() as usize,
        path.len(),
        crate::abi::io::OPEN_FLAG_READ,
    );
    let fd = match syscall::dispatch(&mut open_ctx) {
        Ok(fd) => fd,
        Err(error) => {
            println!("[user  ] demo-launcher open failed: {}", error.as_str());
            return;
        }
    };

    let mut buffer = [0_u8; 24];
    let mut read_ctx = UserSyscall::read(fd, buffer.as_mut_ptr() as usize, buffer.len(), 0);
    let count = match syscall::dispatch(&mut read_ctx) {
        Ok(count) => count,
        Err(error) => {
            println!("[user  ] demo-launcher read failed: {}", error.as_str());
            return;
        }
    };

    let _ = write_stdout(b"[user  ] readme: ");
    let _ = write_stdout(&buffer[..count]);
    let _ = write_stdout(b"\n");

    let mut close_ctx = UserSyscall::close(fd);
    if let Err(error) = syscall::dispatch(&mut close_ctx) {
        println!("[user  ] demo-launcher close failed: {}", error.as_str());
        return;
    }

    if let Err(error) = demo_update_data_file() {
        println!("[user  ] demo data update failed: {}", error.as_str());
        return;
    }

    if let Err(error) = demo_create_session_log() {
        println!("[user  ] demo session log failed: {}", error.as_str());
        return;
    }

    if let Err(error) = demo_remove_temp_file() {
        println!("[user  ] demo temp cleanup failed: {}", error.as_str());
        return;
    }

    let _ = write_stdout(b"[user  ] demo-launcher done\n");
}

fn demo_rust_launcher_entry() {
    let _ = write_stdout(b"[user  ] hello from rust payload (host proxy)\n");
    let _ = write_stdout(b"[user  ] triggering rust page fault (host proxy)\n");
    let _ = write_stdout(b"[user  ] resumed after rust fault handler (host proxy)\n");
    let _ = write_stdout(b"[user  ] triggering rust invalid opcode (host proxy)\n");
    let _ = write_stdout(b"[user  ] resumed after rust invalid opcode handler (host proxy)\n");
    let _ = write_stdout(b"[user  ] triggering rust general protection (host proxy)\n");
    let _ = write_stdout(b"[user  ] resumed after rust general protection handler (host proxy)\n");
}

fn demo_rust_io_launcher_entry() {
    let _ = write_stdout(b"[user  ] hello from rust io payload (host proxy)\n");

    let mut yield_ctx = UserSyscall::yield_now();
    let _ = syscall::dispatch(&mut yield_ctx);
    let _ = write_stdout(b"[user  ] resumed after rust io yield (host proxy)\n");

    if let Err(error) = demo_rust_io_log_launch_context() {
        println!("[user  ] rust io metadata failed: {}", error.as_str());
        return;
    }

    if let Err(error) = demo_rust_io_read_runtime_readme() {
        println!("[user  ] rust io readme failed: {}", error.as_str());
        return;
    }

    if let Err(error) = demo_rust_io_roundtrip_data_file() {
        println!("[user  ] rust io data failed: {}", error.as_str());
        return;
    }

    if let Err(error) = demo_rust_io_create_session_state() {
        println!("[user  ] rust io session failed: {}", error.as_str());
        return;
    }

    if let Err(error) = demo_rust_io_remove_temp_file() {
        println!("[user  ] rust io cleanup failed: {}", error.as_str());
        return;
    }

    if let Err(error) = demo_rust_io_spawn_and_wait_for_rust_child() {
        println!("[user  ] rust io wait failed: {}", error.as_str());
    }
}

fn demo_virgl_launcher_entry() {
    match crate::user::demo::virgl_renderer::run_virgl_render_demo() {
        Ok(report) => {
            let _ = write_stdout(report.as_bytes());
        }
        Err(error) => {
            let line = format!("[user  ] virgl demo failed: {}\n", error.as_str());
            let _ = write_stdout(line.as_bytes());
        }
    }
}

fn appctl_entry() {
    run_cli_host_proxy("appctl", run_appctl_command);
}

fn app_center_entry() {
    run_cli_host_proxy("app-center", run_app_center_command);
}

fn lumina_entry() {
    run_cli_host_proxy_with_status("lumina", dispatch_lumina_command);
}

fn run_cli_host_proxy(program_name: &str, runner: fn(&fs::FileSystem, &str, &[String]) -> String) {
    let cwd = match syscall_string(UserSyscall::current_dir(0, 0), |buffer, length| {
        UserSyscall::current_dir(buffer, length)
    }) {
        Ok(cwd) => cwd,
        Err(error) => {
            let line = format!("{program_name}: {}\n", error.as_str());
            let _ = write_stdout(line.as_bytes());
            return;
        }
    };

    let argc = match syscall_count(UserSyscall::arg_count()) {
        Ok(count) => count,
        Err(error) => {
            let line = format!("{program_name}: {}\n", error.as_str());
            let _ = write_stdout(line.as_bytes());
            return;
        }
    };
    let mut argv = Vec::with_capacity(argc);
    for index in 0..argc {
        match syscall_string(UserSyscall::arg_value(index, 0, 0), |buffer, length| {
            UserSyscall::arg_value(index, buffer, length)
        }) {
            Ok(argument) => argv.push(argument),
            Err(error) => {
                let line = format!("{program_name}: {}\n", error.as_str());
                let _ = write_stdout(line.as_bytes());
                return;
            }
        }
    }

    let Some(global_fs) = fs::global() else {
        let line = format!("{program_name}: internal error\n");
        let _ = write_stdout(line.as_bytes());
        return;
    };
    let output = {
        let fs = global_fs.lock();
        runner(&fs, &cwd, &argv)
    };
    let _ = write_stdout(output.as_bytes());
}

/// Variant of [`run_cli_host_proxy`] for runners that return `(exit_code,
/// output)`.
///
/// The runner receives `(cwd, argv)` and acquires the filesystem internally,
/// matching the signature of [`dispatch_lumina_command`].
fn run_cli_host_proxy_with_status(
    program_name: &str,
    runner: fn(&str, &[String]) -> (i32, String),
) {
    let cwd = match syscall_string(UserSyscall::current_dir(0, 0), |buffer, length| {
        UserSyscall::current_dir(buffer, length)
    }) {
        Ok(cwd) => cwd,
        Err(error) => {
            let line = format!("{program_name}: {}\n", error.as_str());
            let _ = write_stdout(line.as_bytes());
            return;
        }
    };

    let argc = match syscall_count(UserSyscall::arg_count()) {
        Ok(count) => count,
        Err(error) => {
            let line = format!("{program_name}: {}\n", error.as_str());
            let _ = write_stdout(line.as_bytes());
            return;
        }
    };
    let mut argv = Vec::with_capacity(argc);
    for index in 0..argc {
        match syscall_string(UserSyscall::arg_value(index, 0, 0), |buffer, length| {
            UserSyscall::arg_value(index, buffer, length)
        }) {
            Ok(argument) => argv.push(argument),
            Err(error) => {
                let line = format!("{program_name}: {}\n", error.as_str());
                let _ = write_stdout(line.as_bytes());
                return;
            }
        }
    }

    let (_exit_code, output) = runner(&cwd, &argv);
    let _ = write_stdout(output.as_bytes());
}

fn demo_rust_io_spawn_and_wait_for_rust_child() -> Result<()> {
    let catalog_path = DEMO_RUST_CATALOG_PATH.as_bytes();
    let child_argv = [
        ProcessSpawnStringRef::new(
            DEMO_RUST_IO_CHILD_ARGV0.as_ptr() as usize,
            DEMO_RUST_IO_CHILD_ARGV0.len(),
        ),
        ProcessSpawnStringRef::new(
            DEMO_RUST_IO_CHILD_ARGV1.as_ptr() as usize,
            DEMO_RUST_IO_CHILD_ARGV1.len(),
        ),
    ];
    let child_env = [
        ProcessSpawnStringRef::new(
            DEMO_RUST_IO_CHILD_ENV0.as_ptr() as usize,
            DEMO_RUST_IO_CHILD_ENV0.len(),
        ),
        ProcessSpawnStringRef::new(
            DEMO_RUST_IO_CHILD_ENV1.as_ptr() as usize,
            DEMO_RUST_IO_CHILD_ENV1.len(),
        ),
    ];
    let spawn_options = ProcessSpawnOptions::override_argv_env(
        child_argv.as_ptr() as usize,
        child_argv.len(),
        child_env.as_ptr() as usize,
        child_env.len(),
    );
    // Build the exact user-visible spawn ABI payload here so the host proxy
    // exercises override decoding and child launch the same way a real payload
    // would.
    let mut spawn_ctx = UserSyscall::spawn_process_with(
        catalog_path.as_ptr() as usize,
        catalog_path.len(),
        (&spawn_options as *const ProcessSpawnOptions).cast::<u8>() as usize,
        PROCESS_SPAWN_OPTIONS_SIZE,
    );
    let child_pid = syscall::dispatch(&mut spawn_ctx)?;

    let line = format!("[user  ] rust wait-pid: 0x{child_pid:016x}\n");
    let _ = write_stdout(line.as_bytes());

    let mut record = ProcessTerminationRecord::none();
    let mut wait_ctx = UserSyscall::wait_process_blocking(
        child_pid,
        (&mut record as *mut ProcessTerminationRecord).cast::<u8>() as usize,
        PROCESS_TERMINATION_RECORD_SIZE,
    );
    let size = syscall::dispatch(&mut wait_ctx)?;
    if size != PROCESS_TERMINATION_RECORD_SIZE {
        return Err(Error::InternalError);
    }

    match record.kind {
        PROCESS_TERMINATION_KIND_EXIT => {
            let line = format!("[user  ] rust wait-exit: 0x{:016x}\n", record.status);
            let _ = write_stdout(line.as_bytes());
        }
        PROCESS_TERMINATION_KIND_EXCEPTION => {
            let line = format!(
                "[user  ] rust wait-vector: 0x{:016x}\n",
                record.vector as usize
            );
            let _ = write_stdout(line.as_bytes());
            let line = format!(
                "[user  ] rust wait-error: 0x{:016x}\n",
                record.error_code as usize
            );
            let _ = write_stdout(line.as_bytes());
            if record.fault_address_present != 0 {
                let line = format!("[user  ] rust wait-addr: 0x{:016x}\n", record.fault_address);
                let _ = write_stdout(line.as_bytes());
            }
        }
        _ => return Err(Error::InternalError),
    }

    Ok(())
}

fn demo_rust_io_log_launch_context() -> Result<()> {
    let app_id = syscall_string(UserSyscall::app_id(0, 0), |buffer, length| {
        UserSyscall::app_id(buffer, length)
    })?;
    let cwd = syscall_string(UserSyscall::current_dir(0, 0), |buffer, length| {
        UserSyscall::current_dir(buffer, length)
    })?;
    let image_path = syscall_string(UserSyscall::image_path(0, 0), |buffer, length| {
        UserSyscall::image_path(buffer, length)
    })?;
    let manifest_path = syscall_string(UserSyscall::manifest_path(0, 0), |buffer, length| {
        UserSyscall::manifest_path(buffer, length)
    })?;

    let line = format!("[user  ] rust app-id: {}\n", app_id);
    let _ = write_stdout(line.as_bytes());
    let line = format!("[user  ] rust cwd: {}\n", cwd);
    let _ = write_stdout(line.as_bytes());
    let line = format!("[user  ] rust image: {}\n", image_path);
    let _ = write_stdout(line.as_bytes());
    let line = format!("[user  ] rust manifest: {}\n", manifest_path);
    let _ = write_stdout(line.as_bytes());

    let argc = syscall_count(UserSyscall::arg_count())?;
    if argc > 0 {
        let argv0 = syscall_string(UserSyscall::arg_value(0, 0, 0), |buffer, length| {
            UserSyscall::arg_value(0, buffer, length)
        })?;
        let line = format!("[user  ] rust argv0: {}\n", argv0);
        let _ = write_stdout(line.as_bytes());
    }

    let envc = syscall_count(UserSyscall::env_count())?;
    if envc > 0 {
        let env0 = syscall_string(UserSyscall::env_value(0, 0, 0), |buffer, length| {
            UserSyscall::env_value(0, buffer, length)
        })?;
        let line = format!("[user  ] rust env0: {}\n", env0);
        let _ = write_stdout(line.as_bytes());
    }

    Ok(())
}

fn demo_rust_io_read_runtime_readme() -> Result<()> {
    let readme_path = b"/system/runtime/README.txt";
    let mut open_ctx = UserSyscall::open(
        readme_path.as_ptr() as usize,
        readme_path.len(),
        crate::abi::io::OPEN_FLAG_READ,
    );
    let fd = syscall::dispatch(&mut open_ctx)?;

    let mut buffer = [0_u8; 64];
    let mut read_ctx = UserSyscall::read(fd, buffer.as_mut_ptr() as usize, buffer.len(), 0);
    let count = syscall::dispatch(&mut read_ctx)?;

    let mut close_ctx = UserSyscall::close(fd);
    syscall::dispatch(&mut close_ctx)?;

    let _ = write_stdout(b"[user  ] rust file: ");
    let _ = write_stdout(&buffer[..count]);
    let _ = write_stdout(b"\n");
    Ok(())
}

fn demo_rust_io_roundtrip_data_file() -> Result<()> {
    let path = DEMO_RUST_IO_DATA_PATH.as_bytes();
    let mut open_ctx = UserSyscall::open(
        path.as_ptr() as usize,
        path.len(),
        crate::abi::io::OPEN_FLAG_READ_WRITE_CREATE,
    );
    let fd = syscall::dispatch(&mut open_ctx)?;

    let mut write_ctx = UserSyscall::write(
        fd,
        DEMO_RUST_IO_DATA_PAYLOAD.as_ptr() as usize,
        DEMO_RUST_IO_DATA_PAYLOAD.len(),
    );
    let written = syscall::dispatch(&mut write_ctx)?;
    if written != DEMO_RUST_IO_DATA_PAYLOAD.len() {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut seek_ctx = UserSyscall::seek(fd, 0, crate::kernel::fs::SEEK_SET);
    let reset = syscall::dispatch(&mut seek_ctx)?;
    if reset != 0 {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut buffer = [0_u8; 64];
    let mut read_ctx = UserSyscall::read(
        fd,
        buffer.as_mut_ptr() as usize,
        DEMO_RUST_IO_DATA_PAYLOAD.len(),
        0,
    );
    let count = syscall::dispatch(&mut read_ctx)?;

    let mut close_ctx = UserSyscall::close(fd);
    syscall::dispatch(&mut close_ctx)?;

    let _ = write_stdout(b"[user  ] rust data: ");
    let _ = write_stdout(&buffer[..count]);
    let _ = write_stdout(b"\n");
    Ok(())
}

fn demo_rust_io_create_session_state() -> Result<()> {
    let dir = DEMO_RUST_IO_STATE_DIR.as_bytes();
    let mut mkdir_ctx = UserSyscall::make_dir(dir.as_ptr() as usize, dir.len());
    match syscall::dispatch(&mut mkdir_ctx) {
        Ok(_) | Err(Error::AlreadyExists) => {}
        Err(error) => return Err(error),
    }

    let line = format!("[user  ] rust mkdir: {}\n", DEMO_RUST_IO_STATE_DIR);
    let _ = write_stdout(line.as_bytes());

    let path = DEMO_RUST_IO_SESSION_PATH.as_bytes();
    let mut open_ctx = UserSyscall::open(
        path.as_ptr() as usize,
        path.len(),
        crate::abi::io::OPEN_FLAG_READ_WRITE_CREATE,
    );
    let fd = syscall::dispatch(&mut open_ctx)?;

    let mut write_ctx = UserSyscall::write(
        fd,
        DEMO_RUST_IO_SESSION_PAYLOAD.as_ptr() as usize,
        DEMO_RUST_IO_SESSION_PAYLOAD.len(),
    );
    let written = syscall::dispatch(&mut write_ctx)?;
    if written != DEMO_RUST_IO_SESSION_PAYLOAD.len() {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut set_len_ctx = UserSyscall::set_len(fd, DEMO_RUST_IO_SESSION_TRUNCATED.len());
    let new_len = syscall::dispatch(&mut set_len_ctx)?;
    if new_len != DEMO_RUST_IO_SESSION_TRUNCATED.len() {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut seek_ctx = UserSyscall::seek(fd, 0, crate::kernel::fs::SEEK_SET);
    let reset = syscall::dispatch(&mut seek_ctx)?;
    if reset != 0 {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut buffer = [0_u8; 64];
    let mut read_ctx = UserSyscall::read(
        fd,
        buffer.as_mut_ptr() as usize,
        DEMO_RUST_IO_SESSION_TRUNCATED.len(),
        0,
    );
    let count = syscall::dispatch(&mut read_ctx)?;

    let mut close_ctx = UserSyscall::close(fd);
    syscall::dispatch(&mut close_ctx)?;

    let line = format!(
        "[user  ] rust session-file: {}\n",
        DEMO_RUST_IO_SESSION_PATH
    );
    let _ = write_stdout(line.as_bytes());
    let _ = write_stdout(b"[user  ] rust session: ");
    let _ = write_stdout(&buffer[..count]);
    let _ = write_stdout(b"\n");
    Ok(())
}

fn demo_rust_io_remove_temp_file() -> Result<()> {
    let path = DEMO_RUST_IO_TEMP_PATH.as_bytes();
    let mut open_ctx = UserSyscall::open(
        path.as_ptr() as usize,
        path.len(),
        crate::abi::io::OPEN_FLAG_READ_WRITE_CREATE,
    );
    let fd = syscall::dispatch(&mut open_ctx)?;

    let mut write_ctx = UserSyscall::write(
        fd,
        DEMO_RUST_IO_TEMP_PAYLOAD.as_ptr() as usize,
        DEMO_RUST_IO_TEMP_PAYLOAD.len(),
    );
    let written = syscall::dispatch(&mut write_ctx)?;
    if written != DEMO_RUST_IO_TEMP_PAYLOAD.len() {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut close_ctx = UserSyscall::close(fd);
    syscall::dispatch(&mut close_ctx)?;

    let mut remove_ctx = UserSyscall::remove_path(path.as_ptr() as usize, path.len());
    syscall::dispatch(&mut remove_ctx)?;

    let line = format!("[user  ] rust removed: {}\n", DEMO_RUST_IO_TEMP_PATH);
    let _ = write_stdout(line.as_bytes());
    Ok(())
}

fn demo_update_data_file() -> Result<()> {
    let path = DEMO_DATA_PATH.as_bytes();
    let mut open_ctx = UserSyscall::open(
        path.as_ptr() as usize,
        path.len(),
        crate::abi::io::OPEN_FLAG_READ_WRITE,
    );
    let fd = syscall::dispatch(&mut open_ctx)?;

    let payload = b"User data updated from demo-launcher.\n";
    let mut write_ctx = UserSyscall::write(fd, payload.as_ptr() as usize, payload.len());
    let written = syscall::dispatch(&mut write_ctx)?;
    if written != payload.len() {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut seek_ctx = UserSyscall::seek(fd, 0, crate::kernel::fs::SEEK_SET);
    let reset = syscall::dispatch(&mut seek_ctx)?;
    if reset != 0 {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut buffer = [0_u8; 40];
    let read_len = payload.len().min(buffer.len());
    let mut read_ctx = UserSyscall::read(fd, buffer.as_mut_ptr() as usize, read_len, 0);
    let count = syscall::dispatch(&mut read_ctx)?;

    let mut close_ctx = UserSyscall::close(fd);
    syscall::dispatch(&mut close_ctx)?;

    let _ = write_stdout(b"[user  ] data: ");
    let _ = write_stdout(&buffer[..count]);
    let _ = write_stdout(b"\n");
    Ok(())
}

fn demo_remove_temp_file() -> Result<()> {
    let path = DEMO_TEMP_PATH.as_bytes();
    let mut open_ctx = UserSyscall::open(
        path.as_ptr() as usize,
        path.len(),
        crate::abi::io::OPEN_FLAG_READ_WRITE_CREATE,
    );
    let fd = syscall::dispatch(&mut open_ctx)?;

    let payload = b"temporary demo state";
    let mut write_ctx = UserSyscall::write(fd, payload.as_ptr() as usize, payload.len());
    let written = syscall::dispatch(&mut write_ctx)?;
    if written != payload.len() {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut close_ctx = UserSyscall::close(fd);
    syscall::dispatch(&mut close_ctx)?;

    let mut remove_ctx = UserSyscall::remove_path(path.as_ptr() as usize, path.len());
    syscall::dispatch(&mut remove_ctx)?;

    let line = format!("[user  ] removed={}\n", DEMO_TEMP_PATH);
    let _ = write_stdout(line.as_bytes());
    Ok(())
}

fn demo_create_session_log() -> Result<()> {
    let dir = DEMO_SESSION_DIR.as_bytes();
    let mut mkdir_ctx = UserSyscall::make_dir(dir.as_ptr() as usize, dir.len());
    match syscall::dispatch(&mut mkdir_ctx) {
        Ok(_) | Err(Error::AlreadyExists) => {}
        Err(error) => return Err(error),
    }

    let path = DEMO_SESSION_LOG_PATH.as_bytes();
    let mut open_ctx = UserSyscall::open(
        path.as_ptr() as usize,
        path.len(),
        crate::abi::io::OPEN_FLAG_READ_WRITE_CREATE,
    );
    let fd = syscall::dispatch(&mut open_ctx)?;

    let payload = b"demo-launcher session persisted";
    let mut write_ctx = UserSyscall::write(fd, payload.as_ptr() as usize, payload.len());
    let written = syscall::dispatch(&mut write_ctx)?;
    if written != payload.len() {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let truncated = b"demo-launcher session";
    let mut set_len_ctx = UserSyscall::set_len(fd, truncated.len());
    let new_len = syscall::dispatch(&mut set_len_ctx)?;
    if new_len != truncated.len() {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut seek_ctx = UserSyscall::seek(fd, 0, crate::kernel::fs::SEEK_SET);
    let reset = syscall::dispatch(&mut seek_ctx)?;
    if reset != 0 {
        let mut close_ctx = UserSyscall::close(fd);
        let _ = syscall::dispatch(&mut close_ctx);
        return Err(Error::InternalError);
    }

    let mut buffer = [0_u8; 40];
    let read_len = payload.len().min(buffer.len());
    let mut read_ctx = UserSyscall::read(fd, buffer.as_mut_ptr() as usize, read_len, 0);
    let count = syscall::dispatch(&mut read_ctx)?;

    let mut close_ctx = UserSyscall::close(fd);
    syscall::dispatch(&mut close_ctx)?;

    let line = format!("[user  ] session-file={}\n", DEMO_SESSION_LOG_PATH);
    let _ = write_stdout(line.as_bytes());
    let length_line = format!("[user  ] session-len={}\n", truncated.len());
    let _ = write_stdout(length_line.as_bytes());
    let _ = write_stdout(b"[user  ] session: ");
    let _ = write_stdout(&buffer[..count]);
    let _ = write_stdout(b"\n");
    Ok(())
}

fn log_launch_context() {
    // Treat launch metadata logging as best-effort diagnostics: if any probe is
    // unavailable, skip the rest rather than turning the demo into a hard
    // failure.
    let app_id = match syscall_string(UserSyscall::app_id(0, 0), |buffer, length| {
        UserSyscall::app_id(buffer, length)
    }) {
        Ok(value) => value,
        Err(_) => return,
    };

    let version = match syscall_string(UserSyscall::app_version(0, 0), |buffer, length| {
        UserSyscall::app_version(buffer, length)
    }) {
        Ok(value) => value,
        Err(_) => return,
    };

    let argc = match syscall_count(UserSyscall::arg_count()) {
        Ok(count) => count,
        Err(_) => return,
    };

    let envc = match syscall_count(UserSyscall::env_count()) {
        Ok(count) => count,
        Err(_) => return,
    };

    let cwd = match syscall_string(UserSyscall::current_dir(0, 0), |buffer, length| {
        UserSyscall::current_dir(buffer, length)
    }) {
        Ok(cwd) => cwd,
        Err(_) => return,
    };

    let summary = format!(
        "[user  ] launch id={} version={} argc={} envc={} cwd={}\n",
        app_id, version, argc, envc, cwd
    );
    let _ = write_stdout(summary.as_bytes());

    if let Ok(image_path) = syscall_string(UserSyscall::image_path(0, 0), |buffer, length| {
        UserSyscall::image_path(buffer, length)
    }) {
        let line = format!("[user  ] image={}\n", image_path);
        let _ = write_stdout(line.as_bytes());
    }

    if let Ok(manifest_path) = syscall_string(UserSyscall::manifest_path(0, 0), |buffer, length| {
        UserSyscall::manifest_path(buffer, length)
    }) {
        let line = format!("[user  ] manifest={}\n", manifest_path);
        let _ = write_stdout(line.as_bytes());
    }

    if argc > 0 {
        if let Ok(argv0) = syscall_string(UserSyscall::arg_value(0, 0, 0), |buffer, length| {
            UserSyscall::arg_value(0, buffer, length)
        }) {
            let line = format!("[user  ] argv0={}\n", argv0);
            let _ = write_stdout(line.as_bytes());
        }
    }

    if envc > 0 {
        if let Ok(env0) = syscall_string(UserSyscall::env_value(0, 0, 0), |buffer, length| {
            UserSyscall::env_value(0, buffer, length)
        }) {
            let line = format!("[user  ] env0={}\n", env0);
            let _ = write_stdout(line.as_bytes());
        }
    }
}

fn syscall_count(mut context: syscall::SyscallContext) -> Result<usize> {
    syscall::dispatch(&mut context)
}

fn syscall_string<F>(mut probe: syscall::SyscallContext, build: F) -> Result<String>
where
    F: Fn(usize, usize) -> syscall::SyscallContext,
{
    // These metadata syscalls use the usual two-step "size probe, then fill"
    // pattern so user buffers can be sized exactly.
    let length = syscall::dispatch(&mut probe)?;
    let mut buffer = vec![0_u8; length];

    if length == 0 {
        return Ok(String::new());
    }

    let mut read = build(buffer.as_mut_ptr() as usize, buffer.len());
    let count = syscall::dispatch(&mut read)?;
    if count != buffer.len() {
        return Err(Error::InternalError);
    }

    String::from_utf8(buffer).map_err(|_| Error::InvalidArgument)
}

fn write_stdout(bytes: &[u8]) -> Result<usize> {
    // Route all demo output through the normal stdout fd so host proxies and
    // real user payloads share the same visible write path.
    let mut ctx = UserSyscall::write(STDOUT_FD, bytes.as_ptr() as usize, bytes.len());
    syscall::dispatch(&mut ctx)
}
