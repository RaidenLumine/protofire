//! src/user/demo/virgl_renderer.rs
//!
//! Demo 3D renderer that drives the VIRGL syscall surface (#181-189) through
//! the normal user syscall path.
//!
//! The renderer performs a minimal frame presentation sequence:
//! `gpu_device_info` → `gpu_ctx_create` → `gpu_res_create_3d` (the render
//! target) → `gpu_submit_3d` (a clear + draw command stream, opaque bytes the
//! kernel forwards to the GPU device) → `gpu_set_scanout`.
//!
//! The function returns a human-readable report string instead of writing to a
//! file descriptor, so the same entry point works from a shell command (which
//! returns the text), from the demo-runtime host proxy (which prints it), and
//! directly from host tests (which assert on both the report and the mock
//! device state).  When no GPU device is present the report explains that the
//! demo is skipped rather than failing hard.

use alloc::format;
use alloc::string::String;

use crate::abi::gpu as gpu_abi;
use crate::abi::virgl as virgl_abi;
use crate::kernel::syscall;
use crate::user::syscall::UserSyscall;
use crate::Result;

/// Drive one frame through the VIRGL syscall path and report what happened.
pub fn run_virgl_render_demo() -> Result<String> {
    let mut report = String::new();

    // 1. Capability probe — no GPU device is reported, not an error.
    let mut info = [0u8; gpu_abi::GPU_DEVICE_INFO_SIZE];
    let mut info_ctx = UserSyscall::gpu_device_info(info.as_mut_ptr() as usize, info.len());
    syscall::dispatch(&mut info_ctx)?;
    let present = u32::from_le_bytes(info[0..4].try_into().expect("info word 0"));
    let has_virgl = u32::from_le_bytes(info[4..8].try_into().expect("info word 1"));
    let display_width = u32::from_le_bytes(info[8..12].try_into().expect("info word 2"));
    let display_height = u32::from_le_bytes(info[12..16].try_into().expect("info word 3"));
    let max_resources = u32::from_le_bytes(info[16..20].try_into().expect("info word 4"));
    report.push_str(&format!(
        "[gpu   ] device: present={present} virgl={has_virgl} display={display_width}x{display_height} max-res={max_resources}\n"
    ));

    if present == 0 {
        report.push_str("[gpu   ] no GPU device present; demo skipped\n");
        return Ok(report);
    }
    if has_virgl == 0 {
        report.push_str("[gpu   ] VIRGL acceleration unavailable; demo skipped\n");
        return Ok(report);
    }

    // 2. Create a VIRGL context.
    let mut ctx_ctx = UserSyscall::gpu_ctx_create(virgl_abi::VIRGL_DEMO_CTX_ID);
    syscall::dispatch(&mut ctx_ctx)?;
    report.push_str(&format!(
        "[gpu   ] ctx created: {}\n",
        virgl_abi::VIRGL_DEMO_CTX_ID
    ));

    // 3. Create the render-target resource.
    let desc = virgl_abi::build_demo_render_target_desc();
    let mut desc_bytes = [0u8; gpu_abi::GPU_RES_CREATE_3D_DESC_SIZE];
    let desc_len = virgl_abi::serialize_create_3d_desc(&desc, &mut desc_bytes);
    debug_assert_eq!(desc_len, gpu_abi::GPU_RES_CREATE_3D_DESC_SIZE);
    let mut res_ctx = UserSyscall::gpu_res_create_3d(desc_bytes.as_ptr() as usize, desc_len);
    let resource_id = syscall::dispatch(&mut res_ctx)? as u32;
    report.push_str(&format!(
        "[gpu   ] resource created: {resource_id} ({width}x{height} stride={stride} rgba8888)\n",
        resource_id = resource_id,
        width = virgl_abi::VIRGL_DEMO_WIDTH,
        height = virgl_abi::VIRGL_DEMO_HEIGHT,
        stride = virgl_abi::VIRGL_DEMO_STRIDE,
    ));

    // 4. Submit the clear + draw command stream as opaque bytes.
    let (command_words, words_used) = virgl_abi::build_demo_clear_draw();
    let mut command_bytes = [0u8; virgl_abi::VIRGL_CMD_BUFFER_WORDS * 4];
    let bytes_written =
        virgl_abi::words_to_le_bytes(&command_words[..words_used], &mut command_bytes);
    let mut submit_ctx = UserSyscall::gpu_submit_3d(
        virgl_abi::VIRGL_DEMO_CTX_ID,
        command_bytes.as_ptr() as usize,
        bytes_written,
    );
    syscall::dispatch(&mut submit_ctx)?;
    report.push_str(&format!(
        "[gpu   ] submit: ctx={ctx} words={words} bytes={bytes}\n",
        ctx = virgl_abi::VIRGL_DEMO_CTX_ID,
        words = words_used,
        bytes = bytes_written,
    ));

    // 5. Present the render target on the scanout.
    let mut scanout_ctx = UserSyscall::gpu_set_scanout(
        resource_id,
        virgl_abi::VIRGL_DEMO_WIDTH,
        virgl_abi::VIRGL_DEMO_HEIGHT,
    );
    syscall::dispatch(&mut scanout_ctx)?;
    report.push_str(&format!(
        "[gpu   ] scanout: resource={resource_id} {width}x{height}\n",
        resource_id = resource_id,
        width = virgl_abi::VIRGL_DEMO_WIDTH,
        height = virgl_abi::VIRGL_DEMO_HEIGHT,
    ));

    report.push_str("[gpu   ] frame presented\n");
    Ok(report)
}
