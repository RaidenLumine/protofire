//! src/user/program/shell/commands/gpu.rs
//!
//! GPU / VIRGL 3D commands.

use alloc::format;
use alloc::string::String;

/// Run the VIRGL 3D demo renderer and return its report as command output.
/// The renderer drives the GPU syscall surface; when no GPU device is probed
/// the report explains that the demo was skipped.
pub(crate) fn cmd_virgl(_cwd: &str, _argv: &[String]) -> String {
    match crate::user::demo::virgl_renderer::run_virgl_render_demo() {
        Ok(report) => report,
        Err(error) => format!("virgl: {}\n", error.as_str()),
    }
}
