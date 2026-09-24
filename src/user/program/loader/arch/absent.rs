//! src/user/program/loader/arch/absent.rs
//!
//! A target this kernel cannot build a user process for: there is no address
//! space to prepare, and the loader above gets `None` rather than a
//! half-built one.

use super::*;

#[cfg(all(
    not(target_arch = "x86_64"),
    not(all(target_arch = "aarch64", target_os = "none")),
    not(all(target_arch = "riscv64", target_os = "none"))
))]
pub(crate) fn prepare_arch_user_address_space(
    _image_layout: Option<&UserImageLoadPlan>,
    _image: &[u8],
    _arguments: &[String],
    _environment: &[String],
) -> Result<Option<ProcessUserAddressSpace>> {
    Ok(None)
}
