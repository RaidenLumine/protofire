//! src/kernel/syscall/mrt.rs
//!
//! Multicast routing (MRT) control syscalls (#169-174) — VIF and MFC
//! management, mirroring the Linux multicast-routing ioctls.

use crate::abi::mrt::MrtMfcDef;
use crate::abi::mrt::MrtVifDef;
use crate::abi::mrt::MRT_MFC_DEF_SIZE;
use crate::abi::mrt::MRT_VIF_DEF_SIZE;
use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::network::stack::NetworkStack;
use crate::Error;
use crate::Result;

/// Syscall 169: mrt_init(flags) — enable multicast routing.
pub(super) fn mrt_init(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_known_flags(context.arg(0), 0)?;
    super::validate_zeroed_args(context, 1)?;
    NetworkStack::global()
        .ok_or(Error::Unsupported)?
        .mrt()
        .lock()
        .init();
    Ok(super::SyscallDispatch::complete(0))
}

/// Syscall 170: mrt_done(flags) — disable multicast routing.
pub(super) fn mrt_done(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_known_flags(context.arg(0), 0)?;
    super::validate_zeroed_args(context, 1)?;
    NetworkStack::global()
        .ok_or(Error::Unsupported)?
        .mrt()
        .lock()
        .done();
    Ok(super::SyscallDispatch::complete(0))
}

/// Syscall 171: mrt_add_vif(&MrtVifDef, len, flags) → vif index.
pub(super) fn mrt_add_vif(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *const u8;
    let len = context.arg(1);
    super::validate_known_flags(context.arg(2), 0)?;
    super::validate_zeroed_args(context, 3)?;
    if len != MRT_VIF_DEF_SIZE {
        return Err(Error::InvalidArgument);
    }
    let def: MrtVifDef = super::user_memory::read_user_value(ptr, len, MRT_VIF_DEF_SIZE)?;
    let index = NetworkStack::global()
        .ok_or(Error::Unsupported)?
        .mrt()
        .lock()
        .add_vif(&def)?;
    Ok(super::SyscallDispatch::complete(index as usize))
}

/// Syscall 172: mrt_del_vif(vif_index, flags).
pub(super) fn mrt_del_vif(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let index = context.arg(0) as u32;
    super::validate_known_flags(context.arg(1), 0)?;
    super::validate_zeroed_args(context, 2)?;
    NetworkStack::global()
        .ok_or(Error::Unsupported)?
        .mrt()
        .lock()
        .del_vif(index)?;
    Ok(super::SyscallDispatch::complete(0))
}

/// Syscall 173: mrt_add_mfc(&MrtMfcDef, len, flags).
pub(super) fn mrt_add_mfc(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *const u8;
    let len = context.arg(1);
    super::validate_known_flags(context.arg(2), 0)?;
    super::validate_zeroed_args(context, 3)?;
    if len != MRT_MFC_DEF_SIZE {
        return Err(Error::InvalidArgument);
    }
    let def: MrtMfcDef = super::user_memory::read_user_value(ptr, len, MRT_MFC_DEF_SIZE)?;
    NetworkStack::global()
        .ok_or(Error::Unsupported)?
        .mrt()
        .lock()
        .add_mfc(&def)?;
    Ok(super::SyscallDispatch::complete(0))
}

/// Syscall 174: mrt_del_mfc(source_packed, group_packed, flags).
pub(super) fn mrt_del_mfc(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let source = context.arg(0);
    let group = context.arg(1);
    super::validate_known_flags(context.arg(2), 0)?;
    super::validate_zeroed_args(context, 3)?;
    let source = [
        (source >> 24) as u8,
        (source >> 16) as u8,
        (source >> 8) as u8,
        source as u8,
    ];
    let group = [
        (group >> 24) as u8,
        (group >> 16) as u8,
        (group >> 8) as u8,
        group as u8,
    ];
    NetworkStack::global()
        .ok_or(Error::Unsupported)?
        .mrt()
        .lock()
        .del_mfc(IpAddress::V4(source), IpAddress::V4(group))?;
    Ok(super::SyscallDispatch::complete(0))
}
