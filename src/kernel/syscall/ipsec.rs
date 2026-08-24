//! src/kernel/syscall/ipsec.rs
//!
//! IPsec SPD/SAD management syscalls (#164-168).

use crate::abi::ipsec::{
    IpsecSaDef, IpsecSpDef, IpsecStats, IPSEC_SA_DEF_SIZE, IPSEC_SP_DEF_SIZE, IPSEC_STATS_SIZE,
};
use crate::kernel::network::stack::NetworkStack;
use crate::{Error, Result};

/// Syscall 164: ipsec_add_sp(&IpsecSpDef, len, flags) → sp_id.
pub(super) fn ipsec_add_sp(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *const u8;
    let len = context.arg(1);
    let flags = context.arg(2);

    super::validate_known_flags(flags, 0)?;
    super::validate_zeroed_args(context, 3)?;
    if len != IPSEC_SP_DEF_SIZE {
        return Err(Error::InvalidArgument);
    }
    let def: IpsecSpDef = super::user_memory::read_user_value(ptr, len, IPSEC_SP_DEF_SIZE)?;

    let id = NetworkStack::global()
        .ok_or(Error::Unsupported)?
        .ipsec_spd()
        .lock()
        .add(&def)?;
    Ok(super::SyscallDispatch::complete(id as usize))
}

/// Syscall 165: ipsec_del_sp(sp_id, flags).
pub(super) fn ipsec_del_sp(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let sp_id = context.arg(0) as u64;
    super::validate_known_flags(context.arg(1), 0)?;
    super::validate_zeroed_args(context, 2)?;

    let removed = NetworkStack::global()
        .ok_or(Error::Unsupported)?
        .ipsec_spd()
        .lock()
        .remove(sp_id);
    if removed {
        Ok(super::SyscallDispatch::complete(0))
    } else {
        Err(Error::NotFound)
    }
}

/// Syscall 166: ipsec_add_sa(&IpsecSaDef, len, flags) → sa_id.
pub(super) fn ipsec_add_sa(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *const u8;
    let len = context.arg(1);
    let flags = context.arg(2);

    super::validate_known_flags(flags, 0)?;
    super::validate_zeroed_args(context, 3)?;
    if len != IPSEC_SA_DEF_SIZE {
        return Err(Error::InvalidArgument);
    }
    let def: IpsecSaDef = super::user_memory::read_user_value(ptr, len, IPSEC_SA_DEF_SIZE)?;

    let id = NetworkStack::global()
        .ok_or(Error::Unsupported)?
        .ipsec_sad()
        .lock()
        .add(&def)?;
    Ok(super::SyscallDispatch::complete(id as usize))
}

/// Syscall 167: ipsec_del_sa(spi, flags).
pub(super) fn ipsec_del_sa(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let spi = context.arg(0) as u32;
    super::validate_known_flags(context.arg(1), 0)?;
    super::validate_zeroed_args(context, 2)?;

    let removed = NetworkStack::global()
        .ok_or(Error::Unsupported)?
        .ipsec_sad()
        .lock()
        .remove_spi(spi);
    if removed {
        Ok(super::SyscallDispatch::complete(0))
    } else {
        Err(Error::NotFound)
    }
}

/// Syscall 168: ipsec_get_stats(&IpsecStats, len).
pub(super) fn ipsec_get_stats(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *mut u8;
    let len = context.arg(1);
    super::validate_known_flags(context.arg(2), 0)?;
    super::validate_zeroed_args(context, 3)?;
    if len != IPSEC_STATS_SIZE {
        return Err(Error::InvalidArgument);
    }
    super::user_memory::validate_current_process_user_output_buffer(ptr, len, IPSEC_STATS_SIZE)?;

    let stack = NetworkStack::global().ok_or(Error::Unsupported)?;
    let spd = stack.ipsec_spd().lock();
    let sad = stack.ipsec_sad().lock();

    let mut encrypted = 0u64;
    let mut decrypted = 0u64;
    let auth_failures = 0u64;
    let replay_drops = 0u64;
    for sa in sad.by_spi.values() {
        encrypted += sa.packets_out;
        decrypted += sa.packets_in;
    }
    // Replay/auth counters are updated inline; expose the aggregate SA
    // packet counts plus database sizes.
    let stats = IpsecStats {
        enabled: 1,
        sp_count: spd.len() as u32,
        sa_count: sad.len() as u32,
        esp_encrypted: encrypted,
        esp_decrypted: decrypted,
        auth_failures,
        replay_drops,
    };
    drop(spd);
    drop(sad);

    // Serialize IpsecStats (repr(C), 48 bytes): 3×u32 then 3×u64.
    let mut buf = [0u8; IPSEC_STATS_SIZE];
    buf[0..4].copy_from_slice(&stats.enabled.to_ne_bytes());
    buf[4..8].copy_from_slice(&stats.sp_count.to_ne_bytes());
    buf[8..12].copy_from_slice(&stats.sa_count.to_ne_bytes());
    buf[16..24].copy_from_slice(&stats.esp_encrypted.to_ne_bytes());
    buf[24..32].copy_from_slice(&stats.esp_decrypted.to_ne_bytes());
    buf[32..40].copy_from_slice(&stats.auth_failures.to_ne_bytes());
    buf[40..48].copy_from_slice(&stats.replay_drops.to_ne_bytes());

    super::user_memory::copy_user_bytes(&buf, ptr, len)?;
    Ok(super::SyscallDispatch::complete(0))
}
