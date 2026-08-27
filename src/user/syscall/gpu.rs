//! src/user/syscall/gpu.rs
//!
//! User-side VIRGL 3D syscall builders (#181-189) built on top of
//! `UserSyscall`.  Each builder constructs a [`SyscallContext`] with the exact
//! register layout the kernel GPU handlers expect; the renderer drives them
//! through `syscall::dispatch`.

use crate::kernel::syscall::SyscallContext;
use crate::kernel::syscall::SyscallNumber;

impl super::UserSyscall {
    // ── GPU (VIRGL 3D) syscalls ───────────────────────────────────────

    /// Create a VIRGL rendering context with the given `ctx_id`.
    pub const fn gpu_ctx_create(ctx_id: u32) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::GpuCtxCreate as usize,
            [ctx_id as usize, 0, 0, 0, 0, 0],
        )
    }

    /// Destroy the VIRGL rendering context `ctx_id`.
    pub const fn gpu_ctx_destroy(ctx_id: u32) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::GpuCtxDestroy as usize,
            [ctx_id as usize, 0, 0, 0, 0, 0],
        )
    }

    /// Create a 3D resource from the serialised `GpuResCreate3dDesc` at
    /// `desc_ptr` (size `desc_len`), returning the resource id.
    pub const fn gpu_res_create_3d(desc_ptr: usize, desc_len: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::GpuResCreate3d as usize,
            [desc_ptr, desc_len, 0, 0, 0, 0],
        )
    }

    /// Destroy the 3D resource `resource_id` and release its backing.
    pub const fn gpu_res_unref(resource_id: u32) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::GpuResUnref as usize,
            [resource_id as usize, 0, 0, 0, 0, 0],
        )
    }

    /// Upload `data_len` bytes from `data_ptr` into the resource described by
    /// the serialised `GpuTransfer3dDesc` at `desc_ptr`.
    pub const fn gpu_transfer_to_host_3d(
        desc_ptr: usize,
        desc_len: usize,
        data_ptr: usize,
        data_len: usize,
    ) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::GpuTransferToHost3d as usize,
            [desc_ptr, desc_len, data_ptr, data_len, 0, 0],
        )
    }

    /// Read `data_len` bytes from the resource described by the serialised
    /// `GpuTransfer3dDesc` into `data_ptr`.
    pub const fn gpu_transfer_from_host_3d(
        desc_ptr: usize,
        desc_len: usize,
        data_ptr: usize,
        data_len: usize,
    ) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::GpuTransferFromHost3d as usize,
            [desc_ptr, desc_len, data_ptr, data_len, 0, 0],
        )
    }

    /// Submit an opaque VIRGL command stream (`cmd_len` bytes at `cmd_ptr`) to
    /// the context `ctx_id`.
    pub const fn gpu_submit_3d(ctx_id: u32, cmd_ptr: usize, cmd_len: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::GpuSubmit3d as usize,
            [ctx_id as usize, cmd_ptr, cmd_len, 0, 0, 0],
        )
    }

    /// Present `resource_id` on the scanout at `width`×`height`.
    pub const fn gpu_set_scanout(resource_id: u32, width: u32, height: u32) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::GpuSetScanout as usize,
            [
                resource_id as usize,
                width as usize,
                height as usize,
                0,
                0,
                0,
            ],
        )
    }

    /// Read the capability report into the `GPU_DEVICE_INFO_SIZE`-byte buffer
    /// at `ptr`.
    pub const fn gpu_device_info(ptr: usize, len: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::GpuDeviceInfo as usize,
            [ptr, len, 0, 0, 0, 0],
        )
    }
}
