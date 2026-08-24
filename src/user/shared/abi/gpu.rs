//! src/user/shared/abi/gpu.rs
//!
//! src/abi/gpu.rs
//! Shared ABI definitions for the VIRGL 3D userspace interface — syscalls
//! #181-189 expose the virtio-gpu VIRGL protocol to a userspace renderer.

/// GPU syscall numbers.
pub const SYS_GPU_CTX_CREATE: usize = 181;
pub const SYS_GPU_CTX_DESTROY: usize = 182;
pub const SYS_GPU_RES_CREATE_3D: usize = 183;
pub const SYS_GPU_RES_UNREF: usize = 184;
pub const SYS_GPU_TRANSFER_TO_HOST_3D: usize = 185;
pub const SYS_GPU_TRANSFER_FROM_HOST_3D: usize = 186;
pub const SYS_GPU_SUBMIT_3D: usize = 187;
pub const SYS_GPU_SET_SCANOUT: usize = 188;
pub const SYS_GPU_DEVICE_INFO: usize = 189;

/// Byte size of a serialised `GpuResCreate3dDesc` (12 × u32).
pub const GPU_RES_CREATE_3D_DESC_SIZE: usize = 48;
/// Byte size of a serialised `GpuTransfer3dDesc` (11 × u32).
pub const GPU_TRANSFER_3D_DESC_SIZE: usize = 44;
/// Byte size of a serialised `GpuDeviceInfo` (5 × u32).
pub const GPU_DEVICE_INFO_SIZE: usize = 20;

/// Cap for the user-space resource table (mirrors the kernel's per-device
/// resource-table capacity).
pub const GPU_MAX_RESOURCES: u32 = 64;

/// Description for VIRTIO_GPU_CMD_RESOURCE_CREATE_3D (spec §5.7.2).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuResCreate3dDesc {
    pub resource_id: u32,
    pub target: u32,
    pub format: u32,
    pub bind: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub array_size: u32,
    pub levels: u32,
    pub sample_count: u32,
    pub num_samples: u32,
    pub stride: u32,
}

/// Description for VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D / _FROM_HOST_3D.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuTransfer3dDesc {
    pub resource_id: u32,
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub w: u32,
    pub h: u32,
    pub d: u32,
    pub level: u32,
    pub stride: u32,
    pub layer_stride: u32,
    pub offset: u32,
}

/// Capability report returned by the GpuDeviceInfo syscall.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuDeviceInfo {
    /// 1 when a GPU device is present and the interface is usable.
    pub present: u32,
    /// 1 when VIRGL 3D acceleration was negotiated with the device.
    pub has_virgl: u32,
    /// Framebuffer display width (0 when unknown).
    pub display_width: u32,
    /// Framebuffer display height (0 when unknown).
    pub display_height: u32,
    /// Maximum number of simultaneously-live resources.
    pub max_resources: u32,
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    #[test]
    fn gpu_desc_layouts_are_stable() {
        assert_eq!(size_of::<GpuResCreate3dDesc>(), GPU_RES_CREATE_3D_DESC_SIZE);
        assert_eq!(size_of::<GpuTransfer3dDesc>(), GPU_TRANSFER_3D_DESC_SIZE);
        assert_eq!(size_of::<GpuDeviceInfo>(), GPU_DEVICE_INFO_SIZE);
    }

    #[test]
    fn gpu_syscall_numbers_are_contiguous() {
        assert_eq!(SYS_GPU_CTX_CREATE, 181);
        assert_eq!(SYS_GPU_DEVICE_INFO, 189);
        // Every number in [181, 189] is claimed by exactly one GPU syscall.
        let mut seen = [false; 9];
        for &n in &[
            SYS_GPU_CTX_CREATE,
            SYS_GPU_CTX_DESTROY,
            SYS_GPU_RES_CREATE_3D,
            SYS_GPU_RES_UNREF,
            SYS_GPU_TRANSFER_TO_HOST_3D,
            SYS_GPU_TRANSFER_FROM_HOST_3D,
            SYS_GPU_SUBMIT_3D,
            SYS_GPU_SET_SCANOUT,
            SYS_GPU_DEVICE_INFO,
        ] {
            seen[n - 181] = true;
        }
        assert!(seen.iter().all(|&b| b));
    }
}
