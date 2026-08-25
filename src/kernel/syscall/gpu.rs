//! src/kernel/syscall/gpu.rs
//!
//! VIRGL 3D userspace interface syscalls (#181-189).
//!
//! These expose the virtio-gpu VIRGL protocol to a userspace renderer: VIRGL
//! contexts, 3D resources (with kernel-managed DMA backing), host transfers,
//! command submission, scanout presentation, and a capability report.  The
//! actual 3D rendering executes host-side via the hypervisor's VIRGL
//! renderer; the kernel provides the transport a renderer drives.
//!
//! Every handler fails with `Error::Unsupported` when no GPU device has been
//! probed (e.g. host builds without a virtio-gpu device).

use crate::abi::gpu as gpu_abi;
use crate::kernel::drivers::virtio_gpu;
use crate::Error;
use crate::Result;

use super::user_memory;
use super::SyscallContext;
use super::SyscallDispatch;

/// `gpu_ctx_create` — create a VIRGL rendering context (#181).
pub(super) fn gpu_ctx_create(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let ctx_id = context.arg(0) as u32;
    super::validate_zeroed_args(context, 1)?;
    let gpu = virtio_gpu::gpu_device().ok_or(Error::Unsupported)?;
    gpu.ctx_create(ctx_id)?;
    Ok(SyscallDispatch::complete(0))
}

/// `gpu_ctx_destroy` — destroy a VIRGL rendering context (#182).
pub(super) fn gpu_ctx_destroy(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let ctx_id = context.arg(0) as u32;
    super::validate_zeroed_args(context, 1)?;
    let gpu = virtio_gpu::gpu_device().ok_or(Error::Unsupported)?;
    gpu.ctx_destroy(ctx_id)?;
    Ok(SyscallDispatch::complete(0))
}

/// `gpu_res_create_3d` — create a 3D resource with kernel-backed DMA (#183).
pub(super) fn gpu_res_create_3d(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let desc_ptr = context.arg(0) as *const gpu_abi::GpuResCreate3dDesc;
    let desc_len = context.arg(1);
    super::validate_zeroed_args(context, 2)?;
    if desc_len != gpu_abi::GPU_RES_CREATE_3D_DESC_SIZE {
        return Err(Error::InvalidArgument);
    }
    let desc: gpu_abi::GpuResCreate3dDesc = user_memory::read_user_value(
        desc_ptr as *const u8,
        desc_len,
        gpu_abi::GPU_RES_CREATE_3D_DESC_SIZE,
    )?;
    let gpu = virtio_gpu::gpu_device().ok_or(Error::Unsupported)?;
    let resource_id = gpu.create_3d_resource(&desc)?;
    Ok(SyscallDispatch::complete(resource_id as usize))
}

/// `gpu_res_unref` — destroy a 3D resource and release its backing (#184).
pub(super) fn gpu_res_unref(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let resource_id = context.arg(0) as u32;
    super::validate_zeroed_args(context, 1)?;
    let gpu = virtio_gpu::gpu_device().ok_or(Error::Unsupported)?;
    gpu.unref_resource(resource_id)?;
    Ok(SyscallDispatch::complete(0))
}

/// `gpu_transfer_to_host_3d` — copy user data into a resource and upload it
/// to the host (#185).
pub(super) fn gpu_transfer_to_host_3d(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let desc_ptr = context.arg(0) as *const gpu_abi::GpuTransfer3dDesc;
    let desc_len = context.arg(1);
    let data_ptr = context.arg(2) as *const u8;
    let data_len = context.arg(3);
    super::validate_zeroed_args(context, 4)?;
    if desc_len != gpu_abi::GPU_TRANSFER_3D_DESC_SIZE {
        return Err(Error::InvalidArgument);
    }
    let desc: gpu_abi::GpuTransfer3dDesc = user_memory::read_user_value(
        desc_ptr as *const u8,
        desc_len,
        gpu_abi::GPU_TRANSFER_3D_DESC_SIZE,
    )?;
    let gpu = virtio_gpu::gpu_device().ok_or(Error::Unsupported)?;
    user_memory::with_optional_input_slice(data_ptr, data_len, |data| {
        gpu.transfer_to_host_3d(&desc, data)
    })?;
    Ok(SyscallDispatch::complete(0))
}

/// `gpu_transfer_from_host_3d` — transfer a resource region back from the
/// host into a user buffer (#186).
pub(super) fn gpu_transfer_from_host_3d(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let desc_ptr = context.arg(0) as *const gpu_abi::GpuTransfer3dDesc;
    let desc_len = context.arg(1);
    let data_ptr = context.arg(2) as *mut u8;
    let data_len = context.arg(3);
    super::validate_zeroed_args(context, 4)?;
    if desc_len != gpu_abi::GPU_TRANSFER_3D_DESC_SIZE {
        return Err(Error::InvalidArgument);
    }
    let desc: gpu_abi::GpuTransfer3dDesc = user_memory::read_user_value(
        desc_ptr as *const u8,
        desc_len,
        gpu_abi::GPU_TRANSFER_3D_DESC_SIZE,
    )?;
    let gpu = virtio_gpu::gpu_device().ok_or(Error::Unsupported)?;
    user_memory::with_optional_output_slice(data_ptr, data_len, |data| {
        gpu.transfer_from_host_3d(&desc, data)
    })?;
    Ok(SyscallDispatch::complete(0))
}

/// `gpu_submit_3d` — submit a VIRGL command stream to a context (#187).
pub(super) fn gpu_submit_3d(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let ctx_id = context.arg(0) as u32;
    let cmd_ptr = context.arg(1) as *const u8;
    let cmd_len = context.arg(2);
    super::validate_zeroed_args(context, 3)?;
    let gpu = virtio_gpu::gpu_device().ok_or(Error::Unsupported)?;
    user_memory::with_optional_input_slice(cmd_ptr, cmd_len, |cmd| gpu.submit_3d(ctx_id, cmd))?;
    Ok(SyscallDispatch::complete(0))
}

/// `gpu_set_scanout` — present a resource on the display (#188).
pub(super) fn gpu_set_scanout(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let resource_id = context.arg(0) as u32;
    let width = context.arg(1) as u32;
    let height = context.arg(2) as u32;
    super::validate_zeroed_args(context, 3)?;
    let gpu = virtio_gpu::gpu_device().ok_or(Error::Unsupported)?;
    gpu.set_scanout(resource_id, width, height)?;
    Ok(SyscallDispatch::complete(0))
}

/// `gpu_device_info` — report GPU presence and capabilities (#189).
pub(super) fn gpu_device_info(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let ptr = context.arg(0) as *mut u8;
    let len = context.arg(1);
    super::validate_zeroed_args(context, 2)?;
    if len != gpu_abi::GPU_DEVICE_INFO_SIZE {
        return Err(Error::InvalidArgument);
    }
    user_memory::validate_current_process_user_output_buffer(
        ptr,
        len,
        gpu_abi::GPU_DEVICE_INFO_SIZE,
    )?;

    let gpu = virtio_gpu::gpu_device();
    let info = match gpu.as_ref() {
        Some(gpu) => {
            let display = gpu.display_info().unwrap_or((0, 0));
            gpu_abi::GpuDeviceInfo {
                present: 1,
                has_virgl: u32::from(gpu.has_virgl()),
                display_width: display.0,
                display_height: display.1,
                max_resources: gpu_abi::GPU_MAX_RESOURCES,
            }
        }
        None => gpu_abi::GpuDeviceInfo {
            present: 0,
            has_virgl: 0,
            display_width: 0,
            display_height: 0,
            max_resources: 0,
        },
    };

    let mut buf = [0u8; gpu_abi::GPU_DEVICE_INFO_SIZE];
    buf[0..4].copy_from_slice(&info.present.to_ne_bytes());
    buf[4..8].copy_from_slice(&info.has_virgl.to_ne_bytes());
    buf[8..12].copy_from_slice(&info.display_width.to_ne_bytes());
    buf[12..16].copy_from_slice(&info.display_height.to_ne_bytes());
    buf[16..20].copy_from_slice(&info.max_resources.to_ne_bytes());

    user_memory::copy_user_bytes(&buf, ptr, len)?;
    Ok(SyscallDispatch::complete(0))
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "none"))]
    use super::super::test_support;
    use super::super::SyscallContext;
    use super::super::SyscallDispatch;
    use super::super::SyscallNumber;
    use super::*;
    use crate::abi::gpu as gpu_abi;
    use crate::kernel::drivers::virtio_gpu::mock::MockGpuDevice;
    use crate::kernel::drivers::virtio_gpu::set_gpu_device_for_test;
    use crate::kernel::sync::Mutex as TestMutex;
    use alloc::sync::Arc;

    /// Serialises GPU syscall tests: the global GPU_DEVICE is shared.
    static GPU_TEST_LOCK: TestMutex<()> = TestMutex::new(());

    /// Install a fresh mock GPU as the active device and return it.
    fn install_mock_gpu() -> Arc<MockGpuDevice> {
        let gpu = Arc::new(MockGpuDevice::new());
        set_gpu_device_for_test(Some(gpu.clone()));
        gpu
    }

    /// Serialise a `GpuResCreate3dDesc` into its ABI byte layout.
    fn create_3d_desc_bytes() -> [u8; gpu_abi::GPU_RES_CREATE_3D_DESC_SIZE] {
        let desc = gpu_abi::GpuResCreate3dDesc {
            resource_id: 10,
            target: 2,
            format: 1,
            bind: 3,
            width: 64,
            height: 64,
            depth: 1,
            array_size: 1,
            levels: 1,
            sample_count: 0,
            num_samples: 0,
            stride: 256,
        };
        let mut buf = [0u8; gpu_abi::GPU_RES_CREATE_3D_DESC_SIZE];
        let fields = [
            desc.resource_id,
            desc.target,
            desc.format,
            desc.bind,
            desc.width,
            desc.height,
            desc.depth,
            desc.array_size,
            desc.levels,
            desc.sample_count,
            desc.num_samples,
            desc.stride,
        ];
        for (i, v) in fields.iter().enumerate() {
            buf[i * 4..(i + 1) * 4].copy_from_slice(&v.to_ne_bytes());
        }
        buf
    }

    /// Serialise a `GpuTransfer3dDesc` into its ABI byte layout.
    fn transfer_3d_desc_bytes() -> [u8; gpu_abi::GPU_TRANSFER_3D_DESC_SIZE] {
        let desc = gpu_abi::GpuTransfer3dDesc {
            resource_id: 10,
            x: 0,
            y: 0,
            z: 0,
            w: 4,
            h: 4,
            d: 1,
            level: 0,
            stride: 16,
            layer_stride: 64,
            offset: 0,
        };
        let mut buf = [0u8; gpu_abi::GPU_TRANSFER_3D_DESC_SIZE];
        let fields = [
            desc.resource_id,
            desc.x,
            desc.y,
            desc.z,
            desc.w,
            desc.h,
            desc.d,
            desc.level,
            desc.stride,
            desc.layer_stride,
            desc.offset,
        ];
        for (i, v) in fields.iter().enumerate() {
            buf[i * 4..(i + 1) * 4].copy_from_slice(&v.to_ne_bytes());
        }
        buf
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn gpu_ctx_create_and_destroy_round_trip() {
        let _lock = GPU_TEST_LOCK.lock();
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("gpu-ctx");
        let gpu = install_mock_gpu();

        let mut create =
            SyscallContext::new(SyscallNumber::GpuCtxCreate as usize, [7, 0, 0, 0, 0, 0]);
        assert_eq!(
            gpu_ctx_create(&mut create),
            Ok(SyscallDispatch::complete(0))
        );
        assert!(gpu.contexts.lock().contains(&7));

        let mut destroy =
            SyscallContext::new(SyscallNumber::GpuCtxDestroy as usize, [7, 0, 0, 0, 0, 0]);
        assert_eq!(
            gpu_ctx_destroy(&mut destroy),
            Ok(SyscallDispatch::complete(0))
        );
        assert!(!gpu.contexts.lock().contains(&7));

        set_gpu_device_for_test(None);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn gpu_res_create_3d_round_trip() {
        let _lock = GPU_TEST_LOCK.lock();
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("gpu-res-create");
        let gpu = install_mock_gpu();

        let desc = create_3d_desc_bytes();
        let mut ctx = SyscallContext::new(
            SyscallNumber::GpuResCreate3d as usize,
            [
                desc.as_ptr() as usize,
                gpu_abi::GPU_RES_CREATE_3D_DESC_SIZE,
                0,
                0,
                0,
                0,
            ],
        );
        assert_eq!(
            gpu_res_create_3d(&mut ctx),
            Ok(SyscallDispatch::complete(10))
        );
        assert!(gpu.resources.lock().contains_key(&10));

        // Unref removes the resource.
        let mut unref =
            SyscallContext::new(SyscallNumber::GpuResUnref as usize, [10, 0, 0, 0, 0, 0]);
        assert_eq!(gpu_res_unref(&mut unref), Ok(SyscallDispatch::complete(0)));
        assert!(!gpu.resources.lock().contains_key(&10));

        set_gpu_device_for_test(None);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn gpu_transfer_to_host_copies_user_data() {
        let _lock = GPU_TEST_LOCK.lock();
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("gpu-transfer-to");
        let gpu = install_mock_gpu();

        // Create the 4×4×4-byte resource, then upload a full row-set.
        let desc = create_3d_desc_bytes();
        let mut ctx = SyscallContext::new(
            SyscallNumber::GpuResCreate3d as usize,
            [
                desc.as_ptr() as usize,
                gpu_abi::GPU_RES_CREATE_3D_DESC_SIZE,
                0,
                0,
                0,
                0,
            ],
        );
        assert_eq!(
            gpu_res_create_3d(&mut ctx),
            Ok(SyscallDispatch::complete(10))
        );

        let tdesc = transfer_3d_desc_bytes();
        let data = [0xABu8; 64];
        let mut tx = SyscallContext::new(
            SyscallNumber::GpuTransferToHost3d as usize,
            [
                tdesc.as_ptr() as usize,
                gpu_abi::GPU_TRANSFER_3D_DESC_SIZE,
                data.as_ptr() as usize,
                data.len(),
                0,
                0,
            ],
        );
        assert_eq!(
            gpu_transfer_to_host_3d(&mut tx),
            Ok(SyscallDispatch::complete(0))
        );

        // The mock's backing now holds the uploaded bytes.
        let backing = gpu.resources.lock().get(&10).cloned().expect("resource");
        assert_eq!(&backing[..data.len()], &data[..]);
        assert_eq!(gpu.transfers.lock().last(), Some(&(10, 0, 4, 4)));

        set_gpu_device_for_test(None);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn gpu_transfer_from_host_reads_backing() {
        let _lock = GPU_TEST_LOCK.lock();
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("gpu-transfer-from");
        let gpu = install_mock_gpu();

        // Pre-populate a resource in the mock, then read it back via the
        // from-host transfer path.
        {
            let mut resources = gpu.resources.lock();
            resources.insert(10, alloc::vec![0x77u8; 64]);
        }

        let tdesc = transfer_3d_desc_bytes();
        let mut out = [0u8; 64];
        let mut rx = SyscallContext::new(
            SyscallNumber::GpuTransferFromHost3d as usize,
            [
                tdesc.as_ptr() as usize,
                gpu_abi::GPU_TRANSFER_3D_DESC_SIZE,
                out.as_mut_ptr() as usize,
                out.len(),
                0,
                0,
            ],
        );
        assert_eq!(
            gpu_transfer_from_host_3d(&mut rx),
            Ok(SyscallDispatch::complete(0))
        );
        assert!(out.iter().all(|&b| b == 0x77));

        set_gpu_device_for_test(None);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn gpu_submit_3d_records_command() {
        let _lock = GPU_TEST_LOCK.lock();
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("gpu-submit");
        let gpu = install_mock_gpu();

        let cmd = [0x01u8, 0x02, 0x03, 0x04];
        let mut ctx = SyscallContext::new(
            SyscallNumber::GpuSubmit3d as usize,
            [3, cmd.as_ptr() as usize, cmd.len(), 0, 0, 0],
        );
        assert_eq!(gpu_submit_3d(&mut ctx), Ok(SyscallDispatch::complete(0)));
        assert_eq!(gpu.submits.lock().last(), Some(&(3, 4)));

        set_gpu_device_for_test(None);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn gpu_set_scanout_records_resource() {
        let _lock = GPU_TEST_LOCK.lock();
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("gpu-scanout");
        let gpu = install_mock_gpu();

        let mut ctx = SyscallContext::new(
            SyscallNumber::GpuSetScanout as usize,
            [10, 640, 480, 0, 0, 0],
        );
        assert_eq!(gpu_set_scanout(&mut ctx), Ok(SyscallDispatch::complete(0)));
        assert_eq!(*gpu.scanout.lock(), Some((10, 640, 480)));

        set_gpu_device_for_test(None);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn gpu_device_info_reports_present_and_capabilities() {
        let _lock = GPU_TEST_LOCK.lock();
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("gpu-info");
        install_mock_gpu();

        let mut info = [0u8; gpu_abi::GPU_DEVICE_INFO_SIZE];
        let mut ctx = SyscallContext::new(
            SyscallNumber::GpuDeviceInfo as usize,
            [
                info.as_mut_ptr() as usize,
                gpu_abi::GPU_DEVICE_INFO_SIZE,
                0,
                0,
                0,
                0,
            ],
        );
        assert_eq!(gpu_device_info(&mut ctx), Ok(SyscallDispatch::complete(0)));
        let present = u32::from_ne_bytes(info[0..4].try_into().unwrap());
        let has_virgl = u32::from_ne_bytes(info[4..8].try_into().unwrap());
        let width = u32::from_ne_bytes(info[8..12].try_into().unwrap());
        let height = u32::from_ne_bytes(info[12..16].try_into().unwrap());
        assert_eq!(present, 1);
        assert_eq!(has_virgl, 1);
        // The mock GPU reports the default display resolution.
        assert_eq!((width, height), (640, 480));

        set_gpu_device_for_test(None);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn gpu_syscalls_require_a_probed_device() {
        let _lock = GPU_TEST_LOCK.lock();
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("gpu-no-device");
        set_gpu_device_for_test(None);

        let mut ctx = SyscallContext::new(SyscallNumber::GpuCtxCreate as usize, [1, 0, 0, 0, 0, 0]);
        assert_eq!(gpu_ctx_create(&mut ctx), Err(Error::Unsupported));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn gpu_device_info_reports_absent_without_gpu() {
        let _lock = GPU_TEST_LOCK.lock();
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("gpu-info-absent");
        set_gpu_device_for_test(None);

        let mut info = [0u8; gpu_abi::GPU_DEVICE_INFO_SIZE];
        let mut ctx = SyscallContext::new(
            SyscallNumber::GpuDeviceInfo as usize,
            [
                info.as_mut_ptr() as usize,
                gpu_abi::GPU_DEVICE_INFO_SIZE,
                0,
                0,
                0,
                0,
            ],
        );
        assert_eq!(gpu_device_info(&mut ctx), Ok(SyscallDispatch::complete(0)));
        let present = u32::from_ne_bytes(info[0..4].try_into().unwrap());
        assert_eq!(present, 0);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn gpu_res_create_3d_rejects_wrong_desc_len() {
        let _lock = GPU_TEST_LOCK.lock();
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("gpu-bad-len");
        install_mock_gpu();

        let desc = create_3d_desc_bytes();
        let mut ctx = SyscallContext::new(
            SyscallNumber::GpuResCreate3d as usize,
            [desc.as_ptr() as usize, 4, 0, 0, 0, 0],
        );
        assert_eq!(gpu_res_create_3d(&mut ctx), Err(Error::InvalidArgument));

        set_gpu_device_for_test(None);
    }
}
