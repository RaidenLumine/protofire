//! tests/gpu/virgl_demo.rs
//!
//! Integration test for the VIRGL 3D demo renderer.
//!
//! The renderer drives the GPU syscall surface (#181-189) through the normal
//! `UserSyscall` + `syscall::dispatch` path.  This test installs an in-memory
//! `MockGpuDevice` plus a fresh global syscall table, runs the renderer, and
//! asserts both the report text and the mock device state, including a
//! round-trip check that the command bytes the mock received decode back to
//! the canonical clear + draw stream the renderer encoded.

use std::sync::Arc;

use protofire::abi::gpu as gpu_abi;
use protofire::abi::virgl as virgl_abi;
use protofire::kernel::drivers::virtio_gpu::mock::MockGpuDevice;
use protofire::kernel::drivers::virtio_gpu::set_gpu_device_for_test;
use protofire::kernel::syscall;
use protofire::kernel::syscall::Table;
use protofire::user::demo::virgl_renderer::run_virgl_render_demo;

/// Serialises tests: the global syscall table and the global GPU device are
/// process-wide state shared by every test binary in this crate.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Install a fresh global syscall table (leaked for the process lifetime).
fn install_syscall_table() {
    let table: &'static mut Table = Box::leak(Box::new(Table::new()));
    table.init();
    syscall::install_global(table);
}

/// Install a fresh mock GPU and return a handle to it.
fn install_mock_gpu() -> Arc<MockGpuDevice> {
    let gpu = Arc::new(MockGpuDevice::new());
    set_gpu_device_for_test(Some(gpu.clone()));
    gpu
}

#[test]
fn virgl_render_demo_drives_full_frame_pipeline() {
    let _lock = TEST_LOCK.lock().unwrap();
    install_syscall_table();
    let gpu = install_mock_gpu();

    let report = run_virgl_render_demo().expect("render demo should succeed");

    // Capability report.
    assert!(report.contains("present=1"), "report:\n{report}");
    assert!(report.contains("virgl=1"), "report:\n{report}");
    assert!(report.contains("display=640x480"), "report:\n{report}");
    assert!(report.contains("max-res=64"), "report:\n{report}");

    // Context was created through the syscall path.
    assert!(report.contains("ctx created: 1"), "report:\n{report}");
    assert!(gpu.contexts.lock().contains(&1));

    // Render target was created with the demo dimensions.
    assert!(report.contains("resource created: 1"), "report:\n{report}");
    let backing = gpu.resources.lock().get(&1).cloned().expect("resource 1");
    let expected_size = (virgl_abi::VIRGL_DEMO_WIDTH as usize)
        * (virgl_abi::VIRGL_DEMO_HEIGHT as usize)
        * (virgl_abi::VIRGL_DEMO_STRIDE as usize);
    assert_eq!(backing.len(), expected_size);

    // The clear + draw stream was submitted: the mock received exactly the
    // canonical demo command bytes, and those bytes decode back to the same
    // two-command stream the renderer encoded.
    assert!(report.contains("words=13 bytes=52"), "report:\n{report}");
    assert_eq!(gpu.submits.lock().last().copied(), Some((1, 52)));
    let submitted = gpu
        .submitted_commands
        .lock()
        .last()
        .cloned()
        .expect("one submit recorded");

    let mut submitted_words = [0u32; virgl_abi::VIRGL_CMD_BUFFER_WORDS];
    let submitted_word_count = virgl_abi::le_bytes_to_words(&submitted, &mut submitted_words);
    let decoded = virgl_abi::walk_commands(&submitted_words[..submitted_word_count])
        .expect("submitted stream has valid framing");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].command_type, virgl_abi::VIRGL_CMD_CLEAR);
    assert_eq!(decoded[0].args, &virgl_abi::VIRGL_DEMO_CLEAR_COLOR);
    assert_eq!(decoded[1].command_type, virgl_abi::VIRGL_CMD_DRAW);
    assert_eq!(decoded[1].args[0], virgl_abi::VIRGL_DEMO_DRAW_VERTICES);
    assert_eq!(decoded[1].args[2], virgl_abi::VIRGL_DEMO_DRAW_MODE);

    let (canonical, canonical_used) = virgl_abi::build_demo_clear_draw();
    let mut canonical_bytes = vec![0u8; virgl_abi::demo_command_byte_count()];
    let canonical_len =
        virgl_abi::words_to_le_bytes(&canonical[..canonical_used], &mut canonical_bytes);
    assert_eq!(canonical_len, submitted.len());
    assert_eq!(
        submitted, canonical_bytes,
        "submitted bytes must round-trip"
    );

    // The render target was presented on the scanout.
    assert!(
        report.contains("scanout: resource=1 640x480"),
        "report:\n{report}"
    );
    assert_eq!(*gpu.scanout.lock(), Some((1, 640, 480)));
    assert!(report.contains("frame presented"), "report:\n{report}");

    set_gpu_device_for_test(None);
}

#[test]
fn virgl_render_demo_reports_absent_device() {
    let _lock = TEST_LOCK.lock().unwrap();
    install_syscall_table();
    set_gpu_device_for_test(None);

    // Without a probed device the info syscall reports `present=0`; the
    // renderer must skip gracefully instead of failing.
    let report = run_virgl_render_demo().expect("render demo without device should report");
    assert!(report.contains("present=0"), "report:\n{report}");
    assert!(
        report.contains("no GPU device present; demo skipped"),
        "report:\n{report}"
    );
    assert!(!report.contains("frame presented"), "report:\n{report}");

    set_gpu_device_for_test(None);
}

#[test]
fn gpu_device_info_report_is_abi_stable() {
    let _lock = TEST_LOCK.lock().unwrap();
    install_syscall_table();
    let gpu = install_mock_gpu();

    // Exercise the info syscall directly and verify the ABI byte layout the
    // renderer decodes (5 u32 fields, matching GpuDeviceInfo).
    let mut info = [0u8; gpu_abi::GPU_DEVICE_INFO_SIZE];
    let mut info_ctx = protofire::user::syscall::UserSyscall::gpu_device_info(
        info.as_mut_ptr() as usize,
        info.len(),
    );
    syscall::dispatch(&mut info_ctx).expect("info syscall succeeds");
    let present = u32::from_le_bytes(info[0..4].try_into().unwrap());
    let has_virgl = u32::from_le_bytes(info[4..8].try_into().unwrap());
    let width = u32::from_le_bytes(info[8..12].try_into().unwrap());
    let height = u32::from_le_bytes(info[12..16].try_into().unwrap());
    let max_resources = u32::from_le_bytes(info[16..20].try_into().unwrap());
    assert_eq!(present, 1);
    assert_eq!(has_virgl, 1);
    assert_eq!((width, height), (640, 480));
    assert_eq!(max_resources, gpu_abi::GPU_MAX_RESOURCES);
    assert!(
        gpu.contexts.lock().is_empty(),
        "info must not create a context"
    );

    set_gpu_device_for_test(None);
}
