//! src/kernel/drivers/virtio_gpu.rs
//!
//! VirtIO GPU device driver.
//! VirtIO GPU driver — provides a linear framebuffer for display output.
//!
//! Communicates with the device through the VirtIO control virtqueue to:
//!   1. Query display info (resolution, enabled status)
//!   2. Create a 2D resource
//!   3. Attach physical memory as the resource backing
//!   4. Set the resource as the scanout buffer
//!   5. Flush the resource to the display
//!
//! The resulting linear framebuffer is fed to
//! `framebuffer_console::install_console()` so the kernel's text-mode console
//! can render on top of it.
//!
//! ## PCI probe (x86_64)
//!
//! On QEMU x86_64 the virtio-gpu device appears on the PCI bus as
//! `virtio-gpu-pci` (vendor 0x1AF4, device 0x1050).  The driver probes via
//! PCI enumeration, maps the first MMIO BAR, and uses the modern VirtIO 1.0
//! PCI transport (PciModernRegion).  Falls back to the legacy IO-port
//! transport if no MMIO BAR is available.
//!
//! ## Frame-buffer memory
//!
//! Backing memory for the scanout resource is allocated through the kernel's
//! frame allocator (`DmaBuffer`), which provides physically-contiguous,
//! page-aligned memory within the identity-mapped region.

use alloc::sync::Arc;

// Imports used only by the bare-metal x86_64 device probe / VirtioGpuDevice
// machinery; the host build keeps just the syscall-facing interface and the
// in-memory mock.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use alloc::boxed::Box;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::ptr;

use crate::kernel::drivers::framebuffer::FramebufferInfo;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::framebuffer_console;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::{VirtIoMmio, VirtQueue, REG_QUEUE_NOTIFY, VIRTQ_DESC_F_WRITE};
use crate::kernel::drivers::{Driver, DriverCategory};
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::memory::dma::DmaBuffer;
use crate::kernel::sync::Mutex;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::println;
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// PCI constants
// ---------------------------------------------------------------------------

/// Red Hat / QEMU VirtIO vendor ID.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const VIRTIO_VENDOR: u16 = 0x1af4;
/// VirtIO GPU transitional PCI device ID (QEMU virtio-gpu-pci).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const VIRTIO_GPU_PCI_DEVICE_ID: u16 = 0x1050;

// ---------------------------------------------------------------------------
// VirtIO GPU device type (spec §5.7)
// ---------------------------------------------------------------------------

/// VirtIO device type for GPU (type 16, 0x10).
/// Spec reference constant (VirtIO §5.7.1); the driver probes by PCI ID
/// (VIRTIO_GPU_PCI_DEVICE_ID) rather than by virtio device type, so this is
/// kept only to document the protocol.
#[allow(dead_code)]
const VIRTIO_GPU_DEVICE_ID: u32 = 16;

// ---------------------------------------------------------------------------
// GPU commands (spec §5.7.2)
// ---------------------------------------------------------------------------

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32 = 0x0102;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Generic success (no data payload).
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
/// Response to GET_DISPLAY_INFO — contains display info.
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;

// ---------------------------------------------------------------------------
// Pixel formats (spec §5.7.2)
// ---------------------------------------------------------------------------

/// 32-bit BGRx (B in byte 0, G in byte 1, R in byte 2, unused in byte 3).
/// Matches the existing framebuffer console's pixel format.
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_FORMAT_BGR_X888: u32 = 260;

// ---------------------------------------------------------------------------
// Queue indices
// ---------------------------------------------------------------------------

/// Control virtqueue (always queue 0).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CONTROLQ: u16 = 0;
/// Queue size for the control virtqueue.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const QUEUE_SIZE: u16 = 64;

// ---------------------------------------------------------------------------
// Default resolution when display info is unavailable
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const DEFAULT_WIDTH: u32 = 1024;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const DEFAULT_HEIGHT: u32 = 768;

/// Spin-loop iteration limit for bare-metal completion polling.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const POLL_LIMIT: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// VirtIO GPU protocol structures (all repr(C), spec §5.7.2)
// ---------------------------------------------------------------------------

/// Generic control-header sent with every command.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuCtrlHeader {
    hdr_type: u32,
    flags: u32,
    fencing: u64,
    ctx_id: u32,
    padding: u32,
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl VirtioGpuCtrlHeader {
    const fn new(cmd: u32) -> Self {
        Self {
            hdr_type: cmd,
            flags: 0,
            fencing: 0,
            ctx_id: 0,
            padding: 0,
        }
    }
}

/// Generic response header returned in every response.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuRespHeader {
    hdr_type: u32,
    flags: u32,
    fencing: u64,
    ctx_id: u32,
    padding: u32,
}

/// One display entry returned by GET_DISPLAY_INFO.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuDisplayInfo {
    rect_x: u32,
    rect_y: u32,
    rect_w: u32,
    rect_h: u32,
    enabled: u32,
    flags: u32,
}

/// Response to GET_DISPLAY_INFO — up to 16 display entries.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuRespDisplayInfo {
    hdr: VirtioGpuRespHeader,
    displays: [VirtioGpuDisplayInfo; 16],
}

/// Payload for RESOURCE_CREATE_2D.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuResourceCreate2D {
    hdr: VirtioGpuCtrlHeader,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

/// Payload for RESOURCE_ATTACH_BACKING.
///
/// NOTE: repr(C, packed) ensures sizeof matches the spec (44 bytes) rather
/// than the padded 48 bytes that repr(C) alone would produce due to the u64
/// alignment in VirtioGpuCtrlHeader.  No field references are taken from
/// this type — only the struct address is passed to the device as a DMA
/// descriptor address — so the packed repr is safe here.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuAttachBacking {
    hdr: VirtioGpuCtrlHeader,
    resource_id: u32,
    nr_entries: u32,
    padding: [u32; 3],
}

/// A single memory entry in the backing description (scatter-gather).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuMemEntry {
    addr: u64,
    length: u32,
    padding: u32,
}

/// Payload for SET_SCANOUT.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuSetScanout {
    hdr: VirtioGpuCtrlHeader,
    rect_x: u32,
    rect_y: u32,
    rect_w: u32,
    rect_h: u32,
    scanout_id: u32,
    resource_id: u32,
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_CTX_CREATE: u32 = 0x0201;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_CTX_DESTROY: u32 = 0x0202;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_RESOURCE_CREATE_3D: u32 = 0x0204;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D: u32 = 0x0205;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D: u32 = 0x0206;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_CMD_SUBMIT_3D: u32 = 0x0208;

/// Feature bit for VIRGL 3D acceleration (spec §5.7.2, feature bit 0).
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const VIRTIO_GPU_F_VIRGL: u32 = 0;

/// Payload for RESOURCE_FLUSH.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuResourceFlush {
    hdr: VirtioGpuCtrlHeader,
    rect_x: u32,
    rect_y: u32,
    rect_w: u32,
    rect_h: u32,
    resource_id: u32,
    padding: u32,
}

/// Payload for VIRTIO_GPU_CMD_RESOURCE_UNREF.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuResourceUnref {
    hdr: VirtioGpuCtrlHeader,
    resource_id: u32,
    padding: u32,
}

// ---------------------------------------------------------------------------
// VIRGL 3D protocol structures (spec §5.7.2)
// ---------------------------------------------------------------------------

/// Payload for VIRTIO_GPU_CMD_CTX_CREATE.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuCtxCreate {
    hdr: VirtioGpuCtrlHeader,
    nlen: u32,
    context_init: u32,
    debug_name: [u8; 64],
}

/// Payload for VIRTIO_GPU_CMD_RESOURCE_CREATE_3D.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuResourceCreate3D {
    hdr: VirtioGpuCtrlHeader,
    resource_id: u32,
    target: u32,
    format: u32,
    bind: u32,
    width: u32,
    height: u32,
    depth: u32,
    array_size: u32,
    levels: u32,
    sample_count: u32,
    num_samples: u32,
    stride: u32,
    padding: u32,
}

/// Payload for VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D / TRANSFER_FROM_HOST_3D.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuTransferHost3D {
    hdr: VirtioGpuCtrlHeader,
    resource_id: u32,
    x: u32,
    y: u32,
    z: u32,
    w: u32,
    h: u32,
    d: u32,
    level: u32,
    stride: u32,
    layer_stride: u32,
    offset: u32,
}

/// Payload for VIRTIO_GPU_CMD_SUBMIT_3D.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
struct VirtioGpuCmdSubmit3D {
    hdr: VirtioGpuCtrlHeader,
    size: u32,
    padding: u32,
}

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

/// A VirtIO GPU device instance.
///
/// Wraps the MMIO transport, one control virtqueue, and the DMA-able
/// framebuffer backing memory.
///
/// Constructed only by the bare-metal `init_gpu_device` probe; the host build
/// exercises the syscall interface through the in-memory [`mock::MockGpuDevice`]
/// instead.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
struct VirtioGpuDevice {
    transport: VirtIoMmio,
    queue: Mutex<VirtQueue>,
    scanout_resource_id: u32,
    fb: DmaBuffer,
    /// Whether VIRTIO_GPU_F_VIRGL was negotiated with the device.
    has_virgl: bool,
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl VirtioGpuDevice {
    /// Create a new device wrapper.  The transport must have completed
    /// `discover()` (but not yet `init_device()` — that is done by
    /// [`init_queues`]).  The queue is set up via `new_pci` so the ring
    /// layout includes the spec-mandated flags/idx prefix needed for
    /// device-visible ring access.
    fn new(transport: VirtIoMmio, fb: DmaBuffer, has_virgl: bool) -> Self {
        Self {
            transport,
            queue: Mutex::new(VirtQueue::new_pci(QUEUE_SIZE)),
            scanout_resource_id: 1,
            fb,
            has_virgl,
        }
    }

    /// Run the VirtIO device initialisation sequence (configure control queue,
    /// set DRIVER_OK).  Feature negotiation must have completed before this
    /// call (see `init_gpu_device`).
    fn init_queues_and_driver_ok(&self) -> Result<()> {
        // NOTE: Feature negotiation (VIRTIO_GPU_F_VIRGL) is handled in
        // `init_gpu_device` before the device is constructed.  Here we only
        // configure the control queue and set DRIVER_OK.

        // Configure the control queue.
        self.transport.select_queue(CONTROLQ);
        let queue = self.queue.lock();
        let (desc_ptr, avail_ptr, used_ptr) = queue.ring_addrs();
        self.transport.configure_queue(
            queue.queue_size() as u32,
            desc_ptr as u64,
            avail_ptr as u64,
            used_ptr as u64,
        )?;
        drop(queue);

        // Mark the device as ready for operation (VirtIO §3.1 step 8).
        self.transport.set_driver_ok()?;

        println!(
            "[virtio-gpu] device initialised, control queue configured ({} entries)",
            QUEUE_SIZE
        );
        Ok(())
    }

    /// Kick the control queue so the device processes our submission.
    fn kick(&self) {
        self.transport
            .regs()
            .write32(REG_QUEUE_NOTIFY, CONTROLQ as u32);
    }

    /// Poll the used ring until at least one completion is available or the
    /// spin-limit is exhausted.  Uses `sync_device_used_idx` to read the
    /// device-written idx from ring memory (required for correct operation
    /// with the hardware device).
    fn poll_completion(&self) -> Result<()> {
        for _ in 0..POLL_LIMIT {
            let mut queue = self.queue.lock();
            queue.sync_device_used_idx();
            if queue.completed_count() > 0 {
                return Ok(());
            }
            drop(queue);
            core::hint::spin_loop();
        }
        Err(Error::TimedOut)
    }

    /// Execute a GPU command: write `request` as the device-readable
    /// descriptor, read the response into `response`, and return Ok(()) only
    /// when the response header type matches `expected_type`.
    fn do_command<R: Sized + Default>(
        &self,
        request: &impl Sized,
        response: &mut R,
        expected_type: u32,
    ) -> Result<()> {
        let request_size = core::mem::size_of_val(request) as u32;
        let response_size = core::mem::size_of::<R>() as u32;

        // Allocate 2 descriptors: [request (device-readable), response (device-writable)].
        let mut queue = self.queue.lock();
        let head = queue.alloc_chain(2).ok_or(Error::DeviceError)?;
        let req_desc = head;
        let resp_desc = queue.descriptors[req_desc as usize].next;

        queue.set_desc(
            req_desc,
            request as *const _ as u64,
            request_size,
            0, // device-readable; NEXT already set by alloc_chain
        );

        // Zero the response buffer before handing it to the device.
        *response = Default::default();
        queue.set_desc(
            resp_desc,
            response as *mut _ as u64,
            response_size,
            VIRTQ_DESC_F_WRITE,
        );

        queue.submit(head);
        drop(queue);
        self.kick();

        // Wait for the device to write the used ring entry.
        self.poll_completion()?;

        // Consume the completion and check the response.
        let mut queue = self.queue.lock();
        let _completed = queue.consume_completion().ok_or(Error::DeviceError)?;

        // Verify response type.
        Self::check_response(response, expected_type)
    }

    /// Interpret the first 4 bytes of `response` as a response type and
    /// compare it with `expected`.
    fn check_response<R>(response: &R, expected: u32) -> Result<()> {
        // Safety: every GPU response starts with a VirtioGpuRespHeader whose
        // first field is hdr_type (u32).  Reading the first 4 bytes is valid
        // for any repr(C) response struct.
        let resp_type = unsafe { *(response as *const _ as *const u32) };
        if resp_type != expected {
            println!(
                "[virtio-gpu] unexpected response type: got {:#010x}, expected {:#010x}",
                resp_type, expected
            );
            return Err(Error::DeviceError);
        }
        Ok(())
    }

    // ─── High-level GPU operations ─────────────────────────────────

    /// Query display configuration from the device.
    ///
    /// Returns the first enabled display's (width, height), or `None`.
    fn get_display_info(&self) -> Option<(u32, u32)> {
        let req = VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
        let mut resp: VirtioGpuRespDisplayInfo = Default::default();

        if self
            .do_command(&req, &mut resp, VIRTIO_GPU_RESP_OK_DISPLAY_INFO)
            .is_err()
        {
            println!("[virtio-gpu] GET_DISPLAY_INFO failed");
            return None;
        }

        for (i, display) in resp.displays.iter().enumerate() {
            if display.enabled != 0 && display.rect_w > 0 && display.rect_h > 0 {
                println!(
                    "[virtio-gpu] display {}: {}x{} enabled @ ({},{})",
                    i, display.rect_w, display.rect_h, display.rect_x, display.rect_y
                );
                return Some((display.rect_w, display.rect_h));
            }
        }

        println!("[virtio-gpu] no enabled display found");
        None
    }

    /// Create a 2D resource with the given `resource_id`, size, and format.
    fn create_2d_resource(
        &self,
        resource_id: u32,
        width: u32,
        height: u32,
        format: u32,
    ) -> Result<()> {
        let req = VirtioGpuResourceCreate2D {
            hdr: VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_RESOURCE_CREATE_2D),
            resource_id,
            format,
            width,
            height,
        };
        let mut resp: VirtioGpuRespHeader = Default::default();
        self.do_command(&req, &mut resp, VIRTIO_GPU_RESP_OK_NODATA)
    }

    /// Attach physical memory backing to a resource.
    fn attach_backing(&self, resource_id: u32, addr: u64, size: u32) -> Result<()> {
        let entry = VirtioGpuMemEntry {
            addr,
            length: size,
            padding: 0,
        };
        let req = VirtioGpuAttachBacking {
            hdr: VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING),
            resource_id,
            nr_entries: 1, // single contiguous chunk
            padding: [0; 3],
        };
        // ATTACH_BACKING is a two-part command: a data descriptor (the
        // AttachBacking struct) followed by one or more MemEntry descriptors.
        //
        // The VirtIO spec says the request is: [ctrl_hdr | ... | entries]
        // sent as a single device-readable descriptor chain.  However, QEMU's
        // implementation accepts the attach command with a single data
        // descriptor that contains only the header (the entries are embedded
        // in a data descriptor that follows).
        //
        // For simplicity we use a 3-descriptor chain: [ctrl_hdr, mem_entry,
        // response_hdr].  The device reads the first two and writes the third.
        //
        // Unfortunately, the generic do_command only supports 2 descriptors.
        // We inline the queue operations here for the 3-descriptor case.

        let mut queue = self.queue.lock();
        let head = queue.alloc_chain(3).ok_or(Error::DeviceError)?;
        let req_desc = head;
        let entry_desc = queue.descriptors[req_desc as usize].next;
        let resp_desc = queue.descriptors[entry_desc as usize].next;

        queue.set_desc(
            req_desc,
            &req as *const VirtioGpuAttachBacking as u64,
            core::mem::size_of::<VirtioGpuAttachBacking>() as u32,
            0,
        );

        let mut entry_copy = entry;
        queue.set_desc(
            entry_desc,
            &mut entry_copy as *mut VirtioGpuMemEntry as u64,
            core::mem::size_of::<VirtioGpuMemEntry>() as u32,
            0, // device-readable
        );

        let mut resp_hdr: VirtioGpuRespHeader = Default::default();
        queue.set_desc(
            resp_desc,
            &mut resp_hdr as *mut VirtioGpuRespHeader as u64,
            core::mem::size_of::<VirtioGpuRespHeader>() as u32,
            VIRTQ_DESC_F_WRITE,
        );

        queue.submit(head);
        drop(queue);
        self.kick();
        self.poll_completion()?;

        let mut queue = self.queue.lock();
        let _completed = queue.consume_completion().ok_or(Error::DeviceError)?;
        drop(queue);

        if resp_hdr.hdr_type != VIRTIO_GPU_RESP_OK_NODATA {
            println!(
                "[virtio-gpu] ATTACH_BACKING failed: resp={:#010x}",
                resp_hdr.hdr_type
            );
            return Err(Error::DeviceError);
        }

        println!(
            "[virtio-gpu] backing attached: resource_id={} addr={:#x} size={}",
            resource_id, addr, size
        );
        Ok(())
    }

    /// Set a resource as the scanout for a monitor output.
    fn set_scanout(&self, resource_id: u32, width: u32, height: u32) -> Result<()> {
        let req = VirtioGpuSetScanout {
            hdr: VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_SET_SCANOUT),
            rect_x: 0,
            rect_y: 0,
            rect_w: width,
            rect_h: height,
            scanout_id: 0,
            resource_id,
        };
        let mut resp: VirtioGpuRespHeader = Default::default();
        self.do_command(&req, &mut resp, VIRTIO_GPU_RESP_OK_NODATA)
    }

    /// Flush a resource's content to the display.
    fn flush_resource(&self, resource_id: u32, width: u32, height: u32) -> Result<()> {
        let req = VirtioGpuResourceFlush {
            hdr: VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_RESOURCE_FLUSH),
            rect_x: 0,
            rect_y: 0,
            rect_w: width,
            rect_h: height,
            resource_id,
            padding: 0,
        };
        let mut resp: VirtioGpuRespHeader = Default::default();
        self.do_command(&req, &mut resp, VIRTIO_GPU_RESP_OK_NODATA)
    }

    /// Release a previously created resource.
    fn unref_resource(&self, resource_id: u32) -> Result<()> {
        let req = VirtioGpuResourceUnref {
            hdr: VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_RESOURCE_UNREF),
            resource_id,
            padding: 0,
        };
        let mut resp: VirtioGpuRespHeader = Default::default();
        self.do_command(&req, &mut resp, VIRTIO_GPU_RESP_OK_NODATA)
    }

    // ─── VIRGL 3D operations (requires VIRTIO_GPU_F_VIRGL) ─────────

    /// Create a VIRGL 3D rendering context.
    pub fn ctx_create(&self, ctx_id: u32, name: &[u8]) -> Result<()> {
        if !self.has_virgl {
            return Err(Error::Unsupported);
        }
        let mut debug_name = [0u8; 64];
        let nlen = core::cmp::min(name.len(), 63) as u32;
        debug_name[..nlen as usize].copy_from_slice(&name[..nlen as usize]);
        let mut hdr = VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_CTX_CREATE);
        hdr.ctx_id = ctx_id;
        let req = VirtioGpuCtxCreate {
            hdr,
            nlen,
            context_init: 0,
            debug_name,
        };
        let mut resp: VirtioGpuRespHeader = Default::default();
        self.do_command(&req, &mut resp, VIRTIO_GPU_RESP_OK_NODATA)
    }

    /// Destroy a previously-created VIRGL context.
    pub fn ctx_destroy(&self, ctx_id: u32) -> Result<()> {
        if !self.has_virgl {
            return Err(Error::Unsupported);
        }
        let mut hdr = VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_CTX_DESTROY);
        hdr.ctx_id = ctx_id;
        let mut resp: VirtioGpuRespHeader = Default::default();
        self.do_command(&hdr, &mut resp, VIRTIO_GPU_RESP_OK_NODATA)
    }

    /// Create a 3D resource (VIRTIO_GPU_CMD_RESOURCE_CREATE_3D).
    #[allow(clippy::too_many_arguments)]
    pub fn create_3d_resource(
        &self,
        resource_id: u32,
        target: u32,
        format: u32,
        bind: u32,
        width: u32,
        height: u32,
        depth: u32,
        array_size: u32,
        levels: u32,
        sample_count: u32,
        num_samples: u32,
        stride: u32,
    ) -> Result<()> {
        if !self.has_virgl {
            return Err(Error::Unsupported);
        }
        let req = VirtioGpuResourceCreate3D {
            hdr: VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_RESOURCE_CREATE_3D),
            resource_id,
            target,
            format,
            bind,
            width,
            height,
            depth,
            array_size,
            levels,
            sample_count,
            num_samples,
            stride,
            padding: 0,
        };
        let mut resp: VirtioGpuRespHeader = Default::default();
        self.do_command(&req, &mut resp, VIRTIO_GPU_RESP_OK_NODATA)
    }

    /// Transfer data from the host to a 3D resource.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_to_host_3d(
        &self,
        resource_id: u32,
        x: u32,
        y: u32,
        z: u32,
        w: u32,
        h: u32,
        d: u32,
        level: u32,
        stride: u32,
        layer_stride: u32,
        offset: u32,
    ) -> Result<()> {
        if !self.has_virgl {
            return Err(Error::Unsupported);
        }
        let req = VirtioGpuTransferHost3D {
            hdr: VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D),
            resource_id,
            x,
            y,
            z,
            w,
            h,
            d,
            level,
            stride,
            layer_stride,
            offset,
        };
        let mut resp: VirtioGpuRespHeader = Default::default();
        self.do_command(&req, &mut resp, VIRTIO_GPU_RESP_OK_NODATA)
    }

    /// Transfer data from a 3D resource back to the host.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_from_host_3d(
        &self,
        resource_id: u32,
        x: u32,
        y: u32,
        z: u32,
        w: u32,
        h: u32,
        d: u32,
        level: u32,
        stride: u32,
        layer_stride: u32,
        offset: u32,
    ) -> Result<()> {
        if !self.has_virgl {
            return Err(Error::Unsupported);
        }
        let req = VirtioGpuTransferHost3D {
            hdr: VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D),
            resource_id,
            x,
            y,
            z,
            w,
            h,
            d,
            level,
            stride,
            layer_stride,
            offset,
        };
        let mut resp: VirtioGpuRespHeader = Default::default();
        self.do_command(&req, &mut resp, VIRTIO_GPU_RESP_OK_NODATA)
    }

    /// Submit a VIRGL command stream to a context for rendering.
    ///
    /// `cmd_stream` must be valid for the duration of the call; the device
    /// accesses it via DMA (identity-mapped physical memory).
    pub fn submit_3d(&self, ctx_id: u32, cmd_stream: &[u8]) -> Result<()> {
        if !self.has_virgl {
            return Err(Error::Unsupported);
        }
        // SUBMIT_3D uses a 3-descriptor chain:
        //   [0] submit-3d header (device-readable)
        //   [1] command stream data (device-readable)
        //   [2] response header (device-writable)

        let req = VirtioGpuCmdSubmit3D {
            hdr: {
                let mut h = VirtioGpuCtrlHeader::new(VIRTIO_GPU_CMD_SUBMIT_3D);
                h.ctx_id = ctx_id;
                h
            },
            size: cmd_stream.len() as u32,
            padding: 0,
        };

        let mut queue = self.queue.lock();
        let head = queue.alloc_chain(3).ok_or(Error::DeviceError)?;
        let req_desc = head;
        let data_desc = queue.descriptors[req_desc as usize].next;
        let resp_desc = queue.descriptors[data_desc as usize].next;

        queue.set_desc(
            req_desc,
            &req as *const VirtioGpuCmdSubmit3D as u64,
            core::mem::size_of::<VirtioGpuCmdSubmit3D>() as u32,
            0,
        );

        queue.set_desc(
            data_desc,
            cmd_stream.as_ptr() as u64,
            cmd_stream.len() as u32,
            0, // device-readable
        );

        let mut resp_hdr: VirtioGpuRespHeader = Default::default();
        queue.set_desc(
            resp_desc,
            &mut resp_hdr as *mut VirtioGpuRespHeader as u64,
            core::mem::size_of::<VirtioGpuRespHeader>() as u32,
            VIRTQ_DESC_F_WRITE,
        );

        queue.submit(head);
        drop(queue);
        self.kick();
        self.poll_completion()?;

        let mut queue = self.queue.lock();
        let _completed = queue.consume_completion().ok_or(Error::DeviceError)?;
        drop(queue);

        if resp_hdr.hdr_type != VIRTIO_GPU_RESP_OK_NODATA {
            println!(
                "[virtio-gpu] SUBMIT_3D failed: resp={:#010x}",
                resp_hdr.hdr_type
            );
            return Err(Error::DeviceError);
        }

        Ok(())
    }

    /// Full mode-setting sequence: create a resource, attach backing, set
    /// scanout, and flush.
    fn set_resolution(&self, width: u32, height: u32) -> Result<()> {
        let rid = self.scanout_resource_id;

        self.create_2d_resource(rid, width, height, VIRTIO_GPU_FORMAT_BGR_X888)?;
        println!(
            "[virtio-gpu] created 2D resource {}: {}x{} format={}",
            rid, width, height, VIRTIO_GPU_FORMAT_BGR_X888
        );

        let fb_size = width * height * 4; // 32 bpp
        self.attach_backing(rid, self.fb.phys_addr() as u64, fb_size)?;

        self.set_scanout(rid, width, height)?;
        println!("[virtio-gpu] scanout set to resource {}", rid);

        self.flush_resource(rid, width, height)?;
        println!("[virtio-gpu] resource flushed to display");

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Framebuffer state (shared with frame-buffer console)
// ---------------------------------------------------------------------------

use crate::kernel::sync::spinlock::SpinLock;

/// Global framebuffer info, set after successful virtio-gpu init.
static FB_INFO: SpinLock<Option<FramebufferInfo>> = SpinLock::new(None);

/// The fb_info accessor used by framebuffer.rs consumers.
pub fn framebuffer_info() -> Option<FramebufferInfo> {
    *FB_INFO.lock()
}

// ---------------------------------------------------------------------------
// Driver registration (for the DriverManager)
// ---------------------------------------------------------------------------

struct VirtioGpuDriver;

impl Driver for VirtioGpuDriver {
    fn name(&self) -> &'static str {
        "virtio-gpu"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Console
    }

    fn init(&self) -> Result<()> {
        if probe_and_init().is_some() {
            Ok(())
        } else {
            Err(Error::DeviceError)
        }
    }
}

/// Public constructor for DriverManager registration.
pub fn driver() -> Arc<dyn Driver> {
    Arc::new(VirtioGpuDriver)
}

// ---------------------------------------------------------------------------
// GPU device interface (VIRGL 3D syscalls #181-189)
// ---------------------------------------------------------------------------

/// Interface exposed to the GPU syscall layer.  The concrete
/// [`VirtioGpuDevice`] implements it on bare metal; tests install a
/// [`mock::MockGpuDevice`] through [`set_gpu_device_for_test`].
pub trait GpuDevice: Send + Sync {
    fn ctx_create(&self, ctx_id: u32) -> Result<()>;
    fn ctx_destroy(&self, ctx_id: u32) -> Result<()>;
    fn create_3d_resource(&self, desc: &crate::abi::gpu::GpuResCreate3dDesc) -> Result<u32>;
    fn unref_resource(&self, resource_id: u32) -> Result<()>;
    fn transfer_to_host_3d(
        &self,
        desc: &crate::abi::gpu::GpuTransfer3dDesc,
        data: &[u8],
    ) -> Result<()>;
    fn transfer_from_host_3d(
        &self,
        desc: &crate::abi::gpu::GpuTransfer3dDesc,
        data: &mut [u8],
    ) -> Result<()>;
    fn submit_3d(&self, ctx_id: u32, cmd: &[u8]) -> Result<()>;
    fn set_scanout(&self, resource_id: u32, width: u32, height: u32) -> Result<()>;
    fn display_info(&self) -> Option<(u32, u32)>;
    fn has_virgl(&self) -> bool;
}

/// The active GPU device, installed after successful probe (or by tests).
static GPU_DEVICE: Mutex<Option<Arc<dyn GpuDevice>>> = Mutex::new(None);

/// Return the active GPU device, if one is present.
pub fn gpu_device() -> Option<Arc<dyn GpuDevice>> {
    GPU_DEVICE.lock().clone()
}

/// Install (or clear) the active GPU device.  Used by tests to install a
/// mock; the boot path installs the real device via [`init_gpu_device`].
pub fn set_gpu_device_for_test(device: Option<Arc<dyn GpuDevice>>) {
    *GPU_DEVICE.lock() = device;
}

/// Adapter so the real device satisfies the syscall-facing interface.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl GpuDevice for VirtioGpuDevice {
    fn ctx_create(&self, ctx_id: u32) -> Result<()> {
        self.ctx_create(ctx_id, &[])
    }

    fn ctx_destroy(&self, ctx_id: u32) -> Result<()> {
        self.ctx_destroy(ctx_id)
    }

    fn create_3d_resource(&self, desc: &crate::abi::gpu::GpuResCreate3dDesc) -> Result<u32> {
        self.create_3d_resource(
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
        )?;
        Ok(desc.resource_id)
    }

    fn unref_resource(&self, resource_id: u32) -> Result<()> {
        self.unref_resource(resource_id)
    }

    fn transfer_to_host_3d(
        &self,
        desc: &crate::abi::gpu::GpuTransfer3dDesc,
        _data: &[u8],
    ) -> Result<()> {
        // The real device uploads the command; the payload DMA path is not
        // yet wired into the syscall layer, so the data argument is ignored.
        self.transfer_to_host_3d(
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
        )
    }

    fn transfer_from_host_3d(
        &self,
        desc: &crate::abi::gpu::GpuTransfer3dDesc,
        _data: &mut [u8],
    ) -> Result<()> {
        self.transfer_from_host_3d(
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
        )
    }

    fn submit_3d(&self, ctx_id: u32, cmd: &[u8]) -> Result<()> {
        self.submit_3d(ctx_id, cmd)
    }

    fn set_scanout(&self, resource_id: u32, width: u32, height: u32) -> Result<()> {
        self.set_scanout(resource_id, width, height)
    }

    fn display_info(&self) -> Option<(u32, u32)> {
        self.get_display_info()
    }

    fn has_virgl(&self) -> bool {
        self.has_virgl
    }
}

/// In-memory GPU used by the syscall test suite.
pub mod mock {
    use alloc::collections::btree_map::BTreeMap;
    use alloc::vec::Vec;

    use super::*;
    use crate::abi::gpu::{GpuResCreate3dDesc, GpuTransfer3dDesc};

    /// A minimal in-memory GPU: tracks contexts, resource backing bytes, and
    /// the recorded transfer descriptors.
    pub struct MockGpuDevice {
        pub contexts: Mutex<Vec<u32>>,
        pub resources: Mutex<BTreeMap<u32, Vec<u8>>>,
        pub transfers: Mutex<Vec<(u32, u32, u32, u32)>>,
        /// Recorded `(ctx_id, cmd_len)` pairs from `submit_3d` calls.
        pub submits: Mutex<Vec<(u32, u32)>>,
        /// Most recent `set_scanout` call as `(resource_id, width, height)`.
        pub scanout: Mutex<Option<(u32, u32, u32)>>,
    }

    impl Default for MockGpuDevice {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockGpuDevice {
        pub fn new() -> Self {
            Self {
                contexts: Mutex::new(Vec::new()),
                resources: Mutex::new(BTreeMap::new()),
                transfers: Mutex::new(Vec::new()),
                submits: Mutex::new(Vec::new()),
                scanout: Mutex::new(None),
            }
        }
    }

    impl GpuDevice for MockGpuDevice {
        fn ctx_create(&self, ctx_id: u32) -> Result<()> {
            self.contexts.lock().push(ctx_id);
            Ok(())
        }

        fn ctx_destroy(&self, ctx_id: u32) -> Result<()> {
            self.contexts.lock().retain(|&id| id != ctx_id);
            Ok(())
        }

        fn create_3d_resource(&self, desc: &GpuResCreate3dDesc) -> Result<u32> {
            let size = (desc.width as usize)
                .saturating_mul(desc.height as usize)
                .saturating_mul((desc.stride as usize).max(1));
            self.resources
                .lock()
                .insert(desc.resource_id, alloc::vec![0u8; size]);
            Ok(desc.resource_id)
        }

        fn unref_resource(&self, resource_id: u32) -> Result<()> {
            self.resources.lock().remove(&resource_id);
            Ok(())
        }

        fn transfer_to_host_3d(&self, desc: &GpuTransfer3dDesc, data: &[u8]) -> Result<()> {
            {
                let mut resources = self.resources.lock();
                if let Some(backing) = resources.get_mut(&desc.resource_id) {
                    let offset = desc.offset as usize;
                    let end = offset.saturating_add(data.len());
                    if end <= backing.len() {
                        backing[offset..end].copy_from_slice(data);
                    }
                }
            }
            self.transfers
                .lock()
                .push((desc.resource_id, desc.x, desc.w, desc.h));
            Ok(())
        }

        fn transfer_from_host_3d(&self, desc: &GpuTransfer3dDesc, data: &mut [u8]) -> Result<()> {
            let resources = self.resources.lock();
            if let Some(backing) = resources.get(&desc.resource_id) {
                let offset = desc.offset as usize;
                let end = offset.saturating_add(data.len());
                if end <= backing.len() {
                    data.copy_from_slice(&backing[offset..end]);
                }
            }
            Ok(())
        }

        fn submit_3d(&self, ctx_id: u32, cmd: &[u8]) -> Result<()> {
            self.submits.lock().push((ctx_id, cmd.len() as u32));
            Ok(())
        }

        fn set_scanout(&self, resource_id: u32, width: u32, height: u32) -> Result<()> {
            *self.scanout.lock() = Some((resource_id, width, height));
            Ok(())
        }

        fn display_info(&self) -> Option<(u32, u32)> {
            Some((640, 480))
        }

        fn has_virgl(&self) -> bool {
            true
        }
    }
}

// ---------------------------------------------------------------------------
// x86_64 bare-metal probe
// ---------------------------------------------------------------------------

/// Find a virtio-gpu PCI device, initialise it, and install the framebuffer
/// console.  Returns `Some(())` on success.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn probe_and_init() -> Option<()> {
    use crate::arch::mmu::map_device_mmio;
    use crate::arch::x86_64::pci::{
        pci_config_read_u16, pci_config_write_u16, pci_enumerate_buses, PciAddress, COMMAND,
    };
    use crate::kernel::drivers::virtio_pci::PciLegacyMmioRegion;
    use crate::kernel::drivers::virtio_pci_modern::PciModernRegion;

    const CMD_IO_SPACE: u16 = 1 << 0;
    const CMD_MEMORY_SPACE: u16 = 1 << 1;
    const CMD_BUS_MASTER: u16 = 1 << 2;

    let devices = pci_enumerate_buses();
    let device = devices
        .iter()
        .find(|d| d.vendor_id == VIRTIO_VENDOR && d.device_id == VIRTIO_GPU_PCI_DEVICE_ID)?;

    println!(
        "[virtio-gpu] found device at {:02x}:{:02x}.{:x}",
        device.bus, device.device, device.function
    );

    let pci_addr = PciAddress::new(device.bus, device.device, device.function);

    // Enable IO Space, Memory Space, and Bus Master.
    let cmd = unsafe { pci_config_read_u16(pci_addr, COMMAND) };
    unsafe {
        pci_config_write_u16(
            pci_addr,
            COMMAND,
            cmd | CMD_IO_SPACE | CMD_MEMORY_SPACE | CMD_BUS_MASTER,
        );
    }

    // ── Try modern PCI transport via MMIO BAR ──
    let result = if let Some(mmio_bar) = device
        .bars
        .iter()
        .find(|bar| bar.is_mmio && bar.base_address != 0)
    {
        println!(
            "[virtio-gpu] modern transport: MMIO BAR base=0x{:x} size=0x{:x}",
            mmio_bar.base_address, mmio_bar.size
        );

        // Map the MMIO BAR into kernel page tables (identity-mapped).
        let mapping = unsafe { map_device_mmio(mmio_bar.base_address, mmio_bar.size as usize) };
        if mapping.is_none() {
            println!("[virtio-gpu] failed to map MMIO BAR");
            return None;
        }

        let region = Box::new(PciModernRegion::new(
            mmio_bar.base_address as usize,
            device.device_id,
            device.vendor_id,
        ));
        let mut transport = VirtIoMmio::new(region);

        // Verify it's a valid VirtIO device.
        if transport.discover().is_err() {
            println!("[virtio-gpu] modern transport: discover failed");
            return None;
        }

        init_gpu_device(transport)
    } else {
        // ── Fallback: legacy IO-port BAR ──
        let io_bar = device
            .bars
            .first()
            .filter(|bar| !bar.is_mmio && bar.base_address != 0)?;
        let io_base = io_bar.base_address as u16;

        println!("[virtio-gpu] legacy transport: IO BAR base=0x{:x}", io_base);

        let region = Box::new(PciLegacyMmioRegion::new(
            io_base,
            device.device_id,
            device.vendor_id,
        ));
        let mut transport = VirtIoMmio::new(region);

        if transport.discover().is_err() {
            println!("[virtio-gpu] legacy transport: discover failed");
            return None;
        }

        init_gpu_device(transport)
    };

    let (_w, _h) = result?;

    Some(())
}

/// Shared initialisation once the transport is set up.
///
/// 1. `init_device_with_features`
/// 2. Allocate DMA-able framebuffer backing (fixed default resolution for MVP)
/// 3. Configure the control queue and set DRIVER_OK
/// 4. Query display info (informational; uses default for MVP)
/// 5. Create a 2D resource, attach backing, set scanout, flush
/// 6. Install the framebuffer console
///
/// Returns `(width, height)` on success.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn init_gpu_device(transport: VirtIoMmio) -> Option<(u32, u32)> {
    // 1. Negotiate features — request VIRTIO_GPU_F_VIRGL (bit 0) for 3D.
    let virgl_mask = 1u32 << VIRTIO_GPU_F_VIRGL;
    let negotiated = transport.init_device_with_features(virgl_mask).ok()?;
    let has_virgl = (negotiated & virgl_mask) != 0;
    if has_virgl {
        println!("[virtio-gpu] VIRTIO_GPU_F_VIRGL negotiated (3D acceleration available)");
    }

    // Resolution for the MVP — fixed default as requested.
    let fb_width = DEFAULT_WIDTH;
    let fb_height = DEFAULT_HEIGHT;

    // 2. Allocate DMA-able framebuffer backing.
    let fb_bytes = (fb_width * fb_height * 4) as usize;
    let fb_frames = fb_bytes.div_ceil(4096);
    let fb = DmaBuffer::allocate(fb_frames)?;
    println!(
        "[virtio-gpu] allocated {} frames ({}) at phys={:#x}",
        fb_frames,
        fb.len(),
        fb.phys_addr(),
    );

    // 3. Create the device wrapper, configure queue, and set DRIVER_OK.
    let gpu = VirtioGpuDevice::new(transport, fb, has_virgl);
    gpu.init_queues_and_driver_ok().ok()?;

    // 4. Query display info (informational; for logging).
    if let Some((w, h)) = gpu.get_display_info() {
        println!(
            "[virtio-gpu] display reports {}x{} (using {}x{} for MVP)",
            w, h, fb_width, fb_height
        );
    }

    // 5. Full mode-setting sequence with the default resolution.
    gpu.set_resolution(fb_width, fb_height).ok()?;

    // Clear the framebuffer to dark blue.
    let fb_ptr = gpu.fb.as_ptr();
    let pixel_count = (fb_width * fb_height) as usize;
    let fb_u32 = fb_ptr as *mut u32;
    for i in 0..pixel_count {
        unsafe {
            ptr::write_volatile(fb_u32.add(i), 0x00_00_00_80_u32); // dark blue (BGRx)
        }
    }

    // 6. Build the FramebufferInfo and install the console.
    let fb_info = FramebufferInfo {
        physical_address: gpu.fb.phys_addr(),
        size: fb_bytes,
        width: fb_width as u16,
        height: fb_height as u16,
        bpp: 32,
        pitch: fb_width * 4,
    };

    *FB_INFO.lock() = Some(fb_info);

    unsafe {
        framebuffer_console::install_console(fb_ptr, fb_info);
    }
    println!(
        "[virtio-gpu] console installed ({}x{} chars)",
        fb_width / 8,
        fb_height / 16,
    );

    // Hand the device to the syscall layer (VIRGL 3D).  The global keeps the
    // DMA buffer alive for the kernel's lifetime.
    *GPU_DEVICE.lock() = Some(Arc::new(gpu));

    Some((fb_width, fb_height))
}

// ---------------------------------------------------------------------------
// Non-x86_64 / host stub
// ---------------------------------------------------------------------------

/// Host-side / non-x86_64 stub: virtio-gpu not available.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn probe_and_init() -> Option<()> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_header_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuCtrlHeader>(),
            24,
            "VirtioGpuCtrlHeader must be 24 bytes (6 × u32 on 64-bit)"
        );
    }

    #[test]
    fn resp_header_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuRespHeader>(),
            24,
            "VirtioGpuRespHeader must be 24 bytes"
        );
    }

    #[test]
    fn resp_display_info_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuRespDisplayInfo>(),
            24 + 16 * 24, // hdr + 16 display entries × 24 bytes
            "VirtioGpuRespDisplayInfo size mismatch"
        );
    }

    #[test]
    fn resource_create_2d_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuResourceCreate2D>(),
            24 + 4 * 4, // hdr + resource_id + format + width + height
            "VirtioGpuResourceCreate2D size mismatch"
        );
    }

    #[test]
    fn attach_backing_size() {
        // 24 (ctrl_hdr) + 4 + 4 + 12 (padding) = 44; packed repr avoids trailing alignment.
        assert_eq!(
            core::mem::size_of::<VirtioGpuAttachBacking>(),
            44,
            "VirtioGpuAttachBacking must be exactly 44 bytes (spec §5.7.2)"
        );
    }

    #[test]
    fn mem_entry_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuMemEntry>(),
            16, // addr(u64) + length(u32) + padding(u32)
            "VirtioGpuMemEntry must be 16 bytes"
        );
    }

    #[test]
    fn set_scanout_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuSetScanout>(),
            24 + 6 * 4, // hdr + rect_x/y/w/h + scanout_id + resource_id
            "VirtioGpuSetScanout size mismatch"
        );
    }

    #[test]
    fn resource_flush_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuResourceFlush>(),
            24 + 5 * 4 + 4, // hdr + rect_x/y/w/h + resource_id + padding
            "VirtioGpuResourceFlush size mismatch"
        );
    }

    #[test]
    fn resource_unref_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuResourceUnref>(),
            24 + 4 + 4, // hdr + resource_id + padding
            "VirtioGpuResourceUnref must be 32 bytes"
        );
    }

    #[test]
    fn ctx_create_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuCtxCreate>(),
            24 + 4 + 4 + 64, // hdr + nlen + context_init + debug_name[64]
            "VirtioGpuCtxCreate must be 96 bytes"
        );
    }

    #[test]
    fn resource_create_3d_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuResourceCreate3D>(),
            24 + 14 * 4, // hdr + 14 u32 fields
            "VirtioGpuResourceCreate3D must be 80 bytes"
        );
    }

    #[test]
    fn transfer_host_3d_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuTransferHost3D>(),
            24 + 12 * 4, // hdr + 12 u32 fields
            "VirtioGpuTransferHost3D must be 72 bytes"
        );
    }

    #[test]
    fn submit_3d_size() {
        assert_eq!(
            core::mem::size_of::<VirtioGpuCmdSubmit3D>(),
            24 + 2 * 4, // hdr + size + padding
            "VirtioGpuCmdSubmit3D must be 32 bytes"
        );
    }

    #[test]
    fn constants_are_sane() {
        assert_eq!(VIRTIO_GPU_FORMAT_BGR_X888, 260);
        assert_eq!(VIRTIO_GPU_CMD_GET_DISPLAY_INFO, 0x0100);
        assert_eq!(VIRTIO_GPU_CMD_RESOURCE_CREATE_2D, 0x0101);
        assert_eq!(VIRTIO_GPU_CMD_RESOURCE_UNREF, 0x0102);
        assert_eq!(VIRTIO_GPU_CMD_SET_SCANOUT, 0x0103);
        assert_eq!(VIRTIO_GPU_CMD_RESOURCE_FLUSH, 0x0104);
        assert_eq!(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING, 0x0106);
        assert_eq!(VIRTIO_GPU_RESP_OK_NODATA, 0x1100);
        assert_eq!(VIRTIO_GPU_RESP_OK_DISPLAY_INFO, 0x1101);
        assert_eq!(VIRTIO_GPU_F_VIRGL, 0);
        assert_eq!(VIRTIO_GPU_CMD_CTX_CREATE, 0x0201);
        assert_eq!(VIRTIO_GPU_CMD_CTX_DESTROY, 0x0202);
        assert_eq!(VIRTIO_GPU_CMD_RESOURCE_CREATE_3D, 0x0204);
        assert_eq!(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D, 0x0205);
        assert_eq!(VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D, 0x0206);
        assert_eq!(VIRTIO_GPU_CMD_SUBMIT_3D, 0x0208);
    }
}
