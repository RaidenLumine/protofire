# Device Drivers

How a device is found, which driver owns it, and where each driver's
completion actually comes from.  The framework is `src/drivers/mod.rs`; the
drivers that only exist on one machine live under `src/arch/<machine>/`
(`ata`, `ahci`, `pcspkr`, the ACPI/PCI plumbing in `src/arch/pci/`) or in that
machine's `devices` module, which is what
`crate::arch::machine_devices::<name>` names.

## The framework

A driver is an `Arc<dyn Driver>`: a name, a `DriverCategory` (bus, storage,
input, console, network, audio), an `init`, and an optional `probe` that claims
a device id.  `DriverManager::init` registers the drivers in a deliberate
order, and the comments in that function are the record of why:

- the serial console first, because everything after it may have to say
  something;
- the PS/2 keyboard *before* `virtio-input`, so a VirtIO keyboard's injected
  events are decoded by an already-initialised keyboard core;
- ATA PIO before AHCI, so both a legacy IDE and an AHCI controller are found;
- `virtio-gpu` before the bochs framebuffer, so a machine that has both uses the
  accelerator;
- the device-tree probe before any `init`, so a DT-bound device is ready when
  the driver that owns it runs.

`init` then runs each driver; one that fails is reported and the rest continue,
because a machine missing one device is a machine that boots with the others.
Boot-disk discovery is a chain rather than a choice: ATA, then AHCI, then
VirtIO, then NVMe, then USB mass storage — the first one that finds a disk wins,
which is why a QEMU `virt` machine and an AHCI laptop both come up without
configuration.  The network device is probed the same way
(`virtio_net::probe_boot_net`).

## The device ledger

Finding a device and *recording* it are separate acts.  A driver that binds one
calls `record_bound_device` with the device's name, its own name, the category
and the bus address it found it at, and the manager keeps the list.  The ledger
is what `/dev/<name>/` (`src/fs/devfs.rs`) serves: `driver`, `category` and the
bus data are files under the device's directory, so a program can ask which
driver owns a device rather than being told by the boot log.  The runtime checks
read exactly that (`cat /dev/virtio-net/driver`).

The framework also carries the machine seam: a driver that exists on one
machine and not another is compiled per machine, and every other machine
compiles a file that answers under the same module name and reports the
hardware is absent (`*_absent.rs`, and `HAS_PC_SPEAKER` for the one that is a
constant rather than a probe).  That is what keeps a caller from naming an
architecture: `drivers::nvme` exists everywhere, and only its body differs.

## Storage

| Driver | Completion | Scope |
|--------|-----------|-------|
| ATA (PIO) | Polling | The driver is the legacy path: programmed I/O, no DMA, no interrupt |
| AHCI (SATA) | Polling | Discovers controllers through PCI; the driver's own note says it is polling only — no MSI/MSI-X |
| VirtIO block | The transport's | Modern and legacy transports, on the virtio-mmio bus and on PCIe; the boot-disk chain's `virt` path |
| NVMe | Polling | The driver's own comment says it is poll-based: completions are reaped inside the submit-and-wait helpers, and the vector constants and handler exist without a programmed table behind them |
| USB mass storage | Not reachable | Bulk-only transport and SCSI command blocks are implemented; nothing can reach them until xHCI can drive a bus |

## Network

One driver: `virtio_net`, over the modern or legacy transport, with two queues
routed to their own MSI-X vectors.  Its completion path depends on the machine
and that is worth stating plainly — on the two PCIe machines the queues claim
their identities and a transmit waits on that queue's own interrupt, while on
x86_64 no device table is programmed and the completion is polled
([interrupts.md](interrupts.md) has the message path itself).

## PCIe

A PCIe BAR on the device-tree machines sits above the range the kernel maps, so
a driver does not read the address the resource pass assigned; it asks the
platform for a *window* (`arch::platform::pci_register_window`), and the
machine's own file under `src/arch/` decides how that window is reached — a
low alias on AArch64, the identity map on RISC-V.  AArch64 hands out one alias
slot per registered window rather than one fixed address: two drivers reading
their registers at the same alias would each be reading the other's device,
which is what the *second* PCIe driver found.

Interrupts are claimed, not found.  A driver names the MSI-X entries it uses,
the platform allocates identities for them and programs the device's table once
the interrupt controller is up, and the driver parks on an interrupt only after
that — before then the claim answers "not armed" and the completion path polls,
which is what every transport did before any of this existed
([rfcs/0001](../rfcs/0001-spread-message-signalled-interrupts.md) is the
placement design, and [interrupts.md](interrupts.md) has the message path).
Two drivers do this on the device-tree machines — `virtio_net` and the block
driver — and the point of the second one is that the identities are the
*device's*: the pair do not share a claim, a DeviceID, or an LPI range.

## Input and console

The serial UART is the console on every machine (with RISC-V falling back to
the SBI console when it has no UART).  The PS/2 keyboard and mouse are PC
hardware; a device-tree machine uses `virtio-input`, whose events are injected
into the same keyboard core so both routes end in one decoder.  A Linear
framebuffer — bochs-display — is a second console target next to the UART, with
its register map and display record in `drivers/framebuffer_protocol.rs` so a
driver and its consumers share the shape.

## Display and audio

`virtio-gpu` is 2D mode-setting plus the VIRGL 3D userspace interface, and the
interface has a renderer: `src/user/demo/virgl_renderer.rs` presents a frame
through the syscalls (`gpu_device_info`, a context, a 3D resource, a command
stream the kernel forwards to the device, a scanout), and both the shell's
`gpu` command and the demo runtime call it.  The Intel HDA driver finds
controllers through PCI and does CORB/RIRB command and codec discovery; it has
no userspace stream interface, so audio is a driver without a consumer.

## USB

The xHCI driver is a bring-up: it finds the controller through PCI, maps BAR0
and reports port status.  Nothing runs the rings yet, which is why the two USB
drivers above it — HID report decoding and mass-storage transport — are
implemented but not end-to-end.  The register map and the ring structures they
will use are in `drivers/xhci_protocol.rs`.

## Where the code is

| File | What it holds |
|------|---------------|
| `src/drivers/mod.rs` | The `Driver` trait, categories, registration order, boot-disk chain, ledger |
| `src/fs/devfs.rs` | `/dev/<name>/`, the ledger's filesystem view |
| `src/drivers/serial.rs`, `keyboard.rs`, `mouse.rs` | The console and the PC input devices |
| `src/drivers/virtio*.rs` | The VirtIO transports and the block, net, gpu and input devices |
| `src/drivers/nvme*.rs`, `hda*.rs`, `xhci*.rs`, `usb_*.rs` | PCIe storage, audio and USB |
| `src/drivers/framebuffer*.rs` | The bochs display and the console that draws on it |
| `src/arch/<machine>/` | The drivers that are that machine's hardware: ATA/AHCI, PS/2 speaker, PCI enumeration |

## See also

- [interrupts.md](interrupts.md) — where a device's completion comes from
- [boot.md](boot.md) — when drivers are initialised and the boot disk is chosen
