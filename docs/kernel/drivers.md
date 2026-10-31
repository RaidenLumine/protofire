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
| NVMe | Claimed, waits park | The completion queue claims one MSI-X table entry — the entry the controller's own admin completions share, because `Create I/O Completion Queue` fixes a queue's vector before any table can be programmed — and the driver's waits park on it once the platform arms the claim; a machine that refused one polls, exactly as before.  The driver is machine-neutral — it asks the platform for a register window — so all three machines compile the same file, and each boots a message-capable configuration in its own gate (`check-x8664-nvme` on the local APIC's vector window, `check-aarch64-nvme` on a GICv3 ITS, `check-riscv64-nvme` on the AIA IMSIC) |
| USB mass storage | Not reachable | Bulk-only transport and SCSI command blocks are implemented; nothing can reach them until xHCI can drive a bus |

## Network

One driver: `virtio_net`, over the modern or legacy transport, with two queues
routed to their own MSI-X vectors.  Its completion path is one path on every
machine now: the queues claim their identities, a transmit waits on that
queue's own interrupt, and a machine whose claim the platform has not programmed
answers "not armed" and polls instead
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
*device's*: the pair do not share a claim, a DeviceID, or an LPI range.  x86_64
claims the same way through a window of its own IDT
([rfcs/0003](../rfcs/0003-program-the-msix-table-on-x86_64.md)), with the NIC,
the block driver and the xHCI controller as its claimants; NVMe joined them on
all three machines, and it is the class whose driver has to be *woken* rather
than one that also stopped polling — a completion that has no other reason to
be checked, which is what makes the claim path a property of the machine
instead of one driver's shape.

## Input and console

The serial UART is the console on every machine (with RISC-V falling back to
the SBI console when it has no UART).  Its received bytes arrive by interrupt
on all three machines — COM1's vector 36, the PL011's GIC SPI 33 (claimed in
the interrupt registry), the NS16550A's PLIC source 10 (claimed the same way)
— routed and armed once the controller is up
(`arch::interrupt_controller::init`), so console input does not depend on the
timer tick.  On an AIA machine the same source is armed in the supervisor
APLIC domain instead, which turns the UART's line into the MSI carrying
identity 10 (`src/arch/riscv64/aplic.rs`).  A machine whose arm could not
happen keeps the tick's poll rather than lose the input: the device-tree
machines answer `serial::rx_is_interrupt_driven` from the outcome, so a console
that could not be claimed or armed is polled
(`src/kernel/process/scheduler/timer.rs`) instead of silently deaf.  That
includes a **direct-mode** APLIC machine (`aia=aplic`, no IMSIC behind the
domain) — but there the line is not refused: it is armed for the hart's own
delivery window and claimed by reading the window's `claimi` register, and
`make check-riscv64-aplic-direct-runtime` types at the shell and asserts the
RX-interrupt landmark, so that machine's input rides an interrupt too.
The PS/2 keyboard and mouse are PC
hardware; a device-tree machine uses `virtio-input`, whose events are injected
into the same keyboard core so both routes end in one decoder.  That driver's
completions are drained by the timer tick, and that is the MMIO transport's
shape rather than a missing interrupt: the transport carries no identity a
claim could own, so there is nothing for a handler to run for, and no gate
attaches the device — the path is cold on every measured machine
([RFC 0021](../rfcs/0021-what-the-timer-tick-still-polls.md)).  A Linear
framebuffer — bochs-display — is a second console target next to the UART, with
its register map and display record in `drivers/framebuffer_protocol.rs` so a
driver and its consumers share the shape.

### The console is one stream, and a prompt is not atomic

Output from two threads interleaves at whatever granularity the writes have, and
a shell prompt is more than one write: `protofire:`, the working directory and
`$ ` are three.  On a quiet boot nothing notices.  On a demo boot something
does — `demo-launcher-fault` is a program that is *meant* to fault, so its
supervisor restarts it while the shell is at the prompt and its ten lines land
between the pieces.  The serial log then holds a prompt with a service's output
spliced through it, and a character typed at that moment can land between two of
its pieces.

That is a property of the console, not of one reader, and it is why
`scripts/feed-shell-console.sh` and `scripts/press-usb-keys.sh` wait for **the
shell's own line** rather than for anything the console echoes.  An echo is the
terminal echoing keystrokes, which a prompt printed at the same time can split;
the shell's line is printed after the command finished, so it is the one a check
needs.  Both scripts carried the other judgement for a while and failed about
one boot in three; `docs/status.md` records what that cost.

A second reader of the same property is less obvious, because nothing is
missing when it goes wrong.  The console echoes **one write per typed
character** — `feed_char` returns the byte to echo and `feed_input_char` writes
it — so a feeder that types its next line before the previous command has
finished puts an echo in the path of that command's answer.  The answer is one
`write` and writes are serialised, so its bytes survive untouched and in order;
what interleaves is the echo's bytes *between* them, and the answer stops being
a line of its own.  Measured on `make check-x8664-init-no-start`, 2 of 12
boots read

    echo __protofire_feeder_sync_ring3-shell-answered

with every byte of the answer present and the check that requires it on a line
of its own red.  The fix is on the feeder's side — one line in flight at a
time, which the prompt at the top of the shell's loop is what tells it — and
not in the assertion, because an answer's *boundaries* are exactly what that
check is for.

What removes most of the cause rather than working around it: print the prompt
in one write, which the payload shell does now (`shell_write_prompt`).  It took
a boot's answer sharing its line from 3 in 10 to 1 in 10 and not to zero — the
remaining one is the demo payload's own `key: value` line landing on the same
line as the answer, which is the same interleaving one pair of writers over.
That is not free in a demo payload.  Its section is executable but not
writable, so the buffer has to be the caller's frame.  Arithmetic has to be
`wrapping_*`, because a checked add links a panic routine.  And copies have to
be byte loops, because a bulk copy links `memcpy` — and
`make check-payload-relocations` refuses a payload reference to anything outside
the payload, which is what a payload copied to another address cannot have.

## Display and audio

`virtio-gpu` is 2D mode-setting plus the VIRGL 3D userspace interface, and the
interface has a renderer: `src/user/demo/virgl_renderer.rs` presents a frame
through the syscalls (`gpu_device_info`, a context, a 3D resource, a command
stream the kernel forwards to the device, a scanout), and both the shell's
`gpu` command and the demo runtime call it.  The Intel HDA driver asks the
platform for the controller's BAR
(`arch::platform::pci_register_window`, the call NVMe makes), runs CORB/RIRB,
discovers the codec, points its output converter at a stream, and drains a BDL
ring into the controller's stream DMA.  Because the window is the platform's,
the one file drives the controller on x86_64 and on AArch64, where the BAR is
reached through the ECAM window and a low alias; the driver polls, so it claims
no interrupt and the ITS has nothing to do with it.
`/system/dev/audio` is the interface: a write is a `u32` sample rate followed by
interleaved 16-bit stereo samples, the shell's `tone` builtin is a caller on
every machine (a machine with no controller has the node and refuses the
write), and `make check-x8664-hda` and `make check-aarch64-hda` play through it
and read the samples back out of the WAV QEMU's audio backend writes on the
host, measuring the tone's frequency from the wave's own period.  The converter
learns the stream's shape from a
16-bit format word — how many channels, how deep, at what rate, with the rate
encoded as a base rate times a multiplier over a divisor — and it arrives
through `SET_STREAM_FORMAT`, one of the verbs whose payload is two bytes.  The
stream *tag* goes separately, in the channel verb.

## USB

The xHCI driver finds the controller through PCI, maps BAR0, resets and starts
it, and then runs two rings of its own: a command ring it posts to and an event
ring the controller posts completions on.  Device enumeration is Enable Slot →
Address Device → GET_DESCRIPTOR, and a device whose descriptor says HID gets an
interrupt endpoint configured whose reports are decoded into the same keyboard
core the PS/2 and VirtIO paths feed.  The register map and the ring structures
are in `drivers/xhci_protocol.rs`; the machine's half is `drivers/xhci.rs`, and
a machine without PCI answers from `xhci_absent.rs`.

**Scratchpad buffers** are the one thing a controller can declare that the
driver has to provide before it will leave the Halted state: HCSPARAMS2 carries
a ten-bit count split across two five-bit fields, and a count above zero means
DCBAA[0] is not a device slot but the physical address of an *array* of buffer
addresses, each buffer one controller page (`PAGESIZE`).  QEMU's controller
declares none — its `xhci_cap_read` returns `0x0000000f` for the register, the
count field zero — so this path has never executed in any boot this tree can
run, which is why its layout lives in `fill_scratchpad_dcbaa` and is exercised
by host tests rather than by a machine: a real controller declares at least
one, and a driver that does not provide the array starts a controller that
later reads slot contexts out of an address the driver never wrote.  The page
size is the register's value in 4 KiB units, and a controller whose register
does not name a power-of-two page size is skipped with its count and the
register named in the log, because a bring-up cannot otherwise tell that apart
from "no controller on this machine".

A **hub** is one of those devices, with a class of its own: the driver reads its
descriptor for the port count, powers and resets a port, and then addresses what
appears behind it — a device one tier down, which the Slot Context's *route
string* says how to find (one nibble per tier, and the controller walks exactly
those nibbles).  It also **watches the hub's own interrupt endpoint**, which is
where a hub reports which of its ports changed: that report is a bitmap, one bit
per port, and a change the driver has handled is cleared so the report stops.
A port with a device on it that is not enabled is one that just arrived — power where the hub
switches power per port, reset, address — and a port with no device is one that just left,
whose slot and everything behind it is disabled so the next device on the same route can
take it.  The change bits are read back after they are cleared, and a change this driver has
no selector for ends the watch rather than coming back forever.  Every hub found is
watched, including one plugged in behind another: each watch is an entry in a
list, keyed by the hub's slot, so it is the number of hubs and not a table's
size that decides how many are watched.  Without that
endpoint a hub is a device that was scanned once; `make check-x8664-usb-hotplug`
is the check that plugs, unplugs and re-plugs a device while the guest runs.

Four things about it are worth stating plainly.  The rings **carry a cycle
state through their wraps**: the command ring and each endpoint's control,
interrupt and bulk ring place a Link TRB with its Toggle Cycle bit and flip the
cycle state they write when that TRB wraps them, while the event ring — which
the controller produces and this driver consumes — has no Link TRB and is
consumed against the segment size the ERST states, with the cycle bit read from
the control word before the rest of the entry.  That is what makes a ring
usable for a second lap of work; what a lap cannot survive is a gap, because a
consumer stops at the first TRB it does not own — so the link sits where the
lap *ends* rather than at a fixed slot, or a wrap with slots left over would
stop the consumer before it ever reached the link.  That is the design
[RFC 0006](../rfcs/0006-end-a-producer-ring-lap-where-its-work-ends.md) settles,
extending what [RFC 0004](../rfcs/0004-reuse-the-xhci-rings-by-cycle-state.md)
decided after a mount over USB was found to stop completing transfers.  The controller
**claims a vector of its own** and the interrupt drains the event ring, taken
with `try_lock` so an interrupt never waits on the ring's owner; the timer tick
still drains as the fallback, and the lock is why that is an edge rather than
caution: the handler has already acknowledged the message the controller will
not raise again for the ring it left, so the tick is what drains a report that
arrived under a transfer's wait — and a machine whose claim was refused has no
handler at all
([RFC 0021](../rfcs/0021-what-the-timer-tick-still-polls.md)).  A **root port** is watched too, and by
the other mechanism: the controller posts a Port Status Change Event naming the
port, `PORTSC`'s change bits say whether a device arrived or left, and the bits
are cleared — once after the boot's scan, because a change bit that is still
set from the boot is a change the controller will not report again.  A device
that arrived is reset before it is addressed (the specification's order, and
the reset is what enables a USB 2 port), with the reset's own change bit
waiting for the controller to say it finished.  A device
that leaves a root port takes its whole subtree: everything behind a hub is
behind the hub's port.  And the work those reports ask for is done **from the
event-ring drain**, never while a transfer is in flight: answering a hub means
issuing requests, and a request submitted under another one's wait would put a
second TD on a ring whose first is still outstanding.  A submit takes room from its ring's
`RingRoom` first — the TRBs submitted and not yet completed are what a ring's
occupancy is, since the controller does not write its dequeue back into an
endpoint's context until the endpoint stops — and is refused with `Busy`
rather than allowed to overwrite a TRB the controller has not read.  Three checks drive the
whole path:
`make check-x8664-runtime` attaches a keyboard, presses a key through QEMU's
monitor, and asserts the shell's answer — the key is a HID report, the report
is a transfer event, and the event ring's own MSI-X vector is what carries it —
and attaches a **disk** beside it whose first sector carries a pattern the
driver reads back; `make check-x8664-usb-disk` goes further and boots the
host's own SimpleFs image on a USB disk, reads enough of it to wrap the rings,
loads a program out of it, and checks on the host that the guest's writes
reached the image; and `make check-x8664-usb-hotplug` moves a device on and off
a hub's port after the boot, and a device out of and into a root port, which is
the only check that reads a hub's status-change report or a port's change bits
at all.

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
