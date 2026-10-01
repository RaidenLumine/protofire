#!/usr/bin/env sh
# File: scripts/check-riscv64-pci-runtime.sh
# Purpose: Boot riscv64 with a PCIe device attached and check the ECAM walk.
#
# Why this exists
# ---------------
# This machine's PCIe host bridge is described by the device tree, and the
# kernel's device-tree parser used to settle the ECAM window when it read the
# node's `reg` — a decision that cannot work, because `compatible` (which says
# the node *is* a host bridge) comes after `reg` in every device tree QEMU
# writes.  The window was therefore never found, the enumeration never ran, and
# nothing noticed: no gate booted a machine with a PCIe device on it, and the
# two lines that would have said so were only printed by the code that never
# ran.
#
# So this check boots the AIA machine — the one interrupt receiver this kernel
# implements, which is what MSI-X is programmed through — with a virtio-net
# *PCI* device beside the usual MMIO one, and asserts the whole chain: the walk
# finds the window and the device, the kernel's own resource pass gives the
# device's memory BARs addresses (no firmware ran one), and the MSI-X table
# inside a BAR is programmed through the IMSIC and read back.  The read-back is
# the part that says the BAR decodes MMIO: the words only come back if they
# reached the device.
#
# Usage:
#   sh scripts/check-riscv64-pci-runtime.sh

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
QEMU_RISCV64="${QEMU_RISCV64:-qemu-system-riscv64}"
QEMU_RAM="${QEMU_RAM:-2G}"
RISCV64_PCI_LOG="${RISCV64_PCI_LOG:-}"

KERNEL_BIN="${TARGET_DIR}/riscv64gc-unknown-none-elf/${PROFILE}/${CRATE}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

if ! command -v "$QEMU_RISCV64" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the riscv64 PCI check.\n' "$QEMU_RISCV64" >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target riscv64gc-unknown-none-elf --bin "$CRATE" \
    --features demo-disk

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'riscv64 kernel binary not found: %s\n' "$KERNEL_BIN" >&2
    exit 1
fi

remove_log_on_exit=0
if [ -n "$RISCV64_PCI_LOG" ]; then
    mkdir -p "$(dirname "$RISCV64_PCI_LOG")"
    log_file="$RISCV64_PCI_LOG"
    : >"$log_file"
else
    log_file="$(mktemp)"
    remove_log_on_exit=1
fi

cleanup() {
    if [ "$remove_log_on_exit" = "1" ]; then
        rm -f "$log_file"
    fi
}
trap cleanup EXIT INT TERM

require_line() {
    pattern="$1"
    if ! grep -a -F "$pattern" "$log_file" >/dev/null 2>&1; then
        printf 'riscv64 PCI check failed: missing log line: %s\n' "$pattern" >&2
        printf '  last lines of the log:\n' >&2
        tail -n 12 "$log_file" | tr -d '\000' >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf '  full log preserved at: %s\n' "$log_file" >&2
        fi
        exit 1
    fi
}

require_absent() {
    pattern="$1"
    if grep -a -F "$pattern" "$log_file" >/dev/null 2>&1; then
        printf 'riscv64 PCI check failed: unexpected log line: %s\n' "$pattern" >&2
        tail -n 12 "$log_file" | tr -d '\000' >&2
        exit 1
    fi
}

printf 'riscv64 PCI check: 1 cpu, timeout %ss, qemu %s\n' "$TIMEOUT_SECONDS" "$QEMU_RISCV64"
printf '  %s\n' "timeout ${TIMEOUT_SECONDS}s $QEMU_RISCV64 -machine virt,aia=aplic-imsic ... -serial file:$log_file"

set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU_RISCV64" \
    -machine virt,aia=aplic-imsic \
    -cpu rv64 \
    -smp 1 \
    -m "$QEMU_RAM" \
    -kernel "$KERNEL_BIN" \
    -display none \
    -serial "file:$log_file" \
    -no-reboot \
    -no-shutdown \
    -global virtio-mmio.force-legacy=false \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 >/dev/null 2>>"$log_file"
status=$?
set -e

case "$status" in
    0|124) ;;
    *)
        printf 'riscv64 PCI check failed with exit status %s\n' "$status" >&2
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

# The window the device tree describes, at the address it describes it at: QEMU
# `virt` puts this machine's ECAM at 0x3000_0000, and reading it there is what
# the walk does.
require_line "[pci   ] RISC-V PCIe ECAM at 0x0000000030000000, buses 0..=255"

# Two devices: the host bridge itself, and the virtio-net function the demo's
# networking runs on — this boot has no virtio-mmio NIC, so the PCIe path is
# the only way the machine gets a network device at all.
require_line "[pci   ] PCI: 2 device(s) found"
require_line "00:00.0 vend=1b36 dev=0008"
require_line "00:01.0 vend=1af4 dev=1000"
require_line "caps: MSI-X"

require_line "[drivers] no virtio-net device found in the MMIO window"
require_line "[drivers] virtio-net PCI: modern transport BAR at 0x0000000040004000"
require_line "[drivers] virtio-net device found (PCI modern)"
require_line "[kernel] network stack initialized"

# The resource pass gave the device addresses out of the window the host
# bridge's `ranges` describes; without it every BAR reads back as zero, which
# is where this machine used to stop.
require_line "[pci   ] RISC-V BARs: 2 assigned"
require_line "00:01.0 BAR1 0x0000000040000000"

# And the interrupt half then programs a real table through the IMSIC and reads
# it back — the evidence that the BAR decodes MMIO, since the words only come
# back if they reached the device.
require_line "[pci   ] RISC-V MSI-X enabled on 00:01.0"
require_line "[pci   ] RISC-V MSI-X probe: 4 entries read back on 00:01.0"

# And the interrupts those entries would deliver have an owner: the identities
# are registered *before* the function is unmasked, and the receive side is
# walked once — the message a device writes into the hart's MSI page is claimed
# and handed to that handler.  Before this, `register_irq_handler` had no
# callers at all: every device interrupt would have been claimed, found
# handler-less, and counted as spurious.
require_line "[pci   ] RISC-V MSI-X unmasked on 00:01.0: irq 1-4 have a handler"
require_line "[pci   ] RISC-V device MSI: irq 1 claimed"
require_line "[pci   ] RISC-V MSI receive side: irq 1 reached its handler"

# Reading a window the device tree named must not fault the machine.
require_absent "[FATAL]"

if [ "$remove_log_on_exit" = "0" ]; then
    printf 'riscv64 PCI log saved to %s\n' "$log_file"
fi
printf 'riscv64 PCI check passed: ECAM walked, BARs assigned, MSI-X programmed, NIC driven over PCIe\n'
