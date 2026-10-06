#!/usr/bin/env sh
# File: scripts/check-nvme-disk.sh
# Purpose: Boot a machine with the host's own filesystem image on an NVMe
#   device, and require that the kernel drives the controller and mounts it.
#
# Why this exists
# ---------------
# The NVMe driver was written for x86_64 and had never run: no check booted a
# machine with an NVMe device, so nothing noticed that two of its admin
# opcodes were the specification's *neighbours* — `Create I/O Completion
# Queue` sat at 0x03, which the specification reserves, instead of 0x05 —
# and every controller answered "Invalid Command Opcode".  The I/O queues
# were never created, so no read or write through the driver could have
# worked, and [docs/status.md](../docs/status.md) said it did.
#
# Two things fix that at once, and this check is both of them: it attaches a
# real device, so the driver's bring-up runs for the first time; and it
# asserts the whole read path — the controller identifies itself, reports its
# geometry, is chosen as the boot disk, and the filesystem on it mounts.
#
# The image is the one the host `mkimage` writes rather than the kernel's
# in-memory demo volume: a mount is what proves the driver read the partition
# table, the volume headers and the directory tree, which an Identify command
# alone does not.
#
# Usage:
#   sh scripts/check-nvme-disk.sh <x86_64|aarch64> [timeout-seconds]
#
# Exits 0 when the boot reached the mount, 1 otherwise (with the log's tail on
# stderr).

set -eu

cd "$(dirname "$0")/.."

MACHINE="${1:-}"
TIMEOUT_SECONDS="${2:-40}"
PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
NVME_DISK_LOG="${NVME_DISK_LOG:-}"
FEATURES="${FEATURES:-demo-disk}"

case "$MACHINE" in
    x86_64) QEMU="${QEMU:-qemu-system-x86_64}" ;;
    aarch64) QEMU="${QEMU:-qemu-system-aarch64}" ;;
    *)
        printf 'usage: %s <x86_64|aarch64> [timeout-seconds]\n' "$0" >&2
        exit 2
        ;;
esac

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the NVMe disk check.\n' "$QEMU" >&2
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the NVMe disk check.\n' >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac

# The kernel image, built the way that machine boots: an ELF for x86_64, an
# arm64 `Image` for aarch64.
if [ "$MACHINE" = "x86_64" ]; then
    "$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
        --features "$FEATURES"
    KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"
else
    PROFILE="$PROFILE" CRATE="$CRATE" TARGET_DIR="$TARGET_DIR" FEATURES="$FEATURES" \
        sh ./scripts/build-aarch64-image.sh >/dev/null
    KERNEL_BIN="${TARGET_DIR}/aarch64-unknown-none/${PROFILE}/${CRATE}.img"
fi

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'kernel image not found: %s\n' "$KERNEL_BIN" >&2
    exit 1
fi

# The payload relocation check reads an ELF; the aarch64 boot artifact is an
# `Image`, and that machine's copy is checked by its own runtime gate.
if [ "$MACHINE" = "x86_64" ]; then
    sh ./scripts/check-payload-relocations.sh "$KERNEL_BIN"
fi

work="$(mktemp -d)"
log="$work/boot.log"
if [ -n "$NVME_DISK_LOG" ]; then
    mkdir -p "$(dirname "$NVME_DISK_LOG")"
    log="$NVME_DISK_LOG"
fi
: >"$log"

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

image="$work/demo-disk.img"
"$CARGO" run --offline --quiet -- mkimage "$image"

printf 'nvme disk check (%s): timeout %ss, qemu %s\n' "$MACHINE" "$TIMEOUT_SECONDS" "$QEMU"

# No other disk is attached: the NVMe namespace *is* the boot disk, so the boot
# cannot fall back to the in-memory demo volumes and pass on those instead.
# 1 GiB is the x86_64 demo's RAM; the aarch64 kernel needs 2 GiB for its pool.
set +e
if [ "$MACHINE" = "x86_64" ]; then
    timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
        -machine q35 -cpu max -smp 1 -m 1G \
        -kernel "$KERNEL_BIN" \
        -display none -no-reboot -no-shutdown \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -drive "file=$image,if=none,id=nvme0,format=raw" \
        -device nvme,drive=nvme0,serial=protofire \
        -serial "file:$log" >/dev/null 2>&1
else
    timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
        -machine virt -cpu max -smp 1 -m 2G \
        -kernel "$KERNEL_BIN" \
        -display none -no-reboot -no-shutdown \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -drive "file=$image,if=none,id=nvme0,format=raw" \
        -device nvme,drive=nvme0,serial=protofire \
        -serial "file:$log" >/dev/null 2>&1
fi
status=$?
set -e

# 124 is `timeout` killing a machine that is, by design, still running.
case "$status" in
    0|124) ;;
    *)
        printf 'nvme disk check (%s) failed with exit status %s\n' "$MACHINE" "$status" >&2
        printf '  full log preserved at: %s\n' "$log" >&2
        exit "$status"
        ;;
esac

fail() {
    printf 'nvme disk check (%s) failed: %s\n' "$MACHINE" "$1" >&2
    printf '  full log preserved at: %s\n' "$log" >&2
    tail -n 12 "$log" >&2
    exit 1
}

require_log_line() {
    grep -F "$1" "$log" >/dev/null 2>&1 || fail "missing log line: $1"
}

# The controller: found on the machine's bus, brought up, geometry read.
require_log_line "[nvme  ] found NVMe controller "
require_log_line "[nvme  ] initialising NVMe controller at BAR="
require_log_line "[nvme  ] NVMe ready: 3584 blocks × 512 bytes"
# Chosen as the disk to boot from, rather than falling through to the in-memory
# demo volumes.
require_log_line "[driver] detected boot disk: nvme0 (3584 blocks)"
# And the read path over that disk: the MBR, the system slots, the volume
# superblocks and the directory walk, which is what a mount reaches and an
# Identify command does not.
require_log_line "[fs    ] mounted MBR-partitioned SimpleFs volumes from ATA boot disk"
if grep -F "[fs    ] failed to mount SimpleFs volumes from ATA boot disk" "$log" >/dev/null 2>&1; then
    fail "the volume on the NVMe namespace did not mount"
fi

printf 'nvme disk check (%s) passed: controller brought up, boot disk chosen, image mounted\n' "$MACHINE"
