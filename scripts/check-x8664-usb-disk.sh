#!/usr/bin/env sh
# File: scripts/check-x8664-usb-disk.sh
# Purpose: Boot the x86_64 kernel with a real SimpleFs image on a USB disk and
#   require that the volume mounts, that its own programs load, and that the
#   guest's writes reach the image on the host.
#
# Why this exists
# ---------------
# The xHCI rings are small — 64 entries — and a disk read wraps them.  Before
# this check, the only USB storage the boot exercised was a single sector in
# `make check-x8664-runtime`, which never fills a ring, so the driver's ring
# *reuse* was unverified and wrong: the event ring's consumer flipped its
# cycle state one entry before the controller's producer did, wrote back a
# dequeue pointer one entry out of step, and the controller then treated the
# slot it was about to write as the consumer's and dropped every event after
# it.  A disk carrying a filesystem reaches that; a single sector does not.
#
# The image this check boots is the one the host `mkimage` writes, not the
# kernel's in-memory demo disk: it is the only way to attach a volume big
# enough to wrap the rings, and it is what makes the failure the driver's
# rather than the image's — the *same* image mounts over `virtio-blk` (the
# `check-perf-baseline` and demo boots already show that path), so a mount
# that fails here fails in the controller.
#
# What it asserts, and why each one:
#   * the mass-storage device answered INQUIRY and was chosen as the boot disk
#     — the transport works at all;
#   * the boot reached `mounted MBR-partitioned SimpleFs volumes`, which is
#     the read path over a partition table, several SimpleFs volumes and the
#     directory walk that fills and refills the rings;
#   * a program was loaded from `/apps` on that volume, which is a read the
#     mount alone does not prove;
#   * the image's SHA-256 changed on the host, which is a write the guest made
#     through the controller.
#
# Usage:
#   sh scripts/check-x8664-usb-disk.sh
#
# Exits 0 when all four hold, 1 otherwise (with the log's tail on stderr).

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-40}"
QEMU="${QEMU:-qemu-system-x86_64}"
X8664_USB_DISK_LOG="${X8664_USB_DISK_LOG:-}"
FEATURES="${FEATURES:-demo-disk}"

KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the USB disk check.\n' "$QEMU" >&2
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the USB disk check.\n' >&2
    exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
    printf 'sha256sum is not installed; cannot tell whether the guest wrote.\n' >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
    --features "$FEATURES"

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'x86_64 kernel binary not found: %s\n' "$KERNEL_BIN" >&2
    exit 1
fi

# The payloads on the image are read back by the boot, so their references have
# to be relative to themselves — the same check the other x86_64 boot makes,
# for the same reason.
sh ./scripts/check-payload-relocations.sh "$KERNEL_BIN"

work="$(mktemp -d)"
log="$work/boot.log"
if [ -n "$X8664_USB_DISK_LOG" ]; then
    mkdir -p "$(dirname "$X8664_USB_DISK_LOG")"
    log="$X8664_USB_DISK_LOG"
fi
: >"$log"

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

image="$work/demo-disk.img"
"$CARGO" run --offline --quiet -- mkimage "$image"

before="$(sha256sum "$image" | cut -d' ' -f1)"

# No other disk is attached: the USB volume *is* the boot disk, so the boot
# cannot fall back to the in-memory demo volumes and pass on those instead.
printf 'x86_64 USB disk check: 1 cpu, timeout %ss, qemu %s\n' \
    "$TIMEOUT_SECONDS" "$QEMU"

set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 \
    -cpu max \
    -smp 1 \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
    -drive "file=$image,if=none,id=usbdisk,format=raw" \
    -device usb-storage,drive=usbdisk,bus=xhci.0 \
    -serial "file:$log" >/dev/null 2>&1
status=$?
set -e

# 124 is `timeout` killing a machine that is, by design, still running.
case "$status" in
    0|124) ;;
    *)
        printf 'x86_64 USB disk check failed with exit status %s\n' "$status" >&2
        printf '  full log preserved at: %s\n' "$log" >&2
        exit "$status"
        ;;
esac

require_log_line() {
    pattern="$1"
    if ! grep -F "$pattern" "$log" >/dev/null 2>&1; then
        printf 'x86_64 USB disk check failed: missing log line: %s\n' "$pattern" >&2
        printf '  full log preserved at: %s\n' "$log" >&2
        tail -n 12 "$log" >&2
        exit 1
    fi
}

require_log_absent_line() {
    pattern="$1"
    if grep -F "$pattern" "$log" >/dev/null 2>&1; then
        printf 'x86_64 USB disk check failed: unexpected log line: %s\n' "$pattern" >&2
        printf '  full log preserved at: %s\n' "$log" >&2
        grep -F "$pattern" "$log" >&2
        exit 1
    fi
}

# The transport: the device answered, and the kernel chose it as the disk to
# boot from rather than falling through to the in-memory volumes.
require_log_line "[usbmsd] INQUIRY: vendor='QEMU' product='QEMU HARDDISK'"
require_log_line "[driver] detected boot disk: usb-msd"

# The read path over more than one lap of the rings: the MBR, both system
# slots, the volume superblocks and the directory walk.  The failure this
# check exists for prints the other line instead.
require_log_line "[fs    ] system: slot b active (build 2)"
require_log_line "[fs    ] mounted MBR-partitioned SimpleFs volumes from ATA boot disk"
require_log_absent_line "[fs    ] failed to mount SimpleFs volumes from ATA boot disk"

# A program read out of the volume: the mount alone would hold if the driver
# read only the first few blocks.
require_log_line "[user  ] loaded /apps/packages/shell/bin/shell.elf"

# The write path: the volume was mounted writable, the boot repaired what it
# found, and the bytes reached the file the host handed the controller.
after="$(sha256sum "$image" | cut -d' ' -f1)"
if [ "$before" = "$after" ]; then
    printf 'x86_64 USB disk check failed: the image is unchanged, so the guest\n' >&2
    printf '  wrote nothing through the controller (before=after=%s)\n' \
        "$after" >&2
    exit 1
fi

printf 'x86_64 USB disk check passed: image mounted, payload loaded, image %s... -> %s...\n' \
    "$(printf '%s' "$before" | cut -c1-12)" "$(printf '%s' "$after" | cut -c1-12)"
