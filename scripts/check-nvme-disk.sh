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
# Since the driver's completion queue claims an interrupt of its own, this is
# also the gate that makes the claim real.  The device-tree machines boot the
# configuration that can carry a message — a GICv3 with an ITS on AArch64, an
# IMSIC on RISC-V — and the check asserts the three moments: the claim taken
# before the controller runs (the queue's vector is a field of `Create I/O
# Completion Queue`, so it has to be chosen then), the table programmed once
# the controller is up, and a completion MSI the driver's own handler ran for.
# The device-tree machines' GICv2/PLIC configurations still mount (the claim
# is refused or unprogrammable there and the driver polls), and the runtime
# checks assert the refusal on those machines.
#
# Usage:
#   sh scripts/check-nvme-disk.sh <x86_64|aarch64|riscv64> [timeout-seconds]
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
    riscv64) QEMU="${QEMU:-qemu-system-riscv64}" ;;
    *)
        printf 'usage: %s <x86_64|aarch64|riscv64> [timeout-seconds]\n' "$0" >&2
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
case "$MACHINE" in
x86_64)
    "$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
        --features "$FEATURES"
    KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"
    ;;
aarch64)
    PROFILE="$PROFILE" CRATE="$CRATE" TARGET_DIR="$TARGET_DIR" FEATURES="$FEATURES" \
        sh ./scripts/build-aarch64-image.sh >/dev/null
    KERNEL_BIN="${TARGET_DIR}/aarch64-unknown-none/${PROFILE}/${CRATE}.img"
    ;;
riscv64)
    "$CARGO" build --offline $profile_flag --target riscv64gc-unknown-none-elf --bin "$CRATE" \
        --features "$FEATURES"
    KERNEL_BIN="${TARGET_DIR}/riscv64gc-unknown-none-elf/${PROFILE}/${CRATE}"
    ;;
esac

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
#
# A boot runs both halves where a machine has two: the configuration whose
# controller can carry a message (a GICv3 ITS, the AIA IMSIC), where the claim
# has to arm and a completion has to *wake the driver*, and the machine's
# default configuration, where there is no message receiver — the claim is
# refused outright (GICv2: no ITS) or taken and never programmable (PLIC: no
# IMSIC) and the same volume must still mount.  This check used to boot the
# default machine only, so the message half was untested; booting both is what
# keeps the refusal half from becoming untested instead.

fail() {
    printf 'nvme disk check (%s) failed: %s\n' "$MACHINE" "$1" >&2
    printf '  full log: %s\n' "$log" >&2
    tail -n 12 "$log" >&2
    exit 1
}

require_log_line() {
    grep -F "$1" "$log" >/dev/null 2>&1 || fail "missing log line: $1"
}

require_log_absent() {
    if grep -F "$1" "$log" >/dev/null 2>&1; then
        fail "unexpected log line: $1"
    fi
}

# Boot one machine configuration into `$log`.  Every argument after the log
# path is a QEMU argument; the kernel, the display flags and the serial sink
# are common.
boot() {
    boot_log="$1"
    shift
    log="$boot_log"
    set +e
    timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
        -kernel "$KERNEL_BIN" \
        -display none -no-reboot -no-shutdown \
        "$@" \
        -serial "file:$log" >/dev/null 2>&1
    status=$?
    set -e

    # 124 is `timeout` killing a machine that is, by design, still running.
    case "$status" in
        0|124) ;;
        *)
            printf 'nvme disk check (%s) failed with exit status %s\n' "$MACHINE" "$status" >&2
            printf '  full log: %s\n' "$log" >&2
            exit "$status"
            ;;
    esac
}

# The controller and the read path over it, on any configuration: found, brought
# up, geometry read, chosen over the in-memory demo volumes, and the volume
# mounted — which is the MBR, the system slots, the volume superblocks and the
# directory walk, not the Identify command alone.
assert_mounts() {
    require_log_line "[nvme  ] found NVMe controller "
    require_log_line "[nvme  ] initialising NVMe controller at BAR="
    require_log_line "[nvme  ] NVMe ready: 3584 blocks × 512 bytes"
    require_log_line "[driver] detected boot disk: nvme0 (3584 blocks)"
    require_log_line "[fs    ] mounted MBR-partitioned SimpleFs volumes from ATA boot disk"
    if grep -F "[fs    ] failed to mount SimpleFs volumes from ATA boot disk" "$log" >/dev/null 2>&1; then
        fail "the volume on the NVMe namespace did not mount"
    fi
}

# The claim and its delivery, on a configuration whose controller can carry a
# message.  The claim is taken before the controller runs, because the queue's
# vector is a field of `Create I/O Completion Queue`; the table is programmed
# once the interrupt controller is up; and a completion MSI is a message the
# device sent on the identity the claim took and the driver's own handler ran
# for — the difference between "the table was written" and "the device woke
# the driver".
assert_claimed_and_delivered() {
    require_log_line "[nvme  ] completion interrupts claimed: irq "
    require_log_line "[nvme  ] completion MSI (irq "
    case "$MACHINE" in
    x86_64)
        require_log_line "[msix  ] MSI-X on 00:03.0 delivers vectors "
        ;;
    aarch64)
        require_log_line "[its   ] MSI-X on 00:02.0 delivers LPI "
        ;;
    riscv64)
        require_log_line "[pci   ] RISC-V MSI-X unmasked on 00:02.0: irq "
        ;;
    esac
}

printf 'nvme disk check (%s): timeout %ss, qemu %s\n' "$MACHINE" "$TIMEOUT_SECONDS" "$QEMU"

case "$MACHINE" in
x86_64)
    boot "$log" \
        -machine q35 -cpu max -smp 1 -m 1G \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -drive "file=$image,if=none,id=nvme0,format=raw" \
        -device nvme,drive=nvme0,serial=protofire
    assert_mounts
    assert_claimed_and_delivered
    printf 'nvme disk check (x86_64) passed: mounted, completion interrupt claimed and delivered\n'
    ;;
aarch64)
    # The default machine is a GICv2 one, which has no ITS: the claim is
    # refused at probe time, so the driver never prints a claim and the volume
    # still mounts on the polling path.
    secondary="$work/boot-gicv2.log"
    boot "$secondary" \
        -machine virt -cpu max -smp 1 -m 2G \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -drive "file=$image,if=none,id=nvme0,format=raw" \
        -device nvme,drive=nvme0,serial=protofire
    assert_mounts
    require_log_absent "[nvme  ] completion interrupts claimed"
    require_log_absent "[nvme  ] completion MSI (irq "
    require_log_absent "[its   ]"

    # And the same disk on a GICv3 machine, where the ITS is the receiver.
    boot "$log" \
        -machine virt,gic-version=3 -cpu max -smp 1 -m 2G \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -drive "file=$image,if=none,id=nvme0,format=raw" \
        -device nvme,drive=nvme0,serial=protofire
    assert_mounts
    assert_claimed_and_delivered
    printf 'nvme disk check (aarch64) passed: mounted on GICv2 (claim refused, polls) and on GICv3 (claimed and delivered)\n'
    ;;
riscv64)
    # The default machine's PLIC has no IMSIC behind it, so the claim is taken
    # — the identities are the registry's — but its table is never programmed:
    # the mount must still work on the polling path, and the arm's refusal is
    # printed rather than silently leaving the driver waiting.
    secondary="$work/boot-plic.log"
    boot "$secondary" \
        -machine virt -cpu max -smp 1 -m 2G \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -drive "file=$image,if=none,id=nvme0,format=raw" \
        -device nvme,drive=nvme0,serial=protofire
    assert_mounts
    require_log_line "[nvme  ] completion interrupts claimed: irq "
    require_log_absent "[nvme  ] completion MSI (irq "
    require_log_line "[pci   ] RISC-V MSI-X on 00:02.0 not programmed"

    # And the same disk on the AIA machine, where the IMSIC receives.
    boot "$log" \
        -machine virt,aia=aplic-imsic -cpu max -smp 1 -m 2G \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -drive "file=$image,if=none,id=nvme0,format=raw" \
        -device nvme,drive=nvme0,serial=protofire
    assert_mounts
    assert_claimed_and_delivered
    printf 'nvme disk check (riscv64) passed: mounted on the PLIC machine (claim unprogrammable, polls) and on the AIA machine (claimed and delivered)\n'
    ;;
esac
