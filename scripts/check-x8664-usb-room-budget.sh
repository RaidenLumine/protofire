#!/usr/bin/env sh
# File: scripts/check-x8664-usb-room-budget.sh
# Purpose: Prove the xHCI transfer ring's room accounting is load-bearing, by
#   dropping it and requiring the ring's refusal to fire.
#
# Why this exists
# ---------------
# A submit asks its ring's `RingRoom` for the TRBs a TD will use and hands them
# back when the completion is seen.  `docs/status.md` records that **no honest
# caller reaches the refusal**: every submit path here waits for its completion
# before the next one, so at most one TD's worth is outstanding and `Busy` never
# fires.  A depth-one design makes a *dropped release* invisible — occupancy
# climbs silently and some later submit is refused for no visible reason — so
# the only way to know the accounting is real is to break it and watch it
# complain.
#
# The `xhci_ring_room_leak` feature makes `TransferRing::release` drop every
# hand-back.  A USB disk read wraps the ring (that is what
# `check-x8664-usb-disk` exists to read over), so on that same boot the
# occupancy climbs to the budget and `RingRoom::reserve` refuses.
#
# What it asserts:
#   * the transport works — the device answered INQUIRY — so the failure is the
#     ring's budget and not the controller;
#   * `ring has no room for N TRB(s) (63 outstanding); refusing` appears, which
#     is the accounting holding its line at exactly the segment's usable slots;
#   * and the **same boot without the feature** never prints it, which is the
#     control: the refusal is reachable because the accounting was broken, not
#     because the boot is unusual.
#
# Usage:
#   sh scripts/check-x8664-usb-room-budget.sh [timeout-seconds]

set -eu

cd "$(dirname "$0")/.."

TIMEOUT_SECONDS="${1:-60}"
PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
QEMU="${QEMU:-qemu-system-x86_64}"
ROOM_LOG="${ROOM_LOG:-}"
KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

fail() {
    printf 'x86_64 USB ring-room check failed: %s\n' "$1" >&2
    [ -f "${log:-}" ] && tail -n 20 "$log" >&2
    exit 1
}

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the ring-room check.\n' "$QEMU" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

# The same host-made image both boots read: a real SimpleFs volume is what wraps
# the rings, and a single sector would not reach the budget.
image="$work/demo-disk.img"
"$CARGO" run --offline --quiet -- mkimage "$image"

# One boot of the same disk, answering with its own log.
boot_with() {
    log="$2"
    : >"$log"
    case "$PROFILE" in
        release) profile_flag="--release" ;;
        *) profile_flag="" ;;
    esac
    "$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
        --features "$1" >/dev/null
    [ -f "$KERNEL_BIN" ] || fail "x86_64 kernel binary not found: $KERNEL_BIN"
    sh ./scripts/check-payload-relocations.sh "$KERNEL_BIN"
    timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
        -machine q35 \
        -cpu max \
        -smp 1 \
        -m 1G \
        -kernel "$KERNEL_BIN" \
        -display none \
        -no-reboot \
        -no-shutdown \
        -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
        -drive "file=$image,if=none,id=usbdisk,format=raw" \
        -device usb-storage,drive=usbdisk,bus=xhci.0 \
        -serial "file:$log" >/dev/null 2>&1 || true
}

printf 'x86_64 USB ring-room check: timeout %ss, qemu %s\n' "$TIMEOUT_SECONDS" "$QEMU"

# ── The control: an honest boot never fills the budget ─────────────────
control_log="${ROOM_LOG:-$work/control.log}"
boot_with "demo-disk" "$control_log"
grep -a -F "[usbmsd] INQUIRY: vendor='QEMU'" "$control_log" >/dev/null 2>&1 ||
    fail "the control boot never identified the mass-storage device"
if grep -a -F "ring has no room" "$control_log" >/dev/null 2>&1; then
    fail "an honest boot filled the ring's budget, so the depth-one claim is wrong"
fi

# ── The defect: every release dropped, and the ring says so ────────────
leak_log="$work/leak.log"
boot_with "demo-disk,xhci_ring_room_leak" "$leak_log"
grep -a -F "[usbmsd] INQUIRY: vendor='QEMU'" "$leak_log" >/dev/null 2>&1 ||
    fail "the leak boot never identified the mass-storage device, so nothing was tested"
grep -a -F "ring has no room for 1 TRB(s) (63 outstanding); refusing" "$leak_log" >/dev/null 2>&1 ||
    fail "with every release dropped the ring never refused a submit; the accounting is decorative"

printf 'x86_64 USB ring-room check passed: an honest boot never fills the ring, and dropping every release makes it refuse at 63 outstanding\n'
