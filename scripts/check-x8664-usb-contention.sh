#!/usr/bin/env sh
# File: scripts/check-x8664-usb-contention.sh
# Purpose: Force the xHCI interrupt to arrive while the rings are held, and
#   require the timer tick to answer the report the interrupt had to drop.
#
# Why this exists
# ---------------
# RFC 0021 decided that the timer tick's xHCI drain **stays**, and its reason is
# a lock, not caution: the interrupt handler acknowledges the interrupter and
# then takes the rings with `try_lock`, because an interrupt must not wait on a
# transfer's owner.  When that fails the events it did not take are not
# re-offered — the message was acknowledged and the controller raises one per
# 0→1 transition — so the tick is what drains them.  The RFC says plainly that
# this necessity is **argued, not measured**: no gate makes a report arrive
# while someone else holds the rings.
#
# This gate makes it happen.  The `xhci_contention` feature makes the tick's
# `xhci_poll` call the interrupt handler **from inside its own lock**, so the
# handler's `try_lock` fails for real on every tick.  Everything downstream is
# the production path: the handler acknowledges and counts the miss, the tick
# then drains the ring and answers whatever arrived.
#
# What it asserts, in line order (the order is the evidence):
#   * the boot says `interrupt could not take the rings; the tick will drain
#     them` — the miss path ran, at least once;
#   * a device plugged into a hub's port **after** that message is still
#     enumerated (`hub port 1 enumerated (route 0x1)` and a HID device ready) —
#     so the tick answered a report the interrupt could not;
#   * and it is enumerated after the miss line, which is what says the *tick*
#     was the drainer rather than the handler.
#
# Usage:
#   sh scripts/check-x8664-usb-contention.sh [timeout-seconds]

set -eu

cd "$(dirname "$0")/.."

TIMEOUT_SECONDS="${1:-60}"
PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
QEMU="${QEMU:-qemu-system-x86_64}"
CONTENTION_LOG="${CONTENTION_LOG:-}"
FEATURES="${FEATURES:-demo-disk xhci_contention}"
KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

fail() {
    printf 'x86_64 USB contention check failed: %s\n' "$1" >&2
    [ -f "${log:-}" ] && tail -n 20 "$log" >&2
    exit 1
}

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the contention check.\n' "$QEMU" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    printf 'python3 is not installed; cannot drive QEMU\x27s monitor.\n' >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
    --features "$FEATURES"
[ -f "$KERNEL_BIN" ] || fail "x86_64 kernel binary not found: $KERNEL_BIN"
sh ./scripts/check-payload-relocations.sh "$KERNEL_BIN"

work="$(mktemp -d)"
log="$work/boot.log"
monitor_socket="$work/monitor.sock"
if [ -n "$CONTENTION_LOG" ]; then
    mkdir -p "$(dirname "$CONTENTION_LOG")"
    log="$CONTENTION_LOG"
fi
: >"$log"

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

printf 'x86_64 USB contention check: timeout %ss, qemu %s\n' "$TIMEOUT_SECONDS" "$QEMU"

# The guest is typed at so the boot's own scan is finished before anything is
# plugged: the marker is the shell answering, and everything this gate reads is
# after it.
shell_commands() {
    sh ./scripts/feed-shell-console.sh "$log" "$TIMEOUT_SECONDS" \
        'echo contention-marker' \
        'echo contention-done'
}

# Plug a mouse into the hub's port 1 while the guest runs, and wait for the
# guest to say it saw it.  The monitor is the instrument: only QEMU can assert
# the hub's status-change bit, and nothing inside the guest can fake it.
plug_after_marker() {
    python3 - "$monitor_socket" "$log" "$TIMEOUT_SECONDS" <<'PY'
import re
import socket
import sys
import time

monitor, log, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3])

sock = socket.socket(socket.AF_UNIX)
for _ in range(200):
    try:
        sock.connect(monitor)
        break
    except OSError:
        time.sleep(0.1)
else:
    print("contention: QEMU's monitor socket never appeared", file=sys.stderr)
    sys.exit(1)

def command(text):
    sock.sendall((text + "\n").encode())
    time.sleep(0.2)

def read_tail():
    """The log from the marker on: everything before it is the boot's scan."""
    with open(log, "rb") as handle:
        text = handle.read().replace(b"\r", b"")
    marker = text.find(b"contention-marker")
    return text[marker:] if marker >= 0 else b""

def wait_for(pattern, count=1, literal=True):
    if literal:
        pattern = re.escape(pattern)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if len(re.findall(pattern, read_tail())) >= count:
            return
        time.sleep(0.25)
    print("contention: the guest never reported %r" % pattern.decode(), file=sys.stderr)
    sys.exit(1)

# The boot scan is done when the shell answers the marker.
wait_for(b"contention-marker")
time.sleep(1.0)

# The miss path is exercised on every tick by the feature; assert it appears at
# all before plugging, so the enumeration below cannot be attributed to the
# handler having drained it.
wait_for(b"interrupt could not take the rings; the tick will drain them")

command("device_add usb-mouse,id=contention0,bus=xhci.0,port=2.1")
wait_for(b"hub port 1 enumerated (route 0x1)")
wait_for(b"HID mouse ready at slot ")

command("quit")
time.sleep(0.5)
PY
}

set +e
{ shell_commands; } | timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 \
    -cpu max \
    -smp 1 \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -monitor "unix:$monitor_socket,server,nowait" \
    -device qemu-xhci,id=xhci \
    -device usb-kbd,id=contention-kbd,bus=xhci.0 \
    -device usb-hub,id=hub0,bus=xhci.0,port=2 \
    -serial stdio >"$log" 2>&1 &
qemu_pid=$!
set -e

set +e
plug_after_marker
plug_status=$?
set -e

if [ "$plug_status" -ne 0 ]; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    fail "the guest did not follow the plug driven by the tick's drain"
fi

set +e
wait "$qemu_pid"
status=$?
set -e
case "$status" in
    0|124) ;;
    *) fail "the boot exited with status $status" ;;
esac

# The line order is the assertion, read once at the end: the miss has to come
# before the enumeration it explains.
miss_line="$(grep -an 'interrupt could not take the rings' "$log" | head -1 | cut -d: -f1)"
enum_line="$(grep -an 'hub port 1 enumerated (route 0x1)' "$log" | head -1 | cut -d: -f1)"
[ -n "$miss_line" ] || fail "the miss path never ran"
[ -n "$enum_line" ] || fail "the device plugged after the marker was never enumerated"
[ "$miss_line" -lt "$enum_line" ] ||
    fail "the enumeration came before the miss, so the handler, not the tick, drained it"

printf 'x86_64 USB contention check passed: the interrupt could not take the rings, and the tick enumerated the device that arrived\n'
