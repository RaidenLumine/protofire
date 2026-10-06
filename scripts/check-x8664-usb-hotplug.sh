#!/usr/bin/env sh
# File: scripts/check-x8664-usb-hotplug.sh
# Purpose: Boot with a hub that has nothing on its ports, plug a device into
#   it, unplug it, and plug it back in — and require the driver to see all
#   three without a reboot.
#
# Why this exists
# ---------------
# A hub that is scanned once is a hub only for the devices that were already
# plugged into it: its interrupt IN endpoint reports which of its ports
# changed, and until the driver read it, a device plugged in after the boot
# waited for the next boot.  That endpoint is the whole difference between a
# hub and a port multiplier, and nothing in the tree had ever read one.
#
# The observation is the guest's own log, and the *line order* in it is the
# evidence: the device appears behind the hub only after a command typed at
# the shell long after the boot scan, so the enumeration cannot have happened
# at boot.  QEMU's monitor is the instrument that plugs and unplugs — a real
# device being moved — and it cannot be faked from inside the guest: the
# attach is QEMU's USB hub asserting its status-change bit.
#
# What it asserts:
#   * at boot, a keyboard sits on a root port and the hub's ports are empty —
#     no device is enumerated behind the hub before the marker command;
#   * plugging a mouse into the hub's port 1, after that marker, produces
#     "hub port 1 enumerated (route 0x1)" and a HID mouse;
#   * unplugging it produces "hub port 1: device removed (slot N)" — the slot
#     is released, not leaked;
#   * plugging it back in produces the same two lines *again*, which is what
#     a released slot looks like from outside;
#   * and a **second** hub, plugged in behind the first one's sibling, is
#     itself enumerated, watched, and has a device plugged into *it* — which
#     a driver that kept one hub's watch would never see, because the second
#     hub would have taken the watch from the first;
#   * pulling the *keyboard* out of its root port produces the same removal
#     for a device that was there at boot (its port's change bit has to have
#     been cleared once, or the controller never raises the event at all);
#   * and plugging a device into a free root port produces an enumeration
#     there — the other half of the hub's work, driven by the controller's
#     Port Status Change Event rather than by a hub's report.
#
# Usage:
#   sh scripts/check-x8664-usb-hotplug.sh [timeout-seconds]

set -eu

cd "$(dirname "$0")/.."

TIMEOUT_SECONDS="${1:-60}"
PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
QEMU="${QEMU:-qemu-system-x86_64}"
HOTPLUG_LOG="${HOTPLUG_LOG:-}"
FEATURES="${FEATURES:-demo-disk}"

KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the USB hotplug check.\n' "$QEMU" >&2
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
sh ./scripts/check-payload-relocations.sh "$KERNEL_BIN"

work="$(mktemp -d)"
log="$work/boot.log"
monitor_socket="$work/monitor.sock"
if [ -n "$HOTPLUG_LOG" ]; then
    mkdir -p "$(dirname "$HOTPLUG_LOG")"
    log="$HOTPLUG_LOG"
fi
: >"$log"

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

printf 'x86_64 USB hotplug check: timeout %ss, qemu %s\n' "$TIMEOUT_SECONDS" "$QEMU"

# The keyboard is what proves the boot's USB path still runs; the hub is what
# this check is about, and it starts empty.
shell_commands() {
    sh ./scripts/feed-shell-console.sh "$log" "$TIMEOUT_SECONDS" \
        'echo hotplug-marker' \
        'echo serial-done'
}

# The device is moved while the guest runs: QEMU\x27s monitor addresses the
# hub\x27s own port 1 (`port=2.1` — root port 2, its first downstream port), and
# each step waits for the guest to *say* it saw the change rather than for a
# fixed delay, so a slow or a fast boot both work.
plug_and_wait() {
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
    print("hotplug: QEMU's monitor socket never appeared", file=sys.stderr)
    sys.exit(1)

def command(text):
    sock.sendall((text + "\n").encode())
    time.sleep(0.2)

def read_tail():
    """The log from the marker on: everything before it is the boot's scan."""
    with open(log, "rb") as handle:
        text = handle.read().replace(b"\r", b"")
    marker = text.find(b"hotplug-marker")
    return text[marker:] if marker >= 0 else b""

def wait_for(pattern, count=1, literal=True):
    """Wait until the log *after the marker* holds `count` matches.

    Everything before the marker is the boot's scan, so a match here is a
    change the guest saw while it was running and nothing else.
    """
    if literal:
        pattern = re.escape(pattern)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if len(re.findall(pattern, read_tail())) >= count:
            return
        time.sleep(0.25)
    print("hotplug: the guest never reported %r" % pattern.decode(), file=sys.stderr)
    sys.exit(1)

# The boot scan is done when the shell has answered the marker.
wait_for(b"hotplug-marker")
time.sleep(1.0)

command("device_add usb-mouse,id=hotplug0,bus=xhci.0,port=2.1")
wait_for(b"hub port 1 enumerated (route 0x1)")
wait_for(b"HID mouse ready at slot ")

command("device_del hotplug0")
wait_for(b"hub port 1: device removed (slot ")

command("device_add usb-mouse,id=hotplug1,bus=xhci.0,port=2.1")
wait_for(b"hub port 1 enumerated (route 0x1)", count=2)
wait_for(b"HID mouse ready at slot ", count=2)

# A hub behind the other hub: it has a watch of its own, and the mouse behind
# *it* is a tier deeper, so its route string is two nibbles.
command("device_add usb-hub,id=hotplug-hub2,bus=xhci.0,port=3.1")
wait_for(b"hub port 1 enumerated (route 0x1)", count=3)
# The two hubs that were there at boot were watched before the marker; this is
# the third watch, added while the guest runs.
wait_for(b"status-change endpoint watching", count=1)
wait_for(b"downstream port(s), route 0x1")

command("device_add usb-mouse,id=hotplug-deep,bus=xhci.0,port=3.1.1")
wait_for(b"hub port 1 enumerated (route 0x11)")
wait_for(b"HID mouse ready at slot ", count=3)

# A root port, both directions: the keyboard that was there at boot leaves,
# and a mouse that was not arrives on a free port.
command("device_del hotplug-kbd")
wait_for(b"\\[xhci  \\] port [0-9]+: device removed \\(slot ", literal=False)
wait_for(b"slot(s) released")

command("device_add usb-mouse,id=hotplug-root,bus=xhci.0")
wait_for(b"HID mouse ready at slot ", count=4)
wait_for(b"\\[xhci  \\] enumerated port ", literal=False)

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
    -device qemu-xhci,id=xhci,p2=8 \
    -device usb-kbd,id=hotplug-kbd,bus=xhci.0 \
    -device usb-hub,id=hub0,bus=xhci.0,port=2 \
    -device usb-hub,id=hub1,bus=xhci.0,port=3 \
    -device usb-hub,id=hub2,bus=xhci.0,port=4 \
    -device usb-hub,id=hub3,bus=xhci.0,port=5 \
    -serial stdio >"$log" 2>&1 &
qemu_pid=$!
set -e

set +e
plug_and_wait
plug_status=$?
set -e

if [ "$plug_status" -ne 0 ]; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    printf 'x86_64 USB hotplug check failed: the guest did not follow the plug\n' >&2
    tail -n 20 "$log" >&2
    exit 1
fi

set +e
wait "$qemu_pid"
status=$?
set -e

case "$status" in
    0|124) ;;
    *)
        printf 'x86_64 USB hotplug check failed with exit status %s\n' "$status" >&2
        exit "$status"
        ;;
esac

fail() {
    printf 'x86_64 USB hotplug check failed: %s\n' "$1" >&2
    tail -n 20 "$log" >&2
    exit 1
}

# Log lines are compared from a copy with the console's carriage returns
# removed: the shell's prompt redraws lines, and a plain grep would miss a
# line whose text was overwritten in place.
trimmed="$work/trimmed.log"
tr -d '\r' <"$log" >"$trimmed"

require_log_line() {
    grep -a -F "$1" "$trimmed" >/dev/null 2>&1 || fail "missing log line: $1"
}

count_log_lines() {
    grep -a -c -F "$1" "$trimmed" 2>/dev/null || true
}

# The boot itself: the controller, the hub, and an empty downstream.
require_log_line "[xhci  ] hub at slot "
require_log_line "downstream port(s), route 0x0"
require_log_line "status-change endpoint watching"
require_log_line "[xhci  ] HID keyboard ready at slot "

# The three moves, in the only order that means anything: the marker command
# is typed at the shell long after the boot scan, so an enumeration *after*
# it cannot have happened at boot.
marker_line="$(grep -a -n -F "hotplug-marker" "$trimmed" | head -n 1 | cut -d: -f1)"
[ -n "$marker_line" ] || fail "the marker command never reached the shell"

first_line="$(grep -a -n -F "hub port 1 enumerated (route 0x1)" "$trimmed" | head -n 1 | cut -d: -f1)"
[ -n "$first_line" ] || fail "the device plugged into the hub was never enumerated"
[ "$first_line" -gt "$marker_line" ] ||
    fail "the hub's device was enumerated at boot, not when it was plugged in"

require_log_line "hub port 1: device removed (slot "
[ "$(count_log_lines "hub port 1 enumerated (route 0x1)")" -ge 2 ] ||
    fail "the device plugged back into the hub was not enumerated again"
[ "$(count_log_lines "HID mouse ready at slot ")" -ge 4 ] ||
    fail "the mouse was not ready for each of the four plugs"

# Four hubs were there at boot and one more was plugged in behind them.  A
# driver that kept one watch would have taken the earlier ones' away — and the
# device plugged into the *first* hub (the gate's first move) would never have
# been seen at all — while a driver with a table to fill would have stopped
# watching at its last row, which is what the fifth watch here is for.
[ "$(count_log_lines "status-change endpoint watching")" -ge 5 ] ||
    fail "a hub beyond the boot's four was not watched"
[ "$(count_log_lines "downstream port(s), route 0x0")" -ge 4 ] ||
    fail "the four hubs that were there at boot were not all taken up"
require_log_line "downstream port(s), route 0x1"
[ "$(count_log_lines "hub port 1 enumerated (route 0x11)")" -ge 1 ] ||
    fail "the device behind the second hub was never enumerated"

# And the root port: the keyboard that was there at boot is released, and a
# device plugged into a free root port is enumerated there.  The first is the
# case the port-change-bit sync exists for — a port whose change bit is still
# set from the boot says nothing when its device leaves.
[ "$(grep -a -c -E '\[xhci  \] port [0-9]+: device removed' "$trimmed" || true)" -ge 1 ] ||
    fail "the device pulled out of a root port was never seen to leave"
require_log_line "slot(s) released"
[ "$(grep -a -n -E '\[xhci  \] enumerated port ' "$trimmed" | tail -n 1 | cut -d: -f1)" \
    -gt "$marker_line" ] ||
    fail "no device was enumerated on a root port after the boot's scan"

printf 'x86_64 USB hotplug check passed: a hub and a root port saw their devices come and go\n'
