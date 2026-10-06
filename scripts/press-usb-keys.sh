#!/usr/bin/env sh
# File: scripts/press-usb-keys.sh
# Purpose: Type at the guest's USB keyboard, through QEMU's monitor.
#
# Why this exists
# ---------------
# A USB keyboard's input does not reach the guest through the console's serial
# line.  It arrives as a HID report over the xHCI driver's interrupt endpoint —
# a different path from `feed-shell-console.sh`, and the only one that
# exercises it.  The keys come from QEMU's own monitor (`sendkey`), so nothing
# in the guest is simulated; the tree already depends on a monitor socket and a
# python3 client for one (see `probe-x8664-demo-stall.sh`, which says the same
# thing about why python3).
#
# The injection waits for the serial half to be *finished* rather than for a
# fixed moment: a shell has one input stream, and keys typed while a serial
# command is being read would garble both.  The marker is a command the check
# types over serial last (`echo serial-done`), so this file waits for that
# command's *output* — the guest's own evidence that it is back at the prompt.
#
# Usage:
#   sh scripts/press-usb-keys.sh <log-file> <timeout-seconds> <monitor-socket> <text>

set -eu

if [ "$#" -ne 4 ]; then
    printf 'usage: %s <log-file> <timeout-seconds> <monitor-socket> <text>\n' "$0" >&2
    exit 2
fi

log_file="$1"
timeout_seconds="$2"
monitor="$3"
text="$4"

waited=0
while [ "$waited" -lt "$timeout_seconds" ]; do
    if grep -F "serial-done" "$log_file" >/dev/null 2>&1; then
        break
    fi
    sleep 1
    waited=$((waited + 1))
done

# One beat for the prompt, then the keys.
sleep 1

python3 - "$monitor" "$text" <<'PY'
import socket
import sys
import time

monitor, text = sys.argv[1], sys.argv[2]

# The names QEMU's monitor gives the keys this needs.
names = {" ": "spc", "-": "minus", ".": "dot", "/": "slash", "_": "shift-minus"}
keys = [names.get(ch, ch) for ch in text]

sock = socket.socket(socket.AF_UNIX)
for _ in range(100):
    try:
        sock.connect(monitor)
        break
    except OSError:
        time.sleep(0.1)
else:
    print("press-usb-keys: the monitor socket never appeared", file=sys.stderr)
    sys.exit(1)

for key in keys:
    sock.sendall(("sendkey %s 50\n" % key).encode())
    time.sleep(0.05)
sock.sendall(b"sendkey ret 50\n")
time.sleep(0.2)
PY
