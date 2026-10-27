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
# The test is the whole line, not a substring: the console echoes the typed
# command, and the echo contains `serial-done` too, so a substring wait fires
# one beat *before* the shell has printed its answer and the keys can garble
# the command still being read.
#
# Usage:
#   sh scripts/press-usb-keys.sh <log-file> <timeout-seconds> <monitor-socket> <text> <markers>

set -eu

if [ "$#" -ne 5 ]; then
    printf 'usage: %s <log-file> <timeout-seconds> <monitor-socket> <text> <markers>\n' "$0" >&2
    printf '  <markers> is how many feeder markers the serial half types,\n' >&2
    printf '  the last of which is the shell saying the queue is empty\n' >&2
    exit 2
fi

log_file="$1"
timeout_seconds="$2"
monitor="$3"
text="$4"
expected_markers="$5"

waited=0
while [ "$waited" -lt "$timeout_seconds" ]; do
    # The evidence that the serial half is finished: the shell has printed the
    # feeder's markers, one per command, which means the whole queue has been
    # read and answered.
    #
    # The marker appears twice — once in the console's echo of the typed
    # `echo <marker>` line, once in the line the shell prints when it runs it —
    # so counting occurrences would count both.  The answer is the one on a line
    # of its own, which is what this counts: the echo carries `echo ` before the
    # marker and a trailing CR, so it never matches.
    #
    # This used to look for the prompt's `$ ` followed by the marker, because
    # the feeder typed the marker while the previous command was still running
    # and a prompt sat between them.  The feeder now keeps one line in flight,
    # so the answer follows the typed line directly and stands alone — a
    # stronger thing to require, and the same one the checks make of every other
    # answer.
    #
    # Before that it waited for a whole line reading `serial-done`, and that
    # line did not survive contact with a busy console: an exact-line wait could
    # never return, and the injector spent its whole budget on a guest sitting
    # at the prompt the entire time.
    found="$(LC_ALL=C grep -a -c -E '^__protofire_feeder_sync_[0-9]+__$' "$log_file" 2>/dev/null || true)"
    if [ "${found:-0}" -ge "$expected_markers" ]; then
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
