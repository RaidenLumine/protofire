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
    # feeder's marker on its own line for the *last* command, which means the
    # whole queue has been read and answered.
    #
    # This used to look for a whole line reading `serial-done` — the output of
    # the last command the check types.  That line does not survive contact with
    # a busy console: the feeder appends an `echo` of its marker after every
    # command, so the last two lines are typed back to back, and a prompt
    # printed between them puts the second command's characters into the first
    # one's output.  Measured on a real boot, one line carried the word
    # serial-done with two other lines' bytes through it — so an exact-line wait
    # could never return, and the injector spent its whole budget on a guest
    # that was sitting at the prompt the entire time.
    #
    # A marker line, by contrast, is printed by the shell *after* it has run the
    # command, and the feeder waits for that before typing the next one — so
    # seeing the last one means the queue is empty.
    #
    # The dollar sign and the space after it, then the marker: the shell's own
    # line, which the console's echo of the typed command does not produce.
    wanted_marker='$ __protofire_feeder_sync_'
    found="$(LC_ALL=C grep -a -c -F "$wanted_marker" "$log_file" 2>/dev/null || true)"
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
