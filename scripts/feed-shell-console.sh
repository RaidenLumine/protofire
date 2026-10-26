#!/usr/bin/env sh
# File: scripts/feed-shell-console.sh
# Purpose: Type at a guest's console, once the shell is there to read it.
#
# Why this exists
# ---------------
# `-serial file:` can only listen.  A shell reads its commands from the console
# it writes to, and the half of it that a boot never exercises is the half that
# reads: the recovered assembly shell this tree used to ship printed a banner and
# a prompt and then faulted on the first command, and every gate passed, because
# none of them typed.  This is the piece of a check that types.
#
# The feeder writes the guest's console *input* to its stdout, so a check pipes
# it into `qemu ... -serial stdio >log` and reads that log to know when the shell
# is up.  Two things are deliberately not fixed delays:
#
# * When to start typing.  It waits for the shell's own banner, because a
#   keystroke that arrives before the shell is reading is the guest's to drop,
#   and "long enough on this machine" is a timing assumption that becomes a
#   flake on another.
# * When to send the next line.  It appends a uniquely named `echo` after each
#   command and waits for that answer as a whole line.  A fixed pause can put
#   too much input in the console's cooked queue at once, and a prompt is not
#   reliable on an SMP boot where a kernel log can interrupt its three writes.
#   The marker is output the shell itself has finished the preceding command.
# * When to stop.  It holds the console open until the guest stops talking —
#   the check's assertions are all about output that arrives after the shell is
#   up, and on a QEMU that ends the machine at end of input the console closing
#   behind the shell would take that output with it.  "The log stopped growing"
#   needs no per-machine marker to name the last line.
#
# Usage:
#   sh scripts/feed-shell-console.sh <log-file> <timeout-seconds> <line>...
#
# Each <line> is sent with a carriage return and followed by a marker command;
# the feeder waits for that marker's answer before sending the following line.

set -eu

if [ "$#" -lt 3 ]; then
    printf 'usage: %s <log-file> <timeout-seconds> <line>...\n' "$0" >&2
    exit 2
fi

log_file="$1"
timeout_seconds="$2"
shift 2

# Wait until the shell has *run* the marker command.
#
# The marker is a unique name, and it appears in the log twice when everything
# goes well: once as the console echoes the typed line back, and once in the
# line the shell prints when it runs `echo`.  Requiring both is what this used to
# do, and it is why a boot that had done nothing wrong failed about one run in
# three — the echo is the console echoing *typing*, and a prompt printed at the
# same moment can interrupt it, leaving the marker as one occurrence while the
# shell has in fact run the command.
#
# The shell's own output is the one that means the command ran, and it carries
# the prompt's `$ ` immediately before the marker, because the shell prints the
# prompt and then the echo's output.  The console's echo of the typed line has
# the word `echo ` there instead.  So the answer is the marker preceded by the
# prompt's suffix, which is what this waits for.
wait_for_marker() {
    marker="$1"
    # `$` and the space the shell writes after it, then the marker: the shell's
    # own line.
    wanted="\$ $marker"
    # A fifth of a second per poll, not a whole one.  The answer usually arrives
    # within milliseconds of the command being typed, and a boot that types ten
    # commands pays a whole second of slack on each — on a gate whose budget is
    # ninety seconds, that is most of the margin.  `seconds` counts polls in
    # fives so the caller's timeout still means seconds.
    polls=0
    while [ "$(LC_ALL=C grep -a -c -F "$wanted" "$log_file" 2>/dev/null || true)" -lt 1 ]; do
        if [ "$polls" -ge "$((timeout_seconds * 5))" ]; then
            return 1
        fi
        sleep 0.2
        polls=$((polls + 1))
    done
}

waited=0
while [ "$waited" -lt "$timeout_seconds" ]; do
    if grep -F "protofire ring3 shell" "$log_file" >/dev/null 2>&1; then
        break
    fi
    sleep 1
    waited=$((waited + 1))
done

sleep 1
index=0
for line in "$@"; do
    index=$((index + 1))
    marker="__protofire_feeder_sync_${index}__"
    printf '%s\r' "$line"
    printf 'echo %s\r' "$marker"
    if ! wait_for_marker "$marker"; then
        printf 'shell feeder: no marker after: %s\n' "$line" >&2
        exit 1
    fi
done

# Hold the pipe open while the boot finishes, and stop once the guest has been
# quiet for a few seconds — a prompt reprinted by a timed-out read is not
# progress, but the boot still prints after the last answer, so the window is
# wider than the pause between lines above.
quiet=0
last_size=-1
while [ "$quiet" -lt 5 ]; do
    size="$(wc -c <"$log_file" | tr -d ' ')"
    if [ "$size" = "$last_size" ]; then
        quiet=$((quiet + 1))
    else
        quiet=0
    fi
    last_size="$size"
    sleep 1
done
