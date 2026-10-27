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
# * When to start typing.  It waits for the shell's own banner and then for its
#   first prompt, because a keystroke that arrives before the shell is reading
#   is the guest's to drop, and "long enough on this machine" is a timing
#   assumption that becomes a flake on another.
# * When to send the next line.  One line is in flight at a time: after each it
#   waits for the shell to have *finished* it, and a new prompt is what says so.
#   The console echoes each typed character with a write of its own, so a
#   second line typed while the first is still running puts its echo in the
#   path of the first line's answer, and the answer stops being a line of its
#   own — measured on `make check-x8664-init-no-start`, 2 of 12 boots read
#   `echo __protofire_feeder_sync_ring3-shell-answered`, with every byte of the
#   answer present and the check that wants it on a line red.
# * When to stop.  It holds the console open until the guest stops talking —
#   the check's assertions are all about output that arrives after the shell is
#   up, and on a QEMU that ends the machine at end of input the console closing
#   behind the shell would take that output with it.  "The log stopped growing"
#   needs no per-machine marker to name the last line.
#
# Usage:
#   sh scripts/feed-shell-console.sh <log-file> <timeout-seconds> <line>...
#
# Each <line> is typed and waited for; then a marker command is typed and waited
# for.  Its answer is a line of its own, which is what `scripts/press-usb-keys.sh`
# counts to know the serial half is finished.

set -eu

if [ "$#" -lt 3 ]; then
    printf 'usage: %s <log-file> <timeout-seconds> <line>...\n' "$0" >&2
    exit 2
fi

log_file="$1"
timeout_seconds="$2"
shift 2

# A fifth of a second per poll, not a whole one.  An answer usually arrives
# within milliseconds of the command being typed, and a boot that types ten
# commands pays a whole second of slack on each — on a gate whose budget is
# ninety seconds, that is most of the margin.  `seconds` counts polls in fives
# so the caller's timeout still means seconds.
POLLS_PER_SECOND=5

# How many times a fixed string appears in the log, counting occurrences rather
# than lines.
#
# The console echoes every typed *character* as its own write, so two of the
# shell's own lines can share a line of the log.  A count of matching *lines*
# would then miss one; `grep -o` splits each match out first, which is what
# makes this a count of occurrences.
count_occurrences() {
    LC_ALL=C grep -a -o -F "$1" "$log_file" 2>/dev/null | wc -l | tr -d ' '
}

# Wait until the log holds at least `wanted` copies of `string`, or give up.
wait_for_occurrences() {
    string="$1"
    wanted="$2"
    polls=0
    while [ "$(count_occurrences "$string")" -lt "$wanted" ]; do
        if [ "$polls" -ge "$((timeout_seconds * POLLS_PER_SECOND))" ]; then
            return 1
        fi
        sleep 0.2
        polls=$((polls + 1))
    done
}

# Wait for the shell to print one more prompt than it had at `before`.
#
# The prompt is the one signal here that survives this console.  The shell
# prints `protofire:<cwd>$ ` at the top of its loop — after a command's output
# and before it reads again — so a *new* prompt is the shell saying it consumed
# and finished the line before it.  Waiting for it is what keeps one line in
# flight.
#
# It is counted by occurrences for the two reasons the log explains elsewhere:
# the prompt is three writes, so another thread's line can land between them and
# put two prompts on one line of the log; and the `protofire:` prefix is one
# write, so it is never split *within* itself.  Anchoring on the typed line's
# echo instead would not survive — that echo is one write per character, and a
# service's line can land in the middle of the word.
wait_for_prompt() {
    before="$1"
    wait_for_occurrences 'protofire:' "$((before + 1))"
}

waited=0
while [ "$waited" -lt "$timeout_seconds" ]; do
    if grep -F "protofire ring3 shell" "$log_file" >/dev/null 2>&1; then
        break
    fi
    sleep 1
    waited=$((waited + 1))
done

# The banner is printed before the loop, so the prompt that follows it is the
# one the first command is typed at.  Without waiting for it the first command
# could be typed before the shell ever prompted, and then the next prompt would
# not be evidence that the command ran.
prompts="$(count_occurrences 'protofire:')"
if [ "$prompts" -lt 1 ] && ! wait_for_prompt 0; then
    printf 'shell feeder: the shell never prompted\n' >&2
    exit 1
fi
prompts="$(count_occurrences 'protofire:')"

index=0
for line in "$@"; do
    index=$((index + 1))
    marker="__protofire_feeder_sync_${index}__"

    printf '%s\r' "$line"
    if ! wait_for_prompt "$prompts"; then
        printf 'shell feeder: the shell did not finish: %s\n' "$line" >&2
        exit 1
    fi
    prompts="$(count_occurrences 'protofire:')"

    printf 'echo %s\r' "$marker"
    if ! wait_for_prompt "$prompts"; then
        printf 'shell feeder: the shell did not answer: %s\n' "$marker" >&2
        exit 1
    fi
    prompts="$(count_occurrences 'protofire:')"
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
