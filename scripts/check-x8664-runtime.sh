#!/usr/bin/env sh
# File: scripts/check-x8664-runtime.sh
# Purpose: Headless single-CPU QEMU smoke test for the x86_64 demo boot.
#
# Why this exists
# ---------------
# The SMP check next to this one exists to reach the cross-CPU paths, and it
# cannot see a defect that takes one processor down at a time: with four CPUs,
# the other three keep scheduling when one stops, so a boot that is dead on a
# single processor still prints user output under the SMP check.  The
# single-CPU boot is where such a wedge is total, and it is the configuration
# `make run` gives a developer.
#
# The failure this guards against is the kernel handing a processor to a
# process address space that does not map the kernel stack that processor is
# standing on.  Every line of the boot's first half is printed before that
# hand-off, so the shell banner and the service lines are all there and the log
# then simply stops: no user program reached user mode, none printed, none
# exited.  What the user programs say about themselves is therefore the only
# part of the boot that proves the ring-3 path ran, and it is what this check
# asserts.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
QEMU="${QEMU:-qemu-system-x86_64}"
X8664_RUNTIME_LOG="${X8664_RUNTIME_LOG:-}"
# Features the kernel is built with: the demo disk carries the shell, the
# launcher programs and the services whose output is asserted below.
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
    printf '%s is not installed; cannot run the x86_64 runtime check.\n' "$QEMU" >&2
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the x86_64 runtime check.\n' >&2
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

remove_log_on_exit=0
if [ -n "$X8664_RUNTIME_LOG" ]; then
    mkdir -p "$(dirname "$X8664_RUNTIME_LOG")"
    log_file="$X8664_RUNTIME_LOG"
    : >"$log_file"
else
    log_file="$(mktemp)"
    remove_log_on_exit=1
fi

cleanup() {
    if [ "$remove_log_on_exit" = "1" ]; then
        rm -f "$log_file"
    fi
}
trap cleanup EXIT INT TERM

# Capture the guest's serial output with `-serial file:` rather than stdio
# plus a shell redirect, so the check behaves the same however it was
# launched; see the SMP check for the same reasoning.
set -- \
    -machine q35 \
    -cpu max \
    -smp 1 \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0

printf 'x86_64 runtime check: 1 cpu, timeout %ss, qemu %s\n' \
    "$TIMEOUT_SECONDS" "$QEMU"
printf '  %s\n' "timeout ${TIMEOUT_SECONDS}s $QEMU $* -serial file:$log_file"

set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU" "$@" -serial "file:$log_file" \
    >/dev/null 2>>"$log_file"
status=$?
set -e

# 124 is `timeout` killing a machine that is, by design, still running.
case "$status" in
    0|124) ;;
    *)
        printf 'x86_64 runtime check failed with exit status %s\n' "$status" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

fail_with_log() {
    reason="$1"
    bytes="$(wc -c <"$log_file" | tr -d ' ')"

    printf 'x86_64 runtime check failed: %s\n' "$reason" >&2
    printf '  qemu exit status: %s\n' "$status" >&2
    printf '  serial log: %s bytes\n' "$bytes" >&2

    if [ "$bytes" -eq 0 ]; then
        printf '  the guest produced no serial output at all: this is a local\n' >&2
        printf '  invocation problem, not a kernel hang\n' >&2
    else
        printf '  last lines of the log:\n' >&2
        tail -n 12 "$log_file" >&2
    fi

    if [ "$remove_log_on_exit" = "0" ]; then
        printf '  full log preserved at: %s\n' "$log_file" >&2
    else
        printf '  re-run with X8664_RUNTIME_LOG=<path> to keep the log\n' >&2
    fi
    exit 1
}

require_log_line() {
    pattern="$1"
    if ! grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line: $pattern"
    fi
}

require_log_absent_line() {
    pattern="$1"
    if grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "unexpected log line: $pattern"
    fi
}

count_log_line() {
    awk -v needle="$1" '
        index($0, needle) { count += 1 }
        END { print count + 0 }
    ' "$log_file"
}

# ── The boot reached the hand-off point ────────────────────────────────
#
# These are the markers a wedge *does* leave behind: the machine gets this
# far and then stops.  They are asserted so that a failure below says "the
# boot stopped after the hand-off" rather than "the boot never started".
require_log_line "[mem   ] activated x86_64 kernel page tables"
require_log_line "[init  ] starting idle process"
require_log_line "protofire kernel running"
require_log_line "protofire shell (user)"

# ── The user programs ran to the end ───────────────────────────────────
#
# Each of these is printed by a program in ring 3 or about one: the labelled
# launchers, the Rust payload, both demo workers finishing, and the service
# supervisor giving up on the fault launcher after its restart budget — the
# last line the demo prints.  None of them appears if the machine stops at the
# hand-off, which is what makes them the assertion that this boot ran.
require_log_line "[user  ] app-id: demo-launcher-fault"
require_log_line "[user  ] rust app-id: demo-launcher-rust-io"
require_log_line "[demo  ] worker-a done"
require_log_line "[demo  ] worker-b done"
require_log_line "[service] abandoning demo-launcher-fault after its restart budget"

# The launcher programs exit through the process-exit path, and their exit is
# announced by the kernel.  A count rather than one exact line: the log is a
# preemptively scheduled interleaving, so which exit prints on which line is
# not fixed, but how many programs leave ring 3 is.
user_exits="$(count_log_line "[user  ] exit pid=")"
if [ "$user_exits" -lt 5 ]; then
    fail_with_log "expected at least 5 user programs to exit, saw $user_exits"
fi

# ── Nothing reported damage ────────────────────────────────────────────
if grep -F "FATAL" "$log_file" >/dev/null 2>&1; then
    fail_with_log "the kernel reported a fatal error during the run"
fi

# ── The kernel stack's guard is real ───────────────────────────────────
#
# A kernel stack lives in the architecture's own window, its guard is a slice
# of that window nothing ever allocates, and the kernel's tables cover what the
# mapping facts say they cover.  A guard the kernel had to report missing, or a
# kernel range the facts describe but the tables do not map, is a real defect —
# and one that would otherwise first show up as an overflow that corrupts
# memory instead of faulting.
for pattern in \
    "[thread] kernel stack guard pages are not enforced" \
    "[mm    ] kernel table gap"; do
    require_log_absent_line "$pattern"
done

service_lines="$(count_log_line "[service]")"

if [ "$remove_log_on_exit" = "0" ]; then
    printf 'x86_64 runtime log saved to %s\n' "$log_file"
fi

printf 'x86_64 runtime check passed: %s user exits, %s service lines\n' \
    "$user_exits" "$service_lines"
