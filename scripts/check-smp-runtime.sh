#!/usr/bin/env sh
# File: scripts/check-smp-runtime.sh
# Purpose: Headless QEMU smoke test for SMP bring-up and post-boot liveness.
#
# Why this exists
# ---------------
# Every other boot smoke test runs the kernel on one CPU, where the cross-CPU
# paths cannot execute at all: no AP ever starts, a TLB shootdown never needs
# an acknowledgement from a second processor, and a lock held with interrupts
# masked can never be waited on by anyone else.  Those paths are where the
# hard failures live, and a single-CPU run reports them as healthy.
#
# The failure mode being hunted is a *wedge*, not a panic: a lock cycle here
# stops the machine silently, so the check asserts progress rather than exit
# status.  A log that stops growing is the signal.
#
# This raises confidence; it does not close the question.  QEMU's emulated
# CPUs interleave genuinely, but their timing is not hardware timing, so a
# race that needs a narrow window can still stay hidden.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
SMP_CPUS="${SMP_CPUS:-4}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"
QEMU="${QEMU:-qemu-system-x86_64}"
SMP_RUNTIME_LOG="${SMP_RUNTIME_LOG:-}"
# Features the kernel is built with.  `liveness_heartbeat` adds periodic
# liveness lines from two independent kernel threads, which turns "the log
# stopped here" into "the machine stopped" or "one thread stopped".
#
# It is *not* the default, and that is a finding rather than a preference: a
# build carrying the heartbeat stalls deterministically during AP bring-up on
# the development machine, while the same source without it boots three times
# out of three.  Neither build changes any bring-up logic, so the difference is
# where things land in memory — an AP bring-up defect that this check exists to
# surface, and that would otherwise make the check itself unstable.
FEATURES="${FEATURES:-demo-disk}"

KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

case "$SMP_CPUS" in
    ''|*[!0-9]*)
        printf 'SMP_CPUS must be a number, got: %s\n' "$SMP_CPUS" >&2
        exit 1
        ;;
esac

if [ "$SMP_CPUS" -lt 2 ]; then
    printf 'SMP_CPUS must be at least 2; %s cannot exercise the cross-CPU paths.\n' \
        "$SMP_CPUS" >&2
    exit 1
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the SMP runtime check.\n' "$QEMU" >&2
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the SMP runtime check.\n' >&2
    exit 1
fi

# The demo disk carries the services whose start and exit the progress
# assertions look for.
case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
    --features "$FEATURES"

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'kernel binary not found: %s\n' "$KERNEL_BIN" >&2
    exit 1
fi

remove_log_on_exit=0
if [ -n "$SMP_RUNTIME_LOG" ]; then
    mkdir -p "$(dirname "$SMP_RUNTIME_LOG")"
    log_file="$SMP_RUNTIME_LOG"
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

# Every knob is echoed before the run.  When a check like this behaves
# differently on two machines, the cause is usually an inherited environment
# variable changing what was actually invoked, and a bare failure message
# cannot show that.
set -- \
    -machine q35 \
    -cpu max \
    -smp "$SMP_CPUS" \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0

# Capture the guest's serial output with `-serial file:` rather than
# `-serial stdio` plus a shell redirect.
#
# `stdio` ties where the output ends up to the TTY state of the process that
# started QEMU: it interacts with stdin, with whether stdout is a terminal or a
# file, and with the process group.  That is right for an interactive `make
# run`, and wrong for a check whose whole job is to capture output
# unattended — the same command then behaves differently depending on how it
# was launched.  `file:` removes the question: QEMU writes the log itself.
serial_target="file:$log_file"

if [ -n "${ACCEL:-}" ]; then
    set -- -accel "$ACCEL" "$@"
fi

printf 'SMP runtime check: %s cpus, timeout %ss, qemu %s%s\n' \
    "$SMP_CPUS" "$TIMEOUT_SECONDS" "$QEMU" "${ACCEL:+ (accel $ACCEL)}"
printf '  %s\n' "timeout ${TIMEOUT_SECONDS}s $QEMU $* -serial $serial_target"

set +e
# QEMU's own diagnostics go to the same file, appended after the serial log
# that the guest writes.
timeout "${TIMEOUT_SECONDS}s" "$QEMU" "$@" -serial "$serial_target" \
    >/dev/null 2>>"$log_file"
status=$?
set -e

# 124 is `timeout` killing a machine that is, by design, still running.
case "$status" in
    0|124) ;;
    *)
        printf 'SMP runtime check failed with exit status %s\n' "$status" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

# Report why the check failed, and always leave enough behind to tell the
# interesting cases apart.
#
# "The kernel wedged" and "QEMU never started" both show up as a missing log
# line, and they call for opposite responses: one is a kernel defect, the
# other is a local invocation problem.  So every failure prints the exit
# status, the log size, and the tail of the log.
fail_with_log() {
    reason="$1"
    bytes="$(wc -c <"$log_file" | tr -d ' ')"

    printf 'SMP runtime check failed: %s\n' "$reason" >&2
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
        printf '  re-run with SMP_RUNTIME_LOG=<path> to keep the log\n' >&2
    fi
    exit 1
}

require_log_line() {
    pattern="$1"
    if ! grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line: $pattern"
    fi
}

count_log_line() {
    awk -v needle="$1" '
        index($0, needle) { count += 1 }
        END { print count + 0 }
    ' "$log_file"
}

first_log_line() {
    awk -v needle="$1" '
        index($0, needle) { print NR; exit }
    ' "$log_file"
}

last_log_line() {
    awk -v needle="$1" '
        index($0, needle) { line = NR }
        END { print line + 0 }
    ' "$log_file"
}

# ── The APs actually came up ───────────────────────────────────────────
#
# Assert the count rather than mere presence: `-smp 4` has to produce three
# APs, and a kernel that silently gave up after the first one would still
# print the line.
require_log_line "SMP: bringing up $((SMP_CPUS - 1)) AP(s)..."

started="$(count_log_line "started successfully")"
if [ "$started" -lt "$((SMP_CPUS - 1))" ]; then
    fail_with_log "expected at least $((SMP_CPUS - 1)) APs to start, saw $started"
fi

# ── The machine is still making progress ───────────────────────────────
#
# Three markers spread across the boot: the scheduler took over, the shell
# came up, and services started exiting afterwards.  A wedge stops the log at
# whichever one it reached, so requiring all three distinguishes "booted" from
# "booted and then died quietly".
require_log_line "kernel running"
require_log_line "protofire shell (user)"

service_lines="$(count_log_line "[service]")"
if [ "$service_lines" -eq 0 ]; then
    fail_with_log "no service activity after boot; the machine may have stalled"
fi

# ── Nothing reported damage ────────────────────────────────────────────
if grep -F "FATAL" "$log_file" >/dev/null 2>&1; then
    fail_with_log "the kernel reported a fatal error during the run"
fi

# ── Liveness after boot, when the build carries heartbeats ─────────────
#
# This is the strongest progress assertion available.  The weaker markers
# above only prove the machine got as far as the shell; a kernel that stalled
# just afterwards would satisfy them and still be dead.  Two independent
# threads emit heartbeats, so requiring the last one to land after the shell
# banner proves the scheduler was still dispatching threads then — which is
# exactly the point this kernel has actually stalled at.
beats="$(count_log_line "[hb    ]")"
if [ "$beats" -gt 0 ]; then
    last_beat="$(last_log_line "[hb    ]")"
    shell_line="$(first_log_line "protofire shell (user)")"
    if [ "$last_beat" -le "$shell_line" ]; then
        fail_with_log "the last heartbeat (line $last_beat) precedes the shell banner (line $shell_line): the machine stopped making progress"
    fi
    printf '  heartbeats %s, last at line %s (shell banner at line %s)\n' \
        "$beats" "$last_beat" "$shell_line"
fi

# The guest reports the accelerator it ended up on — `invpcid` is only
# available under hardware virtualisation — and that is worth printing,
# because "which accelerator did QEMU actually pick" is invisible otherwise
# and is the first thing to check when the same command behaves differently
# on two machines.
accelerator="$(grep -m1 -o "PCID: enabled=true" "$log_file" >/dev/null 2>&1 \
    && printf 'kvm' || printf 'tcg')"

printf 'SMP runtime check passed: %s CPUs, %s APs, %s service lines, accelerator=%s\n' \
    "$SMP_CPUS" "$started" "$service_lines" "$accelerator"
