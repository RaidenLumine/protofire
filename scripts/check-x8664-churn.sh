#!/usr/bin/env sh
# File: scripts/check-x8664-churn.sh
# Purpose: Boot the kernel with the stack-window churn and check its arithmetic.
#
# The window and the posted-invalidation log both have a fallback that an
# ordinary boot never reaches: the window runs out and stacks come from frames
# at their own addresses, and the log fills and a request asks for a full
# flush.  A fallback nobody reaches is a fallback nobody has tested, so this
# boot asks for more than either can hold and checks the counts that come back:
# how many stacks the window served, how many fell back, and that a full flush
# really was asked for.
#
# It deliberately does *not* assert that the demo finishes.  A longer init
# exposes a pre-existing supervision wedge that has nothing to do with either
# structure — see `src/kernel/vm_churn.rs` — and the churn-free runtime check
# is the one that asserts the demo runs to its end.  What is asserted here is
# the churn's own arithmetic plus the boot getting as far as the shell, all of
# which happen before that wedge can appear.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"
QEMU="${QEMU:-qemu-system-x86_64}"
CHURN_RUNTIME_LOG="${CHURN_RUNTIME_LOG:-}"
# The demo disk carries the boot this runs inside; the churn rides on top of it.
FEATURES="${FEATURES:-demo-disk stack_churn}"

KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the churn check.\n' "$QEMU" >&2
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the churn check.\n' >&2
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
if [ -n "$CHURN_RUNTIME_LOG" ]; then
    mkdir -p "$(dirname "$CHURN_RUNTIME_LOG")"
    log_file="$CHURN_RUNTIME_LOG"
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

printf 'x86_64 churn check: 1 cpu, timeout %ss, qemu %s\n' \
    "$TIMEOUT_SECONDS" "$QEMU"
printf '  %s\n' "timeout ${TIMEOUT_SECONDS}s $QEMU $* -serial file:$log_file"

set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU" "$@" -serial "file:$log_file" \
    >/dev/null 2>>"$log_file"
status=$?
set -e

case "$status" in
    0|124) ;;
    *)
        printf 'churn check failed with exit status %s\n' "$status" >&2
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

fail_with_log() {
    reason="$1"
    printf 'x86_64 churn check failed: %s\n' "$reason" >&2
    printf '  last lines of the log:\n' >&2
    tail -n 12 "$log_file" >&2
    if [ "$remove_log_on_exit" = "0" ]; then
        printf '  full log preserved at: %s\n' "$log_file" >&2
    else
        printf '  re-run with CHURN_RUNTIME_LOG=<path> to keep the log\n' >&2
    fi
    exit 1
}

require_log_line() {
    pattern="$1"
    if ! grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line: $pattern"
    fi
}

# The boot got far enough for the churn to have run, and the machine is not
# reporting damage.
require_log_line "[init  ] starting idle process"
require_log_line "protofire shell (user)"
if grep -F "FATAL" "$log_file" >/dev/null 2>&1; then
    fail_with_log "the kernel reported a fatal error during the churn"
fi

# ── The window was asked for more than it had ──────────────────────────
#
# `fallbacks` is the count of stacks that could not come from the window.  It
# is the whole point of the feature: zero would mean the churn never reached
# the code that decides to fall back.
stacks_line="$(grep -F "[churn ] kernel stacks: " "$log_file" | head -1 || true)"
[ -n "$stacks_line" ] || fail_with_log "missing log line: [churn ] kernel stacks:"
window_backed="$(printf '%s\n' "$stacks_line" | sed -n 's/.*window-backed=\([0-9]*\).*/\1/p')"
fallbacks="$(printf '%s\n' "$stacks_line" | sed -n 's/.*fallbacks=\([0-9]*\).*/\1/p')"
held="$(printf '%s\n' "$stacks_line" | sed -n 's/.*held=\([0-9]*\).*/\1/p')"
for value in "$window_backed" "$fallbacks" "$held"; do
    case "$value" in
        ''|*[!0-9]*) fail_with_log "unreadable churn counts: $stacks_line" ;;
    esac
done
if [ "$window_backed" -lt 1000 ]; then
    fail_with_log "the window served only $window_backed stacks; the churn did not fill it"
fi
if [ "$fallbacks" -eq 0 ]; then
    fail_with_log "no stack fell back; the window was never exhausted"
fi

# ── The log was asked for more than it could hold ──────────────────────
#
# A request that does not fit asks for a full flush instead; zero would mean
# the burst never filled the log, and the path would go untested.
invalidations_line="$(grep -F "[churn ] invalidations: " "$log_file" | head -1 || true)"
[ -n "$invalidations_line" ] || fail_with_log "missing log line: [churn ] invalidations:"
full_flushes="$(printf '%s\n' "$invalidations_line" | sed -n 's/.*full-flushes=\([0-9]*\).*/\1/p')"
case "$full_flushes" in
    ''|*[!0-9]*) fail_with_log "unreadable invalidation counts: $invalidations_line" ;;
esac
if [ "$full_flushes" -eq 0 ]; then
    fail_with_log "no request was promoted; the log was never filled"
fi

if [ "$remove_log_on_exit" = "0" ]; then
    printf 'x86_64 churn runtime log saved to %s\n' "$log_file"
fi

printf 'x86_64 churn check passed: window-backed=%s fallbacks=%s held=%s full-flushes=%s\n' \
    "$window_backed" "$fallbacks" "$held" "$full_flushes"
