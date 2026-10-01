#!/usr/bin/env sh
# File: scripts/check-riscv64-churn.sh
# Purpose: Boot riscv64 with the stack-window churn and check its arithmetic.
#
# The riscv64 counterpart of `check-x8664-churn.sh`, for the same reason: the
# stack window and the invalidations it posts both have fallbacks that an
# ordinary boot never reaches.  Ask for more stacks than the window can hold
# and more invalidations than the log can hold, then check the numbers that
# come back.
#
# Two of the assertions are riscv64's own.  Its window is new, so "the window
# served the stacks" is a claim that had no evidence before this check existed;
# and its edits *post* (sfence.vma is hart-local), so the stack window's
# retirement only completes once every CPU has walked the log — which is what
# the reuse count at the end proves.
#
# Like the x86_64 check, this deliberately does not assert that the demo
# finishes: a longer init can expose the pre-existing supervision wedge
# described in `src/kernel/vm_churn.rs`, and the churn-free runtime check is
# the one that asserts the demo runs to its end.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-90}"
QEMU="${QEMU:-qemu-system-riscv64}"
CHURN_RUNTIME_LOG="${CHURN_RUNTIME_LOG:-}"
FEATURES="${FEATURES:-demo-disk stack_churn}"

KERNEL_BIN="${TARGET_DIR}/riscv64gc-unknown-none-elf/${PROFILE}/${CRATE}"

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
"$CARGO" build --offline $profile_flag --target riscv64gc-unknown-none-elf --bin "$CRATE" \
    --features "$FEATURES"

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'riscv64 kernel binary not found: %s\n' "$KERNEL_BIN" >&2
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
    -machine virt \
    -global virtio-mmio.force-legacy=false \
    -cpu rv64 \
    -smp 1 \
    -m 2G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-device,netdev=net0

printf 'riscv64 churn check: 1 cpu, timeout %ss, qemu %s\n' \
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
    printf 'riscv64 churn check failed: %s\n' "$reason" >&2
    printf '  last lines of the log:\n' >&2
    tail -n 12 "$log_file" | tr -d '\000' >&2
    if [ "$remove_log_on_exit" = "0" ]; then
        printf '  full log preserved at: %s\n' "$log_file" >&2
    else
        printf '  re-run with CHURN_RUNTIME_LOG=<path> to keep the log\n' >&2
    fi
    exit 1
}

require_log_line() {
    pattern="$1"
    if ! grep -a -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line: $pattern"
    fi
}

# The boot got far enough for the churn to have run, and the machine is not
# reporting damage.
require_log_line "[init  ] starting idle process"
# The ring-3 shell's own banner; see the note in `check-x8664-runtime.sh`.  The
# in-kernel host proxy it replaced printed `protofire shell (user)`, and this
# check listens one-way, so the banner is what says the shell — not the proxy —
# got that far.
require_log_line "adastra ring3 shell"
if grep -a -F "FATAL" "$log_file" >/dev/null 2>&1; then
    fail_with_log "the kernel reported a fatal error during the churn"
fi

# ── The window was asked for more than it had ──────────────────────────
#
# `window-backed` is the count of stacks the window served: zero, or a handful,
# would mean riscv64 is still taking the frame-backed shape for everything and
# its guards are still not enforced.  `fallbacks` is the count that could not
# come from the window, which is the code that decides to fall back.
stacks_line="$(grep -a -F "[churn ] kernel stacks: " "$log_file" | head -1 || true)"
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
    fail_with_log "the window served only $window_backed stacks; riscv64's window is not in use"
fi
if [ "$fallbacks" -eq 0 ]; then
    fail_with_log "no stack fell back; the window was never exhausted"
fi

# The fallback is the shape whose guard cannot be enforced on this
# architecture, and the kernel says so — once.  A boot where the fallback runs
# and the report does not appear would mean the report is not telling the
# truth, which matters more than the fallback itself.
require_log_line "[thread] kernel stack guard pages are not enforced"

# ── The retirements came back ──────────────────────────────────────────
#
# An edit here posts (`sfence.vma` is hart-local), so an address the window
# retired is handed out again only once every CPU has walked the log — the
# grace.  The churn walks it and then asks for one more stack, and the window
# announces the first slice that comes back.  Without that line the retirement
# never completed: the window would still work, but it would only ever grow,
# and every stack the machine ever made would cost address space for good.
require_log_line "[thread] kernel stack window: a retired slice is in use again"

# ── The log was asked for more than it could hold ──────────────────────
#
# A request that does not fit asks for a full flush instead; zero would mean
# the burst never filled the log, and the path would go untested.
invalidations_line="$(grep -a -F "[churn ] invalidations: " "$log_file" | head -1 || true)"
[ -n "$invalidations_line" ] || fail_with_log "missing log line: [churn ] invalidations:"
full_flushes="$(printf '%s\n' "$invalidations_line" | sed -n 's/.*full-flushes=\([0-9]*\).*/\1/p')"
case "$full_flushes" in
    ''|*[!0-9]*) fail_with_log "unreadable invalidation counts: $invalidations_line" ;;
esac
if [ "$full_flushes" -eq 0 ]; then
    fail_with_log "no request was promoted; the log was never filled"
fi

if [ "$remove_log_on_exit" = "0" ]; then
    printf 'riscv64 churn runtime log saved to %s\n' "$log_file"
fi

printf 'riscv64 churn check passed: window-backed=%s fallbacks=%s held=%s full-flushes=%s\n' \
    "$window_backed" "$fallbacks" "$held" "$full_flushes"
