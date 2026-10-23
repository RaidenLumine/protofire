#!/usr/bin/env sh
# File: scripts/check-x8664-low-memory.sh
# Purpose: Boot x86_64 on a machine with very little RAM and check it comes up.
#
# Why this exists
# ---------------
# Every other x86_64 boot here runs with a gigabyte or more, so nothing
# notices when the kernel's demand for RAM grows: the image, the frame pool
# and the heap all have headroom, and a change that needs a few more megabytes
# still boots.  The number that matters to a person with a small machine is the
# *minimum*, and it was measured rather than stated — a release build boots
# from about 72 MiB and a debug build from about 74 MiB (the debug image alone
# is ~72 MiB), where the floor is set by the fixed 64 MiB kernel heap
# (`KERNEL_HEAP_SIZE`, `src/memory/heap/tlsf.rs`) and the image, not by any
# hardware threshold.
#
# This check boots at `LOW_MIB` — well under the gigabyte the other gates use,
# with margin over that floor so it is a capability and not a knife edge — and
# asserts two things that only a small machine shows.  The boot must report the
# machine's own small number, and the pool must be *clamped* to the machine's
# RAM (`the machine has N MiB of the pool's span`), which is the frame
# allocator sizing itself from the machine's answer rather than its 512 MiB
# span ([RFC 0019](../docs/rfcs/0019-what-a-frame-is.md)).  And the ring-3
# shell must be reached, which is the same end-to-end evidence the other
# runtime gates rest on.
#
# A machine so small the image does not fit is a different branch and is not
# asserted here: it is the boot's own diagnostic ("the kernel's image ... is in
# no region the machine describes"), and it is the version of this that would
# be worth gating on a machine whose RAM ends inside the image.
#
# Usage:
#   sh scripts/check-x8664-low-memory.sh [timeout-seconds]

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
QEMU="${QEMU:-qemu-system-x86_64}"
# The RAM this boots with, in MiB.  Chosen above the measured floor (~72 MiB
# release, ~74 MiB debug) so the check is a capability rather than the floor
# itself, and far below the gigabyte the other gates use so a regression that
# inflates the kernel's demand is what fails it.
LOW_MIB="${LOW_MIB:-96}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-90}"
FEATURES="${FEATURES:-demo-disk}"
KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

fail() {
    echo "x86_64 low-memory check failed: $1" >&2
    exit 1
}

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the low-memory check.\n' "$QEMU" >&2
    exit 1
fi
if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the low-memory check.\n' >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
    --features "$FEATURES"
[ -f "$KERNEL_BIN" ] || fail "x86_64 kernel binary not found: $KERNEL_BIN"

log_file="$(mktemp)"
trap 'rm -f "$log_file"' EXIT INT TERM

printf 'x86_64 low-memory check: %s MiB, timeout %ss, qemu %s\n' \
    "$LOW_MIB" "$TIMEOUT_SECONDS" "$QEMU"

set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 \
    -cpu max \
    -smp 1 \
    -m "${LOW_MIB}M" \
    -kernel "$KERNEL_BIN" \
    -display none \
    -serial "file:$log_file" \
    -no-reboot \
    -no-shutdown >/dev/null 2>>"$log_file"
status=$?
set -e
case "$status" in
    0|124) ;;
    *)
        cat "$log_file" >&2
        fail "the boot exited with status $status"
        ;;
esac

if grep -a -F "[FATAL" "$log_file" >/dev/null 2>&1; then
    cat "$log_file" >&2
    fail "the ${LOW_MIB} MiB machine hit a fatal error"
fi

# The machine's own number (QEMU reports a little under `LOW_MIB`, so the
# number itself is not asserted), and the pool clamped to it: the frame
# allocator sized from the machine's answer rather than its 512 MiB span.  A
# boot that kept the full span here would be one that had not read the map.
grep -a -E "machine reports [0-9]+ MiB in" "$log_file" >/dev/null 2>&1 ||
    fail "the boot did not report the machine's own RAM (see the log above)"
grep -a -E "the machine has [0-9]+ MiB of the pool's span" "$log_file" >/dev/null 2>&1 ||
    fail "the pool was not clamped to the machine's RAM"

if ! grep -a -F "protofire ring3 shell" "$log_file" >/dev/null 2>&1; then
    cat "$log_file" >&2
    fail "the ${LOW_MIB} MiB machine did not reach the ring-3 shell"
fi

printf 'x86_64 low-memory check passed: a %s MiB machine reported its own RAM, clamped the pool to it, and reached the ring-3 shell\n' \
    "$LOW_MIB"
