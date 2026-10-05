#!/usr/bin/env sh
# File: scripts/check-perf-baseline.sh
# Purpose: Boot the demo with the profilers on and compare the work that boot
#          did against a recorded baseline.
#
# Why counters, and why a boot
# ----------------------------
# A performance gate that measures seconds measures the machine it ran on,
# which is why none of the tree's gates does.  What is compared here is work:
# frames taken, pages mapped, blocks read, packets answered — numbers from
# `src/kernel/perf_baseline.rs`, printed once at a fixed tick.  The same source
# produces the same numbers, so a drift is a change in what the kernel does,
# and that is the kind of change a micro-optimisation is supposed to make
# deliberately.
#
# The baseline is `scripts/perf-baseline.txt`: one `key value tolerance` row
# per counter.  Tolerance is absolute because that is how the counters drift:
# a boot samples its counters when the maintenance thread wakes, so a few
# seconds of scheduling jitter move the counters that are still moving at the
# sample point (heap, DHCP traffic) and leave the ones that stopped at boot
# (frames, page tables, faults) exactly where they were.  `--record` rewrites
# the values and keeps each row's tolerance, so re-recording after an intended
# change does not silently widen what counts as a regression.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
QEMU="${QEMU:-qemu-system-x86_64}"
BASELINE="${BASELINE:-scripts/perf-baseline.txt}"

# The profilers are the point: a default build has no counters to read.
FEATURES="demo-disk perf_baseline fs_profiler net_profiler alloc_profiler fault_profiler"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac
case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac

mode=check
case "${1:-}" in
    '') ;;
    --record) mode=record ;;
    *)
        printf 'usage: %s [--record]\n' "$0" >&2
        exit 2
        ;;
esac

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot measure the boot.\n' "$QEMU" >&2
    exit 1
fi

"$CARGO" build --offline $profile_flag \
    --target x86_64-unknown-none --bin "$CRATE" --features "$FEATURES"

KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"
log="$(mktemp)"
cleanup() {
    rm -f "$log"
}
trap cleanup EXIT INT TERM

# The boot is left running to its timeout on purpose: the sample is taken from
# a tick, not from an event, and the machine after it is a demo nobody asked to
# stop.
set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 -cpu max -smp 1 -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none -no-reboot -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -serial stdio >"$log" 2>&1
set -e

# The console writes CRLF, and a field the parser never sees is a counter the
# check never compares: strip the carriage returns before splitting, or the
# last field on the line fails its `key=value` test and drops out silently.
line="$(tr -d '\r' <"$log" | grep -o '\[perf  \] boot work:.*' | head -n 1 || true)"
if [ -z "$line" ]; then
    printf 'perf baseline check failed: the boot printed no work summary\n' >&2
    printf '  last lines of the boot:\n' >&2
    tail -n 12 "$log" | tr -d '\000' >&2
    exit 1
fi

pairs="$(printf '%s\n' "$line" | sed 's/^\[perf  \] boot work: //' | tr ' ' '\n' \
    | grep -E '^[a-z0-9-]+=[0-9]+$' || true)"

measured() {
    printf '%s\n' "$pairs" | sed -n "s/^$1=//p" | head -n 1
}

if [ "$mode" = "record" ]; then
    new="$(mktemp)"
    {
        printf '# Boot-work baseline for `make check-perf-baseline`.\n'
        printf '#\n'
        printf '# One row per counter the boot prints: `key baseline tolerance`.\n'
        printf '# Tolerance is absolute: the counters a boot is still moving when it\n'
        printf '# samples (heap, DHCP traffic) drift by scheduling jitter, and the ones\n'
        printf '# that stopped at boot do not drift at all.  Re-record with\n'
        printf '# `sh scripts/check-perf-baseline.sh --record`, which keeps every\n'
        printf '# tolerance that is already written down.\n'
        printf '#\n'

        printf '%s\n' "$pairs" | while IFS='=' read -r key value; do
            [ -n "$key" ] || continue
            tolerance=0
            if [ -f "$BASELINE" ]; then
                row="$(awk -v k="$key" '$1 == k { print $3 }' "$BASELINE" | head -n 1)"
                [ -n "$row" ] && tolerance="$row"
            fi
            printf '%s %s %s\n' "$key" "$value" "$tolerance"
        done
    } > "$new"
    mv "$new" "$BASELINE"
    printf 'recorded %s row(s) in %s\n' \
        "$(printf '%s\n' "$pairs" | grep -c .)" "$BASELINE"
    exit 0
fi

if [ ! -f "$BASELINE" ]; then
    printf 'perf baseline not found: %s (record one with --record)\n' "$BASELINE" >&2
    exit 1
fi

counter=0
drifted=0
while read -r key value tolerance; do
    case "$key" in ''|\#*) continue ;; esac

    # The rows are hand-edited, so a malformed one is reported as a row
    # problem rather than as arithmetic on an empty string.
    case "${value:-}:${tolerance:-}" in
        *[!0-9:]*|:*|*:)
            printf 'perf baseline: malformed row for %s (expected "key value tolerance")\n' \
                "$key" >&2
            drifted=1
            continue
            ;;
    esac

    current="$(measured "$key")"
    if [ -z "$current" ]; then
        printf 'perf baseline check failed: %s is in the baseline and not in the boot\n' \
            "$key" >&2
        drifted=1
        continue
    fi

    delta=$((current - value))
    magnitude=$delta
    [ "$magnitude" -lt 0 ] && magnitude=$((0 - magnitude))
    if [ "$magnitude" -gt "$tolerance" ]; then
        printf 'perf baseline: %s is %s, baseline %s (tolerance %s)\n' \
            "$key" "$current" "$value" "$tolerance" >&2
        drifted=1
    fi
    counter=$((counter + 1))
done < "$BASELINE"

# The other direction: a counter the boot prints and the baseline does not
# record is a counter nothing compares, which is how a baseline silently stops
# covering the boot.  Adding a counter therefore means recording it.
for key in $(printf '%s\n' "$pairs" | sed 's/=.*//'); do
    if ! awk -v k="$key" '$1 == k { found = 1 } END { exit !found }' "$BASELINE"; then
        printf 'perf baseline check failed: the boot prints %s, which the baseline does not record\n' \
            "$key" >&2
        drifted=1
    fi
done

if [ "$drifted" != "0" ]; then
    printf 'perf baseline check failed: the boot did different work than the baseline\n' >&2
    printf '  the measured line was:\n    %s\n' "$line" >&2
    printf '  if the change is intended, record it with:\n' >&2
    printf '    sh scripts/check-perf-baseline.sh --record\n' >&2
    exit 1
fi

printf 'perf baseline check passed: %s counter(s) within their recorded tolerance\n' \
    "$counter"
