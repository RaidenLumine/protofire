#!/usr/bin/env sh
# File: scripts/check-perf-baseline-disk.sh
# Purpose: Run the boot-work gate with a disk attached, so the storage workload
#          it measures has its volumes on a device rather than in memory.
#
# Why this exists
# ---------------
# The boot-work baseline measures a defined workload (src/kernel/workload.rs)
# and the boot around it.  Every volume in that boot comes from a
# `MemoryBlockDevice`, which is what makes its counters deterministic — and
# also what makes them a test of the filesystem, the cache and the commit
# protocol rather than of a disk.
#
# The same workload runs here against an NVMe namespace: the demo disk image is
# the boot disk, so the zones the workload writes to — `/data` above all — are
# the device, and the counters that come back are the work of the same
# filesystem over a driver, a controller and a queue.  What it does not measure
# is a *real* disk's latency: QEMU's NVMe is a device model, and the duration
# the boot prints is host-relative either way.  That is why this compares
# counters and leaves the duration where the counters' boot leaves it.
#
# Usage:
#   sh scripts/check-perf-baseline-disk.sh
#   sh scripts/check-perf-baseline-disk.sh --record

set -eu

cd "$(dirname "$0")/.."

CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
SMP_CPUS="${SMP_CPUS:-1}"
BASELINE="${BASELINE:-scripts/perf-baseline-disk.txt}"

mode="${1:-}"
case "$mode" in
    ''|--record) ;;
    *)
        printf 'usage: %s [--record]\n' "$0" >&2
        exit 2
        ;;
esac

# The same image the demo boots, attached as the only disk: the boot then
# mounts its zones from the namespace rather than from memory, which is the
# whole difference this gate is about.
#
# It is written under `target/` rather than into a temporary directory because
# its path is part of the shape the baseline records: a per-run path would make
# every recording describe a machine no later run has.
mkdir -p "$TARGET_DIR"
image="$TARGET_DIR/perf-baseline-disk.img"
"$CARGO" run --offline --quiet -- mkimage "$image"

QEMU_ARGS="-drive file=$image,if=none,id=nvme0,format=raw -device nvme,drive=nvme0,serial=protofire"
export QEMU_ARGS
export SMP_CPUS
export BASELINE
export TARGET_LABEL=check-perf-baseline-disk

if [ "$mode" = "--record" ]; then
    sh scripts/check-perf-baseline.sh --record
else
    sh scripts/check-perf-baseline.sh
fi
