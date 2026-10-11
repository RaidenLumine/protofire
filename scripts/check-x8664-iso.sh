#!/usr/bin/env sh
# File: scripts/check-x8664-iso.sh
# Purpose: Boot the x86_64 kernel from a GRUB ISO — the hand-off a real machine
#   gives — and require that the loader's own memory map is read.
#
# Why this exists
# ---------------
# Every other boot in this tree goes through QEMU's `-kernel` hand-off: a PVH
# entry on x86_64, an `Image` with a device tree on aarch64.  A real machine
# comes up through a *bootloader*, and the first time this tree asked one to
# carry its kernel the answer was `error: ELF files with relocs are not
# supported yet.` — the kernel is linked with `--emit-relocs` because the KASLR
# table is generated from them, and GRUB's multiboot2 loader refuses an ELF
# that still carries relocations.  Nothing but a real loader could have said
# that, which is what the ISO exists for
# ([RFC 0019](../../docs/rfcs/0019-what-a-frame-is.md)).
#
# It is also the only boot that has a Multiboot2 memory map: PVH carries none,
# so `machine reports … in N region(s)` — and the placement check that reads it
# — were a unit test until this gate.
#
# What it asserts:
#   * the loader handed control over the Multiboot2 protocol (`protocol=multiboot2`),
#     so what ran is the loader path and not QEMU's;
#   * the machine's memory map was found (`machine reports … region(s)`), which
#     is the line PVH boots answer instead with "described no memory map";
#   * the kernel's own image is inside a region the map calls usable;
#   * the boot reached the shell and loaded a program out of `/apps`.
#
# Usage:
#   sh scripts/check-x8664-iso.sh
#
# Exits 0 when all four hold, 1 otherwise (with the log's tail on stderr).

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CARGO="${CARGO:-cargo}"
QEMU="${QEMU:-qemu-system-x86_64}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-90}"
X8664_ISO_LOG="${X8664_ISO_LOG:-}"
ISO="${ISO:-target/protofire.iso}"

for tool in grub-mkrescue xorriso; do
    command -v "$tool" >/dev/null 2>&1 ||
        {
            printf '%s is not installed (the GRUB tools); this check cannot build an image without it\n' "$tool" >&2
            exit 1
        }
done

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the ISO check.\n' "$QEMU" >&2
    exit 1
fi

# The image the check boots is the one the Makefile target builds, so the
# target under test is the one that runs.
CARGO="$CARGO" PROFILE="$PROFILE" ISO="$ISO" make iso >/dev/null

work="$(mktemp -d)"
log="$work/boot.log"
if [ -n "$X8664_ISO_LOG" ]; then
    mkdir -p "$(dirname "$X8664_ISO_LOG")"
    log="$X8664_ISO_LOG"
fi
: >"$log"

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

printf 'x86_64 ISO check: 1 cpu, timeout %ss, qemu %s\n' "$TIMEOUT_SECONDS" "$QEMU"

set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 \
    -cpu max \
    -smp 1 \
    -m 1G \
    -cdrom "$ISO" \
    -boot d \
    -display none \
    -no-reboot \
    -no-shutdown \
    -serial "file:$log" >/dev/null 2>&1
status=$?
set -e

# 124 is `timeout` killing a machine that is, by design, still running.
case "$status" in
    0|124) ;;
    *)
        printf 'x86_64 ISO check failed with exit status %s\n' "$status" >&2
        printf '  full log preserved at: %s\n' "$log" >&2
        exit "$status"
        ;;
esac

require_log_line() {
    pattern="$1"
    if ! grep -F "$pattern" "$log" >/dev/null 2>&1; then
        printf 'x86_64 ISO check failed: missing log line: %s\n' "$pattern" >&2
        printf '  full log preserved at: %s\n' "$log" >&2
        tail -n 12 "$log" >&2
        exit 1
    fi
}

require_log_absent_line() {
    pattern="$1"
    if grep -F "$pattern" "$log" >/dev/null 2>&1; then
        printf 'x86_64 ISO check failed: unexpected log line: %s\n' "$pattern" >&2
        grep -F "$pattern" "$log" >&2
        exit 1
    fi
}

# The loader's hand-off, and the fact that it spoke the protocol this tree
# writes a header for.
require_log_line "[boot:loader] arch=x86_64 protocol=multiboot2"

# The map a real loader gives — which QEMU's own hand-off does not — and the
# check that reads it.
require_log_line "[mem   ] machine reports "
require_log_line " region(s); the kernel's pool is "
require_log_line "is in usable RAM"
require_log_absent_line "the machine described no memory map"
require_log_absent_line "FATAL"

# And it is a working machine: the shell came up and a program was loaded out
# of the volume.
require_log_line "[user  ] loaded /apps/packages/shell/bin/shell.elf"

printf 'x86_64 ISO check passed: GRUB handed over on Multiboot2, the loader'"'"'s map\n'
printf '  was read, the kernel'"'"'s image is in usable RAM, and the shell loaded\n'
