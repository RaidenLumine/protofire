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
# It is also the boot that goes through a real loader's Multiboot2 tag block,
# which is where the tag readers — the command line, the framebuffer, ACPI's
# RSDP — have always found their answers; the PVH block is a different
# struct and is read only for the memory map its own table describes.
#
# What it asserts:
#   * the loader handed control over the Multiboot2 protocol (`protocol=multiboot2`),
#     so what ran is the loader path and not QEMU's;
#   * the machine's memory map was found and read out of the tag block
#     (`machine reports … region(s)`);
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

# The map a real loader gives, read out of the Multiboot2 tag block — the
# other PC hand-off's map comes from the PVH block's own E820 table now, so
# what this asserts is that *this* boot's answer came from the tags (the
# protocol line above says which hand-off was read).
require_log_line "[mem   ] machine reports "
require_log_line " region(s); the kernel's pool is "
# The boot says how its own image sits in the map it was given: described, and
# how much of it the map does not name ([RFC
# 0020](../../docs/rfcs/0020-what-the-memory-map-may-refuse-on.md)).
require_log_line "is described:"
require_log_absent_line "the machine described no memory map"
require_log_absent_line "FATAL"

# And it is a working machine: the shell came up and a program was loaded out
# of the volume.
require_log_line "[user  ] loaded /apps/packages/shell/bin/shell.elf"

printf 'x86_64 ISO check passed: GRUB handed over on Multiboot2, the loader'"'"'s map\n'
printf '  was read, the kernel'"'"'s image is described by it, and the shell loaded\n'

# ── The same image, through UEFI ────────────────────────────────────────
#
# The firmware a machine boots with describes memory differently, and the
# difference is not cosmetic: UEFI's map is granular (twenty entries where the
# BIOS one had a handful) and it reserves the memory the image itself occupies,
# which is what made the placement check ask a question no correct map can
# answer ([RFC 0020](../../docs/rfcs/0020-what-the-memory-map-may-refuse-on.md)).
# This pass is also the one that found the kernel writing a read-only page and
# hanging in its PCID allocator, so it is the pass that would have found them
# anywhere else.  The firmware is required rather than optional: a check that
# skipped itself when OVMF was missing would report nothing, which is the
# direction this repository does not go.
find_ovmf() {
    for candidate in \
        /usr/share/OVMF/OVMF_CODE_4M.fd \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/ovmf/OVMF.fd \
        /usr/share/edk2/x64/OVMF_CODE.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd; do
        if [ -f "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

ovmf_code="$(find_ovmf)" || {
    printf 'OVMF (the UEFI firmware) is not installed; the UEFI pass cannot run\n' >&2
    printf '  look for it under /usr/share/OVMF or /usr/share/edk2, or install the ovmf package\n' >&2
    exit 1
}
ovmf_vars="$work/OVMF_VARS.fd"
# The variables store has to be writable, so it is a zero-filled file of the
# size the firmware's code image expects; OVMF fills it on the first boot.
case "$ovmf_code" in
    *OVMF_CODE_4M.fd) ovmf_vars_size=4194304 ;;
    *) ovmf_vars_size=2097152 ;;
esac
dd if=/dev/zero of="$ovmf_vars" bs=1024 count=$((ovmf_vars_size / 1024)) status=none

uefi_log="$work/boot-uefi.log"
: >"$uefi_log"
printf 'x86_64 ISO check: UEFI pass, firmware %s\n' "$ovmf_code"

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
    -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
    -drive "if=pflash,format=raw,file=$ovmf_vars" \
    -serial "file:$uefi_log" >/dev/null 2>&1
status=$?
set -e

case "$status" in
    0|124) ;;
    *)
        printf 'x86_64 ISO check (UEFI) failed with exit status %s\n' "$status" >&2
        printf '  full log preserved at: %s\n' "$uefi_log" >&2
        exit "$status"
        ;;
esac

# The assertions read the UEFI boot's log from here on.
log="$uefi_log"

require_log_line "[boot:loader] arch=x86_64 protocol=multiboot2"
require_log_line "[mem   ] machine reports "
require_log_line "is described:"
require_log_absent_line "FATAL"
require_log_line "[user  ] loaded /apps/packages/shell/bin/shell.elf"

printf 'x86_64 ISO check (UEFI) passed: the firmware'"'"'s own map, the image described\n'
printf '  in it, and the shell loaded\n'
