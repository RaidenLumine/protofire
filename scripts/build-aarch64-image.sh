#!/usr/bin/env sh
# File: scripts/build-aarch64-image.sh
# Purpose: Build the aarch64 kernel as the arm64 `Image` QEMU boots with a
#          device tree.
#
# Why this exists
# ---------------
# QEMU hands a device tree to a kernel only on the Linux boot path, which it
# recognises by the arm64 `Image` header: the magic `ARM\x64` at offset 56.
# A bare-metal ELF passed to `-kernel` gets `x0 = 0` and no blob anywhere in
# memory — which is how this kernel spent its whole life reading hardcoded
# platform constants while carrying a device-tree parser it never fed.  This
# script produces the Image instead.
#
# The header's `text_offset` places the header 64 bytes *before* the kernel's
# link address (`KERNEL_LOAD_ADDRESS` in the linker script), so the code still
# runs where it was linked and no relink is needed.  QEMU loads header and
# payload at `RAM base + text_offset` and starts with `x0` pointing at the
# device tree it wrote for us.
#
# The ELF stays the artifact to debug with; this is the artifact to boot.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
FEATURES="${FEATURES:-demo-disk}"
AARCH64_TARGET="${AARCH64_TARGET:-aarch64-unknown-none}"

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

# `demo-disk` is the default here because every caller that boots the Image is
# booting the demo; an empty FEATURES builds the same Image without it.
if [ -n "$FEATURES" ]; then
    set -- --features "$FEATURES"
else
    set --
fi
"$CARGO" build --offline $profile_flag --target "$AARCH64_TARGET" --bin "$CRATE" "$@"

ELF="${TARGET_DIR}/${AARCH64_TARGET}/${PROFILE}/${CRATE}"
# The demo Image is the default output; the headless smoke builds its own so
# that a run without the demo disk does not overwrite the one a check boots.
IMAGE="${IMAGE:-${ELF}.img}"

if [ ! -f "$ELF" ]; then
    printf 'aarch64 kernel ELF not found: %s\n' "$ELF" >&2
    exit 1
fi

# The toolchain ships llvm-objcopy; look for it where rustc keeps it rather
# than hoping a host binutils can read an aarch64 ELF.
RUSTC="${RUSTC:-rustc}"
SYSROOT="$("$RUSTC" --print sysroot)"
HOST="$("$RUSTC" -vV | sed -n 's/^host: //p')"
OBJCOPY="${OBJCOPY:-${SYSROOT}/lib/rustlib/${HOST}/bin/llvm-objcopy}"
if [ ! -x "$OBJCOPY" ]; then
    OBJCOPY="$(command -v llvm-objcopy || true)"
fi
if [ -z "$OBJCOPY" ] || [ ! -x "$OBJCOPY" ]; then
    printf 'llvm-objcopy not found; cannot build the aarch64 Image\n' >&2
    exit 1
fi

flat="$(mktemp)"
cleanup() {
    rm -f "$flat"
}
trap cleanup EXIT INT TERM

"$OBJCOPY" -O binary "$ELF" "$flat"
payload_size="$(wc -c <"$flat" | tr -d ' ')"
image_size=$((64 + payload_size))

# The 64-byte header, little-endian:
#   0x00  code0         b +64 (branch to the payload, which follows the header)
#   0x04  code1         0
#   0x08  text_offset   0x7FFC0 = 0x80000 - 64, so the *payload* lands on
#                       KERNEL_LOAD_ADDRESS (0x40080000)
#   0x10  image_size    header + payload
#   0x18  flags         0
#   0x20  res0[3]       24 bytes of zero
#   0x38  magic         "ARM\x64"
#   0x3C  res0          4 bytes of zero
#
# `printf` needs the byte values as octal; the image is far below 4 GiB, so the
# size's upper four bytes are zero.
byte() {
    printf '%03o' "$(( $1 & 0xff ))"
}

{
    printf '\020\000\000\024'                          # code0:  b +64
    printf '\000\000\000\000'                          # code1
    printf '\300\377\007\000\000\000\000\000'          # text_offset = 0x7FFC0
    printf "\\$(byte "$image_size")\\$(byte "$((image_size >> 8))")\\$(byte "$((image_size >> 16))")\\$(byte "$((image_size >> 24))")"
    printf '\000\000\000\000'                          # image_size, upper half
    printf '\000\000\000\000\000\000\000\000'          # flags
    printf '\000\000\000\000\000\000\000\000'          # res0[0]
    printf '\000\000\000\000\000\000\000\000'          # res0[1]
    printf '\000\000\000\000\000\000\000\000'          # res0[2]
    printf 'ARM\144'                                   # "ARM\x64"
    printf '\000\000\000\000'                          # res0
    cat "$flat"
} >"$IMAGE"

printf 'aarch64 Image: %s (%s bytes, payload %s)\n' \
    "$IMAGE" "$image_size" "$payload_size"
