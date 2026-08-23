#!/usr/bin/env sh
# File: scripts/doctor.sh
# Purpose: Local environment checker for toolchains and QEMU/GRUB dependencies.

set -eu

TARGET="${TARGET:-x86_64-unknown-none}"

check_tool() {
    tool="$1"
    description="$2"

    if command -v "$tool" >/dev/null 2>&1; then
        printf '[ ok ] %-16s %s\n' "$tool" "$description"
    else
        printf '[ miss] %-16s %s\n' "$tool" "$description"
    fi
}

printf 'protofire toolchain check\n'
printf 'target: %s\n' "$TARGET"

check_tool cargo "Rust package manager"
check_tool rustup "Rust toolchain manager"
check_tool grub-mkrescue "Used for bootable ISO images (no make target uses it yet)"
check_tool qemu-system-x86_64 "Required for make run"
check_tool qemu-system-aarch64 "Required for make run-aarch64 and make check-aarch64-runtime"
check_tool timeout "Required for bounded QEMU smoke checks"
check_tool xorriso "Usually required by grub-mkrescue"

if command -v rustup >/dev/null 2>&1; then
    if rustup target list --installed | grep -qx "$TARGET"; then
        printf '[ ok ] %-16s installed Rust target\n' "$TARGET"
    else
        printf '[ miss] %-16s run: rustup target add %s\n' "$TARGET" "$TARGET"
    fi
fi
