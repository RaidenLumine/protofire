#!/usr/bin/env sh
# File: scripts/doctor.sh
# Purpose: Local environment checker for toolchains and QEMU/GRUB dependencies.

set -eu

TARGET="${TARGET:-x86_64-unknown-none}"
RUST_TARGETS="x86_64-unknown-none aarch64-unknown-none riscv64gc-unknown-none-elf"

check_tool() {
    tool="$1"
    description="$2"

    if command -v "$tool" >/dev/null 2>&1; then
        printf '[ ok ] %-26s %s\n' "$tool" "$description"
    else
        printf '[ miss] %-26s %s\n' "$tool" "$description"
    fi
}

printf 'protofire toolchain check\n'
if command -v rustc >/dev/null 2>&1; then
    printf 'host: %s\n' "$(rustc -vV | sed -n 's/^host: //p')"
else
    printf 'host: unknown (rustc not found)\n'
fi
printf 'target: %s\n' "$TARGET"

check_tool cargo "Rust package manager"
check_tool rustup "Rust toolchain manager"
check_tool qemu-system-x86_64 "Required for make run"
check_tool qemu-system-aarch64 "Required for make run-aarch64 and make check-aarch64-runtime"
check_tool qemu-system-riscv64 "Required for make run-riscv64"
check_tool timeout "Required for bounded QEMU smoke checks"
check_tool grub-mkrescue "Used for bootable ISO images (no make target uses it yet)"
check_tool xorriso "Usually required by grub-mkrescue"

if command -v rustup >/dev/null 2>&1; then
    installed_targets="$(rustup target list --installed)"
    for rust_target in $RUST_TARGETS; do
        if printf '%s\n' "$installed_targets" | grep -qx "$rust_target"; then
            printf '[ ok ] %-26s installed Rust target\n' "$rust_target"
        else
            printf '[ miss] %-26s run: rustup target add %s\n' "$rust_target" "$rust_target"
        fi
    done
fi
