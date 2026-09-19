#!/usr/bin/env sh
# File: scripts/doctor.sh
# Purpose: Local environment checker.  Reports every tool the build needs and
#   exits non-zero when one it depends on is missing.

set -eu

TARGET="${TARGET:-x86_64-unknown-none}"
RUST_TARGETS="x86_64-unknown-none aarch64-unknown-none riscv64gc-unknown-none-elf"

missing_required=0
missing_optional=0

# check_tool <required|optional> <tool> <description>
check_tool() {
    kind="$1"
    tool="$2"
    description="$3"

    if command -v "$tool" >/dev/null 2>&1; then
        printf '[ ok ] %-26s %s\n' "$tool" "$description"
        return 0
    fi

    printf '[miss] %-26s %s\n' "$tool" "$description"
    case "$kind" in
        required) missing_required=$((missing_required + 1)) ;;
        *) missing_optional=$((missing_optional + 1)) ;;
    esac
}

printf 'protofire environment check\n'
if command -v rustc >/dev/null 2>&1; then
    printf 'host: %s\n' "$(rustc -vV | sed -n 's/^host: //p')"
else
    printf 'host: unknown (rustc not found)\n'
fi
printf 'target: %s\n' "$TARGET"
printf 'required: cargo, rustup and the three pinned Rust targets\n'
printf 'optional: QEMU for the run targets, timeout for the smoke checks,\n'
printf '          grub-mkrescue and xorriso for ISO images\n'

check_tool required cargo "Rust package manager"
check_tool required rustup "Rust toolchain manager"
check_tool optional qemu-system-x86_64 "Required for make run"
check_tool optional qemu-system-aarch64 "Required for make run-aarch64 and make check-aarch64-runtime"
check_tool optional qemu-system-riscv64 "Required for make run-riscv64"
check_tool optional timeout "Required for bounded QEMU smoke checks"
check_tool optional grub-mkrescue "Used for bootable ISO images (no make target uses it yet)"
check_tool optional xorriso "Usually required by grub-mkrescue"

# rust-toolchain.toml installs the three bare-metal targets with the toolchain,
# so a miss here means rustup was bypassed or the toolchain predates the pin.
if command -v rustup >/dev/null 2>&1; then
    # rustup prints CRLF line endings on Windows hosts; strip the CR so the
    # exact-match test below works there too.
    installed_targets="$(rustup target list --installed | tr -d '\r')"
    for rust_target in $RUST_TARGETS; do
        if printf '%s\n' "$installed_targets" | grep -qx "$rust_target"; then
            printf '[ ok ] %-26s installed Rust target\n' "$rust_target"
        else
            printf '[miss] %-26s run: rustup target add %s\n' "$rust_target" "$rust_target"
            missing_required=$((missing_required + 1))
        fi
    done
fi

printf '\nrequired: %d missing, optional: %d missing\n' \
    "$missing_required" "$missing_optional"

if [ "$missing_required" -gt 0 ]; then
    printf 'environment incomplete: install the required tools above, then run make doctor again\n' >&2
    exit 1
fi

printf 'environment ready for make check / make clippy / make build\n'
[ "$missing_optional" -eq 0 ] || \
    printf 'optional tools are missing; each [miss] line above names the target that needs it\n'
