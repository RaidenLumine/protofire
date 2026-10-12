#!/usr/bin/env sh
# File: scripts/check-riscv64-aia-runtime.sh
# Purpose: Boot riscv64 on the AIA machine and check the IMSIC path.
#
# Why this exists
# ---------------
# The IMSIC is the AIA interrupt file that receives MSIs, and this kernel's
# driver for it was written against the specification's *direct MMIO* view of
# that file: registers at fixed page offsets, an MSI data word of
# `(1 << 31) | irq`, and a claim register at `+0x30`.  QEMU `virt` implements
# none of those three — its page is only the MSI-write page, the data word is
# the bare identity, and the register file is reached indirectly through the
# `siselect`/`sireg` CSRs, with `stopei` for the claim — so every gate booted
# the PLIC machine instead and the difference went unseen until a boot that
# asked for AIA took an access fault at `base + 0x20`.
#
# What the boot has to show:
#
#   * the kernel picks the **supervisor** IMSIC.  QEMU describes two files —
#     machine mode at 0x2400_0000 and supervisor mode at 0x2800_0000 — and
#     writing the machine one from S-mode is an access fault, so choosing it
#     is the failure this gate exists to catch.
#   * a message is delivered.  Nothing on this machine sends an MSI, so the
#     kernel walks the path itself at boot: it enables an identity, writes the
#     message a device would write into its own MSI page, and reads the
#     identity back out of `stopei`.  That covers the page address, the
#     bare-identity data word, the enable bit, the pending bit and the claim.
#   * the console UART's line reaches the kernel through the APLIC.  On this
#     machine nothing is a PLIC source: the supervisor APLIC domain turns the
#     UART's line into the MSI that carries identity 10, and the IMSIC's
#     claim hands it to the console's handler.  The check types at the shell
#     and asserts the handler's one-time line, because a boot that merely
#     configures the domain would pass without the delivery.
#   * and the machine still comes up: the demo reaches its shell with no fatal
#     error, which is what says the IMSIC took over the external-interrupt path
#     without breaking anything else.
#
# The default (PLIC) machine is `check-riscv64-runtime.sh`; this is the other
# one, and neither substitutes for the other.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
QEMU_RAM="${QEMU_RAM:-2G}"
QEMU_RISCV64="${QEMU_RISCV64:-qemu-system-riscv64}"
RISCV64_AIA_LOG="${RISCV64_AIA_LOG:-}"
FEATURES="${FEATURES:-demo-disk}"

KERNEL_BIN="${TARGET_DIR}/riscv64gc-unknown-none-elf/${PROFILE}/${CRATE}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

if ! command -v "$QEMU_RISCV64" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the riscv64 AIA check.\n' "$QEMU_RISCV64" >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target riscv64gc-unknown-none-elf --bin "$CRATE" \
    --features "$FEATURES"

if [ -n "$RISCV64_AIA_LOG" ]; then
    mkdir -p "$(dirname "$RISCV64_AIA_LOG")"
    log_file="$RISCV64_AIA_LOG"
    : >"$log_file"
    remove_log_on_exit=0
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

printf 'riscv64 AIA check: 1 cpu, timeout %ss, qemu %s\n' "$TIMEOUT_SECONDS" "$QEMU_RISCV64"
printf '  %s\n' "shell_commands | timeout ${TIMEOUT_SECONDS}s $QEMU_RISCV64 -machine virt,aia=aplic-imsic ... -serial stdio"
# The console is typed at, the way the PLIC machine's check types at it: the
# wire interrupt is the APLIC's now, and a boot that merely starts shows the
# configuration but not the delivery.
shell_commands() {
    sh ./scripts/feed-shell-console.sh "$log_file" "$TIMEOUT_SECONDS" \
        'echo ring3-shell-answered'
}
set +e
shell_commands | timeout "${TIMEOUT_SECONDS}s" "$QEMU_RISCV64" \
    -machine virt,aia=aplic-imsic \
    -cpu rv64 \
    -smp 1 \
    -m "$QEMU_RAM" \
    -kernel "$KERNEL_BIN" \
    -display none \
    -serial stdio \
    -no-reboot \
    -no-shutdown \
    -global virtio-mmio.force-legacy=false \
    -netdev user,id=net0 -device virtio-net-device,netdev=net0 >"$log_file" 2>>"$log_file"
status=$?
set -e

case "$status" in
    0|124) ;;
    *)
        printf 'riscv64 AIA check failed with exit status %s\n' "$status" >&2
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

fail_with_log() {
    printf 'riscv64 AIA check failed: %s\n' "$1" >&2
    if [ "$remove_log_on_exit" = "0" ]; then
        printf 'full log preserved at: %s\n' "$log_file" >&2
    fi
    cat "$log_file" >&2
    exit 1
}

require_log_line() {
    pattern="$1"
    if ! grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line: $pattern"
    fi
}

require_log_exact_line() {
    line="$1"
    if ! grep -F -x "$line" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line (whole line): $line"
    fi
}

require_log_absent_line() {
    pattern="$1"
    if grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "unexpected log line: $pattern"
    fi
}

# The machine came up, and came up on the supervisor IMSIC rather than the
# machine-mode file at 0x2400_0000 (which S-mode cannot write).
require_log_line "Protofire kernel prototype starting"
require_log_line "[mem   ] activated riscv64 kernel page tables"
require_log_line "AIA IMSIC:"
require_log_line "base=0x28000000"
require_log_absent_line "base=0x24000000"

# And the message path works: an identity was enabled, a message written into
# the file's own MSI page, and the claim read it back.
require_log_line "AIA IMSIC: self-test delivered and claimed identity "

require_log_line "[init  ] starting idle process"
# The ring-3 shell's own banner: on this machine the boot reaches the shell the
# same way the non-AIA one does, and the proxy it replaced printed
# `protofire shell (user)`.  The FATAL assertion below is what makes this check
# more than "the boot printed something".
require_log_line "adastra ring3 shell"

# And the wire path works end to end.  The UART's line is not a PLIC source on
# this machine: the supervisor APLIC turns it into the MSI that carries
# identity 10, and the IMSIC's claim hands it to the handler the console
# claimed.  The three lines are the three halves — the domain took the
# configuration, the handler's own one-time line says the message arrived as
# an interrupt, and the shell's exact answer says the byte it carried reached
# the reader that typed the line.
require_log_line "[aplic ] source 10 armed at 0x"
require_log_line "[serial] RX interrupt carries input"
require_log_exact_line "ring3-shell-answered"
require_log_absent_line "[FATAL] riscv64 trap"
require_log_absent_line "self-test delivered nothing"
require_log_absent_line "could not be armed"

if [ "$remove_log_on_exit" = "0" ]; then
    printf 'riscv64 AIA log saved to %s\n' "$log_file"
fi
printf 'riscv64 AIA check passed: supervisor IMSIC, self-test delivered, shell reached\n'
