#!/usr/bin/env sh
# File: scripts/check-riscv64-aplic-direct-runtime.sh
# Purpose: Boot the machine whose APLIC has no IMSIC behind it, and check it lives.
#
# Why this exists
# ---------------
# `-machine virt,aia=aplic` puts the PLIC's sources behind an APLIC in
# **direct mode**: the domain delivers by raising the receiving hart's
# supervisor external interrupt, the hart claims by reading its window's
# `claimi` register, and there is no IMSIC for a message to land in.  Before
# this gate the kernel did not drive that mode — and did worse than not
# drive it: `controller()` fell back to the PLIC, `PlicController::init`
# wrote the per-context threshold at `0xc201000` (the PLIC fallback base
# plus the PLIC's own offsets, an address no device answers there), and the
# boot died in a store access fault before the shell.  Measured on QEMU
# 10.2.1, and again while this gate was written: the first driver to arm the
# domain dispatched `claimi`'s raw `topi` word instead of the source number
# it carries, found no handler, and left the line re-pended forever.
#
# What the boot has to show now:
#
#   * the machine is recognised.  The direct-mode controller says so once
#     (`[irq   ] this machine's APLIC is in direct mode`), which is also what
#     makes the choice visible in a log rather than inferred from a clean
#     boot.
#   * the console's line is **armed for direct delivery**: the domain takes
#     the configuration (`[aplic ] source 10 armed ... direct delivery`), and
#     the byte really arrives as an interrupt — the one-time landmark
#     `[serial] RX interrupt carries input` is what says the domain's own
#     `claimi` path ran, and it is the same line the PLIC and IMSIC machines
#     are held to.
#   * the machine comes up: the demo reaches its shell and a typed line is
#     answered.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
QEMU_RAM="${QEMU_RAM:-2G}"
QEMU_RISCV64="${QEMU_RISCV64:-qemu-system-riscv64}"
RISCV64_APLIC_DIRECT_LOG="${RISCV64_APLIC_DIRECT_LOG:-}"
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
    printf '%s is not installed; cannot run the riscv64 direct-mode check.\n' "$QEMU_RISCV64" >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target riscv64gc-unknown-none-elf --bin "$CRATE" \
    --features "$FEATURES"

if [ -n "$RISCV64_APLIC_DIRECT_LOG" ]; then
    mkdir -p "$(dirname "$RISCV64_APLIC_DIRECT_LOG")"
    log_file="$RISCV64_APLIC_DIRECT_LOG"
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

printf 'riscv64 APLIC direct-mode check: 1 cpu, timeout %ss, qemu %s\n' "$TIMEOUT_SECONDS" "$QEMU_RISCV64"
printf '  %s\n' "shell_commands | timeout ${TIMEOUT_SECONDS}s $QEMU_RISCV64 -machine virt,aia=aplic ... -serial stdio"
# The console is typed at, the way the other runtime checks type at theirs:
# what has to be shown is a byte reaching the shell with no wire interrupt
# driven, i.e. through the poll the refusal left in place.
shell_commands() {
    sh ./scripts/feed-shell-console.sh "$log_file" "$TIMEOUT_SECONDS" \
        'echo ring3-shell-answered'
}
set +e
shell_commands | timeout "${TIMEOUT_SECONDS}s" "$QEMU_RISCV64" \
    -machine virt,aia=aplic \
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
        printf 'riscv64 APLIC direct-mode check failed with exit status %s\n' "$status" >&2
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

fail_with_log() {
    printf 'riscv64 APLIC direct-mode check failed: %s\n' "$1" >&2
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

# The machine is up and the direct-mode choice was made out loud.  The
# controller line is also the discriminator for the machine itself: a boot
# that fell back to the PLIC would not print it.
require_log_line "Protofire kernel prototype starting"
require_log_line "[mem   ] activated riscv64 kernel page tables"
require_log_line "[irq   ] this machine's APLIC is in direct mode (no IMSIC behind it); wire sources are claimed through the domain's own claimi register"

# The console's line was armed in the domain for this hart's own delivery
# window.
require_log_line "[aplic ] source 10 armed at 0x"
require_log_line "direct delivery to hart 0"
# And with the console's own priority, out of the scale the policy block in
# `src/arch/riscv64/aplic.rs` defines: the number is asserted, not just the
# fact that some number was written, because the arbitration between sources
# is the number.
require_log_line "(priority 1 of 255)"

# And the machine comes up: the shell is reached and a typed line is
# answered.  The exact answer is the end-to-end evidence — a byte arrived
# from outside, reached the console TTY and came back through the shell.
require_log_line "[init  ] starting idle process"
require_log_line "protofire ring3 shell"
require_log_exact_line "ring3-shell-answered"

# And the delivery really is the domain's: the landmark is printed once, by
# `handle_rx_interrupt`, and only a claim through `claimi` can reach it on
# this machine — the PLIC window does not exist here.  This is what separates
# "armed" from "delivered", which is the difference the first version of this
# driver got wrong (it dispatched the raw `topi` word, found no handler, and
# left the line pendng).
require_log_line "[serial] RX interrupt carries input"
require_log_absent_line "[FATAL] riscv64 trap"

if [ "$remove_log_on_exit" = "0" ]; then
    printf 'riscv64 APLIC direct-mode log saved to %s\n' "$log_file"
fi
printf 'riscv64 APLIC direct-mode check passed: wire source armed in the domain, input arrived as an interrupt\n'
