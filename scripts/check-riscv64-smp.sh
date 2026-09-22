#!/usr/bin/env sh
# File: scripts/check-riscv64-smp.sh
# Purpose: Boot the riscv64 kernel on several emulated harts and assert that the
#   secondary harts actually came up.
#
# Each architecture starts its secondary cores by a different mechanism —
# x86_64 by INIT-SIPI-SIPI, aarch64 through PSCI, riscv64 through the SBI Hart
# State Management extension — and riscv64's had never run: hart discovery read
# the CPU list out of the device tree, the device-tree pointer was never stored
# at boot, and the bring-up loop therefore found zero harts and returned.  The
# machine ran on one hart and the code that starts the others was dead.
#
# The assertions are read from the guest's own serial output: every hart the
# kernel tried was started and answered, and the machine still schedules
# afterwards — a hart that comes up and faults takes the demo with it.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
SMP_CPUS="${SMP_CPUS:-4}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"
QEMU="${QEMU:-qemu-system-riscv64}"

KERNEL_BIN="${TARGET_DIR}/riscv64gc-unknown-none-elf/${PROFILE}/${CRATE}"

case "$SMP_CPUS" in
    ''|*[!0-9]*)
        printf 'SMP_CPUS must be a number, got: %s\n' "$SMP_CPUS" >&2
        exit 1
        ;;
esac

if [ "$SMP_CPUS" -lt 2 ]; then
    printf 'SMP_CPUS must be at least 2; %s cannot exercise the hart path.\n' "$SMP_CPUS" >&2
    exit 1
fi

expected_harts=$((SMP_CPUS - 1))

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target riscv64gc-unknown-none-elf --bin "$CRATE" \
    --features demo-disk

log_file="$(mktemp)"
trap 'rm -f "$log_file"' EXIT INT TERM

# `-serial file:` rather than `stdio`: the capture must not depend on the TTY
# state of whoever started this.
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine virt \
    -global virtio-mmio.force-legacy=false \
    -cpu rv64 \
    -smp "$SMP_CPUS" \
    -m 2G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -serial "file:$log_file" \
    -netdev user,id=net0 -device virtio-net-device,netdev=net0 >/dev/null 2>&1 || true

fail() {
    printf 'riscv64 SMP check failed: %s\n' "$1" >&2
    printf '  last lines of the log:\n' >&2
    tail -n 12 "$log_file" | tr -d '\000' >&2
    exit 1
}

require_line() {
    grep -a -F "$1" "$log_file" >/dev/null 2>&1 || fail "missing log line: $1"
}

# The device tree has to be read before harts can be found in it.
require_line "[init  ] NUMA: single-node topology (node 0, ${SMP_CPUS} CPU(s))"
require_line "[smp] riscv64: bringing up ${expected_harts} secondary hart(s)..."

# Every hart the kernel started came back.
online="$(grep -a -c -F '[smp] riscv64 AP: hart online, entering idle loop' "$log_file" || true)"
[ "$online" = "$expected_harts" ] ||
    fail "expected ${expected_harts} harts online, saw ${online}"
# Which hart is the *boot* hart is not fixed — QEMU hands the reset to whichever
# hart it likes, and boots have landed on 0, 1, 2 and 3 here — so the assertion
# is on the count the bring-up loop reports, not on a particular hart ID.
require_line "[smp] riscv64: hart"
require_line "total APs=${expected_harts}"
if grep -a -F "[smp] riscv64: boot hart ID unknown" "$log_file" >/dev/null 2>&1; then
    fail "the kernel did not record which hart it booted on"
fi

# A hart that comes up and immediately faults takes the demo with it, so the
# boot's own progress lines are the second half of the assertion.
require_line "[demo  ] worker-a done"
require_line "[demo  ] worker-b done"
require_line "[service] kworker-syscall-fs stopped"

for pattern in "[FATAL]" "unhandled riscv64" "[smp] riscv64: SBI hart_start failed"; do
    if grep -a -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail "unexpected log line: $pattern"
    fi
done

# Deliberately not asserted: `[smp] riscv64 AP: warning — MMU not active on
# secondary hart`.  A hart started through SBI HSM comes up with `satp` clear,
# so it runs on the identity map; the kernel says so.  Giving the APs their own
# page tables, per-CPU data, timer and scheduler — which is what would make them
# run threads rather than idle — is the next piece of work, and this check is
# where it gets verified.

printf 'riscv64 SMP check passed: %s CPUs, %s hart(s) online\n' "$SMP_CPUS" "$expected_harts"
