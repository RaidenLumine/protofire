#!/usr/bin/env sh
# File: scripts/check-aarch64-smp.sh
# Purpose: Boot the aarch64 kernel on several emulated CPUs and assert that the
#   secondary cores actually came up.
#
# Why this exists separately from the x86_64 check: x86_64 uses SIPI and an AP
# trampoline, while aarch64 starts its cores through PSCI.  The two were
# different mechanisms with different failure modes, and aarch64's had never
# been exercised — it ran on one core and said so.
#
# The assertions are read from the guest's own serial output:
#   * every CPU the machine has was reported,
#   * every secondary core the kernel tried was started and came online,
#   * nothing faulted on the way.
set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
SMP_CPUS="${SMP_CPUS:-4}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"
QEMU="${QEMU:-qemu-system-aarch64}"

KERNEL_BIN="${TARGET_DIR}/aarch64-unknown-none/${PROFILE}/${CRATE}"

case "$SMP_CPUS" in
    ''|*[!0-9]*)
        printf 'SMP_CPUS must be a number, got: %s\n' "$SMP_CPUS" >&2
        exit 1
        ;;
esac

if [ "$SMP_CPUS" -lt 2 ]; then
    printf 'SMP_CPUS must be at least 2; %s cannot exercise the AP path.\n' "$SMP_CPUS" >&2
    exit 1
fi

expected_aps=$((SMP_CPUS - 1))

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target aarch64-unknown-none --bin "$CRATE" \
    --features demo-disk

log_file="$(mktemp)"
trap 'rm -f "$log_file"' EXIT INT TERM

# `-serial file:` rather than `stdio`: the capture must not depend on the TTY
# state of whoever started this.
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine virt \
    -cpu max \
    -smp "$SMP_CPUS" \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -serial "file:$log_file" >/dev/null 2>&1 || true

fail() {
    printf 'aarch64 SMP check failed: %s\n' "$1" >&2
    printf '  serial log: %s bytes at %s\n' "$(wc -c <"$log_file" | tr -d ' ')" "$log_file" >&2
    exit 1
}

grep -q "^\[smp   \] PSCI version" "$log_file" ||
    fail "the kernel never asked PSCI for its version"
grep -q "^\[smp   \] ${SMP_CPUS} CPUs total, ${expected_aps} AP(s)" "$log_file" ||
    fail "expected ${expected_aps} AP(s) out of ${SMP_CPUS} CPUs"
grep -q "^\[smp   \] ${expected_aps} AP(s) online" "$log_file" ||
    fail "expected ${expected_aps} AP(s) online"

online="$(grep -c '^\[smp   \] AP cpu_id=.* online' "$log_file" || true)"
[ "$online" = "$expected_aps" ] ||
    fail "expected ${expected_aps} APs to report themselves online, saw ${online}"

grep -q 'FATAL' "$log_file" && fail "the boot reported a fatal fault"
grep -q 'CPU_ON rejected' "$log_file" && fail "PSCI refused to start a core"

printf 'aarch64 SMP check passed: %s CPUs, %s AP(s) online\n' "$SMP_CPUS" "$expected_aps"
