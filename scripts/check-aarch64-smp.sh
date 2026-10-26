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

KERNEL_BIN="${TARGET_DIR}/aarch64-unknown-none/${PROFILE}/${CRATE}.img"

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
# The Image, not the ELF: only the arm64 Image boot path is handed a device
# tree, and a kernel that boots without one silently falls back to hardcoded
# platform constants.  See scripts/build-aarch64-image.sh.
FEATURES="demo-disk" PROFILE="$PROFILE" CRATE="$CRATE" TARGET_DIR="$TARGET_DIR" \
    sh ./scripts/build-aarch64-image.sh

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
    # Print the scheduler lines themselves, not the tail of the log.  A
    # `[sched ]` line is printed once, often long before the end of the boot,
    # so a tail can miss the one line the failure is about — and a failure
    # nobody can read is a failure nobody can attribute.
    if grep -a -F '[sched ]' "$log_file" >/dev/null 2>&1; then
        printf '  the scheduler said:\n' >&2
        grep -a -F '[sched ]' "$log_file" >&2
    fi
    tail -n 12 "$log_file" >&2
    exit 1
}

grep -q -F "[smp   ] PSCI version" "$log_file" ||
    fail "the kernel never asked PSCI for its version"
grep -q -F "[smp   ] ${SMP_CPUS} CPUs total, ${expected_aps} AP(s)" "$log_file" ||
    fail "expected ${expected_aps} AP(s) out of ${SMP_CPUS} CPUs"
# The device tree has to have arrived: the CPU list AP discovery walks comes
# from it, and this check is what says the boot is using it rather than the
# hardware fallbacks.
grep -q "info=0x00000000" "$log_file" &&
    fail "the kernel was booted without a device tree"

# "started" is what the boot CPU knows: PSCI returns as soon as it accepts the
# request.  The cores report for themselves on the next line, and that count is
# the one that has to match.
grep -q -F "[smp   ] ${expected_aps} AP(s) started" "$log_file" ||
    fail "expected the boot CPU to start ${expected_aps} AP(s)"

online="$(grep -c '\[smp   \] AP cpu_id=.* online' "$log_file" || true)"
[ "$online" = "$expected_aps" ] ||
    fail "expected ${expected_aps} APs to report themselves online, saw ${online}"

# ── The cores are not decoration ───────────────────────────────────────
#
# Every assertion above is printed *before* the APs enter their dispatch
# loops, and all of them held while those loops were unreachable: the cores
# came up, could not be given any work, and the machine ran its whole demo on
# the boot CPU.  Bringing a core up and using it are different claims, and
# this is the second one:
#
#   * a thread spawned for another core has to wake it, which is the only
#     thing that proves the reschedule IPI was delivered rather than sent;
#   * the demo's workers sleep between steps, and a sleeper parked on a core
#     only wakes if that core takes timer interrupts;
#   * every service stopping is the end of the demo boot.
reschedule_ipis="$(grep -c 'woke on a reschedule IPI' "$log_file" || true)"
[ "$reschedule_ipis" -ge 1 ] ||
    fail "no AP was ever woken by a reschedule IPI: the cores came up and were left idle"

grep -q '\[demo  \] worker-a done' "$log_file" ||
    fail "the demo worker never finished: a thread parked on a core stopped waking"
grep -q '\[service\] kworker-b stopped' "$log_file" ||
    fail "the demo boot never finished: services did not all stop"
grep -q -F '[sched ]' "$log_file" &&
    fail "the scheduler reported a process it cannot place"

grep -q 'FATAL' "$log_file" && fail "the boot reported a fatal fault"
grep -q 'CPU_ON rejected' "$log_file" && fail "PSCI refused to start a core"

printf 'aarch64 SMP check passed: %s CPUs, %s AP(s) online, %s reschedule IPI(s)\n' \
    "$SMP_CPUS" "$expected_aps" "$reschedule_ipis"

# ── A machine whose cores are not all in Aff0 ──────────────────────────
#
# Every assertion above runs a machine whose CPU ids fit the kernel's AP table
# and whose cores all sit in one affinity cluster.  QEMU `virt` with more than
# sixteen CPUs is neither: it names the seventeenth core `cpu@16` with
# `reg = <0x100>`, because that core's MPIDR is `0x100` and its Aff0 is 0 —
# the boot CPU's.
#
# The kernel passed the CPU's *position* to `CPU_ON` instead of its `reg`, and
# read its own identity from Aff0.  So the seventeenth core was refused
# (`CPU_ON rejected: 0xfffffffffffffffe`) and a core that had come up would
# have called itself the boot CPU.  This segment asserts the two numbers are
# kept apart: 17 CPUs present, all 16 APs online, and no refusal.
board_cpus=17
board_log="$(mktemp)"
printf 'aarch64 affinity check: %s CPUs\n' "$board_cpus"
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine virt \
    -cpu max \
    -smp "$board_cpus" \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -serial "file:$board_log" >/dev/null 2>&1 || true

board_fail() {
    printf 'aarch64 affinity check failed: %s\n' "$1" >&2
    printf '  last lines of the log:\n' >&2
    tail -n 12 "$board_log" >&2
    rm -f "$board_log"
    exit 1
}

grep -q -F "[smp   ] ${board_cpus} CPUs total, $((board_cpus - 1)) AP(s)" "$board_log" ||
    board_fail "the kernel did not see all ${board_cpus} CPUs"
board_online="$(grep -c '\[smp   \] AP cpu_id=.* online' "$board_log" || true)"
[ "$board_online" = "$((board_cpus - 1))" ] ||
    board_fail "expected $((board_cpus - 1)) APs online, saw ${board_online}"
grep -q 'CPU_ON rejected' "$board_log" &&
    board_fail "PSCI refused a core the tree says exists"
grep -q 'FATAL' "$board_log" && board_fail "the boot reported a fatal fault"
if ! grep -q 'protofire ring3 shell' "$board_log"; then
    board_fail "the machine never reached the shell"
fi
rm -f "$board_log"
printf '  affinity check passed: %s APs online, no core refused\n' "$board_online"
