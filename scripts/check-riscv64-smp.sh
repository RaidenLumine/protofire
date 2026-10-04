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
# Starting a hart is only half of it, though: one that comes up with no per-CPU
# block, no exception vector of its own, no page table and no scheduler is a
# hart parked in `wfi`, not a CPU.  The assertions below are read from the
# guest's own serial output and cover both halves — every hart the kernel tried
# was started *and* joined as a CPU — and then that the machine still schedules
# afterwards, because a hart that comes up and faults takes the demo with it.

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

# Which hart is the *boot* hart is not fixed — QEMU hands the reset to whichever
# hart it likes, and boots have landed on 0, 1, 2 and 3 here — so the assertions
# are on counts, never on a particular hart ID.
require_line "[init  ] riscv64: BSP percpu cpu_id="
if grep -a -F "[smp] riscv64: boot hart ID unknown" "$log_file" >/dev/null 2>&1; then
    fail "the kernel did not record which hart it booted on"
fi

# Every hart the kernel started came back and reported for itself.  "Started" is
# what the BSP asked for; this is the hart saying it is running.
running="$(grep -a -c -E '\[smp\] riscv64 AP: hart [0-9]+ running' "$log_file" || true)"
[ "$running" = "$expected_harts" ] ||
    fail "expected ${expected_harts} harts to report running, saw ${running}"

# …and then became a CPU, which is the part a hart parked in `wfi` never does:
# its own page table, its per-CPU identity, and its place in the registry the
# scheduler dispatches from.
paging="$(grep -a -c -E '\[smp\] riscv64 AP: hart [0-9]+ paging on' "$log_file" || true)"
[ "$paging" = "$expected_harts" ] ||
    fail "expected ${expected_harts} harts to adopt the kernel page table, saw ${paging}"

online="$(grep -a -c -E '\[smp\] riscv64 AP: hart [0-9]+ online, cpu_id=[0-9]+, entering dispatch loop' "$log_file" || true)"
[ "$online" = "$expected_harts" ] ||
    fail "expected ${expected_harts} harts online as CPUs, saw ${online}"

# A hart that came up and was never used is the failure this check exists to
# catch, so the last claim is about use, not about coming up: every CPU the
# machine has must have dispatched a thread.  The scheduler says so once per
# CPU (see `Scheduler::schedule`), and the count is the whole machine because a
# hart that only runs its boot code never reaches that line.
dispatched="$(grep -a -c -F 'dispatched its first thread' "$log_file" || true)"
[ "$dispatched" = "$SMP_CPUS" ] ||
    fail "expected ${SMP_CPUS} CPUs to dispatch a thread, saw ${dispatched}: a hart came up and was left idle"

# Deliberately not asserted: an arriving reschedule IPI.  The kernel sends the
# request through the SBI IPI extension, and every send is accepted here, but
# this firmware never surfaces it as a software interrupt the S-mode hart can
# take — and S-mode cannot reach the CLINT to raise one itself, which is an
# access fault rather than an IPI.  A cross-hart wake therefore waits for the
# target's next timer tick.  That costs latency, not correctness: the request
# only sets a "look again" flag, and the receiving hart checks its queues on
# every kernel exit.  What would make the assertion possible is a platform
# whose firmware delivers the interrupt; what rules it out is that this one
# does not, and a check that asserted it would be red for the wrong reason.

# A hart that comes up and immediately faults takes the demo with it, so the
# boot's own progress lines are the second half of the assertion.
require_line "[demo  ] worker-a done"
require_line "[demo  ] worker-b done"
require_line "[service] kworker-syscall-fs stopped"

for pattern in "[FATAL]" "unhandled riscv64" "[smp] riscv64: SBI hart_start failed" "MMU not active" "guard pages are not enforced"; do
    if grep -a -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail "unexpected log line: $pattern"
    fi
done

printf 'riscv64 SMP check passed: %s CPUs, %s hart(s) online as CPUs, %s CPU(s) dispatching threads\n' \
    "$SMP_CPUS" "$expected_harts" "$dispatched"
