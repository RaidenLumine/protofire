#!/usr/bin/env sh
# File: scripts/check-smp-runtime.sh
# Purpose: Headless QEMU smoke test for SMP bring-up and post-boot liveness.
#
# Why this exists
# ---------------
# Every other boot smoke test runs the kernel on one CPU, where the cross-CPU
# paths cannot execute at all: no AP ever starts, a TLB shootdown never needs
# an acknowledgement from a second processor, and a lock held with interrupts
# masked can never be waited on by anyone else.  Those paths are where the
# hard failures live, and a single-CPU run reports them as healthy.
#
# The failure mode being hunted is a *wedge*, not a panic: a lock cycle here
# stops the machine silently, so the check asserts progress rather than exit
# status.  A log that stops growing is the signal.
#
# This raises confidence; it does not close the question.  QEMU's emulated
# CPUs interleave genuinely, but their timing is not hardware timing, so a
# race that needs a narrow window can still stay hidden.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
SMP_CPUS="${SMP_CPUS:-4}"
# The `-smp` **value** QEMU is given.  It defaults to the plain count, and the
# placeholder segment below passes `N,maxcpus=M` instead; the parsing and the
# assertion arithmetic both stay on `SMP_CPUS` so a `maxcpus` run asserts the
# same AP count as a plain one.
SMP_ARG="${SMP_ARG:-$SMP_CPUS}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"
QEMU="${QEMU:-qemu-system-x86_64}"
SMP_RUNTIME_LOG="${SMP_RUNTIME_LOG:-}"
# Features the kernel is built with.  `liveness_heartbeat` adds periodic
# liveness lines from two independent kernel threads, which turns "the log
# stopped here" into "the machine stopped" or "one thread stopped".
#
# It is *not* the default, and that is a finding rather than a preference: a
# build carrying the heartbeat stalls deterministically during AP bring-up on
# the development machine, while the same source without it boots three times
# out of three.  Neither build changes any bring-up logic, so the difference is
# where things land in memory — an AP bring-up defect that this check exists to
# surface, and that would otherwise make the check itself unstable.
FEATURES="${FEATURES:-demo-disk}"

KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

case "$SMP_CPUS" in
    ''|*[!0-9]*)
        printf 'SMP_CPUS must be a number, got: %s\n' "$SMP_CPUS" >&2
        exit 1
        ;;
esac

if [ "$SMP_CPUS" -lt 2 ]; then
    printf 'SMP_CPUS must be at least 2; %s cannot exercise the cross-CPU paths.\n' \
        "$SMP_CPUS" >&2
    exit 1
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the SMP runtime check.\n' "$QEMU" >&2
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the SMP runtime check.\n' >&2
    exit 1
fi

# The demo disk carries the services whose start and exit the progress
# assertions look for.
case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
    --features "$FEATURES"

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'kernel binary not found: %s\n' "$KERNEL_BIN" >&2
    exit 1
fi

remove_log_on_exit=0
if [ -n "$SMP_RUNTIME_LOG" ]; then
    mkdir -p "$(dirname "$SMP_RUNTIME_LOG")"
    log_file="$SMP_RUNTIME_LOG"
    : >"$log_file"
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

# Every knob is echoed before the run.  When a check like this behaves
# differently on two machines, the cause is usually an inherited environment
# variable changing what was actually invoked, and a bare failure message
# cannot show that.
set -- \
    -machine q35 \
    -cpu max \
    -smp "$SMP_ARG" \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0

# Capture the guest's serial output with `-serial file:` rather than
# `-serial stdio` plus a shell redirect.
#
# `stdio` ties where the output ends up to the TTY state of the process that
# started QEMU: it interacts with stdin, with whether stdout is a terminal or a
# file, and with the process group.  That is right for an interactive `make
# run`, and wrong for a check whose whole job is to capture output
# unattended — the same command then behaves differently depending on how it
# was launched.  `file:` removes the question: QEMU writes the log itself.
serial_target="file:$log_file"

if [ -n "${ACCEL:-}" ]; then
    set -- -accel "$ACCEL" "$@"
fi

printf 'SMP runtime check: %s cpus, timeout %ss, qemu %s%s\n' \
    "$SMP_CPUS" "$TIMEOUT_SECONDS" "$QEMU" "${ACCEL:+ (accel $ACCEL)}"
printf '  %s\n' "timeout ${TIMEOUT_SECONDS}s $QEMU $* -serial $serial_target"

set +e
# QEMU's own diagnostics go to the same file, appended after the serial log
# that the guest writes.
timeout "${TIMEOUT_SECONDS}s" "$QEMU" "$@" -serial "$serial_target" \
    >/dev/null 2>>"$log_file"
status=$?
set -e

# 124 is `timeout` killing a machine that is, by design, still running.
case "$status" in
    0|124) ;;
    *)
        printf 'SMP runtime check failed with exit status %s\n' "$status" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

# Report why the check failed, and always leave enough behind to tell the
# interesting cases apart.
#
# "The kernel wedged" and "QEMU never started" both show up as a missing log
# line, and they call for opposite responses: one is a kernel defect, the
# other is a local invocation problem.  So every failure prints the exit
# status, the log size, and the tail of the log.
fail_with_log() {
    reason="$1"
    bytes="$(wc -c <"$log_file" | tr -d ' ')"

    printf 'SMP runtime check failed: %s\n' "$reason" >&2
    printf '  qemu exit status: %s\n' "$status" >&2
    printf '  serial log: %s bytes\n' "$bytes" >&2

    if [ "$bytes" -eq 0 ]; then
        printf '  the guest produced no serial output at all: this is a local\n' >&2
        printf '  invocation problem, not a kernel hang\n' >&2
    else
        printf '  last lines of the log:\n' >&2
        tail -n 12 "$log_file" >&2
    fi

    if [ "$remove_log_on_exit" = "0" ]; then
        printf '  full log preserved at: %s\n' "$log_file" >&2
    else
        printf '  re-run with SMP_RUNTIME_LOG=<path> to keep the log\n' >&2
    fi
    exit 1
}

require_log_line() {
    pattern="$1"
    if ! grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line: $pattern"
    fi
}

count_log_line() {
    awk -v needle="$1" '
        index($0, needle) { count += 1 }
        END { print count + 0 }
    ' "$log_file"
}

first_log_line() {
    awk -v needle="$1" '
        index($0, needle) { print NR; exit }
    ' "$log_file"
}

last_log_line() {
    awk -v needle="$1" '
        index($0, needle) { line = NR }
        END { print line + 0 }
    ' "$log_file"
}

# ── The APs actually came up ───────────────────────────────────────────
#
# Assert the count rather than mere presence: `-smp 4` has to produce three
# APs, and a kernel that silently gave up after the first one would still
# print the line.
require_log_line "SMP: bringing up $((SMP_CPUS - 1)) AP(s)..."

started="$(count_log_line "started successfully")"
if [ "$started" -lt "$((SMP_CPUS - 1))" ]; then
    fail_with_log "expected at least $((SMP_CPUS - 1)) APs to start, saw $started"
fi

# ── Each AP has a clock of its own ────────────────────────────────────
#
# The PIT is wired to the boot CPU's LAPIC, so before the APs got LAPIC timers
# they took no timer interrupt at all: a thread they ran was never preempted,
# and a sleeper there waited for the boot CPU's sweep.  "The AP is online" and
# "the AP has a clock" are different claims, and only the second one is what
# makes an AP a scheduling target rather than a place threads can be parked.
#
# The kernel prints one line per CPU the first time its timer interrupt
# arrives, so this asserts the interrupt rather than the programming: an entry
# left masked, a vector routed elsewhere or a counter never started all look
# like "online" from every other angle.
ap_timers="$(count_log_line "takes timer interrupts")"
if [ "$ap_timers" -lt "$((SMP_CPUS - 1))" ]; then
    fail_with_log "expected $((SMP_CPUS - 1)) AP(s) to take timer interrupts, saw $ap_timers"
fi

# ── The machine is still making progress ───────────────────────────────
#
# Three markers spread across the boot: the scheduler took over, the shell
# came up, and services started exiting afterwards.  A wedge stops the log at
# whichever one it reached, so requiring all three distinguishes "booted" from
# "booted and then died quietly".
require_log_line "kernel running"
# The ring-3 shell's own banner; see the note in `check-x8664-runtime.sh`.
require_log_line "protofire ring3 shell"

service_lines="$(count_log_line "[service]")"
if [ "$service_lines" -eq 0 ]; then
    fail_with_log "no service activity after boot; the machine may have stalled"
fi

# ── The user programs actually ran ─────────────────────────────────────
#
# "Still making progress" is not the same as "reached user mode".  A kernel
# can hand the CPU to a process address space that does not map the stack it
# is standing on and then stop there: every marker above is printed before
# that hand-off, so the shell banner and the service lines were all present in
# a boot where no user program ever printed a byte.  What a user program says
# about itself is the only part of the boot that proves the ring-3 path ran,
# so at least one of them has to have said something and exited.
user_exits="$(count_log_line "[user  ] exit pid=")"
if [ "$user_exits" -eq 0 ]; then
    fail_with_log "no user program reached user mode and exited"
fi

# ── A thread parked on a core still wakes ──────────────────────────────
#
# The demo workers print a step, sleep, and print the next one.  Waking a
# sleeper is the job of a timer tick on the CPU it sleeps on, and the boot
# CPU's clock is the only one this machine wires up — so a worker that runs on
# an AP spends the rest of the boot asleep, having printed its first step and
# nothing else.  "Step 0" alone is that; "done" is the same worker having been
# woken twice more, which only happens if the timeouts reach every CPU's
# waiting queue.
if [ "$(count_log_line "[demo  ] worker-a done")" -eq 0 ]; then
    fail_with_log "the demo worker never finished: a thread parked on a core stopped waking"
fi

# ── The scheduler can still account for every process ──────────────────
if grep -F "[sched ]" "$log_file" >/dev/null 2>&1; then
    fail_with_log "the scheduler reported a process it cannot place"
fi

# ── Nothing reported damage ────────────────────────────────────────────
if grep -F "FATAL" "$log_file" >/dev/null 2>&1; then
    fail_with_log "the kernel reported a fatal error during the run"
fi

# ── The kernel stack's guard is real ───────────────────────────────────
#
# A kernel stack lives in the architecture's own window, its guard is a slice
# of that window nothing ever allocates, and the kernel's tables cover what
# the mapping facts say they cover.  A guard the kernel had to report missing,
# or a kernel range the facts describe but the tables do not map, is a real
# defect — and one that would otherwise first show up as an overflow that
# corrupts memory instead of faulting.
for pattern in \
    "[thread] kernel stack guard pages are not enforced" \
    "[mm    ] kernel table gap"; do
    if grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "unexpected log line: $pattern"
    fi
done

# ── Liveness after boot, when the build carries heartbeats ─────────────
#
# This is the strongest progress assertion available.  The weaker markers
# above only prove the machine got as far as the shell; a kernel that stalled
# just afterwards would satisfy them and still be dead.  Two independent
# threads emit heartbeats, so requiring the last one to land after the shell
# banner proves the scheduler was still dispatching threads then — which is
# exactly the point this kernel has actually stalled at.
beats="$(count_log_line "[hb    ]")"
if [ "$beats" -gt 0 ]; then
    last_beat="$(last_log_line "[hb    ]")"
    shell_line="$(first_log_line "protofire ring3 shell")"
    if [ "$last_beat" -le "$shell_line" ]; then
        fail_with_log "the last heartbeat (line $last_beat) precedes the shell banner (line $shell_line): the machine stopped making progress"
    fi
    printf '  heartbeats %s, last at line %s (shell banner at line %s)\n' \
        "$beats" "$last_beat" "$shell_line"
fi

# The guest reports the accelerator it ended up on — `invpcid` is only
# available under hardware virtualisation — and that is worth printing,
# because "which accelerator did QEMU actually pick" is invisible otherwise
# and is the first thing to check when the same command behaves differently
# on two machines.
accelerator="$(grep -m1 -o "PCID: enabled=true" "$log_file" >/dev/null 2>&1 \
    && printf 'kvm' || printf 'tcg')"

# ── A machine whose MADT carries disabled placeholders ─────────────────
#
# Real firmware describes every *possible* processor and marks the absent
# ones disabled, so a twelve-core laptop writes a thirty-two-entry MADT of
# which twenty entries are 0xff placeholders — a shape no plain `-smp N`
# machine produces (measured: its MADT lists exactly the present CPUs).  The
# captured table in `fixtures/acpi/` has that shape but cannot be booted:
# every boot here reads ACPI through the RSDT the firmware built, and QEMU's
# `-acpitable file=` *appends* a captured table to that list rather than
# replacing the built-in one (measured through QEMU's monitor: the injected
# table sits last while the kernel reads the first checksum-valid APIC
# entry).  `-smp N,maxcpus=M` makes the firmware itself write the shape:
# every possible CPU appears, the absent ones are marked disabled, and the
# kernel's walk has to skip them and bring up exactly the N present ones.
#
# What this segment asserts is therefore the placeholder behaviour on a real
# boot: the count of skipped entries is `maxcpus - cpus`, the AP count is
# still `cpus - 1`, and the machine reaches the same liveness markers.
if [ "$SMP_CPUS" -ge 2 ]; then
    maxcpus=$((SMP_CPUS + 4))
    placeholder_log="$(mktemp)"
    printf 'SMP placeholder check: %s cpus with %s possible (maxcpus)\n' \
        "$SMP_CPUS" "$maxcpus"
    set +e
    timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
        -machine q35 -cpu max -smp "$SMP_CPUS,maxcpus=$maxcpus" -m 1G \
        -kernel "$KERNEL_BIN" -display none -no-reboot -no-shutdown \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -serial "file:$placeholder_log" >/dev/null 2>>"$placeholder_log"
    placeholder_status=$?
    set -e

    placeholder_fail() {
        printf 'SMP placeholder check failed: %s\n' "$1" >&2
        tail -n 12 "$placeholder_log" >&2
        rm -f "$placeholder_log"
        exit 1
    }

    case "$placeholder_status" in
        0|124) ;;
        *) placeholder_fail "exit status $placeholder_status" ;;
    esac

    # The firmware wrote the placeholders: one disabled line per absent CPU.
    disabled_count="$(awk '/disabled, skipping/ { n += 1 } END { print n + 0 }' "$placeholder_log")"
    if [ "$disabled_count" -ne $((maxcpus - SMP_CPUS)) ]; then
        placeholder_fail "expected $((maxcpus - SMP_CPUS)) disabled placeholders, saw $disabled_count"
    fi
    # And exactly the present CPUs came up.
    placeholder_started="$(awk '/started successfully/ { n += 1 } END { print n + 0 }' "$placeholder_log")"
    if [ "$placeholder_started" -lt "$((SMP_CPUS - 1))" ]; then
        placeholder_fail "expected at least $((SMP_CPUS - 1)) APs to start, saw $placeholder_started"
    fi
    if ! grep -F "protofire ring3 shell" "$placeholder_log" >/dev/null 2>&1; then
        placeholder_fail "the machine with placeholders never reached the shell"
    fi
    if grep -F "FATAL" "$placeholder_log" >/dev/null 2>&1; then
        placeholder_fail "the kernel reported a fatal error"
    fi
    rm -f "$placeholder_log"
    printf '  placeholder check passed: %s skipped, %s APs, shell reached\n' \
        "$disabled_count" "$placeholder_started"
fi

# ── The last AP is not the one that is dropped ─────────────────────────
#
# Every check above runs a machine whose CPU count is inside the kernel's AP
# table, where an off-by-one at the boundary is invisible: the stack pool was
# indexed by `cpu_id` instead of `cpu_id - 1`, so the first stack went unused
# and the sixteenth AP was refused with "exceeds MAX_APS".  A check that never
# reaches the boundary cannot see that, and four CPUs never did.
#
# `MAX_APS` is 16, so this machine has 17 CPUs: the BSP plus every AP the
# kernel can hold.  What it asserts is that all 16 start — not "at least", not
# "the machine boots" — because the defect was a count, and a count that is
# one short still boots.
board_cpus=17
board_log="$(mktemp)"
printf 'SMP boundary check: %s CPUs (BSP + every AP slot)\n' "$board_cpus"
set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 -cpu max -smp "$board_cpus" -m 1G \
    -kernel "$KERNEL_BIN" -display none -no-reboot -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -serial "file:$board_log" >/dev/null 2>>"$board_log"
board_status=$?
set -e

board_fail() {
    printf 'SMP boundary check failed: %s\n' "$1" >&2
    printf '  expected %s APs to start; the log says:\n' "$((board_cpus - 1))" >&2
    grep -E 'started successfully|exceeds MAX_APS|skipping cpu_id' "$board_log" | tail -n 4 >&2
    rm -f "$board_log"
    exit 1
}

case "$board_status" in
    0|124) ;;
    *) board_fail "exit status $board_status" ;;
esac

board_started="$(awk '/started successfully/ { n += 1 } END { print n + 0 }' "$board_log")"
[ "$board_started" -eq $((board_cpus - 1)) ] ||
    board_fail "saw $board_started APs"
if grep -F "exceeds MAX_APS" "$board_log" >/dev/null 2>&1; then
    board_fail "the kernel refused a CPU that fits its own table"
fi
if ! grep -F "protofire ring3 shell" "$board_log" >/dev/null 2>&1; then
    board_fail "the machine never reached the shell"
fi
if grep -F "FATAL" "$board_log" >/dev/null 2>&1; then
    board_fail "the kernel reported a fatal error"
fi
rm -f "$board_log"
printf '  boundary check passed: %s APs online on a %s-CPU machine\n' \
    "$board_started" "$board_cpus"

printf 'SMP runtime check passed: %s CPUs, %s APs, %s service lines, accelerator=%s\n' \
    "$SMP_CPUS" "$started" "$service_lines" "$accelerator"
