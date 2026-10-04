#!/usr/bin/env sh
# File: scripts/check-riscv64-runtime.sh
# Purpose: Headless QEMU smoke test for the riscv64 demo boot.
#
# Why this exists
# ---------------
# riscv64 was the only architecture with no runtime check: `make check-riscv64`
# is a type check, and nothing ever booted the result.  The cost of that showed
# up twice.  The kernel claimed guard pages it had not installed (the fallback
# arm of `enforce_guard_pages` returned `true` for anything that was not x86_64
# or aarch64), and the SBI timer call did not declare the registers it clobbers,
# so every timer interrupt reported tick 1 — timed waits never woke, `sleep`
# never returned, and the demo stopped at its first user exit.  Both are
# invisible to a type check and loud in a boot.
#
# What the boot has to show: the kernel comes up on its own runtime tables and
# hands control to the scheduler, the service supervisor starts the three kernel
# workers and the shell and the demo launcher, the launcher's U-mode payload runs
# and exits, the demo workers sleep through their steps — which is the timed-wait
# path, and the one the tick bug broke — and every service stops, which is the
# process-exit wakeup path.  The boot then sits at the shell prompt, which is why
# the check ends on a timeout rather than on a shutdown.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
# The kernel embeds a 512 MiB physical-frame pool as a static BSS array, so the
# demo's user slots sit near the top of a gigabyte of address space; 2 GiB keeps
# them comfortably inside RAM (`-m 1G` also boots, but with no margin).
QEMU_RAM="${QEMU_RAM:-2G}"
QEMU_RISCV64="${QEMU_RISCV64:-qemu-system-riscv64}"
RISCV64_RUNTIME_LOG="${RISCV64_RUNTIME_LOG:-}"
FEATURES="${FEATURES:-demo-disk}"
# Which copy of the demo payload the boot must report: the one this build
# assembled (the default) or the one frozen on disk, when the caller asked for
# the ABI gate.  Asserting it is what keeps a gate that means to run an old
# program from passing on a new one.
PAYLOAD_SOURCE="${PAYLOAD_SOURCE:-compiled}"

KERNEL_BIN="${TARGET_DIR}/riscv64gc-unknown-none-elf/${PROFILE}/${CRATE}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

if ! command -v "$QEMU_RISCV64" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the riscv64 runtime check.\n' "$QEMU_RISCV64" >&2
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the riscv64 runtime check.\n' >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target riscv64gc-unknown-none-elf --bin "$CRATE" \
    --features "$FEATURES"

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'riscv64 kernel binary not found: %s\n' "$KERNEL_BIN" >&2
    exit 1
fi

remove_log_on_exit=0
if [ -n "$RISCV64_RUNTIME_LOG" ]; then
    mkdir -p "$(dirname "$RISCV64_RUNTIME_LOG")"
    log_file="$RISCV64_RUNTIME_LOG"
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

set -- \
    -machine virt \
    -global virtio-mmio.force-legacy=false \
    -cpu rv64 \
    -smp 1 \
    -m "$QEMU_RAM" \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-device,netdev=net0

# The console is a two-way line on this machine too: what this script reads is
# the guest's serial output, and the same line is where the shell gets its
# commands.  `-serial stdio` with the output redirected is what can type at the
# prompt, and typing is the half of the shell a boot by itself never exercises.
shell_commands() {
    sh ./scripts/feed-shell-console.sh "$log_file" "$TIMEOUT_SECONDS" \
        'help' 'echo ring3-shell-answered' \
        'cat /service/shell/origin' 'cat /service/shell/sha256'
}

printf 'riscv64 runtime check: 1 cpu, timeout %ss, qemu %s\n' \
    "$TIMEOUT_SECONDS" "$QEMU_RISCV64"
printf '  %s\n' "timeout ${TIMEOUT_SECONDS}s $QEMU_RISCV64 $* -serial stdio >$log_file"

set +e
shell_commands | timeout "${TIMEOUT_SECONDS}s" "$QEMU_RISCV64" "$@" -serial stdio \
    >"$log_file" 2>>"$log_file"
status=$?
set -e

# 124 is `timeout` killing a machine that is, by design, still running: the demo
# ends at the shell prompt, and the shell waits for input.
case "$status" in
    0|124) ;;
    *)
        printf 'riscv64 runtime check failed with exit status %s\n' "$status" >&2
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

fail_with_log() {
    reason="$1"
    printf 'riscv64 runtime check failed: %s\n' "$reason" >&2
    # Keep the whole log.  A failure that cannot be reproduced on the next run
    # is only diagnosable if the run that failed left its evidence behind, and
    # a gate that goes red once in a while is exactly that kind of failure.
    preserved="${TMPDIR:-/tmp}/protofire-riscv64-runtime-failed.log"
    if cp "$log_file" "$preserved" 2>/dev/null; then
        printf '  full log preserved at: %s\n' "$preserved" >&2
    fi
    printf '  last lines of the log:\n' >&2
    # `strings` rather than `cat`: OpenSBI's banner leaves a NUL in the log.
    tail -n 12 "$log_file" | tr -d '\000' >&2
    if [ "$remove_log_on_exit" = "0" ]; then
        printf '  full log preserved at: %s\n' "$log_file" >&2
    else
        printf '  re-run with RISCV64_RUNTIME_LOG=<path> to keep the log\n' >&2
    fi
    exit 1
}

require_log_line() {
    pattern="$1"
    if ! grep -a -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line: $pattern"
    fi
}

require_log_exact_line() {
    line="$1"
    if ! grep -a -F -x "$line" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line (whole line): $line"
    fi
}

require_log_matching() {
    pattern="$1"
    if ! grep -a -E "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "no log line matches: $pattern"
    fi
}

require_log_line_count() {
    pattern="$1"
    expected_count="$2"
    count="$(
        grep -a -c -F "$pattern" "$log_file" || true
    )"
    if [ "$count" != "$expected_count" ]; then
        fail_with_log "unexpected log count for $pattern: expected=$expected_count actual=$count"
    fi
}

first_log_line_number() {
    pattern="$1"
    awk -v needle="$pattern" '
        index($0, needle) { print NR; found = 1; exit }
        END { if (!found) exit 1 }
    ' "$log_file"
}

require_log_line_order() {
    first_pattern="$1"
    second_pattern="$2"
    first_line="$(first_log_line_number "$first_pattern")" || {
        fail_with_log "missing log line for order check: $first_pattern"
    }
    second_line="$(first_log_line_number "$second_pattern")" || {
        fail_with_log "missing log line for order check: $second_pattern"
    }
    if [ "$first_line" -ge "$second_line" ]; then
        fail_with_log "out of order: $first_pattern (line $first_line) should precede $second_pattern (line $second_line)"
    fi
}

require_log_absent_line() {
    pattern="$1"
    if grep -a -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "unexpected log line: $pattern"
    fi
}

# ── The boot reached the hand-off point ────────────────────────────────
require_log_line "Protofire kernel prototype starting"
require_log_line "[boot:loader] qemu-direct"
require_log_line "[mem   ] prepared riscv64 kernel page tables"
require_log_line "[mem   ] activated riscv64 kernel page tables"
require_log_line "[user  ] prepared riscv64 U-mode demo slots=8"
require_log_line "[user  ] loaded /apps/packages/shell/bin/shell.elf id=shell"
require_log_line "[user  ] loaded /apps/packages/demo-launcher/bin/demo.elf id=demo-launcher"
require_log_line "[user  ] image-plan span="
require_log_line "[user  ] process-root root=0x"
require_log_line "[init  ] starting idle process"
require_log_line "protofire kernel running"

# ── The shell is ring-3 code, and it answered what was typed at it ─────
#
# `adastra ring3 shell` is the shell payload's own banner; the in-kernel host
# proxy it replaced printed `protofire shell (user)`, so asserting the new line
# is what keeps a boot from passing on the proxy after this changed.  The prompt
# carries the directory the kernel says the process is in — the manifest's
# `working_dir`, not something the shell remembered.
#
# Those lines are also printed by a shell that never reads a command, which is
# how the recovered assembly shell the other architectures replaced passed for
# as long as nothing typed at it: banner, prompt, and then a fault on the first
# line.  A boot that is never typed at cannot tell those two apart, so this
# check types; `scripts/feed-shell-console.sh` is what does it.
require_log_line "adastra ring3 shell"
require_log_line "adastra:/apps/packages/shell\$ "
require_log_line "[abi   ] shell payload: $PAYLOAD_SOURCE "
require_log_line "adastra shell (ring 3) builtins:"
require_log_exact_line "ring3-shell-answered"
# The service manager's provenance, read back by a ring-3 program: which
# declaration file the kernel read the shell's definition from, and the SHA-256
# of that file's bytes.  Both answers come from `/service`, so a boot whose
# registry lost track of where its services came from cannot print them.
require_log_exact_line "/system/rc.d/defaults.toml"
require_log_matching '^[0-9a-f]{64}$'
# `/system/init.elf` is a program on this target too: it reads the declarations
# off the disk and asks for the services to be started, and says so.  The boot
# left the start to it rather than starting them itself — that line is the
# hand-off, and without it the services below would prove the kernel started
# them, not init.
require_log_line "adastra init (ring 3): reading /system/rc.d"
require_log_line "adastra init: declared "
require_log_line "service(s) registered; leaving the start to init"

# ── The user program ran, and left ─────────────────────────────────────
#
# The payload is the only thing in the boot that proves the U-mode path ran:
# every line above it is printed before the hand-off, and a machine that stops
# at the hand-off still has all of them.
require_log_line "[user  ] riscv64 payload start"
require_log_line "[user  ] riscv64 app-id: demo-launcher"
require_log_line "[abi   ] demo-launcher payload: $PAYLOAD_SOURCE "
require_log_line "[user  ] riscv64 payload resume-1"
require_log_line "[user  ] riscv64 payload resume-2"
require_log_line "[user  ] exit pid="
require_log_line "id=demo-launcher status=42"

# ── The timed waits woke ───────────────────────────────────────────────
#
# The workers sleep between steps, so "step 1" and "done" can only appear if a
# deadline elapsed.  This is the assertion the SBI clobber bug failed: with
# every tick reported as 1, nothing ever expired and the log ended at the first
# user exit.
require_log_line "[demo  ] worker-a step 1"
require_log_line "[demo  ] worker-b step 1"
require_log_line "[demo  ] worker-a done"
require_log_line "[demo  ] worker-b done"

# ── The services stopped ───────────────────────────────────────────────
#
# Each of these is a supervisor thread waking on a child's exit.
require_log_line "[service] kernel thread kworker-a started"
require_log_line "[service] demo-launcher stopped"
require_log_line "[service] kworker-a stopped"
require_log_line "[service] kworker-b stopped"
require_log_line "[service] kworker-syscall-fs stopped"

require_log_line_order "[init  ] starting idle process" "protofire kernel running"
require_log_line_order "[user  ] riscv64 payload start" "[user  ] riscv64 payload resume-2"
require_log_line_order "[user  ] riscv64 payload resume-2" "[user  ] exit pid="
require_log_line_order "[service] kernel thread kworker-a started" "[service] kworker-a stopped"

require_log_line_count "[user  ] riscv64 payload start" 1
require_log_line_count "[user  ] exit pid=" 1

# ── Nothing reported damage ────────────────────────────────────────────
#
# Deliberately *not* asserted here: `[thread] kernel stack guard pages are not
# enforced`.  riscv64 has no stack window yet, so its stacks come from the
# frame-backed fallback and the guard really is missing; the kernel now says so
# instead of claiming otherwise.  When riscv64 gets a window, the line becomes
# a failure here, exactly as it already is in the aarch64 check.
require_log_absent_line "[FATAL]"
require_log_absent_line "[WARN ] riscv64"
require_log_absent_line "unhandled riscv64"
require_log_absent_line "[thread] kernel stack map_region failed"
# The window serves this boot's stacks, so the frame-backed shape — the one
# whose guard cannot be enforced here — is a shape nothing should have taken.
require_log_absent_line "[thread] kernel stack guard pages are not enforced"

if [ "$remove_log_on_exit" = "0" ]; then
    printf 'riscv64 runtime log saved to %s\n' "$log_file"
fi

printf 'riscv64 runtime check passed\n'
