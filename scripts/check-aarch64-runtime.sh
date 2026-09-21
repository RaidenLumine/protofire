#!/usr/bin/env sh
# File: scripts/check-aarch64-runtime.sh
# Purpose: Headless QEMU smoke test for the current AArch64 fault/wait boundary.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-20}"
# The kernel embeds a 512 MiB physical-frame pool as a static BSS array, so the
# loaded image spans ~1.6 GiB of address space.  QEMU's `-kernel` loader refuses
# to fit it into the default 512 MiB, so default to 2 GiB (override via QEMU_RAM).
QEMU_RAM="${QEMU_RAM:-2G}"
QEMU_AARCH64="${QEMU_AARCH64:-qemu-system-aarch64}"
KERNEL_BIN="${TARGET_DIR}/aarch64-unknown-none/${PROFILE}/${CRATE}"
AARCH64_RUNTIME_LOG="${AARCH64_RUNTIME_LOG:-}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

if ! command -v "$QEMU_AARCH64" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the aarch64 runtime check.\n' "$QEMU_AARCH64" >&2
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the aarch64 runtime check.\n' >&2
    exit 1
fi

# The runtime assertions below (demo slots, demo-launcher payload, aarch64
# EL0 fault/wait) all require the in-memory demo volume, which is compiled in
# only when the `demo-disk` cargo feature is enabled.  Build with it explicitly
# rather than relying on `make build-aarch64` (which does not enable it).
case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target aarch64-unknown-none --bin "$CRATE" --features demo-disk

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'aarch64 kernel binary not found: %s\n' "$KERNEL_BIN" >&2
    exit 1
fi

remove_log_on_exit=0
if [ -n "$AARCH64_RUNTIME_LOG" ]; then
    mkdir -p "$(dirname "$AARCH64_RUNTIME_LOG")"
    log_file="$AARCH64_RUNTIME_LOG"
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

set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU_AARCH64" \
    -machine virt \
    -cpu max \
    -smp 1 \
    -m "$QEMU_RAM" \
    -kernel "$KERNEL_BIN" \
    -display none \
    -serial stdio \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-device,netdev=net0 >"$log_file" 2>&1
status=$?
set -e

case "$status" in
    0|124) ;;
    *)
        printf 'aarch64 runtime check failed with exit status %s\n' "$status" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

require_log_line() {
    pattern="$1"
    if ! grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        printf 'missing aarch64 runtime log: %s\n' "$pattern" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    fi
}

require_log_line_count() {
    pattern="$1"
    expected_count="$2"
    count="$(
        awk -v needle="$pattern" '
            index($0, needle) { count += 1 }
            END { print count + 0 }
        ' "$log_file"
    )"
    if [ "$count" != "$expected_count" ]; then
        printf 'unexpected aarch64 runtime log count for %s: expected=%s actual=%s\n' \
            "$pattern" "$expected_count" "$count" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    fi
}

first_log_line_number() {
    pattern="$1"
    awk -v needle="$pattern" '
        index($0, needle) {
            print NR
            found = 1
            exit
        }
        END {
            if (!found) {
                exit 1
            }
        }
    ' "$log_file"
}

require_log_line_order() {
    first_pattern="$1"
    second_pattern="$2"
    first_line="$(first_log_line_number "$first_pattern")" || {
        printf 'missing aarch64 runtime log for order check: %s\n' "$first_pattern" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    }
    second_line="$(first_log_line_number "$second_pattern")" || {
        printf 'missing aarch64 runtime log for order check: %s\n' "$second_pattern" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    }
    if [ "$first_line" -ge "$second_line" ]; then
        printf 'unexpected aarch64 runtime log order: %s (line %s) should appear before %s (line %s)\n' \
            "$first_pattern" "$first_line" "$second_pattern" "$second_line" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    fi
}

require_log_absent_line() {
    pattern="$1"
    if grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        printf 'unexpected aarch64 runtime log: %s\n' "$pattern" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    fi
}

require_log_lines() {
    while IFS= read -r pattern; do
        [ -n "$pattern" ] || continue
        require_log_line "$pattern"
    done
}

require_log_line_orders() {
    while IFS='|' read -r first_pattern second_pattern; do
        [ -n "$first_pattern" ] || continue
        require_log_line_order "$first_pattern" "$second_pattern"
    done
}

require_log_absent_lines() {
    while IFS= read -r pattern; do
        [ -n "$pattern" ] || continue
        require_log_absent_line "$pattern"
    done
}

# Keep this contract aligned with the target-side behaviour verified against
# the actual aarch64 QEMU runtime output.
#
# What this boot has to show: the kernel comes up on its own runtime tables
# (device window, RAM window, and the stack window its own stacks live in) and
# hands control to the scheduler; the service supervisor starts the three
# kernel workers and the three user programs; the aarch64-rust payload takes
# a code-write fault, a stack-exec fault and a nested code-write fault from
# EL0 and resumes after each; two child processes run off the end of their
# stacks and are terminated; the demo workers run to completion; and every
# service stops.
#
# 2026-06-26: the spawn/wait race is fixed via
# PROCESS_SPAWN_FLAG_START_SUSPENDED — children stay suspended until the
# parent calls wait, so a child cannot fault before the parent is ready.  The
# deferred-drop fix for PreparedProcessAddressSpace (moving the drop from the
# trap handler with IRQs disabled to the reap path with IRQs enabled) also
# resolved a pre-existing hang during process termination on aarch64.
require_log_lines <<'EOF'
Protofire kernel prototype starting
[boot:loader] qemu-direct
[boot:init] initializing subsystems
[mem   ] prepared aarch64 kernel page tables
windows=3
[user  ] prepared aarch64 EL0 demo slots=8
exception-stack=
[user  ] loaded /apps/packages/shell/bin/shell.elf id=shell
[user  ] loaded /apps/packages/demo-launcher/bin/demo.elf id=demo-launcher
[user  ] loaded /apps/packages/demo-launcher-rust/bin/demo.elf id=demo-launcher-rust
[user  ] process-root root=0x
kernel=524288 user=
[init  ] starting idle process
protofire kernel running
protofire shell (user)
[user  ] hello from aarch64 rust payload
[user  ] aarch64-rust triggering local code-write fault
[user  ] aarch64-rust resumed after local code-write fault
[user  ] aarch64-rust resumed after local stack-exec fault
[user  ] aarch64-rust triggering nested local code-write fault
[user  ] aarch64-rust resumed after nested local code-write fault
[user  ] aarch64 child stack-exec fault
[user] terminating pid=
access=execute
[user  ] aarch64-rust wait-vector: 0x0000000000000020
[user  ] aarch64-rust wait-error: 0x000000000000000f
[user  ] aarch64-rust wait-fsc: 0x000000000000000f
[user  ] aarch64-rust wait-access: 0x0000000000000002
[user  ] aarch64-rust wait-kind: 0x0000000000000002
[demo  ] worker-a step 0
[demo  ] worker-a done
[demo  ] worker-b step 0
[demo  ] worker-b done
[service] kernel thread kworker-a started
[service] kworker-a stopped
[service] kworker-b stopped
[service] kworker-syscall-fs stopped
[service] demo-launcher stopped
[service] demo-launcher-rust stopped
EOF

# Twice each, because the payload runs twice: once as the launcher and once as
# the image that launcher starts.  The counts are the assertion that the two
# runs both got all the way through their faults and both came back.
require_log_line_count "[user  ] hello from aarch64 rust payload" 2
require_log_line_count "[user  ] aarch64-rust resumed after local code-write fault" 2
require_log_line_count "[user  ] aarch64-rust resumed after local stack-exec fault" 2
require_log_line_count "[user  ] aarch64-rust resumed after nested local code-write fault" 2
require_log_line_count "[user  ] aarch64 child stack-exec fault" 2
require_log_line_count "[user  ] aarch64-rust wait-vector: 0x0000000000000020" 2
require_log_line_count "[user  ] aarch64-rust wait-fsc: 0x000000000000000f" 2

# ── Network boot smoke tests ───────────────────────────────────────────
# FIXME: Re-enable when aarch64 VirtIO networking is stable.
# require_log_line "[driver] detected boot network device"
# require_log_line "[kernel] network stack initialized"

require_log_line_orders <<'EOF'
[user  ] hello from aarch64 rust payload|[user  ] aarch64-rust triggering local code-write fault
[user  ] aarch64-rust triggering local code-write fault|[user  ] aarch64-rust resumed after local code-write fault
[user  ] aarch64-rust resumed after local code-write fault|[user  ] aarch64-rust resumed after local stack-exec fault
[user  ] aarch64-rust resumed after local stack-exec fault|[user  ] aarch64-rust triggering nested local code-write fault
[user  ] aarch64-rust resumed after nested local code-write fault|[user  ] aarch64 child stack-exec fault
[user  ] aarch64 child stack-exec fault|[user  ] aarch64-rust wait-vector: 0x0000000000000020
[init  ] starting idle process|protofire kernel running
[service] kernel thread kworker-a started|[service] kworker-a stopped
[demo  ] worker-a step 1|[demo  ] worker-a done
[demo  ] worker-b step 1|[demo  ] worker-b done
EOF

require_log_absent_lines <<'EOF'
[user  ] aarch64 child code-write unexpectedly succeeded
[user  ] aarch64 child stack-exec unexpectedly succeeded
[user  ] aarch64 child stack-guard unexpectedly succeeded
[user  ] aarch64-rust install-handler failed:
[user  ] aarch64-rust handler-state-fail:
[WARN ] aarch64 lower-el sync fatal
[user  ] refusing invalid aarch64 entry frame
[user  ] refusing invalid aarch64 return frame
[FATAL] invalid aarch64
[FATAL] aarch64 trap
EOF

# The kernel stack's guard page is part of the boot contract, not a property
# of the machine the boot happens to run on.  A stack lives in the
# architecture's own window, its guard is the slice of that window the
# allocator never hands out, and the kernel's tables cover what they say they
# cover — so a guard that had to be reported as missing, or a kernel range the
# facts describe but the tables do not map, fails this check rather than
# showing up later as an overflow that corrupts memory instead of faulting.
require_log_absent_lines <<'EOF'
[thread] kernel stack guard pages are not enforced
[mm    ] kernel table gap
EOF

require_log_absent_line "[user  ] aarch64-rust spawn failed: "
require_log_absent_line "[user  ] aarch64-rust wait failed: "
require_log_absent_line "[user  ] aarch64 wait-status: 0xffffffffffffffff"
require_log_absent_line "[user  ] aarch64-rust wait-status: 0xffffffffffffffff"
require_log_absent_line "[user  ] aarch64 exec-error: "
require_log_absent_line "[user  ] aarch64 spawn-status: "
require_log_absent_line "[user  ] aarch64-rust net-udp-send fail:"

if [ "$remove_log_on_exit" = "0" ]; then
    printf 'aarch64 runtime log saved to %s\n' "$log_file"
fi

printf 'aarch64 runtime check passed at current metadata/fault/wait boundary\n'
