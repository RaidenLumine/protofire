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

require_log_exact_once_lines() {
    while IFS= read -r pattern; do
        [ -n "$pattern" ] || continue
        require_log_line_count "$pattern" 1
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
# 2026-06-26: The spawn/wait race is now fixed via PROCESS_SPAWN_FLAG_START_SUSPENDED.
# The child processes stay suspended until the parent calls wait, eliminating the
# race where a child could fault before the parent was ready.  The deferred-drop
# fix for PreparedProcessAddressSpace (moving the drop from the trap handler
# with IRQs disabled to the reap path with IRQs enabled) also resolved a pre-
# existing hang during process termination on aarch64.
require_log_lines <<'EOF'
protofire kernel prototype starting
[boot:loader] qemu-direct
[boot:init] initializing subsystems
[user  ] prepared aarch64 EL0 demo slots=4
exception-stack=
[user  ] loaded /apps/packages/demo-launcher/bin/demo.elf id=demo-launcher version=0.1.0
user=82 tables=3
id=demo-launcher-rust version=0.1.0
[user  ] aarch64 payload start
[user  ] aarch64 app-id: demo-launcher
[user  ] aarch64 image: /apps/packages/demo-launcher/bin/demo.elf
[user  ] aarch64 cwd: /apps/packages/demo-launcher
[user  ] aarch64 argv0: demo-launcher
[user  ] aarch64 env0: ASTRA_APP_ID=demo-launcher
[user  ] aarch64 reg-argc: 0x0000000000000004
[user  ] aarch64 stack-argc: 0x0000000000000004
[user  ] aarch64 stack-argv0: demo-launcher
[user  ] aarch64 stack-env0: ASTRA_APP_ID=demo-launcher
[user  ] aarch64 exec-request
[user  ] aarch64 app-id: demo-launcher-exec
[user  ] aarch64 image: /apps/packages/demo-launcher-exec/bin/demo.elf
[user  ] aarch64 cwd: /apps/packages/demo-launcher-exec
[user  ] aarch64 argv0: demo-launcher-exec
[user  ] aarch64 env0: ASTRA_EXEC=1
[user  ] aarch64 reg-argc: 0x0000000000000001
[user  ] aarch64 stack-argc: 0x0000000000000001
[user  ] aarch64 stack-argv0: demo-launcher-exec
[user  ] aarch64 stack-env0: ASTRA_EXEC=1
[user  ] aarch64 exec-child
[user  ] hello from aarch64 rust payload
[user  ] aarch64-rust trigger local code-write fault
[user  ] aarch64-rust local-vector: 0x0000000000000024
[user  ] aarch64-rust local-fsc: permission fault level 3
[user  ] aarch64-rust local-access: write
[user] aarch64 handler-preempt-resume
[user  ] aarch64 payload resume-1
[user  ] aarch64 payload resume-2
[user  ] aarch64-rust handler-state-ok
[user  ] aarch64-rust resumed after local code-write handler
[user  ] aarch64-rust trigger local stack-exec fault
[user  ] aarch64 child code-write fault
[user  ] aarch64 code-write wait-vector: 0x0000000000000024
[user  ] aarch64 child stack-exec fault
[user  ] aarch64 stack-exec wait-vector: 0x0000000000000020
[user  ] aarch64 child stack-guard fault
[user  ] aarch64 stack-guard wait-vector: 0x0000000000000024
EOF

require_log_exact_once_lines <<'EOF'
[user  ] aarch64 exec-child
[user  ] aarch64 payload resume-1
[user  ] aarch64 payload resume-2
[user  ] aarch64-rust resumed after local code-write handler
[user  ] aarch64 child code-write fault
[user  ] aarch64 code-write wait-vector: 0x0000000000000024
[user  ] aarch64 stack-exec wait-vector: 0x0000000000000020
[user  ] aarch64 child stack-guard fault
[user  ] aarch64 stack-guard wait-vector: 0x0000000000000024
EOF

require_log_line_count "[user  ] aarch64-rust handler-state-ok" 5
require_log_line_count "[user  ] aarch64 child stack-exec fault" 2
require_log_line_count "[user  ] aarch64 reg-argv: 0x" 2
require_log_line_count "[user  ] aarch64 reg-envp: 0x" 2

# ── Network boot smoke tests ───────────────────────────────────────────
# FIXME: Re-enable when aarch64 VirtIO networking is stable.
# require_log_line "[driver] detected boot network device"
# require_log_line "[kernel] network stack initialized"

require_log_line_orders <<'EOF'
[user  ] hello from aarch64 rust payload|[user  ] aarch64-rust trigger local code-write fault
[user  ] aarch64-rust trigger local code-write fault|[user  ] aarch64-rust resumed after local code-write handler
[user  ] aarch64-rust resumed after local code-write handler|[user  ] aarch64-rust trigger local stack-exec fault
[user  ] aarch64 app-id: demo-launcher|[user  ] aarch64 exec-request
[user  ] aarch64 exec-request|[user  ] aarch64 app-id: demo-launcher-exec
[user  ] aarch64 stack-env0: ASTRA_EXEC=1|[user  ] aarch64 exec-child
[user  ] aarch64 exec-child|[user  ] aarch64 payload resume-1
[user  ] aarch64 payload resume-1|[user  ] aarch64 payload resume-2
[user  ] aarch64-rust trigger local stack-exec fault|[user  ] aarch64 child code-write fault
[user  ] aarch64 child code-write fault|[user  ] aarch64 code-write wait-vector: 0x0000000000000024
[user  ] aarch64 code-write wait-vector: 0x0000000000000024|[user  ] aarch64 child stack-exec fault
[user  ] aarch64 child stack-exec fault|[user  ] aarch64 stack-exec wait-vector: 0x0000000000000020
[user  ] aarch64 stack-exec wait-vector: 0x0000000000000020|[user  ] aarch64 child stack-guard fault
[user  ] aarch64 child stack-guard fault|[user  ] aarch64 stack-guard wait-vector: 0x0000000000000024
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
