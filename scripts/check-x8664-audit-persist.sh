#!/usr/bin/env sh
# File: scripts/check-x8664-audit-persist.sh
# Purpose: Boot with `audit=persist`, play a few commands, and require the
#   audit log the kernel wrote to be readable from the guest's own shell.
#
# Why this exists
# ---------------
# The audit subsystem's persistence path — the maintenance thread draining the
# ring buffer to `/data/audit.log`, append, sync, commit — was written and
# unit-tested, but **nothing enabled it**: `set_persistence` had no caller, and
# no process turned on the capture mask, so the ring filled with nothing and
# nothing was written.  `docs/status.md` recorded it as "only the switch is
# missing", and this is the switch and its proof together.
#
# The switch is the command-line option `audit=persist`, which turns on the
# maintenance thread's drain to `/data/audit.log`.  On a machine whose processes
# have not asked for capture of their own (`AuditSetEnable` #143) the records
# that reach the file are the kernel's own — a privileged service's `AuthEvent`,
# a `MacDenial`, and the `ConfigChange` this very boot emits to say it turned
# persistence on.  That last one is the first record in the file, and it is what
# this gate reads back.
#
# The option is also the first thing to read the **PVH** hand-off's own command
# line: a direct `-kernel` boot carries one, and the kernel read only the
# Multiboot2 tag, so before this a direct boot had no command line at all — the
# option could not have reached the kernel to begin with.
#
# The gate types at the shell (the whole userspace path: `open`, `read`) and
# requires the serialized record to come back out of `/data/audit.log`.  It also
# checks the default is unchanged: a boot with no `audit=` says it is
# memory-only, which is the decision this leaves with the operator.
#
# Usage:
#   sh scripts/check-x8664-audit-persist.sh [timeout-seconds]

set -eu

cd "$(dirname "$0")/.."

TIMEOUT_SECONDS="${1:-60}"
PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
QEMU="${QEMU:-qemu-system-x86_64}"
FEATURES="${FEATURES:-demo-disk}"
KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the audit check.\n' "$QEMU" >&2
    exit 1
fi
if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the audit check.\n' >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
    --features "$FEATURES"
[ -f "$KERNEL_BIN" ] || { printf 'x86_64 kernel binary not found: %s\n' "$KERNEL_BIN" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

fail() {
    printf 'x86_64 audit-persist check failed: %s\n' "$1" >&2
    tail -n 15 "$work/boot.log" >&2
    exit 1
}

# ── The default is unchanged: no `audit=` means memory-only ────────────
#
# This is the decision the change deliberately leaves with the operator, so a
# boot that made persistence the default would fail here rather than pass
# quietly.
default_log="$work/default.log"
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 -cpu max -smp 1 -m 1G \
    -kernel "$KERNEL_BIN" -display none -no-reboot -no-shutdown \
    -serial "file:$default_log" >/dev/null 2>&1 || true
grep -a -F "[audit ] memory-only" "$default_log" >/dev/null 2>&1 ||
    fail "a boot with no audit= option did not say it was memory-only"

# ── `audit=persist`: capture, record, and read it back ────────────────
#
# The feeder pauses between lines, so the `cat` lands well after the first
# flush (the ring is drained every 200 ticks = 2 s).  The commands before it
# are space to get past that flush; any of them produces audited syscalls once
# capture is on.
boot_log="$work/boot.log"
sh ./scripts/feed-shell-console.sh "$boot_log" "$TIMEOUT_SECONDS" \
    'pwd' 'pwd' 'pwd' 'cat /data/audit.log' 'echo audit-persist-done' |
    timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
        -machine q35 -cpu max -smp 1 -m 1G \
        -kernel "$KERNEL_BIN" -append "audit=persist" \
        -display none -no-reboot -no-shutdown \
        -serial stdio >"$boot_log" 2>&1 || true

grep -a -F "[audit ] persistence enabled (audit=persist)" "$boot_log" >/dev/null 2>&1 ||
    fail "the boot did not report that persistence was enabled"
grep -a -F "audit-persist-done" "$boot_log" >/dev/null 2>&1 ||
    fail "the shell did not reach the end of the typed commands"

# The record itself, as the guest's own `cat` read it back: the serialized form
# is `<timestamp> <event> pid=... seq=... data=<hex>`, and the boot's own
# `ConfigChange` record carries the log path in hex — `data=2f646174612f61756469
# 742e6c6f67` is `/data/audit.log`.  Requiring that record and not "any line"
# proves not only that a record landed but that it is the one the boot claims to
# have written.
#
# `grep -c` exits 1 when it matches nothing, which under `set -e` would end the
# script before the failure below could say why — so its status is taken and the
# count judged explicitly.
record="^[0-9]+ config_change pid=[0-9]+ uid=[0-9]+ result=0 seq=[0-9]+ data=2f646174612f61756469742e6c6f67$"
count="$(grep -acE "$record" "$boot_log" || true)"
[ "$count" -ge 1 ] ||
    fail "the boot's own ConfigChange record did not come back out of /data/audit.log"

printf 'x86_64 audit-persist check passed: default stays memory-only, and audit=persist recorded the ConfigChange the shell read back\n'
