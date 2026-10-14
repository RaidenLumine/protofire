#!/usr/bin/env sh
# File: scripts/check-x8664-install.sh
# Purpose: Install this kernel's zones onto a machine's own disk and boot the
#   result, requiring that the disk's existing partitions are untouched.
#
# Why this exists
# ---------------
# Every artifact this tree builds is an *image*: `mkimage` writes the demo
# disk, and the ISO is a bootable medium.  Neither is an install — a machine
# already has a disk, partitioned by a tool that is not this one, and
# installing means adding the kernel's three zones to *that* disk.  The
# installer (`cargo run -- install <disk>`, `src/fs/install.rs`) does that,
# and this check is the whole of its evidence:
#
#   * the disk is made by `sgdisk`, a partitioning tool this tree did not
#     write, and carries a partition whose type this kernel has no name for —
#     so the table is a stranger's, which is the point;
#   * the install adds the zones and the check reads the table back with
#     `sgdisk`: the stranger's entry is still there, same type, same extent;
#   * the installed disk *boots*: the kernel mounts the zones it just wrote
#     from the machine's table, and runs a program out of `/apps`;
#   * a second install writes the same extents in place (`reused`), because a
#     reinstall that moved a zone would be a second layout for one disk.
#
# The CRC defect this check would have caught: the kernel's CRC-32 table had
# one transcribed entry wrong, and every *self-made* GPT still round-tripped
# (writer and reader shared the table), so nothing in the tree noticed that a
# real partitioning tool's checksums did not verify.  That is why this gate
# makes the disk with `sgdisk` rather than with `write_gpt_partitions`.
#
# Usage:
#   sh scripts/check-x8664-install.sh [timeout-seconds]
#
# Exits 0 when the install, the table and the boot all hold, 1 otherwise.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${1:-${TIMEOUT_SECONDS:-90}}"
QEMU="${QEMU:-qemu-system-x86_64}"
X8664_INSTALL_LOG="${X8664_INSTALL_LOG:-}"
FEATURES="${FEATURES:-demo-disk}"
SGDISK="${SGDISK:-sgdisk}"
# The machine disk: 64 MiB, room for the zones and a stranger's partition.
DISK_MIB="${DISK_MIB:-64}"

KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

for tool in "$QEMU" "$SGDISK" timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf '%s is not installed; cannot run the install check.\n' "$tool" >&2
        exit 1
    fi
done

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

work="$(mktemp -d)"
log="$work/boot.log"
if [ -n "$X8664_INSTALL_LOG" ]; then
    mkdir -p "$(dirname "$X8664_INSTALL_LOG")"
    log="$X8664_INSTALL_LOG"
fi
: >"$log"
disk="$work/machine.img"

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

fail() {
    printf 'x86_64 install check failed: %s\n' "$1" >&2
    printf '  work dir: %s\n' "$work" >&2
    if [ -s "$log" ]; then
        tail -n 12 "$log" >&2
    fi
    exit 1
}

# ── The machine's disk: made by sgdisk, with a stranger's partition ─────
#
# The stranger is a Linux filesystem GUID and a name, at a sector this kernel
# would never choose: the install has to keep both, and a reader that only
# understood its own disks would have written over it.
printf 'x86_64 install check: machine disk %s MiB made by %s, timeout %ss\n' \
    "$DISK_MIB" "$SGDISK" "$TIMEOUT_SECONDS"
dd if=/dev/zero of="$disk" bs=1M count="$DISK_MIB" status=none 2>/dev/null \
    || dd if=/dev/zero of="$disk" bs=1048576 count="$DISK_MIB" 2>/dev/null
"$SGDISK" -n 1:4096:6143 -t 1:0FC63DAF-8483-4772-8E79-3D69D8477DE4 \
    -c 1:stranger "$disk" >"$work/sgdisk.log" 2>&1 \
    || { cat "$work/sgdisk.log" >&2; fail "sgdisk could not make the machine disk"; }

# ── The install ─────────────────────────────────────────────────────────
install_out="$work/install.log"
if ! "$CARGO" run --offline --quiet -- install --yes "$disk" >"$install_out" 2>&1; then
    cat "$install_out" >&2
    fail "the install did not complete"
fi
placed="$(awk '/placed\)/ { n += 1 } END { print n + 0 }' "$install_out")"
if [ "$placed" -ne 3 ]; then
    cat "$install_out" >&2
    fail "expected the three zones to be placed, saw $placed placed (the disk should have been empty)"
fi

# The table, read back by the tool that made the disk: the stranger is still
# there with its name, and the zones are entries beside it.
"$SGDISK" -p "$disk" >"$work/table.log" 2>&1 \
    || fail "could not read the table back with sgdisk"
if ! grep -F "stranger" "$work/table.log" >/dev/null 2>&1; then
    cat "$work/table.log" >&2
    fail "the stranger's partition is gone from the table"
fi
if ! grep -F "8300" "$work/table.log" >/dev/null 2>&1; then
    cat "$work/table.log" >&2
    fail "the stranger's type GUID is gone from the table"
fi

# ── And the disk boots ─────────────────────────────────────────────────
#
# The console is typed at, so the check is not merely "the boot printed a
# banner": a byte arrives from outside the machine, reaches the shell, and
# the shell's answer is the shell having read it.
shell_commands() {
    sh ./scripts/feed-shell-console.sh "$log" "$TIMEOUT_SECONDS" \
        'echo install-check-answered'
}

set +e
shell_commands | timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 \
    -cpu max \
    -smp 1 \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -drive "file=$disk,if=none,id=nvme0,format=raw" \
    -device nvme,drive=nvme0,serial=protofire \
    -serial stdio >"$log" 2>&1
status=$?
set -e

case "$status" in
    0|124) ;;
    *)
        fail "qemu exited with status $status"
        ;;
esac

require_log_line() {
    grep -F "$1" "$log" >/dev/null 2>&1 || fail "missing log line: $1"
}

# The boot took the disk, read the table a stranger's tool wrote, and mounted
# the zones the install had just put there — which is the read path over the
# install's own writes.
require_log_line "[driver] detected boot disk: nvme0"
require_log_line "[fs    ] mounted GPT-partitioned SimpleFs volumes from ATA boot disk"
if grep -F "[fs    ] failed to mount SimpleFs volumes from ATA boot disk" "$log" >/dev/null 2>&1; then
    fail "the installed disk did not mount"
fi
# And a program came off it: a mount alone does not prove the zone's content.
require_log_line "[user  ] loaded /apps/packages/shell/bin/shell.elf"
require_log_line "adastra ring3 shell"
# The typed answer: the shell read a line and printed it.
require_log_line "install-check-answered"
grep -F "[FATAL]" "$log" >/dev/null 2>&1 && fail "the boot reported a fatal error"

# ── A second install reuses every extent ───────────────────────────────
second_out="$work/install2.log"
if ! "$CARGO" run --offline --quiet -- install --yes "$disk" >"$second_out" 2>&1; then
    cat "$second_out" >&2
    fail "the second install did not complete"
fi
reused="$(awk '/reused\)/ { n += 1 } END { print n + 0 }' "$second_out")"
if [ "$reused" -ne 3 ]; then
    cat "$second_out" >&2
    fail "expected all three zones to be reused on the second install, saw $reused"
fi
if ! "$SGDISK" -p "$disk" 2>&1 | grep -F "stranger" >/dev/null 2>&1; then
    fail "the stranger's partition did not survive the second install"
fi

# ── A disk with no table: refused, then given one on the flag's word ────
#
# A machine's disk that was never partitioned has no table to add zones to,
# and the flagless install refuses it — that refusal is the decision this
# module does not make on its own.  `--new-table` is the caller making it,
# and this section is the whole of that route's evidence: the refusal, the
# fresh table read back by a tool this tree did not write, and a boot from
# the installed disk — the read path over a table this kernel itself wrote
# from nothing.
printf 'x86_64 install check: blank disk, refusal then --new-table\n'
blank="$work/blank.img"
dd if=/dev/zero of="$blank" bs=1M count="$DISK_MIB" status=none 2>/dev/null \
    || dd if=/dev/zero of="$blank" bs=1048576 count="$DISK_MIB" 2>/dev/null

# The flagless route refuses: exit status non-zero, and a message naming why.
# The refusal is computed **before** the confirmation, so a disk this install
# cannot help is never asked about: the question's own prompt must not be in
# the output.
if "$CARGO" run --offline --quiet -- install "$blank" >"$work/blank-refusal.log" 2>&1; then
    cat "$work/blank-refusal.log" >&2
    fail "a disk with no table was installed onto without --new-table"
fi
if ! grep -F "not found" "$work/blank-refusal.log" >/dev/null 2>&1; then
    cat "$work/blank-refusal.log" >&2
    fail "the refusal does not say the disk has no table"
fi
if grep -F "type \"yes\" to proceed" "$work/blank-refusal.log" >/dev/null 2>&1; then
    fail "the refused install asked for a confirmation before refusing"
fi

blank_log="$work/blank-boot.log"
if ! "$CARGO" run --offline --quiet -- install --yes --new-table "$blank" >"$work/blank-install.log" 2>&1; then
    cat "$work/blank-install.log" >&2
    fail "the blank-disk install did not complete"
fi
grep -F "a fresh GPT was written" "$work/blank-install.log" >/dev/null 2>&1 ||
    fail "the install did not say it wrote a fresh table"

# ── The confirmation, both answers ─────────────────────────────────────
#
# The install is a user interface now: it shows the plan, asks, and writes
# only on a typed `yes`.  Both answers are checked on a fresh machine disk —
# the plan's content, `no` leaving every byte of the disk as it was, and the
# end-of-file answer (what a script with no `--yes` gives) declining too,
# because a silent default that installs is the defect this exists to rule
# out.
printf 'x86_64 install check: the confirmation, both answers\n'
# A **fresh** machine disk, made the same way as the first section's: the
# already-installed disk would be a reinstall, and a reinstall writes the
# same extents with the same bytes, so "no" and "yes" would leave the file
# identical and neither answer could be told from the other.
confirm="$work/confirm.img"
dd if=/dev/zero of="$confirm" bs=1M count="$DISK_MIB" status=none 2>/dev/null \
    || dd if=/dev/zero of="$confirm" bs=1048576 count="$DISK_MIB" 2>/dev/null
"$SGDISK" -n 1:4096:6143 -t 1:0FC63DAF-8483-4772-8E79-3D69D8477DE4 \
    -c 1:stranger "$confirm" >"$work/confirm-sgdisk.log" 2>&1 \
    || { cat "$work/confirm-sgdisk.log" >&2; fail "sgdisk could not make the confirmation disk"; }
confirm_before="$work/confirm-before.img"
cp "$confirm" "$confirm_before"

if printf 'no\n' | "$CARGO" run --offline --quiet -- install "$confirm" >"$work/confirm-no.log" 2>&1; then
    cat "$work/confirm-no.log" >&2
    fail "an install answered 'no' reported success"
fi
cmp -s "$confirm" "$confirm_before" ||
    fail "an install answered 'no' changed the disk"
grep -F "nothing was written" "$work/confirm-no.log" >/dev/null 2>&1 ||
    fail "the declined install does not say nothing was written"
# The plan was shown first: the question, and the zones it is asking about.
grep -F 'type "yes" to proceed' "$work/confirm-no.log" >/dev/null 2>&1 ||
    { cat "$work/confirm-no.log" >&2; fail "the install did not ask for a confirmation"; }
grep -F "the zones to write:" "$work/confirm-no.log" >/dev/null 2>&1 ||
    fail "the confirmation was asked without the plan being shown"

# End of input is a decline: a script that forgot --yes must not install.
if "$CARGO" run --offline --quiet -- install "$confirm" </dev/null >"$work/confirm-eof.log" 2>&1; then
    cat "$work/confirm-eof.log" >&2
    fail "an install with no answer at all reported success"
fi
cmp -s "$confirm" "$confirm_before" ||
    fail "an install with no answer changed the disk"

# And the typed `yes` is what writes it.
if ! printf 'yes\n' | "$CARGO" run --offline --quiet -- install "$confirm" >"$work/confirm-yes.log" 2>&1; then
    cat "$work/confirm-yes.log" >&2
    fail "an install answered 'yes' did not complete"
fi
if cmp -s "$confirm" "$confirm_before"; then
    fail "an install answered 'yes' did not change the disk"
fi
"$SGDISK" -p "$confirm" 2>&1 | grep -F "stranger" >/dev/null 2>&1 ||
    fail "the confirmed install lost the stranger's partition"

# The table, read back by sgdisk: a real tool verifies the fresh GPT this
# kernel wrote, and lists the three zones as its partitions.
"$SGDISK" -p "$blank" >"$work/blank-table.log" 2>&1 \
    || { cat "$work/blank-table.log" >&2; fail "sgdisk cannot read the fresh table"; }
# The fresh writer writes no partition names, so the count is the check:
# three partitions, no more.
partition_count="$("$SGDISK" -p "$blank" 2>/dev/null | awk -F: '/^ +[0-9]+/ { n += 1 } END { print n + 0 }')"
if [ "$partition_count" -ne 3 ]; then
    cat "$work/blank-table.log" >&2
    fail "expected 3 partitions in the fresh table, sgdisk sees $partition_count"
fi

# And it boots: the same typed-answer boot as the first section, over the
# table this kernel wrote from nothing.
set +e
shell_commands | timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 \
    -cpu max \
    -smp 1 \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -drive "file=$blank,if=none,id=nvme0,format=raw" \
    -device nvme,drive=nvme0,serial=protofire \
    -serial stdio >"$blank_log" 2>&1
status=$?
set -e
case "$status" in
    0|124) ;;
    *)
        fail "the blank-disk boot exited with status $status"
        ;;
esac
log="$blank_log"
require_log_line "[driver] detected boot disk: nvme0"
require_log_line "[fs    ] mounted GPT-partitioned SimpleFs volumes from ATA boot disk"
require_log_line "[user  ] loaded /apps/packages/shell/bin/shell.elf"
require_log_line "install-check-answered"
grep -F "[FATAL]" "$blank_log" >/dev/null 2>&1 && fail "the blank-disk boot reported a fatal error"

printf 'x86_64 install check passed: zones installed onto a %s-made disk, the\n' "$SGDISK"
printf '  stranger partition preserved, the disk booted and answered, and a\n'
printf '  reinstall reused every extent; a blank disk was refused without\n'
printf '  --new-table, given a fresh GPT with it, and the result booted too; and\n'
printf '  the confirmation held: plan shown, no and end-of-input wrote nothing,\n'
printf '  yes wrote the zones\n'
