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
# installing means adding this kernel's zones to *that* disk — the system
# zone as its A/B pair, so the boot has a newer build to take and an older
# one to roll back to.  The installer (`cargo run -- install <disk>`,
# `src/fs/install.rs`) does that, and this check is the whole of its evidence:
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
placed="$(awk '/placed[,)]/ { n += 1 } END { print n + 0 }' "$install_out")"
if [ "$placed" -ne 4 ]; then
    cat "$install_out" >&2
    fail "expected the four extents to be placed, saw $placed placed (the disk should have been empty)"
fi
# The system zone is the pair: the plan and the report name each slot's build.
grep -F "build 1" "$install_out" >/dev/null 2>&1 ||
    fail "the install did not place the older system slot (build 1)"
grep -F "build 2" "$install_out" >/dev/null 2>&1 ||
    fail "the install did not place the newer system slot (build 2)"

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
# The system zone is the **pair** the install wrote: the boot selected the
# committed slot with the higher generation, which on a fresh install is B
# (build 2).  A disk with one system slot would read `slot a active` and a
# pair written but not committed would too, so this line is what says the
# install produced the shape the boot looks for.
require_log_line "[fs    ] system: slot b active (build 2)"
# And a program came off it: a mount alone does not prove the zone's content.
require_log_line "[user  ] loaded /apps/packages/shell/bin/shell.elf"
require_log_line "protofire ring3 shell"
# The typed answer: the shell read a line and printed it.
require_log_line "install-check-answered"
grep -F "[FATAL]" "$log" >/dev/null 2>&1 && fail "the boot reported a fatal error"

# ── A second install reuses every extent ───────────────────────────────
second_out="$work/install2.log"
if ! "$CARGO" run --offline --quiet -- install --yes "$disk" >"$second_out" 2>&1; then
    cat "$second_out" >&2
    fail "the second install did not complete"
fi
reused="$(awk '/reused[,)]/ { n += 1 } END { print n + 0 }' "$second_out")"
if [ "$reused" -ne 4 ]; then
    cat "$second_out" >&2
    fail "expected all four extents to be reused on the second install, saw $reused"
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
# kernel wrote, and lists the zones — the pair included — as its partitions.
"$SGDISK" -p "$blank" >"$work/blank-table.log" 2>&1 \
    || { cat "$work/blank-table.log" >&2; fail "sgdisk cannot read the fresh table"; }
# The fresh writer writes no partition names, so the count is the check:
# four partitions — the pair, apps and data — and no more.
partition_count="$("$SGDISK" -p "$blank" 2>/dev/null | awk -F: '/^ +[0-9]+/ { n += 1 } END { print n + 0 }')"
if [ "$partition_count" -ne 4 ]; then
    cat "$work/blank-table.log" >&2
    fail "expected 4 partitions in the fresh table, sgdisk sees $partition_count"
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
require_log_line "[fs    ] system: slot b active (build 2)"
require_log_line "[user  ] loaded /apps/packages/shell/bin/shell.elf"
require_log_line "install-check-answered"
grep -F "[FATAL]" "$blank_log" >/dev/null 2>&1 && fail "the blank-disk boot reported a fatal error"

# ── A disk whose table is not this kernel's is left alone ───────────────
#
# The case a real machine walks into: the boot disk is the machine's own,
# its partition table is a tool's and names no zone, and the demo image's
# bytes happen to sit at the fixed offsets underneath.  Reading those offsets
# would mount the machine's first partition as this kernel's `/apps` and
# `/data` — writable — so the boot must refuse instead
# ([RFC 0027](../../docs/rfcs/0027-never-mount-a-fixed-offset-over-a-table.md)).
foreign="$work/foreign.img"
dd if=/dev/zero of="$foreign" bs=1M count="$DISK_MIB" status=none 2>/dev/null \
    || dd if=/dev/zero of="$foreign" bs=1048576 count="$DISK_MIB" 2>/dev/null
"$CARGO" run --offline --quiet -- mkimage "$work/demo.img" >/dev/null 2>&1
dd if="$work/demo.img" of="$foreign" conv=notrunc status=none
# Replace the demo's own table with a stranger's: sgdisk zaps the MBR and
# writes a fresh GPT whose one entry is a Linux filesystem.
"$SGDISK" -Z "$foreign" >/dev/null 2>&1
"$SGDISK" -n 1:2048:+60M -t 1:0FC63DAF-8483-4772-8E79-3D69D8477DE4 \
    -c 1:stranger "$foreign" >>"$work/sgdisk.log" 2>&1 \
    || { cat "$work/sgdisk.log" >&2; fail "sgdisk could not make the foreign disk"; }

foreign_log="$work/foreign-boot.log"
set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 \
    -cpu max \
    -smp 1 \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -drive "file=$foreign,if=none,id=nvme0,format=raw" \
    -device nvme,drive=nvme0,serial=protofire \
    -serial file:"$foreign_log" >/dev/null 2>&1
status=$?
set -e
case "$status" in
    0|124) ;;
    *)
        fail "the foreign-table boot exited with status $status"
        ;;
esac
log="$foreign_log"
require_log_line "[driver] detected boot disk: nvme0"
require_log_line "[fs    ] the boot disk carries a partition table that names no zone of this kernel's; left alone"
require_log_line "[fs    ] mounted in-memory demo SimpleFs volumes"
# And the fixed offsets were *not* read: that line is the defect this section
# exists for, and it is exactly what the boot printed before the change.
if grep -F "[fs    ] mounted fixed-zone SimpleFs volumes from ATA boot disk" "$foreign_log" >/dev/null 2>&1; then
    fail "the boot read the fixed offsets over a stranger's table"
fi

# ── The same bytes with no table at all still take the fixed offsets ────
#
# The other half of the rule, and the half a careless fix would have broken:
# a disk that carries no partition information anywhere is the shape the
# fixed offsets describe, and it must still boot them.  LBA 0 (the MBR), LBA
# 1 (the primary GPT header) and the last block (the backup) are zeroed, which
# is every place a table could be.
table_less="$work/table-less.img"
cp "$foreign" "$table_less"
dd if=/dev/zero of="$table_less" bs=512 count=2 conv=notrunc status=none
size_bytes="$(stat -c %s "$table_less" 2>/dev/null || stat -f %z "$table_less")"
dd if=/dev/zero of="$table_less" bs=512 seek=$((size_bytes / 512 - 1)) \
    count=1 conv=notrunc status=none

table_less_log="$work/table-less-boot.log"
set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine q35 \
    -cpu max \
    -smp 1 \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -drive "file=$table_less,if=none,id=nvme0,format=raw" \
    -device nvme,drive=nvme0,serial=protofire \
    -serial file:"$table_less_log" >/dev/null 2>&1
status=$?
set -e
case "$status" in
    0|124) ;;
    *)
        fail "the table-less boot exited with status $status"
        ;;
esac
log="$table_less_log"
require_log_line "[driver] detected boot disk: nvme0"
# The fixed-zone route is the discriminator: the in-memory demo volumes print
# a different line, and the boot must have mounted the disk's own zones.  The
# `system: slot ...` line is the partition path's and is correctly absent here.
require_log_line "[fs    ] mounted fixed-zone SimpleFs volumes from ATA boot disk"
if grep -F "[fs    ] mounted in-memory demo SimpleFs volumes" "$table_less_log" >/dev/null 2>&1; then
    fail "the table-less disk fell through to the in-memory demo volumes"
fi

# ── A disk too large to hold is installed without holding it ────────────
#
# The property the device path exists for: a machine's disk is hundreds of
# gigabytes, and an install that read it whole failed with `OutOfMemory`
# long before a zone was placed.  The disk here is 64 GiB and **sparse** —
# `truncate` makes a file of that length with almost no blocks allocated —
# so the check can also require that the install did not read or write the
# whole thing: the file's allocated size stays tiny next to its length
# ([RFC 0028](../../docs/rfcs/0028-install-through-a-device-not-an-image.md)).
if command -v du >/dev/null 2>&1; then
    huge="$work/huge.img"
    truncate -s 64G "$huge" 2>/dev/null \
        || { printf 'x86_64 install check: truncate is unavailable; the sparse-disk section cannot run\n' >&2; exit 1; }
    "$SGDISK" -n 1:4096:6143 -t 1:0FC63DAF-8483-4772-8E79-3D69D8477DE4 \
        -c 1:stranger "$huge" >>"$work/sgdisk.log" 2>&1 \
        || { cat "$work/sgdisk.log" >&2; fail "sgdisk could not make the sparse disk"; }
    huge_out="$work/huge-install.log"
    if ! "$CARGO" run --offline --quiet -- install --yes "$huge" >"$huge_out" 2>&1; then
        cat "$huge_out" >&2
        fail "the install onto a 64 GiB disk did not complete"
    fi
    grep -F "65536 MiB" "$huge_out" >/dev/null 2>&1 \
        || { cat "$huge_out" >&2; fail "the install did not report the disk's own size"; }
    "$SGDISK" -p "$huge" >"$work/huge-table.log" 2>&1 \
        || { cat "$work/huge-table.log" >&2; fail "sgdisk cannot read the sparse disk's table"; }
    grep -F "stranger" "$work/huge-table.log" >/dev/null 2>&1 \
        || fail "the sparse install lost the stranger's partition"
    # The zones are on it, in the same shape the machine disk got.
    huge_partitions="$("$SGDISK" -p "$huge" 2>/dev/null | awk -F: '/^ +[0-9]+/ { n += 1 } END { print n + 0 }')"
    if [ "$huge_partitions" -ne 5 ]; then
        cat "$work/huge-table.log" >&2
        fail "expected 5 partitions on the sparse disk, sgdisk sees $huge_partitions"
    fi
    # And it stayed sparse: an install that read or wrote the whole file
    # would have allocated gigabytes of blocks.
    allocated_kb="$(du -k "$huge" | awk '{ print $1 }')"
    if [ "$allocated_kb" -gt 65536 ]; then
        fail "the sparse disk holds $allocated_kb KiB of blocks: the install touched the whole disk"
    fi
    printf 'x86_64 install check: 64 GiB disk installed, %s KiB of blocks allocated\n' "$allocated_kb"
fi

printf 'x86_64 install check passed: zones installed onto a %s-made disk, the\n' "$SGDISK"
printf '  stranger partition preserved, the disk booted into the system pair (slot\n'
printf '  b, build 2) and answered, and a reinstall reused every extent; a blank\n'
printf '  disk was refused without --new-table, given a fresh GPT with it, and the\n'
printf '  result booted too; the confirmation held: plan shown, no and\n'
printf '  end-of-input wrote nothing, yes wrote the zones; and a disk whose table\n'
printf '  is a stranger s was left alone while the same bytes with no table at all\n'
printf '  still took the fixed offsets; and a 64 GiB disk was installed without\n'
printf '  the install holding it or touching more than a few blocks of it\n'
