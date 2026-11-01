#!/usr/bin/env sh
# File: scripts/check-luks2-zone.sh
# Purpose: Boot a machine whose /data zone is encrypted, and read from it.
#
# Why this exists
# ---------------
# `check-luks2-image` proves the unwrap opens a volume.  This proves the *boot*
# uses it — and "code that is written, wired and never executed" is the defect
# this tree names most often, so the difference matters.  Here the zone the
# machine mounts is a LUKS2 volume, the passphrase arrives on the command line,
# and a file is read through the whole chain: partition table, header, keyslot,
# payload offset, AES-XTS, and the filesystem inside.
#
# The volume comes from `cryptsetup` rather than a fixture in the tree.  A
# fixture carries a salt and a keyslot that a rebuild does not, so it goes
# stale the moment anything else moves; and 512 KiB of header as bytes in the
# repo would be a second copy of a format cryptsetup already writes.  The
# kernel reads the result and cannot make one, which is the division the format
# wants.
#
# Usage:
#   sh scripts/check-luks2-zone.sh

set -eu

cd "$(dirname "$0")/.."

CARGO="${CARGO:-cargo}"
CRYPTSETUP="${CRYPTSETUP:-cryptsetup}"
PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
PASSPHRASE="protofire-zone-passphrase"
IMAGE="$TARGET_DIR/luks2-zone-disk.img"
LOG="$TARGET_DIR/luks2-zone-boot.log"

if ! command -v "$CRYPTSETUP" >/dev/null 2>&1; then
    printf '%s is not installed; cannot build a zone to boot.\n' "$CRYPTSETUP" >&2
    exit 1
fi

mkdir -p "$TARGET_DIR"

# The demo disk, made by the kernel's own builder, then its /data zone replaced
# by an encrypted volume of exactly the same extent.  Replacing rather than
# rebuilding keeps every other zone — and so every other part of the boot —
# the stock machine's.
"$CARGO" run --offline --quiet -- mkimage "$IMAGE" >/dev/null

# `DEMO_DISK_DATA_START_BLOCK` and `DEMO_DISK_DATA_BLOCKS` from
# `src/fs/layout.rs`.  Named here so a change there shows up as a wrong size
# rather than as a volume that quietly does not fit.
data_start_block=2816
data_blocks=1536
data_offset=$((data_start_block * 512))
data_bytes=$((data_blocks * 512))

# The encrypted volume takes the zone's place, so it is written as its own file
# and copied in: `cryptsetup luksFormat` truncates what it is pointed at, and
# pointing it at a slice of the disk would need a loop device and root.
volume="$TARGET_DIR/luks2-zone.img"
rm -f "$volume"
truncate -s "$data_bytes" "$volume"
printf '%s' "$PASSPHRASE" | "$CRYPTSETUP" luksFormat \
    --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --key-size 512 --luks2-keyslots-size 256k --luks2-metadata-size 16k \
    --align-payload 1024 --batch-mode --key-file - "$volume" >/dev/null

# The zone's own bytes, encrypted into the volume.  `mkzone` asks the kernel's
# own builder for the image the disk would carry, so what the boot finds inside
# the payload is the filesystem this build makes — not a fixture, and not
# something the check wrote in a shape only the check knows.
"$CARGO" run --offline --quiet -- mkzone data "$TARGET_DIR/luks2-zone-fs.img" >/dev/null
python3 scripts/luks2-encrypt-payload.py \
    "$volume" "$(printf '%s' "$PASSPHRASE" | "$CRYPTSETUP" luksDump \
        --dump-master-key --key-file - "$volume" 2>/dev/null \
        | sed -n '/MK dump/,$p' | sed '1s/.*MK dump:[[:space:]]*//' \
        | tr -s ' \t' '\n' | grep -E '^[0-9a-f]{2}$' | tr '\n' ' ' | sed 's/ *$//')" \
    "$TARGET_DIR/luks2-zone-fs.img"

# Copy the volume over the zone's extent.  `oflag=seek_bytes` makes `seek` a
# byte offset rather than a count of `bs` blocks — without it `seek=1` writes
# at byte 0 and lands the volume over the partition table, which is what
# happened first and looked like the kernel not finding an encrypted zone.
dd if="$volume" of="$IMAGE" bs=512 seek="$data_offset" count="$data_blocks" \
    oflag=seek_bytes conv=notrunc status=none

# The boot.  `crypt=` carries the passphrase; everything else is the demo
# machine.  The kernel is built with the features a runtime check uses.
"$CARGO" build --offline --target x86_64-unknown-none --bin "$CRATE" \
    --features "demo-disk" >/dev/null

kernel_bin="$TARGET_DIR/x86_64-unknown-none/$PROFILE/$CRATE"
if [ "$PROFILE" = "release" ]; then
    "$CARGO" build --offline --release --target x86_64-unknown-none \
        --bin "$CRATE" --features "demo-disk" >/dev/null
fi

# The console is two-way here for the same reason the runtime check's is: the
# shell is where a *file* gets read, and a boot by itself only shows that the
# zone mounted.  `cat` of a file that exists only inside the encrypted payload
# is the read that crosses the header, the keyslot, the payload offset and
# AES-XTS — the mount alone would hold if the device returned zeros.
shell_commands() {
    # The feeder, not a `printf`: a line typed before the shell is reading is
    # the guest's to drop, and it drops the *front* of it — measured here as
    # `c/shared/note.txt`, which the shell read as an unknown command.  The
    # feeder waits for the banner and then for the prompt, so the command
    # arrives when there is something to read it.
    sh ./scripts/feed-shell-console.sh "$LOG" "$TIMEOUT_SECONDS" \
        'cat /data/public/shared/note.txt'
}

set +e
shell_commands | timeout "${TIMEOUT_SECONDS}s" qemu-system-x86_64 \
    -machine q35 -cpu max -smp 1 -m 1G \
    -drive file="$IMAGE",if=none,id=disk0,format=raw \
    -device nvme,drive=disk0,serial=protofire \
    -append "crypt=$PASSPHRASE" \
    -kernel "$kernel_bin" \
    -display none -no-reboot -no-shutdown \
    -serial stdio >"$LOG" 2>>"$LOG"
status=$?
set -e

case "$status" in
    124|0) ;;
    *)
        printf 'qemu exited with %s\n' "$status" >&2
        exit 1
        ;;
esac

require_line() {
    if ! tr -d '\r' <"$LOG" | grep -aq "$1"; then
        printf 'missing from the boot log: %s\n' "$1" >&2
        printf '  the log is %s\n' "$LOG" >&2
        tail -n 20 "$LOG" | tr -d '\000' >&2
        exit 1
    fi
}

require_line "\[fs    \] a crypt= passphrase was given"
require_line "\[fs    \] zone /data is LUKS2 and opened"

# The proof the zone was *read through*: a string that exists only inside this
# volume's payload.  The encryptor writes it in place of a file's original text
# before encrypting, so no other copy of the machine has it — which is what
# makes the read attributable, and which the first version of this check got
# wrong: it asserted on the file's *original* text, that string also lives in
# the in-memory demo volume, and the gate stayed green with the payload stored
# as plaintext.
require_line "PROTOFIRE-ENCRYPTED-PAYLOAD-PROOF"

printf 'luks2 zone check passed: the boot opened an encrypted /data and read a file from it\n'
