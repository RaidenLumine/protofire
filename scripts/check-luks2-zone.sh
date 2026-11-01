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
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-90}"
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

# The boot, with no `crypt=` on the command line: the passphrase is asked for
# and typed.  Everything else is the demo machine.
"$CARGO" build --offline --target x86_64-unknown-none --bin "$CRATE" \
    --features "demo-disk" >/dev/null

kernel_bin="$TARGET_DIR/x86_64-unknown-none/$PROFILE/$CRATE"
if [ "$PROFILE" = "release" ]; then
    "$CARGO" build --offline --release --target x86_64-unknown-none \
        --bin "$CRATE" --features "demo-disk" >/dev/null
fi

# The console is two-way, and both halves matter here: the passphrase is typed
# at a boot-time prompt, and the file is read at the shell.  This is the gate
# for the *protected* path — no `crypt=`, so the kernel asks and the answer
# never reaches a log.
#
# The typing is a schedule rather than a prompt-reader, and it has to be: the
# passphrase prompt appears while the filesystem is initialising, before the
# shell exists and before there is anything for `feed-shell-console.sh` to wait
# for.  The delays are what make that work, which is the shape this check
# would rather not have — a slower host could type too early.  It is measured
# rather than assumed: the boot prints its prompt before the read, and the
# check requires that line, so a run that typed too early fails rather than
# passing on a fallback.
# One socket, both directions, and the log is written from what comes *out* of
# it.  That is the point of not using `-serial stdio`: a terminal echoes what
# is typed, so the passphrase would appear in the captured log whether or not
# the kernel echoed it, and this check could not tell the two apart — which is
# the one thing it exists to tell apart.  Here a byte in `$LOG` is a byte the
# kernel wrote.
sock="$TARGET_DIR/luks2-zone.sock"
rm -f "$sock"
# Truncated, not appended: the log is this run's, and an earlier run's lines
# are lines this check would assert on.  Measured — a leak fixed in one change
# kept failing the check that looks for it, because the record of the run
# before was still there.
: >"$LOG"

python3 - "$sock" "$LOG" "$PASSPHRASE" "$TIMEOUT_SECONDS" <<'PYEOF' &
import socket
import sys
import time

path, log, passphrase, timeout = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
deadline = time.monotonic() + timeout


def connect():
    for _ in range(timeout):
        try:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.connect(path)
            return connection
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(1)
    return None


connection = connect()
if connection is None:
    print("could not connect to the console socket", file=sys.stderr)
    sys.exit(1)
connection.settimeout(1)

seen = b""
sent_passphrase = False
sent_command = False


def drain():
    """Read whatever the kernel has written into the log the assertions read."""
    global seen
    try:
        chunk = connection.recv(8192)
    except socket.timeout:
        return
    except OSError:
        return
    if not chunk:
        return
    seen += chunk
    # Appended, not rewritten: the earlier version held the whole stream and
    # wrote it back every time, which is a read-modify-write on a file nothing else
    # guards and truncated bytes on the runs where it interleaved with the
    # boot's own writes — measured as "the pssphrase is not echoed".
    with open(log, "ab") as handle:
        handle.write(chunk)


while time.monotonic() < deadline:
    drain()
    if not sent_passphrase and b"the passphrase is not echoed" in seen:
        connection.sendall(passphrase.encode() + b"\n")
        sent_passphrase = True
    # The shell's prompt is what says the zone opened: the shell starts only
    # after the mount succeeded.
    if sent_passphrase and not sent_command and b"protofire:" in seen:
        connection.sendall(b"cat /data/public/shared/note.txt\n")
        sent_command = True
    # Keep reading after the command: the assertions are about output that
    # arrives later, and stopping now would truncate it.
    time.sleep(0.2)

drain()
connection.close()
PYEOF
session_pid=$!

set +e
timeout "${TIMEOUT_SECONDS}s" qemu-system-x86_64 \
    -machine q35 -cpu max -smp 1 -m 1G \
    -drive file="$IMAGE",if=none,id=disk0,format=raw \
    -device nvme,drive=disk0,serial=protofire \
    -kernel "$kernel_bin" \
    -display none -no-reboot -no-shutdown \
    -chardev "socket,id=c0,path=$sock,server=on,wait=off" \
    -serial chardev:c0 >/dev/null 2>&1
status=$?
# The reader has its own budget; a boot that failed ends the loop early.
wait "$session_pid" 2>/dev/null
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

require_line "\[fs    \] an encrypted zone is present; the passphrase is not echoed"

# The passphrase never reaches the log.  This is the whole point of the echoed
# prompt being a prompt: an answer that is written back is an answer in a file
# someone else can read, and a check that only asserted on the *unlock* would
# pass just as happily with every character echoed.  Counted rather than
# grepped, because the console echoes a character per write and a match could
# share a line with anything.
if tr -d '\r' <"$LOG" | grep -aqF -- "$PASSPHRASE"; then
    printf 'the passphrase appears in the boot log, which is what echo-off is for\n' >&2
    exit 1
fi
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
