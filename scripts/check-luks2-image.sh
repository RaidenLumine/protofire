#!/usr/bin/env sh
# File: scripts/check-luks2-image.sh
# Purpose: Prove the LUKS2 unwrap on a volume it did not write.
#
# Why this exists
# ---------------
# `luks2_open` answered `InvalidCredential` to every volume `cryptsetup`
# wrote, and no test in this tree could see it: the LUKS2 tests were built on
# the same misreading as the code.  Three things were wrong at once — the
# keyslot area was never decrypted (it is itself AES-XTS), the AF merge
# implemented `XOR the hash of the previous stripe`, which is not LUKS's
# algorithm, and the merge output was XORed with the derived key, which is
# LUKS1's wrap and not LUKS2's.
#
# This makes a volume with `cryptsetup`, writes a marker into its payload,
# and hands the image to `tests/luks2_probe.rs`.  The judge is the host:
# the master key `cryptsetup luksDump --dump-master-key` reports, and the
# plaintext the host put in the payload.
#
# The KDF iterations are forced to 1000.  A real volume spends seconds in
# PBKDF2 so a passphrase guess costs something; this check is not guessing,
# and a check that takes thirty seconds is one people stop running.
#
# Usage:
#   sh scripts/check-luks2-image.sh

set -eu

cd "$(dirname "$0")/.."

CARGO="${CARGO:-cargo}"
CRYPTSETUP="${CRYPTSETUP:-cryptsetup}"
PASSPHRASE="protofire-test-passphrase"
IMAGE="${LUKS2_PROBE_IMAGE:-target/luks2-probe.img}"

if ! command -v "$CRYPTSETUP" >/dev/null 2>&1; then
    printf '%s is not installed; cannot build a volume to test against.\n' \
        "$CRYPTSETUP" >&2
    exit 1
fi

mkdir -p "$(dirname "$IMAGE")"
rm -f "$IMAGE"
# 64 MiB: the header and keyslot area take the first 16 MiB, and the payload
# needs a sector at least — the marker goes at its start.
truncate -s 64M "$IMAGE"

printf '%s' "$PASSPHRASE" | "$CRYPTSETUP" luksFormat \
    --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --key-size 512 --batch-mode --key-file - "$IMAGE" >/dev/null

# The key the unwrap has to reproduce.  Parsed out of the dump rather than
# hard-coded, because the volume is made fresh on every run.
master="$(printf '%s' "$PASSPHRASE" | "$CRYPTSETUP" luksDump \
    --dump-master-key --key-file - "$IMAGE" 2>/dev/null \
    | sed -n '/MK dump/,$p' | sed '1s/.*MK dump:[[:space:]]*//' \
    | tr -s ' \t' '\n' | grep -E '^[0-9a-f]{2}$' | tr '\n' ' ' | sed 's/ *$//')"
if [ -z "$master" ]; then
    printf 'could not read the master key from cryptsetup; cannot judge a result.\n' >&2
    exit 1
fi

# A marker the driver has to produce in the clear.
#
# It cannot be written by opening the volume: that needs device-mapper, which
# needs root, and this check has to run where the rest of the suite does.  The
# encryption is one AES-XTS pass over the payload's first sector with the key
# the dump just printed, and `tests/luks2_probe.rs` asserts the driver undoes
# it.  Doing it here means the plaintext is a value this tree's code did not
# choose either.
marker="PROTOFIRE-LUKS2-MARKER"
python3 "$(dirname "$0")/luks2-write-marker.py" \
    "$IMAGE" "$master" "$marker" || {
    printf 'could not write the marker into the payload.\n' >&2
    exit 1
}

status=0
LUKS2_PROBE_IMAGE="$IMAGE" \
LUKS2_PROBE_MASTER_KEY="$master" \
    "$CARGO" test --offline --test luks2_probe -- --nocapture || status=$?

if [ "$status" -eq 0 ]; then
    printf 'luks2 image check passed: the unwrap opens a volume cryptsetup wrote\n'
fi
exit "$status"
