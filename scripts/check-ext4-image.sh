#!/usr/bin/env sh
# File: scripts/check-ext4-image.sh
# Purpose: Prove the ext4 driver on a volume it did **not** build.
#
# Why this exists
# ---------------
# Every ext4 test in this tree fed the driver bytes this tree made, and there
# was exactly one test that opened the driver at all: `fuzz_fs_volume_opens`,
# which hands it random bytes and accepts any error it returns.  A test that
# accepts any answer cannot see a wrong one, and the wrong one was there —
# `read_superblock` read the three feature words a word late (compat from the
# address of incompat, incompat from the address of ro_compat), so every real
# volume appeared to carry unknown incompat features and `open` answered
# `Unsupported` to a volume `mkfs.ext4` had just written.
#
# This makes a volume with `mkfs.ext4`, writes a file into it from the host,
# and hands it to the driver through `tests/ext4_probe.rs`: the driver opens
# the volume, reads the file's bytes, and asserts they are the ones the host
# wrote rather than a zeroed buffer.  The host's file is the judge — a name and
# bytes this driver never produced.
#
# The volume is made without `metadata_csum`.  That is a capability this
# driver does not have (it does not read `s_checksum_seed`), not a defect this
# check hides: a volume that carries the feature is refused with `Unsupported`
# and `docs/status.md` records the gap.  What is proven here is the format
# arithmetic the driver does claim — superblock offsets, group descriptors,
# inode tables and extent mapping — against a volume neither it nor this tree
# wrote.
#
# Usage:
#   sh scripts/check-ext4-image.sh

set -eu

cd "$(dirname "$0")/.."

CARGO="${CARGO:-cargo}"
PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"

fail() {
    echo "ext4 image check: $1" >&2
    exit 1
}

for tool in mkfs.ext4 debugfs; do
    command -v "$tool" >/dev/null 2>&1 ||
        fail "$tool is not installed (e2fsprogs); this check cannot report anything without it"
done

work="$(mktemp -d)"
cleanup() { rm -r "$work"; }
trap cleanup EXIT INT TERM

volume="$work/volume.ext4"
dd if=/dev/zero of="$volume" bs=1M count=8 status=none
# No metadata_csum: the driver does not read the checksum seed, so a volume
# that carries the feature is refused, and this check is about the parts of
# the format the driver does claim.
mkfs.ext4 -q -F -O ^metadata_csum -b 4096 -I 256 "$volume" ||
    fail "mkfs.ext4 could not make the volume"

payload="hello-from-mkfs-ext4"
# `debugfs` writes into the image without a loop mount, so this needs no root.
printf '%s' "$payload" >"$work/payload"
debugfs -w -R "write $work/payload probe.txt" "$volume" >/dev/null 2>&1 ||
    fail "debugfs could not inject the probe file"

read_back="$(debugfs -R 'cat /probe.txt' "$volume" 2>/dev/null | tr -d '\000')"
[ "$read_back" = "$payload" ] ||
    fail "the host could not read its own probe file back: '$read_back'"

# The pipeline's status is `sed`'s, not cargo's, so the test's own exit code
# has to be captured: piping straight into `sed` made this check print
# "passed" over three failed tests, which is the one failure mode a gate must
# not have.  A temporary file keeps the indentation without losing the status.
if ! EXT4_PROBE_IMAGE="$volume" \
    "$CARGO" test --offline --profile "$PROFILE" \
    --test ext4_probe -- --nocapture >"$work/test.log" 2>&1
then
    sed 's/^/  /' "$work/test.log" >&2
    fail "the driver did not read the volume mkfs.ext4 wrote"
fi
sed 's/^/  /' "$work/test.log"

echo "ext4 image check passed: a volume mkfs.ext4 wrote is opened, and the"
echo "  file the host wrote into it reads back byte for byte"
