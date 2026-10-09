#!/usr/bin/env sh
# File: scripts/check-ntfs-image.sh
# Purpose: Prove the NTFS driver on a volume it did **not** build.
#
# Why this exists
# ---------------
# Every other NTFS test mounts a fixture this driver wrote itself, and the
# format facts that fixture rests on were measured against a real volume by
# hand, never as a gate.  That is the shape `check-nvme-disk.sh` was written
# for: the NVMe driver had never run, so nothing noticed that two of its admin
# opcodes were the specification's neighbours.
#
# This check makes a volume with `mkntfs`, injects a file with `ntfscp` — a
# name and bytes this driver never wrote — and hands both to the driver through
# the test `a_volume_mkntfs_wrote_is_read_and_written_back`
# (`src/fs/ntfs/tests.rs`).  The driver reads the host's file, creates one of
# its own, and leaves the volume where this script can judge it: `ntfs-3g`'s
# own reader lists the names, reads both files back, and `ntfsfix -n` walks the
# volume's metadata.  So the reader is judged by a *foreign* implementation of
# the format on a volume neither of them built.
#
# Nothing here needs root, QEMU or a mount of the host's own: `ntfscp`,
# `ntfsls`, `ntfscat` and `ntfsfix` all work on the image file directly.  The
# tools are required rather than optional — a check that skipped itself when
# they were missing would be a check that reports nothing, which is the
# direction this repository does not go.
#
# The boot path is *not* what this proves: mounting the driver's filesystem at
# boot needs the zone dispatch in `src/fs/filesystem/` to know the type, which
# is a step of its own.  What is proven here is the driver on the format.
#
# Usage:
#   sh scripts/check-ntfs-image.sh [timeout-seconds]

set -eu

cd "$(dirname "$0")/.."

CARGO="${CARGO:-cargo}"
PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"

fail() {
    echo "ntfs image check: $1" >&2
    exit 1
}

for tool in mkntfs ntfscp ntfsls ntfscat ntfsfix; do
    command -v "$tool" >/dev/null 2>&1 ||
        fail "$tool is not installed (the ntfs-3g tools); this check cannot report anything without it"
done

work="$(mktemp -d)"
cleanup() { rm -r "$work"; }
trap cleanup EXIT INT TERM

# A volume `mkntfs` makes with the shape the driver expects: 512-byte sectors
# and 4096-byte clusters, which is 1024-byte records — the arithmetic the
# fixture's two shapes exist to hold.
volume="$work/volume.ntfs"
dd if=/dev/zero of="$volume" bs=1M count=16 status=none
# `mkntfs` says a word about the file not being a block device and about the
# geometry it could not read from one; that is expected for an image file, so
# its output is kept until something actually fails.
if ! mkntfs -F -q -L protofire-ntfs "$volume" >"$work/mkntfs.log" 2>&1; then
    cat "$work/mkntfs.log" >&2
    fail "mkntfs could not make the volume"
fi

content='hello from the host'
write='written by the driver'
printf '%s\n' "$content" >"$work/hello.txt"
ntfscp -f "$volume" "$work/hello.txt" /hello.txt ||
    fail "could not inject the host's file into the volume"

# The driver's own image is a copy, so the one `mkntfs` made stays as the
# control if a later step needs to look at it.
under_test="$work/under-test.ntfs"
cp "$volume" "$under_test"
written="$work/driver-wrote.ntfs"

PROTOFIRE_NTFS_IMAGE="$under_test" \
PROTOFIRE_NTFS_CONTENT="$content
" \
PROTOFIRE_NTFS_WRITE="$write
" \
PROTOFIRE_NTFS_OUT="$written" \
    "$CARGO" test --offline --lib -- \
    --ignored --exact "fs::ntfs::tests::a_volume_mkntfs_wrote_is_read_and_written_back" ||
    fail "the driver did not read the volume mkntfs made, or did not write it back"

[ -f "$written" ] || fail "the driver left no volume to judge"

# `ntfs-3g`'s own reader, on the volume the driver wrote: the names, both
# files' bytes, and the volume's metadata.
ntfsls "$written" | grep -qx 'written.txt' ||
    fail "ntfs-3g does not list the file the driver created"
ntfsls "$written" | grep -qx 'hello.txt' ||
    fail "ntfs-3g does not list the file that was already there"

[ "$(ntfscat "$written" /written.txt)" = "$write" ] ||
    fail "ntfs-3g reads other bytes than the driver wrote"
[ "$(ntfscat "$written" /hello.txt)" = "$content" ] ||
    fail "the file that was already there changed"

ntfsfix -n "$written" >"$work/ntfsfix.log" 2>&1 ||
    fail "ntfsfix -n does not accept the volume the driver wrote (see $work/ntfsfix.log)"
grep -q 'processed successfully' "$work/ntfsfix.log" ||
    fail "ntfsfix -n finished without accepting the volume"

printf 'ntfs image check passed: mounted a volume mkntfs made, read the host'"'"'s file, and a foreign reader accepts what the driver wrote\n'

# ── A compressed stream, refused rather than misread ────────────────────
#
# `mkntfs -C` makes a volume whose files are compressed, so this is a
# compressed `$DATA` that no part of this driver wrote.  Its runs name
# clusters holding an LZNT1 bitstream, and the reader used to answer a read of
# it with those bytes — at the file's own length, which a caller cannot tell
# from the file.  RFC 0013 decides the refusal; this is where it is proven on
# a volume the driver did not build.
compressed="$work/compressed.ntfs"
dd if=/dev/zero of="$compressed" bs=1M count=16 status=none
if ! mkntfs -F -q -C -L protofire-compressed "$compressed" >"$work/mkntfs-compressed.log" 2>&1; then
    cat "$work/mkntfs-compressed.log" >&2
    fail "mkntfs could not make the compressed volume"
fi
content_name='/big.txt'
yes 'the quick brown fox jumps over the lazy dog' | head -600 >"$work/big.txt"
ntfscp -f "$compressed" "$work/big.txt" "$content_name" ||
    fail "could not inject the compressible file"
ntfsinfo -F "$content_name" "$compressed" 2>/dev/null |
    grep -q 'Attribute flags:.*0x0001' ||
    fail "the file the check injected is not compressed, so it proves nothing"

PROTOFIRE_NTFS_COMPRESSED="$compressed" \
PROTOFIRE_NTFS_COMPRESSED_NAME="$content_name" \
    "$CARGO" test --offline --lib -- \
    --ignored --exact "fs::ntfs::tests::a_compressed_stream_on_a_real_volume_is_refused" ||
    fail "a compressed stream was not refused, or the file was not listed"

printf 'ntfs image check passed (compressed): a compressed stream is refused, not misread\n'
