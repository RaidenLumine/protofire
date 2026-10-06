#!/usr/bin/env sh
# File: scripts/check-x8664-hda.sh
# Purpose: Boot with an Intel HDA controller, play a tone from the shell, and
#   require the samples to reach the host's WAV backend.
#
# Why this exists
# ---------------
# The HDA driver had never been executed by any gate and nothing in the tree
# wrote to `/system/dev/audio`, so three register-map mistakes stood uncaught
# — the stream descriptor's reset and run bits swapped, the stream number
# written into the codec's field instead of the descriptor's, and playback on
# a descriptor the controller hands the codec as *capture*.  Every one of them
# is silent: the driver reports that it wrote every sample, and the machine
# plays nothing.
#
# The observation is outside the guest.  QEMU's `-audiodev wav` writes what the
# codec's voice produces to a file on the host, so "did the samples leave" is a
# property of a file this script can read — the same shape as the USB disk's
# host-side check, and the reason the three bugs above were findable at all.
#
# What it asserts:
#   * the shell's `tone` builtin, which writes the node's `[u32le rate]` plus
#     interleaved samples, reports that it played — the whole userspace path,
#     open included;
#   * the WAV the backend wrote is stereo 16-bit and its data chunk is much
#     larger than a header, which is what an empty data chunk looked like
#     before the fix;
#   * that data carries a square wave at the amplitude the builtin generates:
#     long runs of both peaks, which silence (a run of zeros) cannot fake.
#
# Usage:
#   sh scripts/check-x8664-hda.sh [timeout-seconds]

set -eu

cd "$(dirname "$0")/.."

TIMEOUT_SECONDS="${1:-35}"
PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
QEMU="${QEMU:-qemu-system-x86_64}"
HDA_LOG="${HDA_LOG:-}"
FEATURES="${FEATURES:-demo-disk}"

KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the HDA check.\n' "$QEMU" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    printf 'python3 is not installed; cannot read the WAV the backend writes.\n' >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac

"$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
    --features "$FEATURES"
sh ./scripts/check-payload-relocations.sh "$KERNEL_BIN"

work="$(mktemp -d)"
log="$work/boot.log"
wav="$work/played.wav"
if [ -n "$HDA_LOG" ]; then
    mkdir -p "$(dirname "$HDA_LOG")"
    log="$HDA_LOG"
fi
: >"$log"
: >"$wav"

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

printf 'x86_64 HDA check: timeout %ss, qemu %s\n' "$TIMEOUT_SECONDS" "$QEMU"

# The console is two-way here: the tone is a command, so the shell has to be
# typed at, and the feeder waits for the shell's own banner rather than for a
# delay.
shell_commands() {
    sh ./scripts/feed-shell-console.sh "$log" "$TIMEOUT_SECONDS" \
        'tone 440 200' \
        'echo tone-done'
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
    -audiodev "wav,id=snd0,path=$wav" \
    -device intel-hda \
    -device hda-output,audiodev=snd0 \
    -serial stdio >"$log" 2>&1
status=$?
set -e

case "$status" in
    0|124) ;;
    *)
        printf 'x86_64 HDA check failed with exit status %s\n' "$status" >&2
        exit "$status"
        ;;
esac

fail() {
    printf 'x86_64 HDA check failed: %s\n' "$1" >&2
    tail -n 12 "$log" >&2
    exit 1
}

require_log_line() {
    grep -F "$1" "$log" >/dev/null 2>&1 || fail "missing log line: $1"
}

# The controller, its codec, and the converter the stream is routed to.
require_log_line "[hda   ] HDA controller ready"
require_log_line "[hda   ] playback: output converter nid="
# And the userspace path: the shell opened the node and wrote the tone.
require_log_line "tone: played"
require_log_line "tone-done"

# The samples themselves, as the host saw them.
python3 - "$wav" <<'PY' || fail "the WAV the backend wrote does not carry the tone"
import struct
import sys
import wave

with wave.open(sys.argv[1]) as played:
    channels = played.getnchannels()
    width = played.getsampwidth()
    rate = played.getframerate()
    frames = played.getnframes()
    data = played.readframes(frames)

if channels != 2 or width != 2:
    print(f"expected stereo 16-bit, got {channels} channels of {width * 8} bits")
    sys.exit(1)
if frames < 1000:
    print(f"the backend wrote only {frames} frames; nothing was played")
    sys.exit(1)

# The builtin generates a square wave at +8000/-8000.  Resampled to the
# backend's own rate the peaks come back as +7999 (0x1f3f -> 3f 1f) and -8000
# (0xe0c0 -> c0 e0); both halves of the wave have to be there, and a run of
# them is what silence cannot produce.
positive = data.count(b"\x3f\x1f")
negative = data.count(b"\xc0\xe0")
if positive < 100 or negative < 100:
    print(f"peaks: +{positive} -{negative}; the tone is not in the file")
    sys.exit(1)
print(f"wav: {frames} frames at {rate} Hz, {positive} positive and {negative} negative peaks")
PY

printf 'x86_64 HDA check passed: the shell played a tone and the host WAV carries it\n'
