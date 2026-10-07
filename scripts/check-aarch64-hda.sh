#!/usr/bin/env sh
# File: scripts/check-aarch64-hda.sh
# Purpose: Boot the AArch64 machine with an Intel HDA controller, play a tone
#   from the shell, and require the samples to reach the host's WAV backend.
#
# Why this exists
# ---------------
# `make check-x8664-hda` proved the driver on the machine whose configuration
# space is reached through port I/O, and the driver spent its life compiled
# only there: on AArch64 the module resolved to `hda_absent.rs`, so the machine
# answered every write to `/system/dev/audio` with `Unsupported`.  What made
# that a scope statement rather than a fact was the probe: it read BAR0 out of
# the x86_64 configuration mechanism by hand instead of asking the platform for
# the window, the way NVMe already did.
#
# The probe now asks `arch::platform::pci_register_window`, the same call NVMe
# makes, and this gate is what says the whole path runs on this machine: the
# ECAM window is walked, the controller's BAR is mapped through the platform's
# low alias, the codec is discovered, the shell opens the node and writes PCM,
# and QEMU's `-audiodev wav` writes what the codec's voice produced to a file on
# the host.  The driver polls and claims no interrupt, so the ITS is not on this
# path — that is the half still missing for a device that signals.
#
# What it asserts, the same things the x86_64 gate does:
#   * the controller, its codec and the output converter the stream is routed
#     to, named in the boot log;
#   * the shell's `tone` builtin, the whole userspace path, open included;
#   * the WAV the backend wrote is stereo 16-bit, its data chunk is much larger
#     than a header, and it carries a square wave at the amplitude the builtin
#     generates;
#   * the wave's period, converted back to a frequency, is the one the builtin
#     asked for (`tone 440 200`) to within a few percent.
#
# Usage:
#   sh scripts/check-aarch64-hda.sh [timeout-seconds]

set -eu

cd "$(dirname "$0")/.."

TIMEOUT_SECONDS="${1:-40}"
PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
QEMU="${QEMU:-qemu-system-aarch64}"
HDA_LOG="${HDA_LOG:-}"
FEATURES="${FEATURES:-demo-disk}"
# The kernel embeds a 512 MiB physical-frame pool, so the Image needs more than
# QEMU's default RAM; the runtime smoke uses the same value.
QEMU_RAM="${QEMU_RAM:-2G}"

KERNEL_BIN="${TARGET_DIR}/aarch64-unknown-none/${PROFILE}/${CRATE}.img"

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the HDA check.\n' "$QEMU" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    printf 'python3 is not installed; cannot read the WAV the backend writes.\n' >&2
    exit 1
fi

# The Image, not the ELF: only the arm64 `Image` boot path is handed a device
# tree, and the ECAM window the PCIe walk needs is described there rather than
# assumed.  The build script does that translation; this is the artifact QEMU
# boots.
PROFILE="$PROFILE" CRATE="$CRATE" CARGO="$CARGO" TARGET_DIR="$TARGET_DIR" \
    FEATURES="$FEATURES" sh ./scripts/build-aarch64-image.sh

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'aarch64 kernel image not found: %s\n' "$KERNEL_BIN" >&2
    exit 1
fi

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

printf 'aarch64 HDA check: timeout %ss, qemu %s\n' "$TIMEOUT_SECONDS" "$QEMU"

# The console is two-way here too: the tone is a command, so the shell has to
# be typed at, and the feeder waits for the shell's own banner.
shell_commands() {
    sh ./scripts/feed-shell-console.sh "$log" "$TIMEOUT_SECONDS" \
        'tone 440 200' \
        'echo tone-done'
}

set +e
shell_commands | timeout "${TIMEOUT_SECONDS}s" "$QEMU" \
    -machine virt \
    -cpu max \
    -smp 1 \
    -m "$QEMU_RAM" \
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
        printf 'aarch64 HDA check failed with exit status %s\n' "$status" >&2
        exit "$status"
        ;;
esac

fail() {
    printf 'aarch64 HDA check failed: %s\n' "$1" >&2
    tail -n 12 "$log" >&2
    exit 1
}

require_log_line() {
    grep -F "$1" "$log" >/dev/null 2>&1 || fail "missing log line: $1"
}

# The controller, its codec, and the converter the stream is routed to — all of
# it through the platform's PCIe window, which is the half x86_64 never had to
# exercise.
require_log_line "[hda   ] found HDA controller"
require_log_line "[hda   ] HDA controller ready"
require_log_line "[hda   ] playback: output converter nid="
# And the userspace path: the shell opened the node and wrote the tone.
require_log_line "tone: played"
require_log_line "tone-done"

# The samples themselves, as the host saw them.
python3 - "$wav" <<'PY' || fail "the WAV the backend wrote does not carry the tone"
import array
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

# The builtin generates a square wave at +8000/-8000 and asks for 440 Hz
# through the node's rate header.  Resampled to the backend's own rate the
# peaks come back as +7999 and -8000, and a run of them is what silence cannot
# produce.
positive = data.count(b"\x3f\x1f")
negative = data.count(b"\xc0\xe0")
if positive < 100 or negative < 100:
    print(f"peaks: +{positive} -{negative}; the tone is not in the file")
    sys.exit(1)

# The tone's frequency, measured from the wave's own period.
left = array.array("h")
left.frombytes(data)
left = left[0::channels]
transitions = []
previous = 0
for index, sample in enumerate(left):
    if sample > 1000:
        sign = 1
    elif sample < -1000:
        sign = -1
    else:
        continue
    if previous != 0 and sign != previous:
        transitions.append(index)
    previous = sign
if len(transitions) < 16:
    print(f"only {len(transitions)} transitions in the wave; nothing to measure")
    sys.exit(1)

intervals = sorted(
    transitions[i + 1] - transitions[i] for i in range(len(transitions) - 1)
)
median = intervals[len(intervals) // 2]
kept = [i for i in intervals if abs(i - median) <= max(1, median // 10)]
half_period = sum(kept) / len(kept)
measured = rate / (2.0 * half_period)
expected = 440.0
if abs(measured - expected) > expected * 0.05:
    print(
        f"the tone is {measured:.1f} Hz, not the {expected:.0f} Hz the shell "
        f"asked for (half-period {half_period:.2f} frames at {rate} Hz)"
    )
    sys.exit(1)
print(
    f"wav: {frames} frames at {rate} Hz, {positive} positive and {negative} "
    f"negative peaks, tone {measured:.1f} Hz (asked for {expected:.0f} Hz)"
)
PY

printf 'aarch64 HDA check passed: the shell played a tone and the host WAV carries it\n'
