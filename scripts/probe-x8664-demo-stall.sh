#!/usr/bin/env sh
# File: scripts/probe-x8664-demo-stall.sh
# Purpose: Boot the x86_64 demo and, if it stops, ask QEMU where the guest is.
#
# There is a stall in this boot that prints nothing: the demo stops part way
# through, the log simply ends, and no `[sched ]` line appears — so the
# placement watchdog, which speaks only for a thread it cannot find in any
# queue, has nothing to say.  `src/kernel/vm_churn.rs` records what is known
# about it, including that it does not reproduce on demand.
#
# This is the observation that works anyway.  A guest that cannot print can
# still be *examined*: QEMU's monitor reports the guest's registers from
# outside, so the instruction pointer at the moment of the stall says whether
# the CPU is in the payload's user code or in the kernel, and which.  Map it
# with the symbol table of the image that was booted:
#
#   nm -n target/x86_64-unknown-none/debug/protofire | less
#
# The run also reports how much host CPU the guest burned while stalled: a
# spinning guest and a parked one call for different investigations, and this
# is the cheapest place to tell them apart.
#
# Usage:
#   sh scripts/probe-x8664-demo-stall.sh [seconds] [log path]
#
# Exits 0 when the demo reached its end (nothing to see), 1 when it stalled
# and the registers below are the finding.

set -eu

cd "$(dirname "$0")/.."

LIMIT_SECONDS="${1:-60}"
LOG="${2:-$(pwd)/probe-demo-stall.log}"
MONITOR="$(mktemp -u)/protofire-monitor.sock"
MONITOR_DIR="$(dirname "$MONITOR")"

KERNEL="target/x86_64-unknown-none/debug/protofire"
if [ ! -f "$KERNEL" ]; then
    printf 'kernel image not found: %s\n' "$KERNEL" >&2
    printf 'run `make build-x8664-demo` first\n' >&2
    exit 1
fi

mkdir -p "$MONITOR_DIR"
mkdir -p "$(dirname "$LOG")"
: >"$LOG"

qemu-system-x86_64 -machine q35 -cpu max -smp 1 -m 1G \
    -kernel "$KERNEL" \
    -display none -no-reboot -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -serial "file:$LOG" \
    -monitor "unix:$MONITOR,server,nowait" >/dev/null 2>&1 &
qemu_pid=$!

cleanup() {
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    rm -rf "$MONITOR_DIR"
}
trap cleanup EXIT INT TERM

marker="[service] abandoning demo-launcher-fault after its restart budget"
waited=0
reached=no
while [ "$waited" -lt "$((LIMIT_SECONDS * 10))" ]; do
    if grep -qF "$marker" "$LOG" 2>/dev/null; then
        reached=yes
        break
    fi
    sleep 0.1
    waited=$((waited + 1))
done

if [ "$reached" = "yes" ]; then
    printf 'the demo reached its end (%s lines); nothing to see\n' \
        "$(wc -l <"$LOG")"
    exit 0
fi

# The guest stopped.  How hard was the CPU working while it did?
read_cpu_ticks() {
    awk '{print $14 + $15}' "/proc/$qemu_pid/stat" 2>/dev/null || echo 0
}
before="$(read_cpu_ticks)"
sleep 2
after="$(read_cpu_ticks)"
burned=$((after - before))

printf 'the demo did not reach its end in %ss (%s lines)\n' \
    "$LIMIT_SECONDS" "$(wc -l <"$LOG")"
printf 'host CPU burned during two stalled seconds: %s ticks ' "$burned"
if [ "$burned" -gt 100 ]; then
    printf '(spinning guest)\n'
else
    printf '(parked guest)\n'
fi
printf 'last line: %s\n' "$(tail -1 "$LOG")"

# Ask the monitor for the guest's registers.  python3 is the only socket
# client the tree already depends on; the monitor socket is a plain unix
# socket and one `info registers` is the whole protocol.
python3 - "$MONITOR" <<'PY'
import socket, sys, time

path = sys.argv[1]
deadline = time.time() + 5
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(2.0)
while True:
    try:
        client.connect(path)
        break
    except OSError:
        if time.time() > deadline:
            print("(monitor socket never appeared)")
            raise SystemExit
        time.sleep(0.05)
time.sleep(0.2)
try:
    client.recv(4096)
except OSError:
    pass
client.sendall(b"info registers\n")
time.sleep(0.5)
out = b""
try:
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        out += chunk
except OSError:
    pass
for line in out.decode(errors="replace").splitlines():
    if line.startswith(("RIP=", "RSP=", "RFL=", "CR3=")):
        print("  " + line[:120])
PY

exit 1
