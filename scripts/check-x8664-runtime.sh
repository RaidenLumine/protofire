#!/usr/bin/env sh
# File: scripts/check-x8664-runtime.sh
# Purpose: Headless single-CPU QEMU smoke test for the x86_64 demo boot.
#
# Why this exists
# ---------------
# The SMP check next to this one exists to reach the cross-CPU paths, and it
# cannot see a defect that takes one processor down at a time: with four CPUs,
# the other three keep scheduling when one stops, so a boot that is dead on a
# single processor still prints user output under the SMP check.  The
# single-CPU boot is where such a wedge is total, and it is the configuration
# `make run` gives a developer.
#
# The failure this guards against is the kernel handing a processor to a
# process address space that does not map the kernel stack that processor is
# standing on.  Every line of the boot's first half is printed before that
# hand-off, so the shell banner and the service lines are all there and the log
# then simply stops: no user program reached user mode, none printed, none
# exited.  What the user programs say about themselves is therefore the only
# part of the boot that proves the ring-3 path ran, and it is what this check
# asserts.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
QEMU="${QEMU:-qemu-system-x86_64}"
X8664_RUNTIME_LOG="${X8664_RUNTIME_LOG:-}"
# Features the kernel is built with: the demo disk carries the shell, the
# launcher programs and the services whose output is asserted below.
FEATURES="${FEATURES:-demo-disk}"
# Which copy of `demo-launcher-rust-io`'s payload the boot must report: the one
# this build compiled (the default), or the one frozen on disk when the caller
# asked for the ABI gate.  Asserting it here is what keeps a gate that means to
# run an old program from passing on a new one.
PAYLOAD_SOURCE="${PAYLOAD_SOURCE:-compiled}"
# Set by `make check-x8664-init-no-start`: the init program on the disk reads
# the declarations and asks for nothing to be started, so the boot's fallback
# is what has to start the services, and the assertions below say so.
INIT_NO_START="${INIT_NO_START:-0}"

KERNEL_BIN="${TARGET_DIR}/x86_64-unknown-none/${PROFILE}/${CRATE}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

if ! command -v "$QEMU" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the x86_64 runtime check.\n' "$QEMU" >&2
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the x86_64 runtime check.\n' >&2
    exit 1
fi

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
"$CARGO" build --offline $profile_flag --target x86_64-unknown-none --bin "$CRATE" \
    --features "$FEATURES"

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'x86_64 kernel binary not found: %s\n' "$KERNEL_BIN" >&2
    exit 1
fi

# The payloads this boot is about to run were copied out of the image, so their
# references have to be relative to themselves.  The image is built, the
# relocation table is right there, and a payload that refers to the kernel's
# copy of something would run the wrong instruction — cheap to check here,
# expensive to see in a log.
sh ./scripts/check-payload-relocations.sh "$KERNEL_BIN"

remove_log_on_exit=0
if [ -n "$X8664_RUNTIME_LOG" ]; then
    mkdir -p "$(dirname "$X8664_RUNTIME_LOG")"
    log_file="$X8664_RUNTIME_LOG"
    : >"$log_file"
else
    log_file="$(mktemp)"
    remove_log_on_exit=1
fi

cleanup() {
    if [ "$remove_log_on_exit" = "1" ]; then
        rm -f "$log_file"
    fi
    if [ -n "${usb_disk:-}" ]; then
        rm -f "$usb_disk"
    fi
}
trap cleanup EXIT INT TERM

# The console is a two-way line on this machine: the guest's serial output is
# what this script reads, and the same line is where the shell gets its
# commands.  `-serial stdio` with the output redirected is therefore the
# configuration that can type at the prompt at all — `-serial file:` can only
# listen — and typing is the half of the shell that a boot by itself never
# exercises.  See the SMP check for why the other checks stay one-way.
#
# The USB disk carries a pattern in its first sector.  A disk that reports its
# capacity has answered a question; only a *block* coming back with the bytes
# the host wrote shows the read path, and the pattern is what tells those bytes
# from a zeroed buffer.  The filesystem rejects the image afterwards — it is not
# a SimpleFs volume — which is a read of its own.
usb_disk="$(mktemp)"
if ! truncate -s 8M "$usb_disk" 2>/dev/null; then
    dd if=/dev/zero of="$usb_disk" bs=1M count=8 2>/dev/null
fi
printf 'PROTOFIRE-USB-DISK' | dd of="$usb_disk" bs=1 conv=notrunc 2>/dev/null

set -- \
    -machine q35 \
    -cpu max \
    -smp 1 \
    -m 1G \
    -kernel "$KERNEL_BIN" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
    -drive "file=$usb_disk,if=none,id=usbdisk,format=raw" \
    -device usb-storage,drive=usbdisk,bus=xhci.0

printf 'x86_64 runtime check: 1 cpu, timeout %ss, qemu %s\n' \
    "$TIMEOUT_SECONDS" "$QEMU"
printf '  %s\n' "timeout ${TIMEOUT_SECONDS}s $QEMU $* -serial stdio >$log_file"

# What is typed at the shell, and why these:
#
# `help` proves the command path end to end — read, split, dispatch, write — and
# `echo` prints a line that the console's echo of the typed line cannot imitate:
# the echo puts the command's own words on that line, so the check below matches
# the answer as a whole line rather than as a substring.  The last two read the
# service manager's own record of where the shell's declaration came from: a
# ring-3 program reading a kernel-served file, so the answer is the boot's
# registry and not the payload's memory.  The feeder waits for the shell's
# banner, not for a delay; see its own header for the rest.
shell_commands() {
    # The frozen payload is a shell from before the `sigasync` builtin existed,
    # and what that gate is for is exactly this: an old payload keeps working.
    # So the signal test is asked for only by the boots whose payload was built
    # with it — a frozen payload is not asked to grow a command.
    if [ "$PAYLOAD_SOURCE" = "frozen" ]; then
        sh ./scripts/feed-shell-console.sh "$log_file" "$TIMEOUT_SECONDS" \
            'help' 'echo ring3-shell-answered' \
            'cat /service/shell/origin' 'cat /service/shell/sha256' \
            'cat /dev/virtio-net/driver' 'cat /dev/virtio-net/category' \
            'cat /dev/bochs-fb/driver' \
            'cat /dev/xhci/driver' 'cat /dev/xhci/category' \
            'echo serial-done'
    else
        sh ./scripts/feed-shell-console.sh "$log_file" "$TIMEOUT_SECONDS" \
            'help' 'echo ring3-shell-answered' \
            'cat /service/shell/origin' 'cat /service/shell/sha256' \
            'cat /dev/virtio-net/driver' 'cat /dev/virtio-net/category' \
            'cat /dev/bochs-fb/driver' 'cat /dev/xhci/driver' \
            'cat /dev/xhci/category' 'sigasync' 'echo serial-done'
    fi
}

set +e
# The USB keyboard has its own way in: QEMU's monitor drives it, and the
# injector waits for the serial half to finish so one input stream is never
# typed at twice.  Its key press is what makes the controller's event ring
# raise an interrupt at all — the ring is otherwise quiet after boot.
usb_monitor="$(mktemp -u)/protofire-usb-monitor.sock"
usb_monitor_dir="$(dirname "$usb_monitor")"
mkdir -p "$usb_monitor_dir"
sh ./scripts/press-usb-keys.sh "$log_file" "$TIMEOUT_SECONDS" "$usb_monitor" \
    "echo usbkeys" &
usb_injector=$!

shell_commands | timeout "${TIMEOUT_SECONDS}s" "$QEMU" "$@" \
    -monitor "unix:$usb_monitor,server,nowait" -serial stdio \
    >"$log_file" 2>>"$log_file"
status=$?
set -e

kill "$usb_injector" 2>/dev/null || true
wait "$usb_injector" 2>/dev/null || true
rm -rf "$usb_monitor_dir"

# 124 is `timeout` killing a machine that is, by design, still running.
case "$status" in
    0|124) ;;
    *)
        printf 'x86_64 runtime check failed with exit status %s\n' "$status" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

fail_with_log() {
    reason="$1"
    bytes="$(wc -c <"$log_file" | tr -d ' ')"

    printf 'x86_64 runtime check failed: %s\n' "$reason" >&2
    printf '  qemu exit status: %s\n' "$status" >&2
    printf '  serial log: %s bytes\n' "$bytes" >&2

    if [ "$bytes" -eq 0 ]; then
        printf '  the guest produced no serial output at all: this is a local\n' >&2
        printf '  invocation problem, not a kernel hang\n' >&2
    else
        printf '  last lines of the log:\n' >&2
        tail -n 12 "$log_file" >&2
    fi

    # The scheduler says out loud when it has lost track of a thread, and that
    # line is what turns "the boot did not finish" into something to act on —
    # which thread, and whether the machine was already missing it.  It is
    # printed rather than asserted: a run that says this and *does* finish is a
    # machine that recovered, and the verdict here stays "did it finish?".
    if grep -F "[sched ]" "$log_file" >/dev/null 2>&1; then
        printf '  the scheduler reported threads it lost track of:\n' >&2
        grep -F "[sched ]" "$log_file" >&2
    fi

    if [ "$remove_log_on_exit" = "0" ]; then
        printf '  full log preserved at: %s\n' "$log_file" >&2
    else
        printf '  re-run with X8664_RUNTIME_LOG=<path> to keep the log\n' >&2
    fi
    exit 1
}

require_log_line() {
    pattern="$1"
    if ! grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line: $pattern"
    fi
}

require_log_absent_line() {
    pattern="$1"
    if grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "unexpected log line: $pattern"
    fi
}

require_log_exact_line() {
    line="$1"
    if ! grep -F -x "$line" "$log_file" >/dev/null 2>&1; then
        fail_with_log "missing log line (whole line): $line"
    fi
}

require_log_matching() {
    pattern="$1"
    if ! grep -E "$pattern" "$log_file" >/dev/null 2>&1; then
        fail_with_log "no log line matches: $pattern"
    fi
}

count_log_line() {
    awk -v needle="$1" '
        index($0, needle) { count += 1 }
        END { print count + 0 }
    ' "$log_file"
}

# ── The boot reached the hand-off point ────────────────────────────────
#
# These are the markers a wedge *does* leave behind: the machine gets this
# far and then stops.  They are asserted so that a failure below says "the
# boot stopped after the hand-off" rather than "the boot never started".
require_log_line "[mem   ] activated x86_64 kernel page tables"
require_log_line "[init  ] starting idle process"
# `/system/init.elf` is a program, not a stub: it reads the declarations off
# the disk and asks for the services to be started.  These two lines are it
# saying so, and they are the only evidence that the file the kernel spawned
# did anything at all.
# The system volume is a pair: the demo disk commits slot B as the newer
# build, so a boot that takes "the newest committed slot" has to say B.
# A boot that fell back to the first slot would read the same files and
# still pass everything below, which is why this line is asserted.
require_log_line "system: slot b active (build 2)"
# And where a running machine writes: the boot says it once, so the
# policy in `src/fs/write_locations.rs` is visible in a log rather than
# only in the source.
require_log_line "runtime writes: /tmp (volatile), /data (persistent)"
require_log_line "adastra init (ring 3): reading /system/rc.d"
# The distribution's first install: the disk stages a package in the download
# cache and init installs it, so a boot shows the whole loop rather than only
# the host tests showing it.
require_log_line "adastra init: installed demo-installed@1.0.0"
require_log_line "adastra init: declared "
# The boot registered the declarations and left the start to that program
# instead of starting them itself: this is the hand-off, and without it the
# services below would be evidence of the kernel starting them, not of init.
require_log_line "service(s) registered; leaving the start to init"
if [ "$INIT_NO_START" = "1" ]; then
    # The other half of the hand-off, and the only boot that reaches it: an
    # init program that never asks leaves the services pending, and the
    # supervisor starts them when the deadline passes.
    require_log_line "adastra init: leaving the start to the kernel"
    require_log_line "init left pending"
fi
# The services this boot runs are the ones the disk declares, not the kernel's
# built-in list: the demo disk is built with `/system/rc.d/defaults.toml`, and
# this line is the boot saying it read them.  A disk without the directory
# prints the other line, which is also a real path — but not this one.
require_log_line "declaration(s) in /system/rc.d"
require_log_line "protofire kernel running"
# The shell is ring-3 code on this architecture: the payload on the demo disk
# prints its own banner and prompt, and the in-kernel host proxy it replaced
# printed `protofire shell (user)` instead.  Asserting the new lines is what
# keeps a boot from passing on the proxy after this changed.
require_log_line "adastra ring3 shell"
# Which copy of the shell went on the disk: the one this build compiled, or the
# one frozen in `src/user/demo/fixtures/`.  The ABI gate runs this same script
# with `PAYLOAD_SOURCE=frozen`, so the interactive assertions below are then
# being made of a shell that was *not* rebuilt — which is the only shape in
# which "we do not break userspace" has something to be false about.
require_log_line "[abi   ] shell payload: $PAYLOAD_SOURCE "
# The prompt is the payload's, and the directory in it is the one the kernel
# says the process is in — the manifest's `working_dir`, not something the
# shell remembered.  A shell that printed a stale or invented path would not
# have this line.
require_log_line "adastra:/apps/packages/shell\$ "

# ── The shell answered what was typed at it ────────────────────────────
#
# The lines above come from the shell's own start-up.  They are also printed by
# a shell that never reads a command, which is how the recovered assembly shell
# this replaced passed for as long as nothing typed at it: it printed a banner
# and a prompt and then faulted on the first line, because its `read_line` kept
# the line at `[rsp]` — the return address — and `ret` jumped to the command
# bytes.  A boot that is never typed at cannot tell those two apart, so this
# check does type.
require_log_line "adastra shell (ring 3) builtins:"
require_log_exact_line "ring3-shell-answered"
# The service manager's provenance, read back by a ring-3 program: which
# declaration file the kernel read the shell's definition from, and the SHA-256
# of that file's bytes.  Both answers come from `/service`, so a boot whose
# registry lost track of where its services came from cannot print them.
require_log_exact_line "/system/rc.d/defaults.toml"
require_log_matching '^[0-9a-f]{64}$'
# The device ledger, read back the same way: the driver that owns the NIC and
# what kind of device it is.  The boot line says the ledger recorded it; these
# two say a ring-3 program can see it through `/dev`.
require_log_line "owned by virtio-net (network)"
require_log_exact_line "virtio-net"
require_log_exact_line "network"
# The NIC's interrupts are its own now: the claim before the controller is up,
# the table programmed once it is, and a completion that arrived on the vector
# the driver named for its queue — the message-signalled path RFC 0003 decided
# for this machine.  A boot that only wrote the table without a handler behind
# it fails on the last of the three.
require_log_line "[virtio-net] device interrupts claimed: irq "
require_log_line "[msix  ] MSI-X on 00:02.0 delivers vectors "
if ! grep -a -qE "\[virtio-net\] (RX|TX) MSI \(irq " "$log_file"; then
    printf 'x86_64 runtime check failed: no queue reported an MSI\n' >&2
    tail -n 12 "$log_file" >&2
    exit 1
fi
# And one a *driver* reported rather than a probe: the bochs-display this
# machine has is found inside the driver's own init, and it says so itself.
require_log_line "owned by bochs-fb (console)"
require_log_exact_line "bochs-fb"
# And the USB host, end to end: the controller is found, reset and started, a
# slot is enabled and the device on the port is addressed, and a HID keyboard's
# interrupt endpoint is configured.  The driver's own log is the evidence —
# nothing here reads a register — and it is the first gate that boots this path
# at all: the controller, the command/event rings, the device enumeration and
# the HID endpoint were all implemented and unverified.
require_log_line "[xhci  ] found xHCI controller at "
require_log_line "[xhci  ] controller initialised and running"
require_log_line "[xhci  ] enabled slot "
require_log_line "[xhci  ] device addressed at slot "
require_log_line "[xhci  ] HID keyboard ready at slot "
require_log_line "owned by xhci (bus)"
require_log_exact_line "xhci"
require_log_exact_line "bus"
# And the interrupt the controller raises for itself: a key pressed on the USB
# keyboard is a HID report, the report is a transfer event on the event ring,
# and the event ring's own MSI-X vector is what says so — which is the one
# thing the tick-polled ring could not prove.  The key press comes from QEMU's
# monitor, so the guest is not simulating anything.
require_log_line "[xhci  ] event ring MSI (irq "
require_log_exact_line "usbkeys"
# And the machine's USB mass storage, from the same controller: a disk the
# guest enumerated, spoke bulk-only SCSI to, read the capacity of, and then
# read a *block* from — the bytes in that line are the pattern this script
# wrote into the image before booting, which is what makes it a read rather
# than a zeroed buffer.  The kernel prefers it as the boot disk, and the
# filesystem reads it again to see whether it is a volume it knows.
require_log_line "[xhci  ] mass storage device detected at slot "
require_log_line "[xhci  ] mass storage initialised at slot "
require_log_line "[usbmsd] USB mass storage: 16384 blocks x 512 bytes = 8 MiB"
require_log_line \
    "[usbmsd] sector 0: [50, 52, 4f, 54, 4f, 46, 49, 52, 45, 2d, 55, 53, 42, 2d, 44, 49]"
require_log_line "[driver] detected boot disk: usb-msd (16384 blocks)"

# ── A signal taken asynchronously, end to end ──────────────────────────
#
# The shell's `sigasync` builtin installs a handler with its own trampoline,
# sends itself SIGUSR1, and then spins in a register the trampoline clobbers.
# The three lines below are only printed if the whole path ran: the kernel
# entered the handler on an interrupt return, the handler's own return reached
# the trampoline, `SIGRETURN` resumed the interrupted instruction, and the
# register it clobbered came back from the frame — the last line is the
# difference between a frame that carries the interrupted context and one that
# only carries where it was.
# A payload that was frozen before the builtin existed cannot run it; that boot
# is the check that it still runs everything else.
if [ "$PAYLOAD_SOURCE" != "frozen" ]; then
    require_log_line "[user  ] signal handler ran"
    require_log_line "[user  ] resumed after sigreturn"
    require_log_line "[user  ] interrupted register survived"
fi

# ── The user programs ran to the end ───────────────────────────────────
#
# Each of these is printed by a program in ring 3 or about one: the labelled
# launchers, the Rust payload, both demo workers finishing, and the service
# supervisor giving up on the fault launcher after its restart budget — the
# last line the demo prints.  None of them appears if the machine stops at the
# hand-off, which is what makes them the assertion that this boot ran.
require_log_line "[user  ] app-id: demo-launcher-fault"
require_log_line "[user  ] rust app-id: demo-launcher-rust-io"
require_log_line "[abi   ] demo-launcher-rust-io payload: $PAYLOAD_SOURCE "
# The second program the disk can freeze: the launcher's own child.  Both
# lines are asserted, so a run with the frozen feature has to ship *both*
# copies from disk — one program started by the other.
require_log_line "[abi   ] demo-launcher-rust payload: $PAYLOAD_SOURCE "
require_log_line "[demo  ] worker-a done"
require_log_line "[demo  ] worker-b done"
require_log_line "[service] abandoning demo-launcher-fault after its restart budget"

# The launcher programs exit through the process-exit path, and their exit is
# announced by the kernel.  A count rather than one exact line: the log is a
# preemptively scheduled interleaving, so which exit prints on which line is
# not fixed, but how many programs leave ring 3 is.
user_exits="$(count_log_line "[user  ] exit pid=")"
if [ "$user_exits" -lt 5 ]; then
    fail_with_log "expected at least 5 user programs to exit, saw $user_exits"
fi

# ── A retired stack's address came back ────────────────────────────────
#
# A kernel stack is handed a slice of the window, and when the stack dies the
# slice is retired until every CPU has dropped its translation for it.  If that
# grace were never satisfied the machine would still look healthy — the window
# would simply grow forever and the property would be gone without a symptom,
# which is exactly the kind of regression a check exists to catch.  The demo
# tears stacks down and creates more, so one slice does come back, and the
# kernel says so once.
require_log_line "[thread] kernel stack window: a retired slice is in use again"

# ── Nothing reported damage ────────────────────────────────────────────
if grep -F "FATAL" "$log_file" >/dev/null 2>&1; then
    fail_with_log "the kernel reported a fatal error during the run"
fi

# ── The kernel stack's guard is real ───────────────────────────────────
#
# A kernel stack lives in the architecture's own window, its guard is a slice
# of that window nothing ever allocates, and the kernel's tables cover what the
# mapping facts say they cover.  A guard the kernel had to report missing, or a
# kernel range the facts describe but the tables do not map, is a real defect —
# and one that would otherwise first show up as an overflow that corrupts
# memory instead of faulting.
for pattern in \
    "[thread] kernel stack guard pages are not enforced" \
    "[mm    ] kernel table gap"; do
    require_log_absent_line "$pattern"
done

service_lines="$(count_log_line "[service]")"

if [ "$remove_log_on_exit" = "0" ]; then
    printf 'x86_64 runtime log saved to %s\n' "$log_file"
fi

printf 'x86_64 runtime check passed: %s user exits, %s service lines\n' \
    "$user_exits" "$service_lines"
