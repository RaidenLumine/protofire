#!/usr/bin/env sh
# File: scripts/check-aarch64-runtime.sh
# Purpose: Headless QEMU smoke test for the current AArch64 fault/wait boundary.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${TARGET_DIR:-target}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-20}"
# The kernel embeds a 512 MiB physical-frame pool as a static BSS array, so the
# loaded image spans ~1.6 GiB of address space.  QEMU's `-kernel` loader refuses
# to fit it into the default 512 MiB, so default to 2 GiB (override via QEMU_RAM).
QEMU_RAM="${QEMU_RAM:-2G}"
QEMU_AARCH64="${QEMU_AARCH64:-qemu-system-aarch64}"
KERNEL_BIN="${TARGET_DIR}/aarch64-unknown-none/${PROFILE}/${CRATE}.img"
AARCH64_RUNTIME_LOG="${AARCH64_RUNTIME_LOG:-}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

if ! command -v "$QEMU_AARCH64" >/dev/null 2>&1; then
    printf '%s is not installed; cannot run the aarch64 runtime check.\n' "$QEMU_AARCH64" >&2
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    printf 'timeout is not installed; cannot bound the aarch64 runtime check.\n' >&2
    exit 1
fi

# The runtime assertions below (demo slots, demo-launcher payload, aarch64
# EL0 fault/wait) all require the in-memory demo volume, which is compiled in
# only when the `demo-disk` cargo feature is enabled.  Build with it explicitly
# rather than relying on `make build-aarch64` (which does not enable it).
case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac
# The Image, not the ELF: only the arm64 Image boot path is handed a device
# tree, and a kernel that boots without one silently falls back to hardcoded
# platform constants.  See scripts/build-aarch64-image.sh.
# Overridable so the ABI gate can ask for the frozen payload instead of the
# one this build compiled.
FEATURES="${FEATURES:-demo-disk}" PROFILE="$PROFILE" CRATE="$CRATE" TARGET_DIR="$TARGET_DIR" \
    sh ./scripts/build-aarch64-image.sh

if [ ! -f "$KERNEL_BIN" ]; then
    printf 'aarch64 kernel binary not found: %s\n' "$KERNEL_BIN" >&2
    exit 1
fi

remove_log_on_exit=0
gicv3_log=""
if [ -n "$AARCH64_RUNTIME_LOG" ]; then
    mkdir -p "$(dirname "$AARCH64_RUNTIME_LOG")"
    log_file="$AARCH64_RUNTIME_LOG"
    : >"$log_file"
else
    log_file="$(mktemp)"
    remove_log_on_exit=1
fi

cleanup() {
    if [ "$remove_log_on_exit" = "1" ]; then
        rm -f "$log_file"
        # The GICv3 boot's log is a second temporary, and a failure inside the
        # assertions that read it exits with `$log_file` pointing there.
        [ -z "${gicv3_log:-}" ] || rm -f "$gicv3_log"
    fi
}
trap cleanup EXIT INT TERM

# The console is a two-way line on this machine too: the guest's serial output is
# what this script reads, and the same line is where the shell gets its commands.
# `-serial stdio` with the output redirected is therefore the configuration that
# can type at the prompt at all, and typing is the half of the shell a boot by
# itself never exercises.  What made an earlier attempt at this fail was not
# stdio itself: QEMU's stdio back-end is qualified by the terminal it inherits,
# and with a *tty* on stdin and a redirected stdout it wrote nothing here.  The
# feeder pipes stdin, so there is no terminal in the picture, and the guest's
# output lands in the log exactly as it does with `-serial file:`.
shell_commands() {
    sh ./scripts/feed-shell-console.sh "$log_file" "$TIMEOUT_SECONDS" \
        'help' 'echo ring3-shell-answered' \
        'cat /service/shell/origin' 'cat /service/shell/sha256' \
        'cat /dev/virtio-net/driver' 'cat /dev/virtio-net/category'
}

set +e
shell_commands | timeout "${TIMEOUT_SECONDS}s" "$QEMU_AARCH64" \
    -machine virt \
    -cpu max \
    -smp 1 \
    -m "$QEMU_RAM" \
    -kernel "$KERNEL_BIN" \
    -display none \
    -serial stdio \
    -no-reboot \
    -no-shutdown \
    -global virtio-mmio.force-legacy=false \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 >"$log_file" 2>>"$log_file"
status=$?
set -e

case "$status" in
    0|124) ;;
    *)
        printf 'aarch64 runtime check failed with exit status %s\n' "$status" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit "$status"
        ;;
esac

require_log_line() {
    pattern="$1"
    if ! grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        bytes="$(wc -c <"$log_file" | tr -d ' ')"
        printf 'missing aarch64 runtime log: %s\n' "$pattern" >&2
        printf '  serial log: %s bytes\n' "$bytes" >&2
        # Keep the whole log; see the riscv64 check for why a failure that may
        # not reproduce is worth the disk.
        preserved="${TMPDIR:-/tmp}/protofire-aarch64-runtime-failed.log"
        if cp "$log_file" "$preserved" 2>/dev/null; then
            printf '  full log preserved at: %s\n' "$preserved" >&2
        fi
        if [ "$bytes" -eq 0 ]; then
            printf '  the guest produced no serial output at all: that is a local\n' >&2
            printf '  invocation problem, not a kernel hang\n' >&2
        fi
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    fi
}

require_log_exact_line() {
    line="$1"
    if ! grep -F -x "$line" "$log_file" >/dev/null 2>&1; then
        printf 'missing aarch64 runtime log line (whole line): %s\n' "$line" >&2
        printf '  last lines of the log:\n' >&2
        tail -n 12 "$log_file" >&2
        exit 1
    fi
}

require_log_matching() {
    pattern="$1"
    if ! grep -a -E "$pattern" "$log_file" >/dev/null 2>&1; then
        printf 'no aarch64 runtime log line matches: %s\n' "$pattern" >&2
        tail -n 12 "$log_file" >&2
        exit 1
    fi
}

require_log_line_count() {
    pattern="$1"
    expected_count="$2"
    count="$(
        awk -v needle="$pattern" '
            index($0, needle) { count += 1 }
            END { print count + 0 }
        ' "$log_file"
    )"
    if [ "$count" != "$expected_count" ]; then
        printf 'unexpected aarch64 runtime log count for %s: expected=%s actual=%s\n' \
            "$pattern" "$expected_count" "$count" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    fi
}

# Assert on the pieces of a `write_prefixed_hex` line rather than on the line
# they usually form together.
#
# That payload prints such a line with three writes — the prefix, the number,
# the newline — because it carries no formatter.  The console serialises each
# *write*, not each line, so a kernel thread printing between two of them
# splits the line, and the log then reads
#
#     [user  ] aarch64-rust wait-vector: [demo  ] worker-a step 1
#     [demo  ] worker-b step 1
#     0x0000000000000020
#
# which is a correct run.  Asserting the joined line made this check red in
# two of four `make verify` runs with nothing behind it.  What the payload
# does guarantee is that the prefix arrives whole — it is one write — and
# that its number follows, on the same line when nothing interleaved and on a
# later one when something did.  That is what this asserts, and it still pins
# the number: a wrong syndrome fails here exactly as it did before.
#
# A payload that built the whole line in one buffer before writing it would
# let these go back to a plain line match.  That changes the bytes of a frozen
# fixture, so it is a deliberate re-freeze rather than a quiet tidy-up.
require_log_fragments() {
    prefix="$1"
    value="$2"
    expected_count="$3"
    stats="$(
        awk -v prefix="$prefix" -v value="$value" '
            index($0, prefix) > 0 {
                seen += 1
                rest = substr($0, index($0, prefix))
                if (index(rest, value) > 0) { matched += 1; pending = 0 }
                else { pending = 1 }
                next
            }
            pending && index($0, value) > 0 { matched += 1; pending = 0 }
            END { print seen + 0, matched + 0 }
        ' "$log_file"
    )"
    seen="${stats% *}"
    matched="${stats#* }"
    if [ "$seen" != "$expected_count" ] || [ "$matched" != "$expected_count" ]; then
        printf 'unexpected aarch64 runtime log fragments: %s expected=%s seen=%s matched=%s\n' \
            "$prefix" "$expected_count" "$seen" "$matched" >&2
        preserved="${TMPDIR:-/tmp}/protofire-aarch64-runtime-failed.log"
        if cp "$log_file" "$preserved" 2>/dev/null; then
            printf '  full log preserved at: %s\n' "$preserved" >&2
        fi
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    fi
}

first_log_line_number() {
    pattern="$1"
    awk -v needle="$pattern" '
        index($0, needle) {
            print NR
            found = 1
            exit
        }
        END {
            if (!found) {
                exit 1
            }
        }
    ' "$log_file"
}

require_log_line_order() {
    first_pattern="$1"
    second_pattern="$2"
    first_line="$(first_log_line_number "$first_pattern")" || {
        printf 'missing aarch64 runtime log for order check: %s\n' "$first_pattern" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    }
    second_line="$(first_log_line_number "$second_pattern")" || {
        printf 'missing aarch64 runtime log for order check: %s\n' "$second_pattern" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    }
    if [ "$first_line" -ge "$second_line" ]; then
        printf 'unexpected aarch64 runtime log order: %s (line %s) should appear before %s (line %s)\n' \
            "$first_pattern" "$first_line" "$second_pattern" "$second_line" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    fi
}

require_log_absent_line() {
    pattern="$1"
    if grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
        printf 'unexpected aarch64 runtime log: %s\n' "$pattern" >&2
        if [ "$remove_log_on_exit" = "0" ]; then
            printf 'full aarch64 runtime log preserved at: %s\n' "$log_file" >&2
        fi
        cat "$log_file" >&2
        exit 1
    fi
}

require_log_lines() {
    while IFS= read -r pattern; do
        [ -n "$pattern" ] || continue
        require_log_line "$pattern"
    done
}

require_log_line_orders() {
    while IFS='|' read -r first_pattern second_pattern; do
        [ -n "$first_pattern" ] || continue
        require_log_line_order "$first_pattern" "$second_pattern"
    done
}

require_log_absent_lines() {
    while IFS= read -r pattern; do
        [ -n "$pattern" ] || continue
        require_log_absent_line "$pattern"
    done
}

# Keep this contract aligned with the target-side behaviour verified against
# the actual aarch64 QEMU runtime output.
#
# What this boot has to show: the kernel comes up on its own runtime tables
# (device window, RAM window, and the stack window its own stacks live in) and
# hands control to the scheduler; the service supervisor starts the three
# kernel workers and the three user programs; the aarch64-rust payload takes
# a code-write fault, a stack-exec fault and a nested code-write fault from
# EL0 and resumes after each; two child processes run off the end of their
# stacks and are terminated; the demo workers run to completion; and every
# service stops.
#
# 2026-06-26: the spawn/wait race is fixed via
# PROCESS_SPAWN_FLAG_START_SUSPENDED — children stay suspended until the
# parent calls wait, so a child cannot fault before the parent is ready.  The
# deferred-drop fix for PreparedProcessAddressSpace (moving the drop from the
# trap handler with IRQs disabled to the reap path with IRQs enabled) also
# resolved a pre-existing hang during process termination on aarch64.
require_log_lines <<'EOF'
Protofire kernel prototype starting
[boot:loader] qemu-direct
[boot:init] initializing subsystems
[mem   ] prepared aarch64 kernel page tables
windows=3
[user  ] prepared aarch64 EL0 demo slots=8
exception-stack=
[user  ] loaded /apps/packages/shell/bin/shell.elf id=shell
[user  ] loaded /apps/packages/demo-launcher/bin/demo.elf id=demo-launcher
[user  ] loaded /apps/packages/demo-launcher-rust/bin/demo.elf id=demo-launcher-rust
[user  ] process-root root=0x
kernel=524288 user=
[init  ] starting idle process
protofire kernel running
adastra ring3 shell
[user  ] hello from aarch64 rust payload
[user  ] aarch64-rust triggering local code-write fault
[user  ] aarch64-rust resumed after local code-write fault
[user  ] aarch64-rust resumed after local stack-exec fault
[user  ] aarch64-rust triggering nested local code-write fault
[user  ] aarch64-rust resumed after nested local code-write fault
[user  ] aarch64 child stack-exec fault
[user] terminating pid=
access=execute
[demo  ] worker-a step 0
[demo  ] worker-a done
[demo  ] worker-b step 0
[demo  ] worker-b done
[service] kernel thread kworker-a started
[service] kworker-a stopped
[service] kworker-b stopped
[service] kworker-syscall-fs stopped
[service] demo-launcher stopped
[service] demo-launcher-rust stopped
EOF

# The payload's syndrome lines are the three-write ones the helper above
# exists for, so they are asserted as fragments rather than in the list.
require_log_fragments "[user  ] aarch64-rust wait-vector:" "0x0000000000000020" 2
require_log_fragments "[user  ] aarch64-rust wait-error:" "0x000000000000000f" 2
require_log_fragments "[user  ] aarch64-rust wait-fsc:" "0x000000000000000f" 2
require_log_fragments "[user  ] aarch64-rust wait-access:" "0x0000000000000002" 2
require_log_fragments "[user  ] aarch64-rust wait-kind:" "0x0000000000000002" 2

# Twice each, because the payload runs twice: once as the launcher and once as
# the image that launcher starts.  The counts are the assertion that the two
# runs both got all the way through their faults and both came back.
require_log_line "[abi   ] demo-launcher payload: ${PAYLOAD_SOURCE:-compiled} "

# ── The shell is ring-3 code, and it answered what was typed at it ─────
#
# `adastra ring3 shell` above is the shell payload's own banner; the in-kernel
# host proxy it replaced printed `protofire shell (user)`, so asserting the new
# line is what keeps a boot from passing on the proxy after this changed.  The
# prompt carries the directory the kernel says the process is in — the
# manifest's `working_dir`, not something the shell remembered.
#
# Those lines are also printed by a shell that never reads a command, which is
# how the recovered assembly shell this replaced passed for as long as nothing
# typed at it: banner, prompt, and then a fault on the first line, because its
# `read_line` kept the line at `[rsp]` — the return address — and `ret` jumped
# to the command bytes.  A boot that is never typed at cannot tell those two
# apart, so this check types; `scripts/feed-shell-console.sh` is what does it.
require_log_line "[abi   ] shell payload: ${PAYLOAD_SOURCE:-compiled} "
require_log_line "adastra:/apps/packages/shell\$ "
require_log_line "adastra shell (ring 3) builtins:"
# `/system/init.elf` is a program on this target too: it reads the declarations
# off the disk and asks for the services to be started, and says so.  The boot
# left the start to it rather than starting them itself — that line is the
# hand-off, and without it the services below would prove the kernel started
# them, not init.
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
require_log_line "adastra init: declared "
require_log_line "service(s) registered; leaving the start to init"
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

# ── The PCIe window the device tree describes was reached ──────────────
#
# This machine's host bridge is described the same way riscv64's is, and the
# parser settled it when it read `reg` — a decision that cannot work, because
# `compatible` comes after `reg` in every device tree QEMU writes.  The window
# was never found, `probe_and_enumerate` returned None, and nothing said so,
# because no gate had a PCIe device on the bus to look for.  This boot has its
# network device *only* on that bus, so the lines below are also the end of the
# chain: the ECAM is mapped, the BARs are assigned, and the driver drives the
# device through the modern PCI transport.
require_log_line "[pci   ] AArch64 PCIe ECAM mapped PA="
require_log_line "[pci   ] AArch64 BARs: 2 assigned"
require_log_line "[pci   ] PCI: 2 device(s) found"
require_log_line "00:01.0 vend=1af4 dev=1000"
require_log_line "00:01.0 BAR4 0x0000000010004000"
require_log_line "caps: MSI-X"
require_log_line "[drivers] no virtio-net device found in the MMIO window"
require_log_line "[drivers] virtio-net device found (PCI modern)"

require_log_line_count "[user  ] hello from aarch64 rust payload" 2
require_log_line_count "[user  ] aarch64-rust resumed after local code-write fault" 2
require_log_line_count "[user  ] aarch64-rust resumed after local stack-exec fault" 2
require_log_line_count "[user  ] aarch64-rust resumed after nested local code-write fault" 2
require_log_line_count "[user  ] aarch64 child stack-exec fault" 2
# ── The device tree arrived and was used ──────────────────────────────
#
# QEMU hands a device tree over only on the arm64 `Image` boot path, and this
# check boots that Image.  Two assertions, because either alone can pass while
# the kernel is really running on hardcoded constants: the hand-off address
# must not be the zero a bare-metal ELF gets, and the device tree must have
# driven a probe — the virtio-mmio window is enumerated from it rather than
# guessed.
require_log_absent_line "info=0x00000000"
require_log_line "[drivers] probing"

# ── Network boot smoke tests ───────────────────────────────────────────
#
# These two were commented out with "re-enable when aarch64 VirtIO
# networking is stable", and the reason they failed was not the driver:
# this boot attached its virtio-mmio device without asking QEMU for the
# modern interface, so the device answered as a legacy one (version 1)
# and the probe — which drives the modern register layout — correctly
# refused it.  The machine now passes `VIRT_FORCE_LEGACY`, the same option
# the x86_64 and riscv64 smokes pass, and the two lines below are what the
# network stack says when it really does come up.
require_log_line "[driver] detected boot network device"
require_log_line "[kernel] network stack initialized"

require_log_line_orders <<'EOF'
[user  ] hello from aarch64 rust payload|[user  ] aarch64-rust triggering local code-write fault
[user  ] aarch64-rust triggering local code-write fault|[user  ] aarch64-rust resumed after local code-write fault
[user  ] aarch64-rust resumed after local code-write fault|[user  ] aarch64-rust resumed after local stack-exec fault
[user  ] aarch64-rust resumed after local stack-exec fault|[user  ] aarch64-rust triggering nested local code-write fault
[user  ] aarch64-rust resumed after nested local code-write fault|[user  ] aarch64 child stack-exec fault
[user  ] aarch64 child stack-exec fault|[user  ] aarch64-rust wait-vector:
[init  ] starting idle process|protofire kernel running
[service] kernel thread kworker-a started|[service] kworker-a stopped
[demo  ] worker-a step 1|[demo  ] worker-a done
[demo  ] worker-b step 1|[demo  ] worker-b done
EOF

require_log_absent_lines <<'EOF'
[user  ] aarch64 child code-write unexpectedly succeeded
[user  ] aarch64 child stack-exec unexpectedly succeeded
[user  ] aarch64 child stack-guard unexpectedly succeeded
[user  ] aarch64-rust install-handler failed:
[user  ] aarch64-rust handler-state-fail:
[WARN ] aarch64 lower-el sync fatal
[user  ] refusing invalid aarch64 entry frame
[user  ] refusing invalid aarch64 return frame
[FATAL] invalid aarch64
[FATAL] aarch64 trap
EOF

# The kernel stack's guard page is part of the boot contract, not a property
# of the machine the boot happens to run on.  A stack lives in the
# architecture's own window, its guard is the slice of that window the
# allocator never hands out, and the kernel's tables cover what they say they
# cover — so a guard that had to be reported as missing, or a kernel range the
# facts describe but the tables do not map, fails this check rather than
# showing up later as an overflow that corrupts memory instead of faulting.
require_log_absent_lines <<'EOF'
[thread] kernel stack guard pages are not enforced
[mm    ] kernel table gap
EOF

require_log_absent_line "[user  ] aarch64-rust spawn failed: "
require_log_absent_line "[user  ] aarch64-rust wait failed: "
require_log_absent_line "[user  ] aarch64 wait-status: 0xffffffffffffffff"
require_log_absent_line "[user  ] aarch64-rust wait-status: 0xffffffffffffffff"
require_log_absent_line "[user  ] aarch64 exec-error: "
require_log_absent_line "[user  ] aarch64 spawn-status: "
require_log_absent_line "[user  ] aarch64-rust net-udp-send fail:"

if [ "$remove_log_on_exit" = "0" ]; then
    printf 'aarch64 runtime log saved to %s\n' "$log_file"
fi

# ── The same kernel on a GICv3 machine ────────────────────────────────
#
# The machine above is a GICv2 one (`arm,cortex-a15-gic` in its device tree),
# so everything asserted so far was asserted against the controller the
# original driver understood.  A GICv3 is a different shape: the CPU interface
# is the `ICC_*` system registers rather than a frame at `0x0801_0000`, the
# SGI/PPI bank lives in a per-PE redistributor rather than in the distributor,
# and SGIs are sent by affinity.  Programming the v2 layout onto one used to
# end in a data abort at exactly that CPU-interface address, inside
# interrupt-controller init.
#
# So this second boot is the same kernel on the other controller, and it has to
# do more than start: with two CPUs, the AP is brought up through the same
# per-CPU path a GICv3 needs — find this core's redistributor, wake it, enable
# its own interface — and the timer tick that drives the rest of the boot is
# delivered as a Group 1 PPI through that interface.  A boot that reached the
# scheduler on a controller it had not really initialised is not a thing that
# can happen here, which is why the assertions are the milestones themselves
# and not just the absence of the old refusal.
#
# The refusal messages and the v2-interface fault stay asserted absent: they
# are what a regression would look like, and a boot that fell back to the v2
# driver would print or fault at exactly one of them.
gicv3_log="$(mktemp)"
set +e
timeout "${TIMEOUT_SECONDS}s" "$QEMU_AARCH64" \
    -machine virt,gic-version=3 \
    -cpu max \
    -smp 2 \
    -m "$QEMU_RAM" \
    -kernel "$KERNEL_BIN" \
    -display none \
    -serial "file:$gicv3_log" \
    -no-reboot \
    -no-shutdown \
    -global virtio-mmio.force-legacy=false \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 >/dev/null 2>&1
set -e

# The assertions below all read `$log_file`, so point it at this boot while
# they run and put it back afterwards.
main_log="$log_file"
log_file="$gicv3_log"

require_log_absent_line "aarch64 interrupt driver implements GICv2"
require_log_absent_line "far=0x0000000008010000"

require_log_line "[irq   ] GICv3 at "
# The controller has one redistributor per PE, and this machine has two.
require_log_line "2 redistributor frame(s)"
require_log_line "[smp   ] 2 CPUs total, 1 AP(s)"
require_log_line "[smp   ] AP cpu_id=1 online"
require_log_line "[pci   ] AArch64 PCIe ECAM mapped PA="
require_log_line "[kernel] network stack initialized"
require_log_line "protofire kernel running"

log_file="$main_log"
rm -f "$gicv3_log"

printf 'aarch64 runtime check passed at current metadata/fault/wait boundary\n'
