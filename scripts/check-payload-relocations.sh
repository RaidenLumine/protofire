#!/usr/bin/env sh
# File: scripts/check-payload-relocations.sh
# Purpose: Assert that a demo payload's relocations all name the payload.
#
# Why this exists
# ---------------
# A payload is compiled into the kernel image and then copied out of its
# section and run at another address.  Every reference it makes has to be
# relative to itself: a `lea rip+sym` into the section survives the move, an
# absolute address does not — it still names the kernel's copy.
#
# The existing payload tests read the *host* build's disassembly and reject
# 64-bit absolute immediates.  That missed three absolute 32-bit addresses in
# `adastra_demo_program_rust`: the exception-recovery handlers were defined
# outside the section and installed with a function-pointer cast, so `mov
# $imm32, %rsi` carried the kernel image's address of each handler into a
# program that runs at another one.
#
# The check that catches that class is at the linker's level rather than the
# decoder's: read the image's relocation table and require every entry of a
# payload section to name that section.  A 32-bit immediate that happens to be
# a small constant is not distinguishable from an address in the instruction
# stream, but a *relocation* is exactly a reference the linker had to resolve.
#
# Usage:
#   sh scripts/check-payload-relocations.sh [path-to-kernel-image]

set -eu

cd "$(dirname "$0")/.."

IMAGE="${1:-target/x86_64-unknown-none/debug/protofire}"
SECTIONS="adastra_demo_program_rust adastra_demo_program_rust_io adastra_demo_program_payload adastra_shell_payload"

if [ ! -f "$IMAGE" ]; then
    printf 'payload relocations: no image at %s (build it first)\n' "$IMAGE" >&2
    exit 1
fi

if ! command -v readelf >/dev/null 2>&1; then
    printf 'payload relocations: readelf is not installed\n' >&2
    exit 1
fi

work="$(mktemp)"
cleanup() {
    rm -f "$work"
}
trap cleanup EXIT INT TERM

readelf -r -W "$IMAGE" >"$work"

# One payload section's relocations, and the ones that name something else.
#
# The header line is localized ("Relocation section '.rela<name>' ..." in
# English, "重定位节 '.rela<name>' ..." otherwise), so the section is found by
# the quoted name rather than by the words around it.
check_section() {
    section="$1"
    awk -v section="$section" '
        function report() {
            if (n > 0) {
                for (i = 1; i <= n; i++) print "    " lines[i]
                bad = 1
            }
            n = 0
        }
        /^.*'"'"'\.rela[^'"'"']*'"'"'/ {
            match($0, /'"'"'\.rela[^'"'"']*'"'"'/)
            name = substr($0, RSTART + 1, RLENGTH - 2)
            in_section = (substr(name, 6) == section)
            next
        }
        in_section && NF == 0 { in_section = 0 }
        in_section && $3 ~ /^R_X86_64_/ {
            if ($5 != section) { n++; lines[n] = $0 }
        }
        END { report(); exit bad }
    ' "$work"
}

failed=0
for section in $SECTIONS; do
    if ! out="$(check_section "$section")"; then
        printf 'payload relocations: %s refers outside itself:\n' "$section" >&2
        printf '%s\n' "$out" >&2
        printf '  a payload is copied to another address and run there, so every\n' >&2
        printf '  reference it makes must be relative to the payload itself\n' >&2
        failed=1
    fi
done

if [ "$failed" -ne 0 ]; then
    exit 1
fi

printf 'payload relocations: %s section(s) self-contained\n' \
    "$(printf '%s\n' $SECTIONS | wc -l | tr -d ' ')"
