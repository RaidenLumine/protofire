#!/usr/bin/env sh
# File: scripts/check-kaslr-relocs.sh
# Purpose: Fail if the KASLR relocation table drops an entry the kernel stores.
#
# Why this exists
# ---------------
# The relocation table `tools/gen-kaslr-relocs` writes is what a future KASLR
# would apply to a relocated image (`src/arch/x86_64/kaslr.rs`).  It is not
# compiled in yet, so nothing else looks at it — which is how it lost 45
# entries unnoticed: the tool derived the kernel's end from the LOAD
# segments, the frame pool moved out of every segment, and every record whose
# value was `__pool_start`, `__pool_end` or `__image_end` was dropped as
# "spurious" without a line saying so.  A table that silently shrinks is
# worse than one that fails: the day KASLR is enabled, the relocated kernel
# computes its pool bounds from stale link-time numbers.
#
# The tool proves each record against the symbol it names (`site == st_value
# + addend` at the record's width) and reports what it drops by reason.  This
# gate holds it to that proof — zero unresolved, zero unreadable, zero
# mismatches — and to the invariant that matters by name: each boundary
# symbol the kernel stores is in the kept entries at least once.  A record is
# kept only when the proof holds, so a boundary that comes back empty can
# only be a loss, which is the defect this gate exists for.
#
# Usage:
#   sh scripts/check-kaslr-relocs.sh [path-to-kernel-elf]

set -eu

cd "$(dirname "$0")/.."

ELF="${1:-target/x86_64-unknown-none/debug/protofire}"
CARGO="${CARGO:-cargo}"

if [ ! -f "$ELF" ]; then
    printf 'kaslr relocs: no kernel ELF at %s (build it first)\n' "$ELF" >&2
    exit 1
fi

out="$(mktemp)"
log="$(mktemp)"
cleanup() {
    rm -f "$out" "$log"
}
trap cleanup EXIT INT TERM

set +e
KASLR_RELOCS_EXPLAIN=1 "$CARGO" run --offline -q -p gen-kaslr-relocs -- "$ELF" "$out" >"$log" 2>&1
status=$?
set -e

if [ "$status" -ne 0 ]; then
    printf 'kaslr relocs: the generator failed on %s\n' "$ELF" >&2
    cat "$log" >&2
    exit 1
fi

fail() {
    printf 'kaslr relocs check failed: %s\n' "$1" >&2
    cat "$log" >&2
    exit 1
}

# The proof's own arithmetic has to hold for every record: an unresolved or
# unreadable record is one the tool could not check, and a mismatch is one
# the linker's file does not confirm.  Today every record resolves and every
# one matches; a change that breaks either is worth stopping on, because
# both mean the table is being shaped by something other than the linker's
# answer.
summary="$(grep 'KASLR relocs: ' "$log" | tail -n 1)" || true
[ -n "$summary" ] || fail 'the generator printed no summary'
case "$summary" in
    *'(0 unresolved symbol'*) ;;
    *) fail "records the generator could not resolve to a symbol: $summary" ;;
esac
case "$summary" in
    *', 0 unreadable site,'*) ;;
    *) fail "records whose site the generator could not read: $summary" ;;
esac
case "$summary" in
    *', 0 value mismatch,'*) ;;
    *) fail "records the linker's file does not confirm (value mismatch): $summary" ;;
esac

kept="$(printf '%s\n' "$summary" | awk '{ if ($1 == "KASLR" && $2 == "relocs:") print $3 }')"
[ -n "$kept" ] && [ "$kept" -gt 0 ] || fail "no entries were kept: $summary"

# Each boundary symbol the kernel stores has to be in the kept entries.  The
# check is "at least one" because the count itself is code's: how many places
# store `__pool_start` is the pool accessors' shape, and a change that stops
# storing one is a change that can say so where it does.  Empty is never
# code's: the kernel's own `pool_range()` and `kernel_image_range()` read
# exactly these addresses, and an empty count means the table dropped them.
for symbol in __pool_start __pool_end __image_end; do
    if grep -q "boundary $symbol: not in the symbol table" "$log"; then
        fail "$symbol is not in the symbol table of $ELF (the linker script does not define it)"
    fi
    if ! grep -Eq "^boundary $symbol: [1-9][0-9]* kept$" "$log"; then
        fail "$symbol has no kept relocation, and the kernel stores its address (the table lost it)"
    fi
done

grep -E '^(KASLR relocs:|boundary )' "$log" | sed 's/^/kaslr relocs: /'
printf 'kaslr relocs check passed: every stored boundary is in the proven table\n'
