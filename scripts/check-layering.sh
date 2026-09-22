#!/usr/bin/env sh
# File: scripts/check-layering.sh
# Purpose: Ratchet the kernel's module dependency edges.
#
# Kernel layering is not a diagram, it is a count: every `use` or inline path of
# the form `crate::kernel::<module>::` inside `src/kernel/<other_module>/` is one
# edge in the dependency graph.  This script censuses those edges and compares
# the census against `scripts/layering-baseline.txt`.  An edge that grows fails
# the gate; an edge that shrinks also fails, with the command to re-record, so
# the baseline always describes the tree instead of a tree that used to exist.
#
# Why a ratchet again: the kernel has real cycles today — `fs` and `process`
# depend on each other, so do `process` and `smp`, `process` and `sync`,
# `memory` and `fs` — and unwinding them is a sequence of careful cuts, not one
# commit.  A gate that demanded zero would be switched off in a day; a census
# that only ratchets down makes each cut finishable and each regression
# attributable, and it says exactly how much is left.
#
# What is counted
# ---------------
# One edge per occurrence of `crate::kernel::<module>::` in a file under
# `src/kernel/<module>/` (or `src/kernel/<module>.rs`) that names a *different*
# module.  Line comments are stripped first, so prose that mentions a path —
# including `//!` and `///` — does not count; a path inside a string does, which
# is the price of not parsing Rust here.  Self-references are skipped: a module
# may use its own items however it likes.
#
# Usage:
#   sh scripts/check-layering.sh             # check against the baseline
#   sh scripts/check-layering.sh --record    # rewrite the baseline

set -eu

cd "$(dirname "$0")/.."

BASELINE="${BASELINE:-scripts/layering-baseline.txt}"

mode=check
case "${1:-}" in
    '') ;;
    --record) mode=record ;;
    -h|--help)
        sed -n '2,30p' "$0"
        exit 0
        ;;
    *)
        printf 'unsupported argument: %s\n' "$1" >&2
        exit 1
        ;;
esac

if [ ! -f "$BASELINE" ]; then
    printf 'layering baseline not found: %s\n' "$BASELINE" >&2
    printf 'run with --record to create it\n' >&2
    exit 1
fi

work="$(mktemp -d)"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

# Every edge in the tree, as `<from> <to> <count>` sorted by the pair.
census() {
    find src/kernel -name '*.rs' | sort | while read -r file; do
        rel="${file#src/kernel/}"
        case "$rel" in
            */*) from="${rel%%/*}" ;;
            *) from="${rel%.rs}" ;;
        esac
        awk -v from="$from" '
            { line = $0; sub(/\/\/.*/, "", line) }
            {
                rest = line
                while (match(rest, /crate::kernel::[a-z_0-9]+::/)) {
                    tok = substr(rest, RSTART, RLENGTH)
                    sub(/^crate::kernel::/, "", tok)
                    sub(/::$/, "", tok)
                    if (tok != from) print from, tok
                    rest = substr(rest, RSTART + RLENGTH)
                }
            }
        ' "$file"
    done | sort | uniq -c | awk '{ print $2, $3, $1 }' | sort -k1,1 -k2,2
}

census >"$work/census.txt"

if [ "$mode" = "record" ]; then
    next_baseline="$work/baseline.new"
    grep -E '^[[:space:]]*(#|$)' "$BASELINE" >"$next_baseline" || true
    awk '{ printf "%-28s %-28s %s\n", $1, $2, $3 }' "$work/census.txt" >>"$next_baseline"
    mv "$next_baseline" "$BASELINE"
    printf 'recorded %s layering edges in %s\n' \
        "$(wc -l <"$work/census.txt" | tr -d ' ')" "$BASELINE"
    exit 0
fi

# Baseline rows, comments stripped: `<from> <to> <count>`.
awk '
    { sub(/#.*/, "") }
    NF == 0 { next }
    NF != 3 { printf "malformed baseline line: %s\n", $0 > "/dev/stderr"; bad = 1; next }
    { print $1, $2, $3 > "'"$work"'/baseline.txt" }
    END { exit bad }
' "$BASELINE"

failed=0

# Every edge in the baseline: grown, shrunk, or unchanged.
while read -r from to baseline_count; do
    case "$baseline_count" in
        *[!0-9]*)
            printf 'baseline count is not a number: %s %s %s\n' "$from" "$to" "$baseline_count" >&2
            failed=1
            continue
            ;;
    esac

    count="$(awk -v f="$from" -v t="$to" '$1 == f && $2 == t { print $3 }' "$work/census.txt")"
    count="${count:-0}"

    if [ "$count" -gt "$baseline_count" ]; then
        printf 'layering: %s -> %s grew from %s to %s\n' \
            "$from" "$to" "$baseline_count" "$count" >&2
        printf '  a new dependency between these modules needs to be argued for,\n' >&2
        printf '  not added: see the layering notes in docs/fmts/code-style.md\n' >&2
        failed=1
    elif [ "$count" -lt "$baseline_count" ]; then
        printf 'layering: %s -> %s shrank from %s to %s\n' \
            "$from" "$to" "$baseline_count" "$count" >&2
        printf '  good, but the census has to follow in the same change:\n' >&2
        printf '  sh scripts/check-layering.sh --record\n' >&2
        failed=1
    fi
done <"$work/baseline.txt"

# And every edge the tree has that the baseline does not know about at all.
while read -r from to count; do
    if ! awk -v f="$from" -v t="$to" '$1 == f && $2 == t { found = 1 } END { exit !found }' \
        "$work/baseline.txt"; then
        printf 'layering: new edge %s -> %s (%s)\n' "$from" "$to" "$count" >&2
        printf '  record it deliberately with --record if it belongs\n' >&2
        failed=1
    fi
done <"$work/census.txt"

if [ "$failed" != "0" ]; then
    exit 1
fi

printf 'layering check passed: %s edges, unchanged\n' \
    "$(wc -l <"$work/census.txt" | tr -d ' ')"
