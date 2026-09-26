#!/usr/bin/env sh
# File: scripts/check-arch-fanout.sh
# Purpose: Ratchet the architecture gates that live outside `src/arch/`.
#
# Porting the kernel to a fourth architecture should mean writing that
# architecture's own directory.  Today it does not: code all over the tree
# decides what to do with `#[cfg(target_arch = "…")]`, so a new architecture
# has to find and edit every one of them.  Those gates are the wall that
# "more hardware" runs into, and a wall nobody measures is a wall nobody
# moves.
#
# This check counts them, per file, and compares the result with
# `scripts/arch-fanout-baseline.txt`.  Every `target_arch = "x86_64"`,
# `"aarch64"`, or `"riscv64"` in a `.rs` file outside `src/arch/` is one
# occurrence.  A count that grows fails the gate; a count that shrinks also
# fails, with the command to re-record, so the baseline always describes the
# tree instead of a tree that used to exist.
#
# What is counted and what is not
# -------------------------------
# Only the three names the tree knows.  A bare `not(any(target_arch = …))`
# arm counts once per name in it, not once for "some other architecture":
# the file still has to be edited for a fourth one, which is what the number
# is about.  Line comments are stripped first, so prose that mentions a gate
# does not count.  `target_os` gates are deliberately not counted — a new
# architecture is bare-metal as well, so those gates do not move.
#
# Usage:
#   sh scripts/check-arch-fanout.sh             # check against the baseline
#   sh scripts/check-arch-fanout.sh --record    # rewrite the baseline

set -eu

cd "$(dirname "$0")/.."

BASELINE="${BASELINE:-scripts/arch-fanout-baseline.txt}"

mode=check
case "${1:-}" in
    '') ;;
    --record) mode=record ;;
    -h|--help)
        sed -n '2,33p' "$0"
        exit 0
        ;;
    *)
        printf 'unsupported argument: %s\n' "$1" >&2
        exit 1
        ;;
esac

if [ ! -f "$BASELINE" ]; then
    printf 'arch-fanout baseline not found: %s\n' "$BASELINE" >&2
    printf 'run with --record to create it\n' >&2
    exit 1
fi

work="$(mktemp -d)"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

# Every file outside `src/arch/` that names an architecture, and how many
# times, as `<path under src/> <count>` sorted by path.
census() {
    find src -name '*.rs' -not -path 'src/arch/*' | sort | while read -r file; do
        rel="${file#src/}"
        count="$(awk '
            { line = $0; sub(/\/\/.*/, "", line) }
            {
                rest = line
                while (match(rest, /target_arch *= *"(x86_64|aarch64|riscv64)"/)) {
                    n++
                    rest = substr(rest, RSTART + RLENGTH)
                }
            }
            END { print n + 0 }
        ' "$file")"
        if [ "$count" -gt 0 ]; then
            printf '%s %s\n' "$rel" "$count"
        fi
    done
}

census >"$work/census.txt"

files="$(wc -l <"$work/census.txt" | tr -d ' ')"
occurrences="$(awk '{ total += $2 } END { print total + 0 }' "$work/census.txt")"

if [ "$mode" = "record" ]; then
    next_baseline="$work/baseline.new"
    awk -v files="$files" -v occurrences="$occurrences" '
        /^#/ { print; next }
        /^$/ { print; next }
        { exit }
    ' "$BASELINE" >"$next_baseline"
    printf '# %s files, %s occurrences outside src/arch\n\n' \
        "$files" "$occurrences" >>"$next_baseline"
    awk '{ printf "%-52s %s\n", $1, $2 }' "$work/census.txt" >>"$next_baseline"
    mv "$next_baseline" "$BASELINE"
    printf 'recorded %s files, %s occurrences in %s\n' \
        "$files" "$occurrences" "$BASELINE"
    exit 0
fi

# Baseline rows, comments stripped: `<path> <count>`.
awk '
    { sub(/#.*/, "") }
    NF == 0 { next }
    NF != 2 { printf "malformed baseline line: %s\n", $0 > "/dev/stderr"; bad = 1; next }
    { print $1, $2 > "'"$work"'/baseline.txt" }
    END { exit bad }
' "$BASELINE"

failed=0

# Every file in the baseline: grown, shrunk, or unchanged.
while read -r path baseline_count; do
    case "$baseline_count" in
        *[!0-9]*)
            printf 'baseline count is not a number: %s %s\n' "$path" "$baseline_count" >&2
            failed=1
            continue
            ;;
    esac

    count="$(awk -v p="$path" '$1 == p { print $2 }' "$work/census.txt")"
    count="${count:-0}"

    if [ "$count" -gt "$baseline_count" ]; then
        printf 'arch fanout: %s grew from %s to %s\n' \
            "$path" "$baseline_count" "$count" >&2
        printf '  a gate outside src/arch/ is one more place a new\n' >&2
        printf '  architecture has to be taught: ask the arch layer instead\n' >&2
        printf '  (see §14 of docs/fmts/code-style.md)\n' >&2
        failed=1
    elif [ "$count" -lt "$baseline_count" ]; then
        printf 'arch fanout: %s shrank from %s to %s\n' \
            "$path" "$baseline_count" "$count" >&2
        printf '  good, but the census has to follow in the same change:\n' >&2
        printf '  sh scripts/check-arch-fanout.sh --record\n' >&2
        failed=1
    fi
done <"$work/baseline.txt"

# And every file the census found that the baseline does not know about.
while read -r path count; do
    if ! awk -v p="$path" '$1 == p { found = 1 } END { exit !found }' \
        "$work/baseline.txt"; then
        printf 'arch fanout: new gate in %s (%s)\n' "$path" "$count" >&2
        printf '  record it deliberately with --record if it belongs\n' >&2
        failed=1
    fi
done <"$work/census.txt"

if [ "$failed" != "0" ]; then
    exit 1
fi

printf 'arch-fanout check passed: %s files, %s occurrences, unchanged\n' \
    "$files" "$occurrences"
