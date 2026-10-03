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
# What a row has to say
# ---------------------
# A row is `<path> <count>`, and may carry `# <reason>` after it.  The reason
# is why that file names an architecture at all, and every row needs one,
# because there are exactly two honest answers:
#
#   * a fact about the machine — an ABI record only one architecture has, a
#     driver for hardware only one machine has.  A fourth architecture does
#     have to decide what it does here; there is nothing to shim.
#   * a gap somebody has yet to close — the question is one the architecture
#     should be answering, and the fix is to move it behind `src/arch/`.
#
# The check does not believe either answer; it just refuses a row that gives
# neither.  `--record` preserves the reasons already written, so a row keeps
# its argument while the tree changes under it, and a row that grows fails
# *with* its recorded reason printed: a reason that covered the old count may
# not cover the new one.
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

# Baseline rows as `<path>\t<count>\t<reason>`; the reason is the text after
# `#`, and may be empty.  Read before either mode runs, because `--record`
# keeps the reasons it finds.
rows_from_baseline() {
    awk '
        {
            line = $0
            reason = ""
            hash = index(line, "#")
            if (hash > 0) {
                reason = substr(line, hash + 1)
                line = substr(line, 1, hash - 1)
            }
            path = ""; count = ""
            n = split(line, field, /[[:space:]]+/)
            for (i = 1; i <= n; i++) {
                if (field[i] == "") continue
                if (path == "") path = field[i]
                else if (count == "") count = field[i]
            }
            if (path == "" || count == "") next
            gsub(/^[[:space:]]+/, "", reason)
            gsub(/[[:space:]]+$/, "", reason)
            printf "%s\t%s\t%s\n", path, count, reason
        }
    ' "$BASELINE"
}

rows_from_baseline >"$work/baseline.tsv"

if [ "$mode" = "record" ]; then
    next_baseline="$work/baseline.new"
    # Keep the prose header, drop any totals line a previous record wrote and
    # the blank lines around it: there is exactly one totals line, it is the
    # one appended below, and a record has to be idempotent — the previous
    # version kept the old gap as well and grew the file by a line a run.
    awk -v files="$files" -v occurrences="$occurrences" '
        /^# [0-9]+ files, [0-9]+ occurrences outside src\/arch$/ { next }
        /^#/ { print; next }
        { exit }
    ' "$BASELINE" >"$next_baseline"
    printf '\n# %s files, %s occurrences outside src/arch\n\n' \
        "$files" "$occurrences" >>"$next_baseline"
    # Keep each row's reason: it is the argument for the row, and a re-record
    # is a change in the tree, not a change of mind about why the row exists.
    awk -v reasons="$work/baseline.tsv" '
        BEGIN {
            while ((getline row < reasons) > 0) {
                split(row, field, "\t")
                reason[field[1]] = field[3]
            }
        }
        {
            if (($1 in reason) && reason[$1] != "") {
                printf "%-52s %s  # %s\n", $1, $2, reason[$1]
            } else {
                printf "%-52s %s\n", $1, $2
            }
        }
    ' "$work/census.txt" >>"$next_baseline"
    mv "$next_baseline" "$BASELINE"
    printf 'recorded %s files, %s occurrences in %s\n' \
        "$files" "$occurrences" "$BASELINE"
    unreasoned="$(rows_from_baseline | awk -F'\t' '$3 == "" { n++ } END { print n + 0 }')"
    if [ "$unreasoned" != "0" ]; then
        printf '%s row(s) have no reason yet: the check fails until each says\n' \
            "$unreasoned" >&2
        printf 'whether it is a fact about the machine or a gap to close.\n' >&2
    fi
    exit 0
fi

failed=0

# Every file in the baseline: grown, shrunk, unchanged, or unexplained.
while IFS="$(printf '\t')" read -r path baseline_count reason; do
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
        if [ -n "$reason" ]; then
            printf '  this row is recorded as: %s\n' "$reason" >&2
            printf '  the count grew anyway, so the reason does not cover it\n' >&2
        fi
        printf '  (see §14 of docs/fmts/code-style.md)\n' >&2
        failed=1
    elif [ "$count" -lt "$baseline_count" ]; then
        printf 'arch fanout: %s shrank from %s to %s\n' \
            "$path" "$baseline_count" "$count" >&2
        printf '  good, but the census has to follow in the same change:\n' >&2
        printf '  sh scripts/check-arch-fanout.sh --record\n' >&2
        failed=1
    elif [ -z "$reason" ]; then
        printf 'arch fanout: %s names an architecture and does not say why\n' \
            "$path" >&2
        printf '  every row is one of two things: a fact about the machine,\n' >&2
        printf '  or a gap to close.  Move the question behind the arch layer,\n' >&2
        printf '  or write the fact down after the count and re-record.\n' >&2
        failed=1
    fi
done <"$work/baseline.tsv"

# And every file the census found that the baseline does not know about.
while read -r path count; do
    if ! awk -F'\t' -v p="$path" '$1 == p { found = 1 } END { exit !found }' \
        "$work/baseline.tsv"; then
        printf 'arch fanout: new gate in %s (%s)\n' "$path" "$count" >&2
        printf '  ask the arch layer instead, or record it with a reason that\n' >&2
        printf '  says why it is a fact about the machine\n' >&2
        failed=1
    fi
done <"$work/census.txt"

if [ "$failed" != "0" ]; then
    exit 1
fi

printf 'arch-fanout check passed: %s files, %s occurrences, each with a reason\n' \
    "$files" "$occurrences"
