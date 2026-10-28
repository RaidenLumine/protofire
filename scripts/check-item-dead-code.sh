#!/usr/bin/env sh
# File: scripts/check-item-dead-code.sh
# Purpose: Hold the line on item-level `#[allow(dead_code)]` counts.
#
# Why this exists
# ---------------
# `check-dead-code-allows.sh` requires a reason on every *file-level* allow and
# says why: one annotation turns the lint off for a whole file.  It also says
# what it does not cover — an item-level allow names one item, so the next
# unused item in the file still reports.
#
# That is true one item at a time and false in aggregate.  276 of them in this
# tree means an item can be added, silenced, and never seen again: the lint is
# still on for everything else, so nothing reports, and the total drifts up
# with no signal.  The same argument as `layering-baseline.txt`, against a
# different counter.
#
# The rule is a ratchet.  A file may not grow past its recorded count.  A file
# that shrinks is re-recorded in the same change with `--record`, which lowers
# the number for good.  A file that appears with any count is a failure: it has
# no recorded number and therefore no argument.
#
# Usage:
#   sh scripts/check-item-dead-code.sh             # check against the baseline
#   sh scripts/check-item-dead-code.sh --record    # rewrite the baseline

set -eu

cd "$(dirname "$0")/.."

BASELINE="scripts/item-dead-code-baseline.txt"

# The count per file, in the baseline's own shape.
census() {
    grep -rc '#\[allow(dead_code)\]' --include='*.rs' src tests 2>/dev/null |
        grep -v ':\$' |
        grep -v ':0$' |
        awk -F: '{printf "%s %s\n", $2, $1}' |
        sort -k2
}

if [ "${1:-}" = "--record" ]; then
    {
        printf '%s\n' \
            '# Item-level `#[allow(dead_code)]` counts, read by' \
            '# scripts/check-item-dead-code.sh.' \
            '#' \
            '# Each line is `<count> <path>`.  The gate fails when a file grows past' \
            '# its number; a file that shrinks must be re-recorded with `--record`,' \
            '# which is what keeps the total falling instead of drifting back up.' \
            '#' \
            '# This is a ratchet, not a budget: the number is what the tree has, and' \
            '# the argument for each remaining item is that it is either generated' \
            '# (the payload macro emits a fixed set per architecture) or part of an' \
            '# interface that a host build cannot reach.  THREE of the payload' \
            '# macro copies are `fork_process`: the shell payload is their only' \
            '# caller and a host build does not expand it, so the host lint sees no' \
            '# caller while the bare-metal build has one.' \
            '#'
        census
    } > "$BASELINE"
    total="$(census | awk '{s += $1} END {print s + 0}')"
    printf 'item dead-code: recorded %s annotation(s) across %s file(s)\n' \
        "$total" "$(census | wc -l | tr -d ' ')"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

census > "$work/now"
awk '!/^#/ && NF == 2 { print }' "$BASELINE" > "$work/was"

status=0

# A file that grew, or appeared with no recorded number.
while read -r count path; do
    was="$(awk -v p="$path" '$2 == p { print $1 }' "$work/was")"
    if [ -z "$was" ]; then
        printf '  %s: %s item-level allow(s), and no baseline entry\n' "$path" "$count"
        status=1
    elif [ "$count" -gt "$was" ]; then
        printf '  %s: %s item-level allow(s), baseline says %s\n' "$path" "$count" "$was"
        status=1
    fi
done < "$work/now"

# A file that shrank and was not re-recorded: the number is now stale, and a
# stale number is room to grow back into.
while read -r count path; do
    if ! awk -v p="$path" '$2 == p { found = 1 } END { exit found ? 0 : 1 }' "$work/now"; then
        printf '  %s: baseline says %s, and the file is gone\n' "$path" "$count"
        status=1
    fi
done < "$work/was"

if [ "$status" -ne 0 ]; then
    printf 'item dead-code: the counts above are not what the baseline records\n' >&2
    printf '  a file may not grow; re-record a shrink with --record\n' >&2
    exit 1
fi

total="$(awk '{s += $1} END {print s + 0}' "$work/now")"
printf 'item dead-code: %s annotation(s) across %s file(s), at or below the baseline\n' \
    "$total" "$(wc -l < "$work/now" | tr -d ' ')"
