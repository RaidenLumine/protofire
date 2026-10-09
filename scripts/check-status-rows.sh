#!/usr/bin/env sh
# File: scripts/check-status-rows.sh
# Purpose: Hold the line on how long one row of the per-module census may get.
#
# `docs/status.md` is the census: for each subsystem, what the code does today
# and what it does not do yet.  A row is one line of a Markdown table, and a
# row that grows into a *history* stops being either half of that — the stages
# a subsystem landed are `docs/rfcs/`'s to tell, and the mechanism is
# `docs/kernel/`'s.  The row that made this gate exist was NTFS at 9,715 bytes
# in one line: a diff no reviewer reads and a line no editor can edit, because
# every change to it has to be made by a script that matches the whole line.
#
# The rule is a budget per row, measured in bytes of the line itself:
# no row of a per-module table in `docs/status.md` may be longer than BUDGET,
# except the rows recorded in `scripts/status-row-baseline.txt`, and those may
# be no longer than the number recorded there.  A row that grows past its
# number, and a row not in the baseline that grows past the budget, both fail.
# A row that is shortened **lowers its number in the same change**
# (`--record`), which is what makes the baseline the truth about the file and
# keeps the excess shrinking instead of being renewed.
#
# The rows in the baseline carry prose that has not been moved to where it
# belongs yet.  Each of them is a census that still tells a story: shortening
# one is a change of its own, and this gate is what keeps the count falling.
#
# Usage:
#   sh scripts/check-status-rows.sh             # check against the baseline
#   sh scripts/check-status-rows.sh --record    # rewrite the baseline

set -eu

cd "$(dirname "$0")/.."

STATUS="docs/status.md"
BASELINE="scripts/status-row-baseline.txt"

# How long one row of the census may be, in bytes of the whole line (the
# table's cells share it).  This is where the largest row that is still a
# census sits — NTFS, at 1,212 bytes, once the story of its thirteen stages
# moved to the RFC that decided them — so a row that grows past it has almost
# certainly started telling a story again.
BUDGET=1300

# What a row is called: the first cell of the table.  The cells share the line,
# so a row's length is the length of that line.
ROW_NAME='
    function row_name(line,   name) {
        name = substr(line, 2)
        sub(/\|.*$/, "", name)
        gsub(/^[ \t]+|[ \t]+$/, "", name)
        return name
    }
'

ROWS="$ROW_NAME"'
    /^\|/ {
        name = row_name($0)
        if (name == "" || name ~ /^-+$/) next
        printf "%s\t%d\n", name, length($0)
    }
'

rows() {
    # `LC_ALL=C` for the length: the budget is in bytes, and an awk in a UTF-8
    # locale counts characters, which would make the same row a different
    # number on a different host.
    LC_ALL=C awk "$ROWS" "$STATUS"
}

if [ "${1:-}" = "--record" ]; then
    {
        printf '%s\n' \
            '# Rows of docs/status.md that are longer than the census budget,' \
            '# read by scripts/check-status-rows.sh.' \
            '#' \
            '# Each row is `<row name> <bytes>`: the length of the line the row' \
            '# is, as the check measures it.  The check fails when a row grows' \
            '# past its number here, and when a row that is not listed grows' \
            '# past the budget; a row that is *shortened* has to be re-recorded' \
            '# in the same change (`sh scripts/check-status-rows.sh --record`),' \
            '# so the numbers below only ever fall.' \
            '#' \
            '# These rows say more than a census should: each one still tells' \
            '# the story of what landed in its subsystem.  The story belongs in' \
            '# the RFC that decided it and the mechanism in docs/kernel/;' \
            '# shortening a row is a change of its own, and this file is what' \
            '# keeps the total falling rather than being renewed.' \
            '#'
        rows | LC_ALL=C awk -v budget="$BUDGET" -F'\t' '$2 > budget { print $1, $2 }' |
            sort -k2,2rn
    } >"$BASELINE"
    printf 'status rows: recorded %s row(s) over the %s-byte budget\n' \
        "$(grep -cv '^#' "$BASELINE" || true)" "$BUDGET"
    exit 0
fi

[ -f "$BASELINE" ] || {
    echo "status rows: no baseline at $BASELINE (record one with --record)" >&2
    exit 1
}

# One process reads both files, so the loop cannot end up in a subshell whose
# failure the shell never sees.
LC_ALL=C awk -v budget="$BUDGET" -v baseline="$BASELINE" "$ROW_NAME"'
    BEGIN {
        while ((getline line < baseline) > 0) {
            if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
            name = line
            sub(/[ \t]+[0-9]+[ \t]*$/, "", name)
            bytes = line
            sub(/^.*[ \t]/, "", bytes)
            allowed[name] = bytes + 0
        }
        close(baseline)
    }
    {
        name = row_name($0)
        if (name == "" || name ~ /^-+$/) next
        bytes = length($0)
        if (name in allowed) {
            if (bytes > allowed[name]) {
                printf "  %s grew to %d bytes, past the %d recorded\n", \
                    name, bytes, allowed[name] > "/dev/stderr"
                bad = 1
            }
            seen[name] = 1
        } else if (bytes > budget) {
            printf "  %s is %d bytes, past the %d-byte budget and not recorded\n", \
                name, bytes, budget > "/dev/stderr"
            bad = 1
        }
    }
    END {
        for (name in allowed) {
            if (!(name in seen)) {
                printf "  the baseline records %s, which %s no longer has\n", \
                    name, "docs/status.md" > "/dev/stderr"
                bad = 1
            }
        }
        if (bad) {
            print "status rows: a row of the census is longer than it may be" > "/dev/stderr"
            print "  a census row says what exists and what is missing; the story of" > "/dev/stderr"
            print "  how it got there is docs/rfcs/'"'"'s and the mechanism docs/kernel/'"'"'s" > "/dev/stderr"
            print "  (see the header of scripts/check-status-rows.sh)" > "/dev/stderr"
            exit 1
        }
        printf "status row check passed: every row within the %d-byte budget or its recorded length\n", budget
    }
' "$STATUS"
