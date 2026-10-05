#!/usr/bin/env sh
# File: scripts/check-rfcs.sh
# Purpose: Keep the RFC directory honest: one decimal number per document, a
#          status from the fixed set, supersede links that agree with the
#          files they name, and an index generated from the documents instead
#          of maintained by hand.
#
# Why this exists
# ---------------
# The RFC directory is the one part of the documentation where a *number* is
# the point: it is how code cites a decision, how a later document supersedes
# an earlier one, and how a reader finds the argument that was made.  That
# makes three failures expensive and all three are mechanical:
#
#   * a number reused or skipped, so `RFC 0007` names two different designs;
#   * a status that lies — `Implemented` in the file, `Accepted` in the index,
#     or a document that says it supersedes one that does not agree;
#   * an index that drifts from the documents it lists, which is what a hand
#     maintained table does (this tree's rule: a hand maintained number is a
#     number that will eventually be wrong).
#
# So the index is generated from the files between two markers in the
# directory's README, and this script is what says it is still generated.  The
# number is four decimal digits, never hexadecimal and never reused; see the
# README's "Numbering and layout" for what that buys.
#
# Usage:
#   sh scripts/check-rfcs.sh            # check the directory and its index
#   sh scripts/check-rfcs.sh --record   # rewrite the index from the documents
#   RFCS_DIR=/tmp/fixture sh scripts/check-rfcs.sh

set -eu

cd "$(dirname "$0")/.."

RFCS_DIR="${RFCS_DIR:-docs/rfcs}"
INDEX="${INDEX_FILE:-$RFCS_DIR/README.md}"
TEMPLATE="0000-template.md"

statuses="Draft Proposed Accepted Implemented Superseded Rejected"

mode=check
case "${1:-}" in
    '') ;;
    --record) mode=record ;;
    *)
        printf 'usage: %s [--record]\n' "$0" >&2
        exit 2
        ;;
esac

if [ ! -d "$RFCS_DIR" ]; then
    printf 'check-rfcs: no such directory: %s\n' "$RFCS_DIR" >&2
    exit 1
fi

work="$(mktemp -d)"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

: >"$work/problems"
: >"$work/rows"

problem() {
    printf '%s\n' "$1" >>"$work/problems"
}

# The number in a file name: exactly four decimal digits, which is what keeps
# `ls`, `sort` and diff order equal to numeric order.
number_of() {
    printf '%s\n' "${1%%-*}"
}

for file in "$RFCS_DIR"/*.md; do
    [ -f "$file" ] || continue
    name="${file##*/}"
    [ "$name" = "README.md" ] && continue

    number="$(number_of "$name")"
    case "$number" in
        [0-9][0-9][0-9][0-9]) ;;
        *)
            problem "$name: the file name must start with four decimal digits and a dash"
            continue
            ;;
    esac

    # The template is not an RFC: its heading and its Supersedes line are the
    # placeholders a writer replaces, so it is checked for being present and
    # for nothing else here.
    if [ "$name" = "$TEMPLATE" ]; then
        continue
    fi

    first_line="$(sed -n '1p' "$file")"
    title="$(printf '%s\n' "$first_line" | sed -n 's/^# RFC [0-9][0-9][0-9][0-9]: //p')"
    if [ -z "$title" ]; then
        problem "$name: the first line must be '# RFC $number: <title>'"
    else
        heading_number="$(printf '%s\n' "$first_line" | sed -n 's/^# RFC \([0-9]*\):.*/\1/p')"
        [ "$heading_number" = "$number" ] ||
            problem "$name: the heading says RFC $heading_number, the name says $number"
        case "$title" in
            *.) problem "$name: the title ends with a period, which the template asks it not to" ;;
        esac
    fi

    status="$(sed -n 's/^- \*\*Status:\*\* //p' "$file" | head -n 1)"
    if [ -z "$status" ]; then
        problem "$name: no '- **Status:** ...' line"
    else
        found=0
        for allowed in $statuses; do
            [ "$status" = "$allowed" ] && found=1
        done
        [ "$found" = "1" ] ||
            problem "$name: status '$status' is not one of: $statuses"
    fi

    supersedes="$(sed -n 's/^- \*\*Supersedes:\*\* //p' "$file" | head -n 1)"
    case "$supersedes" in
        ''|none) ;;
        [0-9][0-9][0-9][0-9]) printf '%s %s\n' "$number" "$supersedes" >>"$work/supersedes" ;;
        *) problem "$name: 'Supersedes' must be 'none' or an RFC number" ;;
    esac

    [ "$number" = "0000" ] && continue
    printf '%s\t%s\t%s\t%s\n' "$number" "$name" "${status:-?}" "${title:-?}" >>"$work/rows"
done

if [ ! -f "$RFCS_DIR/$TEMPLATE" ]; then
    problem "the template is missing: $TEMPLATE"
fi
[ -s "$work/rows" ] || problem "there are no RFCs in $RFCS_DIR"

# Two files with one number are two designs behind one citation.
duplicates="$(cut -f1 "$work/rows" | sort | uniq -d)"
[ -z "$duplicates" ] || problem "these numbers are used twice: $(printf '%s ' $duplicates)"

# Supersede links agree with the statuses at both ends: the successor names a
# document that says it was superseded, and a superseded document is named.
if [ -f "$work/supersedes" ]; then
    while read -r successor superseded; do
        if [ "$successor" = "$superseded" ]; then
            problem "RFC $successor says it supersedes itself"
            continue
        fi
        row="$(awk -F'\t' -v n="$superseded" '$1 == n { print $3 }' "$work/rows" | head -n 1)"
        if [ -z "$row" ]; then
            problem "RFC $successor supersedes RFC $superseded, which is not in this directory"
        elif [ "$row" != "Superseded" ]; then
            problem "RFC $successor supersedes RFC $superseded, whose status is '$row'"
        fi
    done <"$work/supersedes"
fi

# The other end of the same link, checked whether or not anything names one.
while IFS="$(printf '\t')" read -r number name status title; do
    [ "$status" = "Superseded" ] || continue
    if [ ! -f "$work/supersedes" ] ||
        ! cut -d' ' -f2 "$work/supersedes" | grep -qx "$number"; then
        problem "RFC $number says it is superseded and no document names it"
    fi
done <"$work/rows"

# The index, generated from the rows above and compared with the one in the
# README (or written into it, with --record).
{
    printf '| RFC | Status | Subject |\n'
    printf '|-----|--------|---------|\n'
    sort -k1,1 "$work/rows" | while IFS="$(printf '\t')" read -r number name status title; do
        printf '| [%s](%s) | %s | %s |\n' "$number" "$name" "$status" "$title"
    done
} >"$work/table"

if [ ! -f "$INDEX" ]; then
    problem "no index to check: $INDEX"
elif ! grep -q '<!-- rfcs-table:start -->' "$INDEX"; then
    problem "$INDEX has no '<!-- rfcs-table:start -->' marker to generate the table between"
fi

if [ "$mode" = "record" ]; then
    if [ -s "$work/problems" ]; then
        printf 'check-rfcs: fix these before recording:\n' >&2
        sed 's/^/  /' "$work/problems" >&2
        exit 1
    fi
    recorded="$(mktemp)"
    awk -v table="$work/table" '
        /<!-- rfcs-table:start -->/ {
            print
            while ((getline line < table) > 0) print line
            skipping = 1
            next
        }
        /<!-- rfcs-table:end -->/ { skipping = 0 }
        !skipping { print }
    ' "$INDEX" >"$recorded"
    mv "$recorded" "$INDEX"
    printf 'recorded %s RFC row(s) in %s\n' "$(wc -l <"$work/rows" | tr -d ' ')" "$INDEX"
    exit 0
fi

if [ -f "$INDEX" ] && grep -q '<!-- rfcs-table:start -->' "$INDEX"; then
    awk '
        /<!-- rfcs-table:start -->/ { inside = 1; next }
        /<!-- rfcs-table:end -->/ { inside = 0; next }
        inside
    ' "$INDEX" >"$work/index-table"
    if ! cmp -s "$work/table" "$work/index-table"; then
        problem "the index in $INDEX does not match the documents; run '$0 --record'"
    fi
fi

if [ -s "$work/problems" ]; then
    printf 'check-rfcs: the RFC directory and its index disagree with themselves\n\n' >&2
    sed 's/^/  /' "$work/problems" >&2
    printf '\n%s problem(s)\n' "$(wc -l <"$work/problems" | tr -d ' ')" >&2
    exit 1
fi

printf 'rfc check passed: %s document(s), index generated from them\n' \
    "$(wc -l <"$work/rows" | tr -d ' ')"
