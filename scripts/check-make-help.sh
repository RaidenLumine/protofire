#!/usr/bin/env sh
# File: scripts/check-make-help.sh
# Purpose: Fail when `make help` and the Makefile's own targets disagree — a
#          target the list does not name, or a name the Makefile does not
#          define.
#
# Why this exists
# ---------------
# `make help` is this tree's index of what can be run, and `AGENTS.md` leans on
# it: "`make help` lists every target".  That claim was false in both
# directions.  Fifteen targets had drifted out of the list — among them three
# ratchets (`check-arch-fanout`, the frozen-payload gates) and the two SMP
# smokes — so a gate nobody could discover was a gate only its author ran; and
# the list is prose, so the next target added by hand can drift the same way.
# A hand-maintained list of targets is a list that will eventually be wrong, in
# exactly the way a hand-maintained index is.
#
# What it reads
# -------------
# The two shapes the file is actually written in, and nothing else: a target is
# a line whose name starts at column one and ends in `:`, and a listing is a
# `'  make <name> - …'` line of the `help` recipe.  Prose that happens to say
# `make something` elsewhere is not read, so a sentence cannot be mistaken for
# a listing.
#
# Usage:
#   sh scripts/check-make-help.sh
#   MAKEFILE=/tmp/fixture.mk sh scripts/check-make-help.sh

set -eu

cd "$(dirname "$0")/.."

MAKEFILE="${MAKEFILE:-Makefile}"

if [ ! -f "$MAKEFILE" ]; then
    printf 'make-help check failed: %s not found\n' "$MAKEFILE" >&2
    exit 1
fi

work="$(mktemp -d)"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

# A target: `name:` at column one.  Anchored on both ends so a `$(VAR):` rule, a
# continuation or an indented line is not a target.
grep -oE '^[a-z][a-z0-9-]*:' "$MAKEFILE" | tr -d ':' | sort -u > "$work/targets"

# A listing: the `help` recipe's own line shape, which is a quoted line that
# opens with two spaces and `make `.  The names are padded to a column, so the
# gap before the dash is spaces rather than one space.  The recipe ends at the
# next line that starts at column one, which is the rule after it.
sed -n "/^help:/,/^[^[:space:]]/p" "$MAKEFILE" \
    | sed -n "s/^[[:space:]]*'  make \([a-z0-9-]*\)[[:space:]]*- .*/\1/p" \
    | sort -u > "$work/listed"

if [ ! -s "$work/targets" ]; then
    printf 'make-help check failed: %s defines no targets this check can see\n' "$MAKEFILE" >&2
    exit 1
fi
if [ ! -s "$work/listed" ]; then
    printf 'make-help check failed: the `help` recipe in %s lists nothing\n' "$MAKEFILE" >&2
    exit 1
fi

missing="$(comm -13 "$work/listed" "$work/targets")"
stale="$(comm -23 "$work/listed" "$work/targets")"

if [ -n "$missing" ] || [ -n "$stale" ]; then
    if [ -n "$missing" ]; then
        printf 'make-help check failed: the Makefile defines targets `make help` does not name:\n' >&2
        printf '  %s\n' $missing >&2
    fi
    if [ -n "$stale" ]; then
        printf 'make-help check failed: `make help` names targets the Makefile does not define:\n' >&2
        printf '  %s\n' $stale >&2
    fi
    exit 1
fi

printf 'make-help check passed: %s target(s), each one named\n' \
    "$(grep -c . "$work/targets")"
