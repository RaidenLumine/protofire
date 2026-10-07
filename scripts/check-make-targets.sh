#!/usr/bin/env sh
# File: scripts/check-make-targets.sh
# Purpose: Fail when the three places the Makefile declares its targets — the
#          rules themselves, `.PHONY`, and the `help` recipe — disagree.
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
# `.PHONY` is the same target set written a second time, and it had drifted
# too: eleven targets were missing, among them `build-x8664`, `run-x8664` and
# `clippy-targets`.  That one is worse than a missing line in a list, because
# it fails *silently and successfully*: a target that is not `.PHONY` is
# skipped when a file of that name exists, and `make` says so and exits zero.
# `make build` depends on `build-x8664`, so a stray file called `build-x8664`
# in the tree root made the whole build a no-op that reported success.
#
# What it reads
# -------------
# The shapes the file is actually written in, and nothing else: a target is a
# line whose name starts at column one and ends in `:`, a listing is a
# `'  make <name> - …'` line of the `help` recipe, and a declaration is a
# `.PHONY:` rule or a `PHONY :=`/`PHONY +=` assignment — the two forms a
# section can use, whichever way the file is laid out.  Prose that happens to
# say `make something` elsewhere is not read, so a sentence cannot be mistaken
# for a listing, and a `$(…)` expansion contributes no names.
#
# Usage:
#   sh scripts/check-make-targets.sh
#   MAKEFILE=/tmp/fixture.mk sh scripts/check-make-targets.sh

set -eu

cd "$(dirname "$0")/.."

MAKEFILE="${MAKEFILE:-Makefile}"

if [ ! -f "$MAKEFILE" ]; then
    printf 'make-targets check failed: %s not found\n' "$MAKEFILE" >&2
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

# A `.PHONY` declaration, in either form: one rule listing every target
# (`.PHONY: a b \` continued by backslashes) or a section declaring its own
# (`PHONY += a b`).  The list may run over many lines, so the continuations are
# joined first — the raw file is kept for the `help` recipe, whose own
# continuations have to stay separate lines.  A line that applies an
# accumulated list expands to a `$`, which no name matches, so it adds none.
awk '{ if (sub(/\\$/, "")) printf "%s ", $0; else print }' "$MAKEFILE" > "$work/joined"
awk '
    /^\.PHONY:/ || /^PHONY[[:space:]]*[:+]?=/ {
        line = $0
        sub(/^\.PHONY:[[:space:]]*/, "", line)
        sub(/^PHONY[[:space:]]*[:+]?=[[:space:]]*/, "", line)
        count = split(line, name, /[[:space:]]+/)
        for (i = 1; i <= count; i++) {
            if (name[i] ~ /^[a-z][a-z0-9-]*$/) print name[i]
        }
    }
' "$work/joined" | sort -u > "$work/phony"

if [ ! -s "$work/targets" ]; then
    printf 'make-targets check failed: %s defines no targets this check can see\n' \
        "$MAKEFILE" >&2
    exit 1
fi
if [ ! -s "$work/listed" ]; then
    printf 'make-targets check failed: the `help` recipe in %s lists nothing\n' "$MAKEFILE" >&2
    exit 1
fi
if [ ! -s "$work/phony" ]; then
    printf 'make-targets check failed: %s declares nothing `.PHONY`\n' "$MAKEFILE" >&2
    exit 1
fi

# Each list has to hold exactly the same names, and every direction is a
# failure: a target no list declares is one `make` may silently skip, and a
# name with no target behind it is a promise the list still makes.
missing_phony="$(comm -13 "$work/phony" "$work/targets")"
stale_phony="$(comm -23 "$work/phony" "$work/targets")"
missing_help="$(comm -13 "$work/listed" "$work/targets")"
stale_help="$(comm -23 "$work/listed" "$work/targets")"

if [ -n "$missing_phony$stale_phony$missing_help$stale_help" ]; then
    if [ -n "$missing_phony" ]; then
        printf 'make-targets check failed: `.PHONY` does not declare these targets:\n' >&2
        printf '  %s\n' $missing_phony >&2
    fi
    if [ -n "$stale_phony" ]; then
        printf 'make-targets check failed: `.PHONY` declares names the Makefile does not define:\n' >&2
        printf '  %s\n' $stale_phony >&2
    fi
    if [ -n "$missing_help" ]; then
        printf 'make-targets check failed: `make help` does not name these targets:\n' >&2
        printf '  %s\n' $missing_help >&2
    fi
    if [ -n "$stale_help" ]; then
        printf 'make-targets check failed: `make help` names targets the Makefile does not define:\n' >&2
        printf '  %s\n' $stale_help >&2
    fi
    exit 1
fi

printf 'make-targets check passed: %s target(s), declared and named\n' \
    "$(grep -c . "$work/targets")"
