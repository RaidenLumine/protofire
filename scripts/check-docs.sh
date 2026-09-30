#!/usr/bin/env sh
# File: scripts/check-docs.sh
# Purpose: Fail when a document names a file, or links to one, that the tree does not have.
#
# Why this exists
# ---------------
# An audit of `docs/` against the tree found twelve citations of files that are
# not there.  Four of them had moved — `src/kernel/smp/discovery.rs` became
# `src/arch/x86_64/acpi.rs` when ACPI parsing moved to the architecture it
# describes, and five syscall handler files were renamed into the shape
# `tls_handler.rs` -> `tls.rs` — and the rest had never existed at all:
# `src/user/shared/net.rs` anchored a whole document section describing an HTTP
# client and server that are in no revision of this repository, and `version.rs`
# was a module row for a version-comparison function that is nowhere in the tree.
# Every one of them read as authoritative, which is what makes this class of
# drift expensive: the reader cannot tell a claim about the code from a claim
# about a tree that no longer exists.
#
# What is checked
# ---------------
# 1. A `src/...` or `tests/...` path in backticks must exist as written.
# 2. A bare filename in backticks (`tls.rs`, `commands/fs.rs`) must exist
#    somewhere under `src/`, `tests/`, or the repository root.  `docs/fmts/`
#    `testing.md` writes `manager.rs` and means `tests/memory/manager.rs`; the
#    subject that makes a relative citation resolvable is prose, so the check
#    is by name.
# 3. A line-number citation (`foo.rs:123`) is a failure outright.  Line numbers
#    rot: the two this tree carried had drifted by more than 170 lines before
#    they were removed, and nothing can check one without parsing Rust.  Cite
#    the file and name the symbol; the symbol is what a reader searches for.
# 4. A relative Markdown link must resolve from the document that holds it.
#    This one is exact, and it is the only check here that can be.
#
# What is not checked
# -------------------
# Numbers, and prose.  "40 network syscalls" and "10,824 lines of x86_64 code"
# both need a definition of the set before a machine can count it, and neither
# definition is written down; the status document records them as unverified
# rather than guessing.  A sentence like "the ring buffer is installed" is a
# claim about behaviour, and no document checker can settle it.
#
# One consequence of (1) and (2) is worth stating because it bites: a document
# may not name an absent file *as a file*.  Write "there is no `net` module",
# not "there is no `net.rs`" — the second form is exactly what this check
# exists to catch, and it cannot tell a warning about a ghost from a citation
# of one.  (It also cannot: `net.rs` names two real files further down the
# tree, so the warning would pass either way.  Name the module.)
#
# Three shapes are not citations and are skipped: the extension on its own
# (`.rs`), a header example written the way a file writes it (`//! build.rs`),
# and a pattern rather than a path (`src/fs/simplefs/{vfs,file_io}.rs`,
# `tests/<area>/<name>.rs`).  A pattern is checked by the rule it states, not
# by this script.
#
# There is no baseline.  A citation either names a file that exists or it does
# not, so unlike the ratchets there is nothing to re-record.
#
# Usage:
#   sh scripts/check-docs.sh
#   sh scripts/check-docs.sh -h

set -eu

cd "$(dirname "$0")/.."

case "${1:-}" in
    '') ;;
    -h|--help)
        sed -n '2,50p' "$0"
        exit 0
        ;;
    *)
        printf 'unsupported argument: %s\n' "$1" >&2
        exit 1
        ;;
esac

work="$(mktemp -d)"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

# Every Rust basename the tree has, for check (2).
{
    find src tests -name '*.rs' -exec basename {} \;
    find . -maxdepth 1 -name '*.rs' -exec basename {} \;
} | sort -u > "$work/basenames"

: > "$work/citations"
: > "$work/links"

# Every Markdown file in the tree, not just the ones under `docs/`: the root
# documents cite the code as often as the reference pages do.  `target/` is
# build output and `.git/` is not part of the tree.
for doc in $(find . -name '*.md' -not -path './target/*' -not -path './.git/*' | sort); do
    # (1)-(3): backticked `.rs` citations, with the line they came from.  The
    # suffix is part of the pattern because check (3) exists to catch it: a
    # citation that stops at `.rs` would never match `*:[0-9]*` below.
    awk '
        {
            rest = $0
            while (match(rest, /`[^`]*\.rs(:[0-9]+)?`/)) {
                printf "%s %d %s\n", FILENAME, NR, substr(rest, RSTART + 1, RLENGTH - 2)
                rest = substr(rest, RSTART + RLENGTH)
            }
        }
    ' "$doc" >> "$work/citations"

    # (4): relative Markdown link targets.  Absolute URLs, mail links and bare
    # anchors are not paths into this tree.
    awk '
        {
            rest = $0
            while (match(rest, /\]\([^)]*\)/)) {
                target = substr(rest, RSTART + 2, RLENGTH - 3)
                rest = substr(rest, RSTART + RLENGTH)
                if (target != "" && target !~ /^(https?:|mailto:|#)/) {
                    printf "%s %s\n", FILENAME, target
                }
            }
        }
    ' "$doc" >> "$work/links"
done

: > "$work/stale"
citations=0
links=0

while read -r doc line cite; do
    [ -n "${cite:-}" ] || continue

    # A header example is written the way the file writes it.
    cite="${cite#//! }"

    # The extension on its own names no file.
    [ "$cite" != ".rs" ] || continue

    # A pattern describes a set of files rather than one of them.
    case "$cite" in
        *"{"* | *"<"* | *">"* | *"*"*) continue ;;
    esac

    citations=$((citations + 1))

    case "$cite" in
        *:[0-9]*)
            printf '%s:%s: line-number citation `%s` — cite the file and name the symbol\n' \
                "$doc" "$line" "$cite" >> "$work/stale"
            continue
            ;;
    esac

    base="${cite##*/}"
    if [ "${cite#src/}" != "$cite" ] || [ "${cite#tests/}" != "$cite" ]; then
        [ -e "$cite" ] || printf '%s:%s: no such path `%s`\n' \
            "$doc" "$line" "$cite" >> "$work/stale"
    else
        grep -qxF "$base" "$work/basenames" || printf '%s:%s: no such file `%s`\n' \
            "$doc" "$line" "$cite" >> "$work/stale"
    fi
done < "$work/citations"

while read -r doc target; do
    [ -n "${target:-}" ] || continue
    links=$((links + 1))

    path="${target%%#*}"
    [ -n "$path" ] || continue

    dir="${doc%/*}"
    [ -e "$dir/$path" ] || printf '%s: link `%s` resolves to nothing\n' \
        "$doc" "$target" >> "$work/stale"
done < "$work/links"

if [ -s "$work/stale" ]; then
    printf 'check-docs: the documents name things the tree does not have\n\n' >&2
    cat "$work/stale" >&2
    printf '\n%s citation(s) or link(s) to fix\n' "$(wc -l < "$work/stale")" >&2
    exit 1
fi

printf 'docs check passed: %s citations, %s links, 0 stale\n' "$citations" "$links"
