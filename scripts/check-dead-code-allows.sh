#!/usr/bin/env sh
# File: scripts/check-dead-code-allows.sh
# Purpose: Require a reason and an exit condition on every file-level
#          `#![allow(dead_code)]`.
#
# Why this exists
# ---------------
# A file-level `allow(dead_code)` is the one annotation the compiler cannot
# argue with: it turns the lint off for everything in the file, so the next
# unused item is invisible and the file's dead weight grows without a signal.
# Two of them in this tree outlived their reasons — a skeleton that said
# "step 1b wires the consumers" after step 1b had been done, and a set of
# accessors described as "no callers in the kernel" that had four.
#
# The convention that keeps them honest is two comment lines above the
# annotation, and this check is what makes it a rule rather than a habit:
#
#     // Why: <what is legitimately unused here>
#     // When to remove: <the condition that retires this line>
#     #![allow(dead_code)]
#
# An item-level `#[allow(dead_code)]` is not covered: it names one item, and
# the next unused item in the same file still reports.
#
# Usage:
#   sh scripts/check-dead-code-allows.sh

set -eu

cd "$(dirname "$0")/.."

files="$(find src tests -name '*.rs' | sort)"
status=0

for file in $files; do
    # Every file-level allow, and whether the comment block above it carries
    # the two lines this convention asks for.  The awk keeps the last comment
    # block it saw and judges the allow against it.
    problems="$(awk -v file="$file" '
        /^#!\[allow\(dead_code\)\]/ {
            if (!(saw_why && saw_when)) {
                printf "  %s:%d: %s\n", file, NR,
                    (saw_why ? "no \"When to remove\"" : "no \"Why\"")
            }
            saw_why = 0; saw_when = 0
            next
        }
        /^[ \t]*$/ { saw_why = 0; saw_when = 0; next }
        /^[ \t]*\/\// {
            if ($0 ~ /Why:/ || $0 ~ /Reason:/) saw_why = 1
            if ($0 ~ /When to remove:/) saw_when = 1
            next
        }
        { saw_why = 0; saw_when = 0 }
    ' "$file")"

    if [ -n "$problems" ]; then
        printf '%s\n' "$problems"
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    printf 'dead-code allows: the lines above need a reason and an exit\n' >&2
    printf '  see docs/fmts/code-style.md, "File-level allow(dead_code)"\n' >&2
    exit 1
fi

count="$(rg -c '^#!\[allow\(dead_code\)\]' src tests 2>/dev/null | awk -F: '{s += $2} END {print s + 0}')"
printf 'dead-code allows: %s file-level annotation(s), each with a reason\n' "$count"
