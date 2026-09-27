#!/usr/bin/env sh
# File: scripts/check-unsafe-comments.sh
# Purpose: Hold the line on undocumented `unsafe` blocks, configuration by
#          configuration.
#
# The tree has far more `unsafe` blocks than it has written safety arguments,
# and a lint switched on to `deny` over all of them at once would be answered
# with boilerplate: a comment on every block, none of which argues anything.
# This check holds the line where it is instead.  Every configuration listed in
# `scripts/unsafe-comment-baseline.txt` may report *no more* undocumented
# blocks than the number recorded there, and a count that falls has to be
# recorded in the same change — so the baseline is always the truth about the
# tree, and a new undocumented block turns the gate red for the change that
# added it rather than for whoever merges next.
#
# The counts are the `unsafe block missing a safety comment` and
# `unsafe impl missing a safety comment` diagnostics from clippy's
# `undocumented_unsafe_blocks` lint — both of them, because an `unsafe impl`
# missing its argument is as undocumented as a block and the block-only match
# this script used to apply left twenty-seven of them uncounted.  It counts
# *diagnostics*, not source items: an `unsafe fn` body and a block inside a
# macro are reported differently again, so a number is only comparable against
# a baseline produced by the same toolchain (`rust-toolchain.toml`) and the
# same lint messages.  If this script suddenly reports a drop to zero
# everywhere, suspect those messages before believing the cleanup.
#
# The test build is counted with `--all-targets`, so `tests/` is covered.  The
# three bare-metal targets are counted without it: a lib test target does not
# build for a target with no test harness, and `--all-targets` there exits 101
# while reporting exactly the same lib-only count.
#
# Usage:
#   sh scripts/check-unsafe-comments.sh             # check against the baseline
#   sh scripts/check-unsafe-comments.sh --record    # rewrite the baseline

set -eu

cd "$(dirname "$0")/.."

CARGO="${CARGO:-cargo}"
CARGO_FLAGS="${CARGO_FLAGS:---offline}"
BASELINE="${BASELINE:-scripts/unsafe-comment-baseline.txt}"

# The configurations the count is taken over.  `host` is the default target
# (the host build, tests included); the rest are the kernel's three
# architectures, plus the aarch64 host: every architecture module is written to
# compile on a host as well, that configuration is built by `make check`, and a
# configuration no ratchet counts is where debt goes to hide.
CONFIGS="host x86_64-unknown-none aarch64-unknown-none riscv64gc-unknown-none-elf aarch64-unknown-linux-gnu"

# The lint reports unsafe *blocks* and unsafe *impls* under two messages, and
# both are counted: the impls were invisible to an earlier version of this
# script that matched only the block message, which is how twenty-seven of them
# went without an argument while the baseline said the tree was clean.
LINT_MESSAGE_BLOCK="unsafe block missing a safety comment"
LINT_MESSAGE_IMPL="unsafe impl missing a safety comment"

mode=check
case "${1:-}" in
    '') ;;
    --record) mode=record ;;
    -h|--help)
        sed -n '8,30p' "$0"
        exit 0
        ;;
    *)
        printf 'unsupported argument: %s\n' "$1" >&2
        exit 1
        ;;
esac

if [ ! -f "$BASELINE" ]; then
    printf 'unsafe-comment baseline not found: %s\n' "$BASELINE" >&2
    printf 'run with --record to create it\n' >&2
    exit 1
fi

work="$(mktemp -d)"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

# Run clippy for one configuration with the lint enabled and count the
# diagnostics.  The count is written to the file named by the second argument
# so that a `record` run and a `check` run share exactly one measurement.
measure() {
    config="$1"
    out="$work/$config.log"

    case "$config" in
        host) clippy_targets="--all-targets"; clippy_target="" ;;
        *) clippy_targets=""; clippy_target="--target $config" ;;
    esac

    if ! "$CARGO" clippy $CARGO_FLAGS $clippy_targets $clippy_target -- \
        -W clippy::undocumented_unsafe_blocks >"$out" 2>&1; then
        printf 'clippy failed for configuration %s:\n' "$config" >&2
        tail -n 20 "$out" >&2
        exit 1
    fi

    # One pass over the log with both messages as patterns: `grep -c` counts
    # the lines that match either, and prints `0` rather than failing when the
    # tree is clean.
    count="$(grep -c -F -e "$LINT_MESSAGE_BLOCK" -e "$LINT_MESSAGE_IMPL" "$out" || true)"
    printf '%s %s\n' "$config" "$count" >>"$work/measured.txt"
}

: >"$work/measured.txt"
for config in $CONFIGS; do
    measure "$config"
done

measured_for() {
    awk -v c="$1" '$1 == c { print $2 }' "$work/measured.txt"
}

# Baseline rows, with comments stripped.  Each remaining non-blank line has to
# be exactly `<config> <count>`.
awk '
    { sub(/#.*/, "") }
    NF == 0 { next }
    NF != 2 { printf "malformed baseline line: %s\n", $0 > "/dev/stderr"; bad = 1; next }
    { print $1, $2 > "'"$work"'/baseline.txt" }
    END { exit bad }
' "$BASELINE"

if [ "$mode" = "record" ]; then
    # Keep the file's own prose (the comments and blank lines, in order) and
    # re-emit the rows, so re-recording never loses the explanation.
    next_baseline="$work/baseline.new"
    grep -E '^[[:space:]]*(#|$)' "$BASELINE" >"$next_baseline" || true
    for config in $CONFIGS; do
        printf '%-28s %s\n' "$config" "$(measured_for "$config")" >>"$next_baseline"
    done
    mv "$next_baseline" "$BASELINE"
    printf 'recorded unsafe-comment baseline in %s\n' "$BASELINE"
    for config in $CONFIGS; do
        printf '  %-28s %s\n' "$config" "$(measured_for "$config")"
    done
    exit 0
fi

failed=0

while read -r config _; do
    known=0
    for candidate in $CONFIGS; do
        if [ "$candidate" = "$config" ]; then
            known=1
        fi
    done
    if [ "$known" = "0" ]; then
        printf 'baseline names an unknown configuration: %s\n' "$config" >&2
        failed=1
    fi
done <"$work/baseline.txt"

for config in $CONFIGS; do
    baseline="$(awk -v c="$config" '$1 == c { print $2 }' "$work/baseline.txt")"
    if [ -z "$baseline" ]; then
        printf 'baseline has no count for configuration %s\n' "$config" >&2
        failed=1
        continue
    fi
    case "$baseline" in
        *[!0-9]*)
            printf 'baseline count for %s is not a number: %s\n' "$config" "$baseline" >&2
            failed=1
            continue
            ;;
    esac

    count="$(measured_for "$config")"
    if [ "$count" -gt "$baseline" ]; then
        printf 'unsafe comments: %s has %s undocumented blocks or impls, baseline is %s\n' \
            "$config" "$count" "$baseline" >&2
        printf '  a new `unsafe` block or `impl` needs a `// SAFETY:` comment saying\n' >&2
        printf '  why the invariants hold there (docs/fmts/unsafe-and-safety.md §3)\n' >&2
        failed=1
    elif [ "$count" -lt "$baseline" ]; then
        printf 'unsafe comments: %s dropped from %s to %s\n' \
            "$config" "$baseline" "$count" >&2
        printf '  good, but the baseline has to follow in the same change:\n' >&2
        printf '  sh scripts/check-unsafe-comments.sh --record\n' >&2
        failed=1
    else
        printf '  %-28s %s (unchanged)\n' "$config" "$count"
    fi
done

if [ "$failed" != "0" ]; then
    exit 1
fi

printf 'unsafe-comment check passed\n'
