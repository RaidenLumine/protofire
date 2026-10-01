#!/usr/bin/env sh
# File: scripts/check-abi-mirror.sh
# Purpose: Keep the ABI records and their user-space mirror in step.
#
# `src/abi/` is the kernel's copy of the ABI records and `src/user/shared/abi/`
# is the copy user code uses.  Both exist on purpose: the shared tree is
# vendored, so it has to be a copy rather than a `pub use`, and a copy is only
# as good as the check that keeps it honest.  Nothing watched the two, and they
# drifted the one way copies drift — the kernel's side grew three blocks of
# exactly the API user code needs (the `SA_*` restart flags, the
# architecture-neutral exception-handler flags, the `NetworkStatus`
# accessors) while the user's side kept none of them, and user code reached
# back into the kernel's copy to get them.
#
# So this checks three things:
#
#   1. every file in `src/abi/` is declared by `src/abi/mod.rs`.  A file the
#      compiler never sees is not code — three of them sat in this directory
#      undeclared, one listing prctl codes that collided with the prctl codes
#      the kernel actually implements.
#   2. every declared record has a mirror, and every mirror has a record.
#   3. the two bodies are identical below the header.  The mirror's header is
#      the only place the two are allowed to differ, and it has to record where
#      the file came from (`//! src/abi/<name>.rs`).
#
# A pair that is meant to differ is listed in `scripts/abi-mirror-baseline.txt`
# with its reason, and a stale row — one whose difference is gone — fails too,
# so the list describes the tree instead of a tree that used to exist.
#
# Usage:
#   sh scripts/check-abi-mirror.sh

set -eu

cd "$(dirname "$0")/.."

BASELINE="${BASELINE:-scripts/abi-mirror-baseline.txt}"
KERNEL_DIR="src/abi"
SHARED_DIR="src/user/shared/abi"

if [ ! -f "$BASELINE" ]; then
    printf 'ABI mirror baseline not found: %s\n' "$BASELINE" >&2
    exit 1
fi

# Everything after the leading `//!` header block: the part that has to match.
body_of() {
    awk 'BEGIN { header = 1 }
         header && /^\/\/!/ { next }
         header && /^[[:space:]]*$/ { next }
         { header = 0; print }' "$1"
}

declared_modules() {
    awk '/^pub mod [a-z_0-9]+;/ { name = $3; sub(/;$/, "", name); print name }' "$1"
}

# The baseline rows name files with their extension; every lookup here works in
# bare names, so strip it in one place.
baseline_kind() {
    awk -v want="$1" '
        { name = $1; sub(/\.rs$/, "", name) }
        name == want { print $2 }
    ' "$BASELINE" | head -1
}

baseline_reason() {
    awk -v want="$1" '
        { line = $0; sub(/#/, "|", line); split(line, parts, "|") }
        { name = $1; sub(/\.rs$/, "", name) }
        name == want { print parts[2] }
    ' "$BASELINE" | head -1
}

work="$(mktemp -d)"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

records="$(cd "$KERNEL_DIR" && ls *.rs | sed 's/\.rs$//' | grep -v '^mod$' | sort)"
# `mod.rs` is not a record, but the two module lists are compared like any
# other pair: the shared tree's list is one line shorter, and that difference
# is recorded rather than special-cased.
names="$(printf 'mod\n%s\n' "$records" | sort)"
declared="$(declared_modules "$KERNEL_DIR/mod.rs" | sort)"
shared_names="$(cd "$SHARED_DIR" && ls *.rs | sed 's/\.rs$//' | grep -v '^mod$' | sort)"

failed=0

fail() {
    printf '%s\n' "$1" >&2
    failed=1
}

# 1. Declared, and only declared files.
for name in $records; do
    if ! printf '%s\n' "$declared" | grep -qx "$name"; then
        fail "abi: src/abi/$name.rs is not declared by src/abi/mod.rs"
        fail "  a file the compiler never sees is not code"
    fi
done
for name in $declared; do
    if [ ! -f "$KERNEL_DIR/$name.rs" ]; then
        fail "abi: src/abi/mod.rs declares $name, which is not there"
    fi
done

# 2. Mirrors both ways.
for name in $shared_names; do
    if [ ! -f "$KERNEL_DIR/$name.rs" ]; then
        fail "abi: $SHARED_DIR/$name.rs has no kernel-side record"
    fi
done

# 3. The header records the origin, and the bodies match.
differs=""
kernel_only=""
for name in $names; do
    mirror="$SHARED_DIR/$name.rs"
    if [ ! -f "$mirror" ]; then
        kernel_only="$kernel_only $name"
        continue
    fi
    # A pair recorded as deliberately different is not a mirror, so it does not
    # carry the origin line — it says what it is instead.
    if [ "$(baseline_kind "$name")" != "differs" ]; then
        if ! head -4 "$mirror" | grep -qx "//! src/abi/$name.rs"; then
            fail "abi: $mirror does not record its origin (//! src/abi/$name.rs)"
        fi
    fi
    body_of "$KERNEL_DIR/$name.rs" >"$work/kernel"
    body_of "$mirror" >"$work/shared"
    if ! cmp -s "$work/kernel" "$work/shared"; then
        differs="$differs $name"
    fi
done

# Baseline rows: `<file> <differs|kernel-only>  # <reason>`.
baseline_names="$(awk '
    { sub(/#.*/, "") }
    NF == 0 { next }
    { name = $1; sub(/\.rs$/, "", name); print name }
' "$BASELINE")"

for name in $differs; do
    kind="$(baseline_kind "$name")"
    if [ "$kind" != "differs" ]; then
        fail "abi: src/abi/$name.rs and its mirror differ, and the difference is not recorded"
        fail "  record it in $BASELINE with a reason, or make the two copies agree"
        continue
    fi
done

for name in $kernel_only; do
    kind="$(baseline_kind "$name")"
    if [ "$kind" != "kernel-only" ]; then
        fail "abi: src/abi/$name.rs has no mirror and that is not recorded"
        continue
    fi
done

for name in $baseline_names; do
    case " $differs $kernel_only " in
        *" $name "*) ;;
        *)
            fail "abi: $BASELINE records '$name', which is not a difference any more"
            continue
            ;;
    esac
    reason="$(baseline_reason "$name")"
    case "$(printf '%s' "$reason" | tr -d ' ')" in
        '')
            fail "abi: $BASELINE records '$name' without a reason"
            ;;
    esac
done

if [ "$failed" -ne 0 ]; then
    printf 'ABI mirror check failed\n' >&2
    exit 1
fi

printf 'ABI mirror check passed: %s record(s), %s recorded difference(s)\n' \
    "$(printf '%s\n' "$names" | wc -l | tr -d ' ')" \
    "$(printf '%s\n' "$baseline_names" | grep -c . || true)"
