#!/usr/bin/env sh
# File: scripts/check-bits-is-a-leaf.sh
# Purpose: Hold `protofire-bits` to being what it says it is.
#
# Why this exists
# ---------------
# The crate's manifest says anything added to it may use `core` and `alloc`
# and nothing else.  That is easy to write and easy to break: a file moved into
# it that names `crate::Error` looks fine to a reader, and the dependency it
# re-creates is exactly the cycle the crate was made to break.
#
# What makes this cheap is that the build already refuses it.  There is no
# `crate::` in `protofire-bits` — the kernel depends on this crate, not the
# other way round — so a reference to one is an unresolved path and the crate
# does not compile.  This gate is therefore not a second census: it builds the
# crate alone, on the host and for every bare-metal target, which is the thing
# a dependency on the kernel would break.
#
# Building it *alone* is the part that matters.  `cargo build` of the whole
# workspace would compile the kernel first and could hide a reference that only
# resolves because the kernel happens to be in the same build graph; `-p` names
# one package and cargo builds only its own dependencies.
#
# Usage:
#   sh scripts/check-bits-is-a-leaf.sh

set -eu

cd "$(dirname "$0")/.."

CARGO="${CARGO:-cargo}"

targets="x86_64-unknown-none aarch64-unknown-none riscv64gc-unknown-none-elf"

for target in $targets; do
    if ! "$CARGO" build --offline -p protofire-bits --target "$target" >/dev/null 2>&1; then
        printf 'bits-is-a-leaf: protofire-bits does not build alone for %s\n' "$target" >&2
        printf '  it is supposed to need nothing but core and alloc; a `crate::`\n' >&2
        printf '  reference in it would be exactly that failure\n' >&2
        "$CARGO" build --offline -p protofire-bits --target "$target" 2>&1 | tail -20 >&2
        exit 1
    fi
done

# And its tests, which are the half that proves the crate is useful on its own
# rather than merely compilable.
if ! "$CARGO" test --offline -p protofire-bits >/dev/null 2>&1; then
    printf 'bits-is-a-leaf: protofire-bits tests do not pass on their own\n' >&2
    "$CARGO" test --offline -p protofire-bits 2>&1 | tail -20 >&2
    exit 1
fi

printf 'bits-is-a-leaf check passed: protofire-bits builds alone for %s target(s) and its tests pass\n' \
    "$(printf '%s\n' $targets | wc -l | tr -d ' ')"
