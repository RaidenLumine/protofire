#!/usr/bin/env sh
# File: scripts/check-reproducible-build.sh
# Purpose: Build the same artifacts twice, in two clean trees, and require the
#          bytes to be identical.
#
# Why this exists
# ---------------
# A release is only worth signing if someone else can rebuild it and get the
# same bytes: a signature over an artifact nobody can reproduce certifies a
# build, not a source tree.  "Reproducible" is therefore a property the tree
# has to keep, and this is the check that keeps it: the same source, built
# twice in two directories that share nothing, has to come out byte for byte
# the same.
#
# Nothing here pins a hash.  Pinning one would fail on every honest change and
# pass on a build that merely matched an old value; what is asserted is
# determinism, which is the property a release depends on.
#
# What is compared
# ----------------
# The three kernel artifacts a release ships (the x86_64 and riscv64 ELFs and
# the aarch64 `Image` a machine boots) and the demo disk image `mkimage`
# writes.  The two build trees are fresh: `CARGO_TARGET_DIR` points at each in
# turn, so nothing is reused and a path that leaked into an artifact, a
# timestamp, or an iteration order that varies between processes all show up
# as a difference.
#
# The trees live under `$REPRO_BUILD_ROOT` (the repository's own build
# directory by default) rather than in `$TMPDIR`, because a fresh build of all
# three targets is a couple of gigabytes and `/tmp` is often a memory-backed
# filesystem.  They are removed at the end unless `KEEP_REPRO_BUILDS=1`.
#
# `PROFILE` selects which artifacts are checked, so the release build is the
# same check with `PROFILE=release` — that is the one a release would run.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
ROOT="${REPRO_BUILD_ROOT:-target/repro-check}"
KEEP_REPRO_BUILDS="${KEEP_REPRO_BUILDS:-0}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

case "$PROFILE" in
    release) profile_flag="--release" ;;
    *) profile_flag="" ;;
esac

first="${ROOT}/build-one"
second="${ROOT}/build-two"

cleanup() {
    if [ "$KEEP_REPRO_BUILDS" = "1" ]; then
        printf 'reproducible build: trees kept at %s and %s\n' "$first" "$second"
        return
    fi
    rm -rf "$first" "$second"
}
trap cleanup EXIT INT TERM

rm -rf "$first" "$second"
mkdir -p "$first" "$second"

# Build every artifact a release ships, in one tree.  The output is kept in a
# log so a failure shows why instead of scrolling past.
build_tree() {
    dir="$1"
    log="$dir/build.log"

    {
        CARGO_TARGET_DIR="$dir" "$CARGO" build --offline $profile_flag \
            --target x86_64-unknown-none --bin "$CRATE" --features demo-disk
        CARGO_TARGET_DIR="$dir" "$CARGO" build --offline $profile_flag \
            --target riscv64gc-unknown-none-elf --bin "$CRATE" --features demo-disk
        CARGO_TARGET_DIR="$dir" PROFILE="$PROFILE" TARGET_DIR="$dir" FEATURES=demo-disk \
            sh ./scripts/build-aarch64-image.sh
        CARGO_TARGET_DIR="$dir" "$CARGO" run --offline --quiet -- \
            mkimage "$dir/demo-disk.img"
    } >"$log" 2>&1 || {
        printf 'reproducible build: the build in %s failed:\n' "$dir" >&2
        tail -n 20 "$log" >&2
        exit 1
    }
}

printf 'reproducible build: building twice into %s and %s\n' "$first" "$second"
build_tree "$first"
build_tree "$second"

artifact() {
    dir="$1"
    name="$2"
    printf '%s/%s' "$dir" "$name"
}

compare() {
    label="$1"
    relative="$2"
    a="$(artifact "$first" "$relative")"
    b="$(artifact "$second" "$relative")"

    if [ ! -f "$a" ] || [ ! -f "$b" ]; then
        printf 'reproducible build check failed: %s was not built in both trees\n' "$label" >&2
        exit 1
    fi

    if cmp -s "$a" "$b"; then
        printf '  %-38s %10s bytes  identical\n' \
            "$label" "$(wc -c <"$a" | tr -d ' ')"
        return 0
    fi

    printf 'reproducible build check failed: %s differs between two clean builds\n' \
        "$label" >&2
    printf '  first : %s bytes in %s\n' "$(wc -c <"$a" | tr -d ' ')" "$a" >&2
    printf '  second: %s bytes in %s\n' "$(wc -c <"$b" | tr -d ' ')" "$b" >&2
    printf '  first difference: ' >&2
    cmp "$a" "$b" 2>&1 | head -n 1 >&2 || true
    KEEP_REPRO_BUILDS=1
    printf '  both trees are kept for inspection (KEEP_REPRO_BUILDS=1)\n' >&2
    exit 1
}

compare "x86_64 kernel ELF" "x86_64-unknown-none/${PROFILE}/${CRATE}"
compare "aarch64 kernel Image" "aarch64-unknown-none/${PROFILE}/${CRATE}.img"
compare "riscv64 kernel ELF" "riscv64gc-unknown-none-elf/${PROFILE}/${CRATE}"
compare "demo disk image" "demo-disk.img"

printf 'reproducible build check passed: 4 artifact(s) byte-identical across two clean %s builds\n' \
    "$PROFILE"
