#!/usr/bin/env sh
# File: scripts/make-release.sh
# Purpose: Build the artifacts a release ships, sign each with a fresh
#          one-time key, and leave the signatures and key records beside them.
#
# Why a script
# ------------
# The pieces already exist: `make check-reproducible-build` says the bytes are
# reproducible, and `cargo run -- sign-release` spends a one-time key on an
# artifact.  A release is the *order* they happen in — build the four artifacts
# the reproducibility gate builds, give each one the name it ships under, sign
# it with a key that has never signed anything else, and check the signature
# with the verifier a user would use.  Done by hand, that order is where a
# signature ends up over the wrong file.
#
# What this does not do
# --------------------
# It does not tag, publish, or choose a version.  The version comes from
# Cargo.toml, where bumping it is a deliberate act (a 1.x bump is a promise
# about the ABI), and uploading the bundle is the maintainer's.  See
# CONTRIBUTING.md -> Releasing for the order around this script.
#
# Usage:
#   sh scripts/make-release.sh              # PROFILE=release into dist/<version>
#   PROFILE=debug sh scripts/make-release.sh  # the same, for a dry run
#   RELEASE_DIR=/tmp/out sh scripts/make-release.sh

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-release}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
KEEP_RELEASE_BUILD="${KEEP_RELEASE_BUILD:-0}"

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

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
if [ -z "$version" ]; then
    printf 'cannot read the package version from Cargo.toml\n' >&2
    exit 1
fi

out="${RELEASE_DIR:-dist/$version}"
build="$out/build"
mkdir -p "$out"

# A second run would spend a second key on the same version.  `sign-release`
# refuses to overwrite a signature anyway; saying so here means the refusal
# costs a message rather than a full rebuild.
for name in "$CRATE-$version-x86_64.elf" "$CRATE-$version-aarch64.img" \
    "$CRATE-$version-riscv64.elf" "$CRATE-$version-demo-disk.img"; do
    if [ -e "$out/$name.sig" ]; then
        printf 'release: %s is already signed — a key signs one artifact, so this would be a second release of %s\n' \
            "$out/$name.sig" "$version" >&2
        exit 1
    fi
done

log="$out/build.log"
printf 'release: building %s artifacts for %s into %s\n' "$PROFILE" "$version" "$build"
{
    CARGO_TARGET_DIR="$build" "$CARGO" build --offline $profile_flag \
        --target x86_64-unknown-none --bin "$CRATE" --features demo-disk
    CARGO_TARGET_DIR="$build" "$CARGO" build --offline $profile_flag \
        --target riscv64gc-unknown-none-elf --bin "$CRATE" --features demo-disk
    CARGO_TARGET_DIR="$build" PROFILE="$PROFILE" TARGET_DIR="$build" FEATURES=demo-disk \
        sh ./scripts/build-aarch64-image.sh
    CARGO_TARGET_DIR="$build" "$CARGO" run --offline --quiet -- \
        mkimage "$build/demo-disk.img"
} >"$log" 2>&1 || {
    printf 'release: the build failed:\n' >&2
    tail -n 20 "$log" >&2
    exit 1
}

# The name each artifact ships under.  The two kernel ELFs are both called
# `protofire` in their build trees, so the release name is also what keeps
# their signatures and key records apart.
ship() {
    source_path="$1"
    name="$2"
    if [ ! -f "$source_path" ]; then
        printf 'release: %s was not built\n' "$source_path" >&2
        exit 1
    fi
    cp "$source_path" "$out/$name"
    printf '%s\n' "$out/$name"
}

x86_64_elf="$(ship "$build/x86_64-unknown-none/$PROFILE/$CRATE" "$CRATE-$version-x86_64.elf")"
aarch64_image="$(ship "$build/aarch64-unknown-none/$PROFILE/$CRATE.img" "$CRATE-$version-aarch64.img")"
riscv64_elf="$(ship "$build/riscv64gc-unknown-none-elf/$PROFILE/$CRATE" "$CRATE-$version-riscv64.elf")"
demo_disk="$(ship "$build/demo-disk.img" "$CRATE-$version-demo-disk.img")"

# One key per artifact.  `sign-release` refuses to write over an existing
# signature or key record, which is what makes a second run of this script
# spend a second key instead of quietly replacing the first.
sign_one() {
    artifact="$1"
    key_id="$2"
    printf 'release: signing %s with one-time key %s\n' "$(basename "$artifact")" "$key_id"
    "$CARGO" run --offline --quiet -- sign-release "$artifact" "$key_id" "$out"
    "$CARGO" run --offline --quiet -- verify-signature \
        "$artifact" "$artifact.sig" "$out/$key_id.public.toml"
}

sign_one "$x86_64_elf" "$CRATE-$version-x86_64"
sign_one "$aarch64_image" "$CRATE-$version-aarch64"
sign_one "$riscv64_elf" "$CRATE-$version-riscv64"
sign_one "$demo_disk" "$CRATE-$version-demo-disk"

# Checksums are not a signature: they say what the bundle held, and the
# signature is what a rebuild is checked against.
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$out" && sha256sum ./*.elf ./*.img >SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
    (cd "$out" && shasum -a 256 ./*.elf ./*.img >SHA256SUMS)
else
    printf 'release: no sha256 tool found; SHA256SUMS not written\n' >&2
fi

build_bytes="$(du -sh "$build" 2>/dev/null | awk '{print $1}')"
if [ "$KEEP_RELEASE_BUILD" = "1" ]; then
    printf 'release: build tree kept at %s (%s)\n' "$build" "$build_bytes"
else
    rm -rf "$build"
fi

printf '\nrelease %s is in %s\n' "$version" "$out"
ls -1 "$out" | sed 's/^/  /'
printf '\nA user checks a rebuild against the signature and the key record:\n'
printf '  cargo run -- verify-signature %s %s.sig %s/%s.public.toml\n' \
    "$x86_64_elf" "$x86_64_elf" "$out" "$CRATE-$version-x86_64"
printf 'The private half of each key is gone with the process that made it;\n'
printf 'the key records are what goes in the release beside the artifacts.\n'
