#!/usr/bin/env sh
# File: scripts/check-feature-matrix.sh
# Purpose: Build every configuration the manifest declares.
#
# Why this exists
# ---------------
# `Cargo.toml` declares thirteen switches beyond `default`, and the tree's
# gates use five of them (the ones a boot hands to `make check-*`).  The rest
# are described in the manifest and used by nothing that runs: a feature whose
# code has rotted away still reads as shipped, because nothing builds it.
# That is the same defect this project keeps finding in code ("written, wired,
# and never executed") one level up, in the build graph.
#
# So each feature is built in the configuration it belongs to — the shipped
# `demo-disk` build plus that one switch — and then all of them together, which
# is what catches two features that compile alone and not in each other's
# company.  This is the union and the singletons, not the powerset: the pairs
# that matter are the ones a gate boots (frozen payload, an init that asks for
# nothing, the stack churn), and each of those has a check of its own.
#
# Usage:
#   sh scripts/check-feature-matrix.sh
#
# Exits non-zero naming the first configuration that did not build.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
CRATE="${CRATE:-protofire}"
CARGO="${CARGO:-cargo}"
TARGET="${TARGET:-x86_64-unknown-none}"
TARGET_DIR="${TARGET_DIR:-target}"

# The base every other configuration is built on: the disk the demos ship with,
# which is what `make run` and the runtime gates use.
BASE_FEATURES="${BASE_FEATURES:-demo-disk}"

# Features the matrix does not build, each with the reason.  A feature belongs
# here when it is not part of a kernel build at all, and the reason has to say
# where it is built instead.
EXCLUDED="runtime"
excluded_reason() {
    case "$1" in
        runtime)
            printf '%s' 'the standalone ring-3 runtime bridge, which the kernel build never enables (the kernel carries its own bridge); its configuration is the payload build, not this one'
            ;;
        *) printf '%s' 'no reason recorded' ;;
    esac
}

features="$(awk '
    /^\[features\]/ { in_features = 1; next }
    /^\[/ { in_features = 0 }
    in_features && /^[a-z_]+ *=/ {
        name = $0
        sub(/ *=.*/, "", name)
        if (name != "default") print name
    }
' Cargo.toml)"

if [ -z "$features" ]; then
    printf 'feature matrix: no features found in Cargo.toml\n' >&2
    exit 1
fi

checked=0
checked_features=""
for feature in $features; do
    case " $EXCLUDED " in
        *" $feature "*)
            printf 'feature matrix: skipping %s — %s\n' "$feature" "$(excluded_reason "$feature")"
            continue
            ;;
    esac
    printf 'feature matrix: %s + %s ... ' "$BASE_FEATURES" "$feature"
    if log="$("$CARGO" check --offline --target "$TARGET" --bin "$CRATE" \
        --features "$BASE_FEATURES,$feature" 2>&1)"; then
        printf 'ok\n'
    else
        printf 'FAILED\n'
        printf '%s\n' "$log" | tail -n 20 >&2
        exit 1
    fi
    checked=$((checked + 1))
    checked_features="$checked_features $feature"
done

# And every one of them at once, which is what catches two switches that are
# fine apart and not together.
all="$(printf '%s' "$checked_features" | tr ' ' ',' | sed 's/^,//')"
printf 'feature matrix: %s + all of them ... ' "$BASE_FEATURES"
if log="$("$CARGO" check --offline --target "$TARGET" --bin "$CRATE" \
    --features "$BASE_FEATURES,$all" 2>&1)"; then
    printf 'ok\n'
else
    printf 'FAILED\n'
    printf '%s\n' "$log" | tail -n 20 >&2
    exit 1
fi

printf 'feature matrix check passed: %s configuration(s) plus the union\n' "$checked"
