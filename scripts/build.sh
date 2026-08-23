#!/usr/bin/env sh
# File: scripts/build.sh
# Purpose: Wrapper around `make build` that validates the requested build profile.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

exec make build PROFILE="$PROFILE"
