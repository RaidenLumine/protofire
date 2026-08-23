#!/usr/bin/env sh
# File: scripts/run.sh
# Purpose: Wrapper that assembles runtime assets and launches the x86_64 QEMU demo.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
exec make run PROFILE="$PROFILE"
