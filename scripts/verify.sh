#!/usr/bin/env sh
# File: scripts/verify.sh
# Purpose: Tiered verification script that runs P0/P1/P2/P3 quality gates.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
RUN_X86_64_RUNTIME="${RUN_X86_64_RUNTIME:-0}"
RUN_AARCH64_RUNTIME="${RUN_AARCH64_RUNTIME:-0}"
VERIFY_TIER="${1:-${VERIFY_TIER:-p2}}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

case "$VERIFY_TIER" in
    p0|P0) VERIFY_TIER="p0" ;;
    p1|P1) VERIFY_TIER="p1" ;;
    p2|P2) VERIFY_TIER="p2" ;;
    p3|P3) VERIFY_TIER="p3" ;;
    *)
        printf 'unsupported VERIFY_TIER: %s\n' "$VERIFY_TIER" >&2
        exit 1
        ;;
esac

run_make_step() {
    description="$1"
    target="$2"
    printf '==> verify[%s]: %s\n' "$VERIFY_TIER" "$description"
    make "$target" PROFILE="$PROFILE"
}

check_kernel_headers() {
    total_files=0
    path_headers=0
    summary_headers=0

    files="$(find src/kernel -type f -name '*.rs' | sort)"
    for file in $files; do
        total_files=$((total_files + 1))
        relative_path="${file#./}"

        first_line="$(sed -n '1p' "$file")"
        second_line="$(sed -n '2p' "$file")"

        if [ "$first_line" = "//! $relative_path" ]; then
            path_headers=$((path_headers + 1))
        fi

        if printf '%s\n' "$second_line" | grep -Eq '^//! [^[:space:]].+'; then
            summary_headers=$((summary_headers + 1))
        fi
    done

    printf 'header coverage: path=%s summary=%s total=%s\n' \
        "$path_headers" "$summary_headers" "$total_files"

    if [ "$path_headers" -ne "$total_files" ] \
        || [ "$summary_headers" -ne "$total_files" ]; then
        printf 'kernel header coverage check failed\n' >&2
        return 1
    fi
}

run_p0() {
    # P0 keeps the baseline strict: format, multi-target builds, and source headers.
    run_make_step "make fmt-check" fmt-check
    run_make_step "make check (host + x86_64 target)" check
    run_make_step "make check-aarch64" check-aarch64
    run_make_step "make build" build
    run_make_step "make build-aarch64" build-aarch64

    printf '==> verify[%s]: kernel header coverage\n' "$VERIFY_TIER"
    check_kernel_headers
}

run_p1() {
    # P1 adds the fast host regressions that catch wake-order, ABI, and path drift.
    run_p0
    run_make_step "make test-lib" test-lib
    run_make_step "make test-concurrency" test-concurrency
    run_make_step "make test-fast" test-fast
}

run_p2() {
    # P2 extends the gate to storage and recovery suites, including fault matrices.
    run_p1
    run_make_step "make test-storage" test-storage
}

run_p3() {
    # P3 is the release-grade gate: static analysis plus optional AArch64 QEMU runtime smoke.
    # x86_64 runtime smoke is exercised manually via `make run`.
    run_p2
    run_make_step "make clippy" clippy
    if [ "$RUN_AARCH64_RUNTIME" = "1" ]; then
        run_make_step "make check-aarch64-runtime" check-aarch64-runtime
    else
        printf '==> verify[%s]: skipping aarch64 runtime smoke (set RUN_AARCH64_RUNTIME=1 to enable)\n' \
            "$VERIFY_TIER"
    fi
}

case "$VERIFY_TIER" in
    p0) run_p0 ;;
    p1) run_p1 ;;
    p2) run_p2 ;;
    p3) run_p3 ;;
esac

printf 'verify[%s] complete\n' "$VERIFY_TIER"
