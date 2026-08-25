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

check_source_headers() {
    total_files=0
    path_headers=0
    blank_headers=0
    separated_headers=0

    # Every `.rs` file in the repository must open with:
    #   line 1: `//! <relative_path>`
    #   line 2: `//!` (blank)
    #   followed by the `//!` description lines,
    # and a blank line must separate the whole `//!` header block from the
    # first body line (the convention requested by the maintainer).
    files="$(find . -type f -name '*.rs' -not -path './target/*' | sort)"
    for file in $files; do
        total_files=$((total_files + 1))
        relative_path="${file#./}"

        first_line="$(sed -n '1p' "$file")"
        second_line="$(sed -n '2p' "$file")"

        if [ "$first_line" = "//! $relative_path" ]; then
            path_headers=$((path_headers + 1))
        fi

        if [ "$second_line" = "//!" ]; then
            blank_headers=$((blank_headers + 1))
        fi

        # The first non-`//!`, non-blank line must come at least two lines
        # after the last `//!` header line (i.e. one blank line between).
        if awk '
            NR == 1 && $0 !~ /^\/\/!/ { exit 0 }
            $0 ~ /^\/\/!/ { last = NR; next }
            $0 == "" { next }
            { exit (NR - last >= 2) ? 0 : 1 }
        ' "$file"; then
            separated_headers=$((separated_headers + 1))
        fi
    done

    printf 'header coverage: path=%s blank=%s separated=%s total=%s\n' \
        "$path_headers" "$blank_headers" "$separated_headers" "$total_files"

    if [ "$path_headers" -ne "$total_files" ] \
        || [ "$blank_headers" -ne "$total_files" ] \
        || [ "$separated_headers" -ne "$total_files" ]; then
        printf 'source header coverage check failed\n' >&2
        return 1
    fi
}

check_commit_hooks() {
    hooks_path="$(git config --get core.hooksPath 2>/dev/null || true)"
    if [ -n "$hooks_path" ] && [ -x "$hooks_path/commit-msg" ]; then
        printf 'commit hook: installed (%s/commit-msg)\n' "$hooks_path"
    else
        printf 'commit hook: NOT installed — run `make install-hooks`\n' >&2
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

    printf '==> verify[%s]: source header coverage\n' "$VERIFY_TIER"
    check_source_headers

    printf '==> verify[%s]: commit message hook\n' "$VERIFY_TIER"
    check_commit_hooks
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
