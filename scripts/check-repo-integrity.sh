#!/usr/bin/env sh
# File: scripts/check-repo-integrity.sh
# Purpose: Fail when the object database or a reference is broken.
#
# Why this exists
# ---------------
# A `git commit` that is interrupted while it writes objects can leave a
# reference pointing at a file that was never finished — in the accident this
# check was written for, `refs/heads/master` named a zero-byte commit and the
# index's cache-tree pointed at objects that were not there.  Nothing noticed
# until the next commit failed with an error about an object it could not
# read, which is a long way from the cause and reads like corruption of the
# whole repository.
#
# `git fsck` names that state directly, runs in under a second on this tree,
# and exits zero for the benign notices a reset or an amend leaves behind
# (dangling commits, unreachable blobs).  Those are filtered out here; anything
# else — a missing object, a broken link, an unreadable ref — is a failure.
#
# Usage:
#   sh scripts/check-repo-integrity.sh

set -eu

cd "$(dirname "$0")/.."

if ! command -v git >/dev/null 2>&1; then
    printf 'check-repo-integrity: git is not installed\n' >&2
    exit 1
fi

# A checkout that was copied without its .git directory has nothing to check.
if [ ! -d .git ]; then
    printf 'check-repo-integrity: no .git directory; skipping\n' >&2
    exit 0
fi

out="$(mktemp)"
cleanup() {
    rm -f "$out"
}
trap cleanup EXIT INT TERM

set +e
git fsck --no-progress >"$out" 2>&1
status=$?
set -e

# The notices a normal history carries: objects nothing points at any more,
# normally because a commit was amended or a branch was reset.  `git fsck`
# still exits 0 for them.
problems="$(grep -v -e 'dangling ' -e 'unreachable ' -e '^悬空' -e '^不可达' "$out" || true)"

if [ -n "$problems" ] || [ "$status" -ne 0 ]; then
    printf 'check-repo-integrity: the repository object database is not sound\n' >&2
    if [ -n "$problems" ]; then
        printf '%s\n' "$problems" >&2
    fi
    if [ "$status" -ne 0 ]; then
        printf 'git fsck exited %s\n' "$status" >&2
    fi
    printf 'A reference or an index entry is naming an object that is missing or\n' >&2
    printf 'unreadable, which usually means a `git commit` was interrupted.\n' >&2
    printf 'See the repair in the commit that added this check.\n' >&2
    exit 1
fi

printf 'repo integrity check passed: %s notice(s) tolerated\n' \
    "$(grep -c -e 'dangling ' -e 'unreachable ' -e '^悬空' -e '^不可达' "$out" || true)"
