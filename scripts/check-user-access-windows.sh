#!/usr/bin/env sh
# File: scripts/check-user-access-windows.sh
# Purpose: Keep the user-access window opened from one place.
#
# Why this exists
# ---------------
# The window that lets the kernel touch user memory — x86_64's EFLAGS.AC,
# AArch64's PSTATE.PAN, RISC-V's sstatus.SUM — is *per-hart* state, not a
# per-call flag and not a per-thread one.  Two things follow, and both have
# already gone wrong in this tree:
#
#   * A handler that opens the window and then waits holds it open across a
#     context switch.  Whatever runs next on that hart inherits the permission,
#     and another thread that closes its own window closes the waiting thread's
#     too — the shape that killed a ring-3 console reader on riscv64.
#   * A helper called inside an already-open window used to close it on the way
#     out, because the guard set the protection bit unconditionally instead of
#     restoring what it found.  The guard saves and restores now, but the rule
#     below is what keeps the nesting shallow enough to reason about.
#
# So the window is opened in exactly one module — `syscall/memory/user.rs`,
# whose helpers scope it to a single copy and whose documentation states the
# rule — and every other caller reaches user memory through those helpers.  An
# open-coded `with_user_access_guard` somewhere else is the first step back to
# the bug above, and this gate refuses it here rather than in a boot that only
# fails on one machine.
#
# The one exception, and why it is not the shape this gate exists for
# -------------------------------------------------------------------
# `src/memory/manager/pfault.rs` opens the window around the copy-on-write
# copy, and it has to.  On riscv64 a demo slot is identity-mapped: the slot's
# virtual address *is* the frame's physical address, and a process root
# splices a user PTE table over exactly that 2 MiB block, replacing the
# supervisor block the kernel's own tables have there.  The fault handler
# therefore reads the frame it is copying through a `U=1` entry, and with
# `sstatus.SUM` clear that read is itself a page fault — measured, the kernel
# stopped inside the fault handler with no trap reported, because the fault
# arrived while one was already being handled.  The other two machines do not
# need it (`x86_64` and `aarch64` map user pages so the supervisor can read
# them), so the window costs them nothing.
#
# The two failures this gate was written for are a window held *across a
# context switch* and a window that closes one it did not open.  Neither
# applies here: a page fault runs to its return, and the guard saves and
# restores.  That is an argument, not a check, which is why the exception is
# one named file rather than a rule the gate cannot see.
#
# Usage:
#   sh scripts/check-user-access-windows.sh

set -eu

cd "$(dirname "$0")/.."

# The module that owns the window, and the module that defines it.
OWNER="src/syscall/memory/user.rs"
DEFINITION="src/arch/user_access.rs"
# The fault handler's copy-on-write copy; see the header for why.
FAULT_HANDLER="src/memory/manager/pfault.rs"

offenders="$(grep -rn -e 'with_user_access_guard' src --include='*.rs' \
    | grep -v "^${DEFINITION}:" \
    | grep -v "^${OWNER}:" \
    | grep -v "^${FAULT_HANDLER}:" || true)"

if [ -n "$offenders" ]; then
    printf 'user-access windows: only %s and %s may open one; found:\n' \
        "$OWNER" "$FAULT_HANDLER" >&2
    printf '%s\n' "$offenders" >&2
    exit 1
fi

printf 'user-access windows: the window is opened only in %s and %s\n' \
    "$OWNER" "$FAULT_HANDLER"
