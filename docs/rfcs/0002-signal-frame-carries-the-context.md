# RFC 0002: Carry the interrupted context in the signal frame

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-05
- **Supersedes:** none

## Summary

The frame an async signal leaves on the user stack carried three words: where
the interrupted code was (instruction pointer, stack pointer, status) and the
signal number.  This RFC makes it carry the interrupted *context* — every
general register as well — and fixes the trampoline contract so that the frame
is always the address the trampoline's own stack pointer holds.

## Motivation

`sigreturn` exists to put the interrupted code back.  A handler is a function:
it is free to clobber every caller-saved register, and the trampoline the
kernel leaves as its return address clobbers a few more.  With a frame that
records only where the code was, the interrupted computation resumes at the
right instruction with the handler's register values — which is not a restore,
it is a restart with somebody else's registers.

No gate could see this, because nothing in the tree shipped a trampoline: the
kernel's delivery path was reachable in principle and reached by nothing.  The
same situation hid a second defect, recorded here because it is the reason the
first one mattered (see the implementation note).

## Design

Each frame is its machine's user context, flattened, with `signal` last:

| Machine | Registers | Control words | Size |
|---------|-----------|---------------|------|
| x86_64 | `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rbp`, `r8`..`r15` | `orig_rip`, `orig_rsp`, `orig_rflags` | 152 bytes |
| AArch64 | `x0`..`x30` | `orig_elr`, `orig_sp`, `orig_spsr` | 280 bytes |
| RISC-V 64 | `x1`..`x31` (so `x2` is the stack pointer) | `orig_sepc`, `orig_sstatus` | 272 bytes |

Segment selectors, `cs`/`ss` on x86_64, are deliberately *not* in the frame:
they are the machine's, not the program's, and a record the user can write is
the last place to read them from.

The frame goes where the trampoline's stack pointer will be, on all three
machines: the delivery aligns a base below the interrupted stack pointer, and
the handler is entered so that its own return lands on that base.  AArch64 and
RISC-V get there through the link register (`x30`, `ra`), because their `ret`
does not read the stack; x86_64 pushes a return-address word below the frame,
because its `ret` does.  The trampoline is then one instruction away from the
syscall: pass your own SP.

## Alternatives

- **Carry only what a handler may clobber** (caller-saved registers).  Half the
  size, and correct for a handler that obeys its ABI.  Rejected because it
  makes the interrupted code's fate depend on the handler's discipline, and a
  signal frame is the wrong place to require discipline:
  `docs/fmts/` says unsafe code argues its invariants — this one would be
  argued nowhere.
- **Keep the four-word frame and document the limitation.**  Rejected as the
  same mistake in a different shape: the kernel would be calling it `sigreturn`
  while not restoring anything a signal could have moved.
- **Have the kernel write the trampoline** (a restorer page, as Linux's vDSO
  does).  Attractive — it would make the path reachable by any program — but it
  is a mapping and an ABI decision of its own, not part of restoring a
  context, and the syscall already takes the trampoline's address from the
  program.  Left for an RFC that wants it.

## Drawbacks

- The frame is 5–9 times larger, so a delivery costs more user stack.  A
  process whose stack is nearly full can be delivered a signal it cannot take
  — the delivery validates the region and gives up, so the signal is lost
  rather than the stack corrupted, but it is a real failure mode that a
  four-word frame rarely hit.
- The frame's shape is now a wire format a program can depend on, which is
  what the trampoline is: a change to it later is a change to that contract.

## Compatibility and migration

`SYS_SIGRETURN` (#134) still takes a pointer to the machine's frame, and no
program in the tree passed one, so nothing needed migrating.  The kernel's own
delivery and restore are the only two readers, and they moved together.

## How this is proven

The shell payload's `sigasync` builtin installs an async handler with its own
trampoline, sends itself `SIGUSR1`, and spins in a register that trampoline
clobbers — so the value is only there again if the frame carried it and the
restore put it back.  `scripts/check-x8664-runtime.sh` drives it and requires
three lines: the handler ran, the shell resumed after `sigreturn`, and the
interrupted register survived.

The test is x86_64-only for now.  The aarch64 and RISC-V halves of the payload
compile and are not exercised, and the reason is recorded below rather than
left as a silent gap.

## Implementation note

Writing the test found the defect that had made the whole path unusable on two
of the three machines: delivery wrote the trampoline's address into a stack
slot, which is how x86_64 returns and not how AArch64 or RISC-V do, so a
handler's `ret` there went to whatever the interrupted code had left in its
link register.  That is fixed here (the delivery sets `x30`/`ra`), and the
frame's address is the trampoline's stack pointer on every machine.

The aarch64/riscv64 ports of `sigasync` need the same treatment in their own
payload sections.  The kernel side is done and shared; only the payload half
is x86_64.
