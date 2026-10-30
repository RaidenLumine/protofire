# RFC 0034: Deliver a user exception on riscv64

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-30
- **Supersedes:** none

## Summary

RISC-V was the only machine that did not deliver a user-mode exception to the
handler the program installed: a fault terminated the process instead.  This
adds the third architecture's delivery path — a handler table per thread, a
frame type in the ABI, and the trap-glue branch that hands a fault over — and
it changes nothing the other two already do.  `README.md` no longer calls this
target `Partial`.

## Motivation

`README.md`'s architecture table said `Partial` for
`riscv64gc-unknown-none-elf`, and named exactly one reason:
`ReturnFromException` in `src/arch/riscv64/trap.rs` fell through, so a fault
that a program had installed a handler for was treated as one it had not.
The `SyscallAction::ReturnFromException` arm carried the source comment "RISC-V
doesn't yet support user exception delivery; fall through to set the result".

That is a different failure from a kernel that never implements exceptions.
A program on RISC-V can *install* a handler — syscall 22 was wired and
`install_user_exception_handler` returned `Unsupported`, which a payload can
see — but nothing ever calls it, and the process dies at the first fault.  Two
of the three architectures therefore ran a class of program the third could
not, and the difference was not a hardware limit: RISC-V has `stvec`, `scause`
and `stval` exactly as the other two have their equivalents.

The shared machinery had been in place the whole time.
`src/kernel/process/thread/exception.rs` contains the frame stack, the
nested-delivery policy, the stack-pointer arithmetic and the install
validation, all generic over the frame type — and it named no architecture.
What riscv64 lacked was the things a machine supplies: a frame type in the
ABI, a handler table on the thread, and the trap-glue branch.

## Current state

- `src/kernel/process/thread/exception.rs` — architecture-free.  It knows
  `PendingExceptionFrameStack<CAPACITY>`, `plan_user_exception_delivery`,
  `build_user_exception_delivery`, `install_user_exception_handler_registration`
  and `finish_user_exception_delivery`, and nothing about a machine.
- `src/arch/x86_64/thread.rs` and `src/arch/aarch64/thread.rs` — each holds a
  handler table, a pending-frame stack, a registration type and
  `deliver_*`/`resume_*` functions.  The two are the same shape written twice.
- `src/arch/riscv64/thread.rs` — held a saved context and nothing else.  Its
  module comment said the state existed "so that the `Thread` has the same
  shape on every architecture and adding state later does not mean touching
  the kernel's one struct".
- `src/arch/riscv64/trap.rs` — `riscv64_trap_dispatch` ended every
  synchronous exception that was not a syscall or a resolvable page fault with
  a `[FATAL]` line and a stopped machine.
- `src/abi/exception.rs` — declared `X86_64UserExceptionFrame` and
  `AArch64UserExceptionFrame`, with offsets, and no RISC-V one.
- `src/arch/thread.rs` — `install_user_exception_handler` and
  `user_exception_frame_layout` each answered `Unsupported`/`None` for
  riscv64, in a `cfg(not(any(x86_64, aarch64)))` arm.
- `src/kernel/process/thread/mod.rs` — gated the shared module on
  `any(x86_64, aarch64, test)`, which is why the machinery could be shared
  without being compiled.

## Design

**The frame is the ABI's, and it is the signal frame plus a cause.**
`RiscV64UserExceptionFrame` carries `vector` (the `scause` code), `error_code`
(`stval`), `fault_address`, `regs` (`x1`..`x31` in
`RISCV64_SIGNAL_FRAME_REGS` order), `instruction_pointer` and
`saved_program_status`.  The register block is the same order the signal
frame uses, because both are "the context to resume in" and two orders for
one thing is a conversion at every use site.  The two CSRs are the pair an
`sret` needs.

**The thread gets the state the other two have.** `RiscV64UserThreadState`
gains `exception_handlers` (16 slots, indexed by `scause` code — the highest
delivered code is 15, so the table is sized to the code space rather than to a
round number) and `pending_exception_frames`.  `clear` drops both, `snapshot`
takes them, `restore` puts them back, and `validate` checks the context — each
of which the other two already did and riscv64 had no reason not to.

**The delivered codes are the faults a program can meaningfully handle**:
instruction-address-misaligned, instruction-access-fault,
instruction-page-fault, load- and store-address-misaligned, load- and
store-access-fault, load- and store-page-fault.  `illegal-instruction` and
`breakpoint` are *not* delivered: the first is what a bad program does, not
what it handles, and the second is how a debugger stops it.  An install for a
code outside the set answers `Unsupported`, which is the same answer the other
two give for a vector they do not deliver.

**The trap path asks the program before it stops the machine.** After the two
answers the kernel already knew how to give — "this is a syscall" and "this
page fault is demand-paging or copy-on-write" — a synchronous exception from
user mode goes to `deliver_user_exception`, which looks up the thread's
handler for that `scause` code and, if there is one, rewrites the trap frame
to enter it.  Only when there is no handler does the `[FATAL]` line still
print, which is the old behaviour and now the correct one: a fault nobody
registered for is a fault nobody can handle.

**`ReturnFromException` resumes.** The handler calls `return_from_exception`
with the frame pointer, the kernel reads the frame back from the user stack —
it is the handler's memory, so it is re-validated rather than trusted — and
both the thread's saved context and the trap frame are set from it.  The
frame pointer must name the delivery at the top of the pending stack; one that
does not is `InvalidArgument`, not a silent success.

**Delivery is split so a host can drive it.** `deliver_riscv64_user_exception`
reads a trap frame; `deliver_riscv64_user_exception_from_context` takes the
resumed context and returns the handler's.  The second is what the host tests
call, and it is the same split `aarch64` uses.  Without it the only evidence
would be the boot, and a boot is not where handler-table indexing gets
debugged.

## Alternatives

**Leave it `Partial`.** The honest option, and the one the tree had been
taking.  It loses because the reason was an unfinished branch rather than a
machine that cannot do the thing, and because the gap was invisible from
inside the tree: a program that installed a handler got a success back and
then died at the fault it was handling.

**Deliver every `scause` code.** Simpler to state, and wrong: `breakpoint` is
how a debugger stops a program, and a program that can handle it can swallow
its own trace traps.  `U64` gives the same answer for `illegal-instruction`,
and a machine that lets a program resume from one has no answer for the
instruction it did not understand.

**Reuse the signal frame instead of adding a frame type.** The signal frame
carries the register block and the two CSRs but not `scause`/`stval`, and a
handler needs the cause to decide what to do.  Adding two fields to the signal
frame would change a format `sigreturn` already reads, for a purpose
`sigreturn` does not have.

**Give the frame the x86_64 shape** (`vector`, `error_code`, then named
registers, then IP/SP/status).  The ABI is per-architecture already — the
aarch64 frame names `x0`..`x30` and the x86_64 one names `rax`..`r15` — so
there is no cross-machine shape to match, and RISC-V's own register names are
the honest ones.

## Drawbacks

`RiscV64UserThreadState` is now as large as the other two, and every riscv64
thread carries two `Mutex`es it will usually never hold anything in.  That is
the same cost the other two pay, and the alternative — an allocated table that
exists only when used — is a heap allocation on the path that terminates a
process.

`deliver_riscv64_user_exception_from_context` returns `Result<Option<..>>`
where `Result<bool>` would do, because the handler's context has to come back
to the caller.  That is one more thing to forget to check, and the trap-frame
wrapper is where it is checked once.

The payload that proves delivery works is a fault the demo triggers *on
purpose*, so every boot now takes one store-page-fault round trip it did not
take before.  Measured on a single boot, the extra line appears between
`resume-2` and the exit; it does not move the run past its 30-second timeout.

## Compatibility and migration

Additive in the ABI: a new frame type and new constants, no change to an
existing record.  A program that does not install a handler behaves exactly as
it did — its faults still terminate it, with the same `[FATAL]` line.

The one behaviour change is for a program that *does* install a handler and
then faults: it now runs the handler instead of dying.  Nothing in the tree
did that on riscv64 before this, because the install answered `Unsupported`.

`src/kernel/process/thread/mod.rs` loses its architecture gate entirely.  The
module holds no architecture-specific code, so the gate was gating the shared
machinery for a reason the shared machinery did not have; `check-arch-fanout`
recorded the row as a `fact:` ("riscv64 has no such path") which stopped being
true, and the row is gone rather than renumbered.

## How this is proven

**The boot, which is the only evidence the trap glue ran.**
`make check-riscv64-runtime` now requires three lines from the demo payload:

```text
[user  ] riscv64 triggering local store fault
delivered riscv64 exception store-page-fault to handler pid=
[user  ] riscv64 resumed after local store fault
```

The first says the store happened, the second is the kernel's own record of
handing the fault over, and the third can only be printed by code that ran
after the fault — the handler skipped the faulting instruction and the process
continued to its exit 42.  Disabling delivery in the trap path was measured:
the same boot then prints `[FATAL] riscv64 trap scause=0xf` and never reaches
the third line, which is the old behaviour reproduced rather than described.

**The host tests, for the half a host can hold still.** Seven assertions in
`src/kernel/process/thread/tests.rs` cover the install (recorded, refused for
a code outside the set, zero clears it), the frame round trip (`regs`,
`instruction_pointer` and `saved_program_status` in and out), the delivery
bookkeeping (a frame is placed below the interrupted stack pointer, the
pending depth rises, a pointer that is not the delivered one is refused), the
decline path, and nested delivery.  Every one was mutation-tested: dropping
the delivery bookkeeping fails the depth assertion with `left: 0, right: 1`,
dropping the vector gate fails the refusal test, and making
`PendingExceptionFrameStack::names_top` accept any pointer fails both the
nested test and the delivery-bookkeeping one.

`names_top` is the shape that mutation test found: the rule "this pointer is
the delivery at the top" was written once at the resume call site and again
inside `pop_expected`, so a mutation to either left the other covering for it
and the tests stayed green.  The rule now has one home on the stack type and
both callers ask it, which is why the mutation bites.

**The ABI layout**, in `src/abi/exception.rs`: the offsets a user handler
decodes are pinned, and the flags are asserted equal to the
architecture-neutral set the other two already match.

## Unresolved questions

**Nested delivery has host tests but no boot.** The pending stack, the
`ALLOW_NESTED` flag and the `Blocked` answer are exercised by
`riscv64_nested_delivery_follows_the_two_flags`, which walks all three flag
combinations and checks that returns unwind in LIFO order — but no riscv64
payload triggers a fault inside its own handler, so the boot half is
unverified.  aarch64 has such a demo
(`demo_program_aarch64_fault_payload.S` resumes from three faults including a
nested one); riscv64 has one fault and one resume.  Adding the nested case is
a payload change, not a kernel one, and it is the next thing this row should
gain.

The test also records a rule the install enforces and this RFC does not
otherwise state: `ALLOW_NESTED` is refused unless
`REQUIRE_EXCEPTION_STACK` is set too.  Nested delivery on the interrupted
program's own stack would let the inner handler trample it, so the two flags
travel together and a registration with only the first is `InvalidArgument`.

**`error_code` carries `stval` for every delivered code, including the ones
where it is not an address.** For a page fault it is the faulting address, and
that is the case the frame's `fault_address` field is for.  For an access
fault or a misaligned access it is also an address; for the codes that have no
such value it is zero.  A handler that reads it as an address for a code that
does not carry one sees a zero rather than an error, and nothing currently
tells it which case it is in beyond `vector`.
